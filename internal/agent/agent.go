package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DragonSecurity/drill/pkg/proto"
	"github.com/DragonSecurity/drill/pkg/util"
	"github.com/gorilla/websocket"
)

type Config struct {
	Tenant             string            `mapstructure:"tenant"`
	ID                 string            `mapstructure:"id"`
	Server             string            `mapstructure:"server"`
	Auth               string            `mapstructure:"auth"`
	To                 string            `mapstructure:"to"`
	WebTargets         map[string]string `mapstructure:"web_targets"`
	TCPTargets         map[string]string `mapstructure:"tcp_targets"`
	UDPTargets         map[string]string `mapstructure:"udp_targets"`
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify"`
}

type LoggerLike interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

func Run(ctx context.Context, cfg Config, log *util.Logger) error {
	ctlURL := strings.TrimRight(cfg.Server, "/") + "/_control"
	q := url.Values{}
	if cfg.Tenant != "" {
		q.Set("tenant", cfg.Tenant)
	}
	if cfg.Auth != "" {
		q.Set("auth", cfg.Auth)
	}
	if cfg.ID != "" {
		q.Set("id", cfg.ID)
	}
	u, _ := url.Parse(ctlURL)
	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	u.Scheme = scheme
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}}
	c, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			log.Errorf("ws dial failed: %s (resp: %s)", err, string(b))
		}
		return fmt.Errorf("ws dial failed: %w", err)
	}
	log.Infof("connected. exposing local %s", cfg.To)

	// Send register
	reg := &proto.Register{ID: cfg.ID, Tenant: cfg.Tenant, To: cfg.To, WebTargets: cfg.WebTargets, TCPTargets: cfg.TCPTargets, UDPTargets: cfg.UDPTargets}
	_ = c.WriteJSON(&proto.Envelope{Type: "register", Register: reg})

	a := &agent{cfg: cfg, log: log, c: c, httpc: &http.Client{Timeout: 25 * time.Second}}
	return a.run(ctx)
}

type agent struct {
	cfg   Config
	log   *util.Logger
	c     *websocket.Conn
	httpc *http.Client

	tcpMu sync.Mutex
	tcp   map[string]net.Conn // connID -> conn
}

func (a *agent) run(ctx context.Context) error {
	a.tcp = map[string]net.Conn{}
	for {
		var env proto.Envelope
		if err := a.c.ReadJSON(&env); err != nil {
			return err
		}
		switch env.Type {
		case "http_request":
			go a.handleHTTP(env.RequestID, env.Service, env.Request)
		case "tcp_open":
			go a.handleTCPOpen(env.ConnID, env.Service)
		case "tcp_data":
			a.tcpMu.Lock()
			conn := a.tcp[env.ConnID]
			a.tcpMu.Unlock()
			if conn != nil && len(env.Data) > 0 {
				_, _ = conn.Write(env.Data)
			}
		case "tcp_close":
			a.tcpMu.Lock()
			conn := a.tcp[env.ConnID]
			delete(a.tcp, env.ConnID)
			a.tcpMu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
		}
	}
}

func (a *agent) handleHTTP(reqID, service string, req *proto.Request) {
	target := a.cfg.To
	if service != "" && a.cfg.WebTargets != nil {
		if t, ok := a.cfg.WebTargets[service]; ok {
			target = t
		}
	}
	if target == "" {
		_ = a.c.WriteJSON(&proto.Envelope{Type: "http_response", RequestID: reqID, Response: &proto.Response{Status: 502, Error: "no target"}})
		return
	}
	base, err := url.Parse(target)
	if err != nil {
		_ = a.c.WriteJSON(&proto.Envelope{Type: "http_response", RequestID: reqID, Response: &proto.Response{Status: 502, Error: err.Error()}})
		return
	}
	up := *base
	up.Path = singleJoin(base.Path, req.Path)
	up.RawQuery = req.RawQuery
	httpReq, _ := http.NewRequest(req.Method, up.String(), io.NopCloser(strings.NewReader(string(req.Body))))
	for k, vv := range req.Header {
		for _, v := range vv {
			httpReq.Header.Add(k, v)
		}
	}
	httpReq.Header.Del("Accept-Encoding")
	resp, err := a.httpc.Do(httpReq)
	if err != nil {
		_ = a.c.WriteJSON(&proto.Envelope{Type: "http_response", RequestID: reqID, Response: &proto.Response{Status: 502, Error: err.Error()}})
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	rhead := map[string][]string(resp.Header)
	_ = a.c.WriteJSON(&proto.Envelope{Type: "http_response", RequestID: reqID, Response: &proto.Response{Status: resp.StatusCode, Header: rhead, Body: b}})
}

func singleJoin(a, b string) string {
	if strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/") {
		return a + strings.TrimPrefix(b, "/")
	}
	if !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/") {
		return a + "/" + b
	}
	return a + b
}

func (a *agent) handleTCPOpen(connID, service string) {
	target, ok := a.cfg.TCPTargets[service]
	if !ok {
		_ = a.c.WriteJSON(&proto.Envelope{Type: "tcp_close", ConnID: connID})
		return
	}
	conn, err := net.Dial("tcp", target)
	if err != nil {
		_ = a.c.WriteJSON(&proto.Envelope{Type: "tcp_close", ConnID: connID})
		return
	}
	a.tcpMu.Lock()
	a.tcp[connID] = conn
	a.tcpMu.Unlock()
	// Pump local->remote
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				// Copy data to new slice to avoid race
				d := make([]byte, n)
				copy(d, buf[:n])
				_ = a.c.WriteJSON(&proto.Envelope{Type: "tcp_data", ConnID: connID, Data: d})
			}
			if err != nil {
				_ = a.c.WriteJSON(&proto.Envelope{Type: "tcp_close", ConnID: connID})
				_ = conn.Close()
				a.tcpMu.Lock()
				delete(a.tcp, connID)
				a.tcpMu.Unlock()
				return
			}
		}
	}()
}
