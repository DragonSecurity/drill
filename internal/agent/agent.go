package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/DragonSecurity/drill/pkg/proto"
	"github.com/DragonSecurity/drill/pkg/util"
	"github.com/gorilla/websocket"
)

type Config struct {
	Tenant     string
	ID         string
	AuthToken  string
	ServerURL  string
	LocalTo    string
	WebTargets map[string]string
	TCPTargets map[string]string
	UDPTargets map[string]string
}

type safeWS struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (s *safeWS) WriteJSON(v any) error { s.mu.Lock(); defer s.mu.Unlock(); return s.c.WriteJSON(v) }

type tcpLocal struct {
	conn     net.Conn
	id, dest string
}

func Run(ctx context.Context, cfg Config, log *util.Logger) error {
	if cfg.ServerURL == "" {
		return errors.New("missing --server")
	}
	if cfg.LocalTo == "" {
		cfg.LocalTo = "http://127.0.0.1:3000"
	}
	serverBase, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}
	localHTTP, err := url.Parse(cfg.LocalTo)
	if err != nil {
		return fmt.Errorf("invalid --to url: %w", err)
	}

	ctrl := *serverBase
	ctrl.Path = path.Join(ctrl.Path, "/_control")
	q := ctrl.Query()
	if cfg.Tenant != "" {
		q.Set("tenant", cfg.Tenant)
	}
	if cfg.ID != "" {
		q.Set("id", cfg.ID)
	}
	if cfg.AuthToken != "" {
		q.Set("auth", cfg.AuthToken)
	}
	ctrl.RawQuery = q.Encode()
	wsCtrl := ctrl
	if serverBase.Scheme == "https" {
		wsCtrl.Scheme = "wss"
	} else {
		wsCtrl.Scheme = "ws"
	}

	log.Infof("dialing control: %s", wsCtrl.String())
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: serverBase.Scheme == "https" && (strings.Contains(serverBase.Host, "localhost") || strings.HasSuffix(serverBase.Host, ".local"))}, HandshakeTimeout: 10 * time.Second}
	c, _, err := dialer.DialContext(ctx, wsCtrl.String(), nil)
	if err != nil {
		return fmt.Errorf("ws dial failed: %w", err)
	}
	defer c.Close()
	s := &safeWS{c: c}

	log.Infof("connected. HTTP %s | web_targets=%d | TCP=%d | UDP=%d", localHTTP.String(), len(cfg.WebTargets), len(cfg.TCPTargets), len(cfg.UDPTargets))

	parsedWeb := map[string]*url.URL{}
	for name, raw := range cfg.WebTargets {
		if u, err := url.Parse(raw); err == nil {
			parsedWeb[name] = u
		}
	}

	tcpMap := struct {
		sync.Mutex
		m map[string]*tcpLocal
	}{m: make(map[string]*tcpLocal)}

	for {
		var env proto.Envelope
		if err := c.ReadJSON(&env); err != nil {
			return err
		}
		switch env.Type {
		case "request":
			var req proto.Request
			if json.Unmarshal(env.Payload, &req) != nil {
				continue
			}
			go handleHTTPRequest(s, &req, localHTTP, parsedWeb, log)
		case "tcp_open":
			var open proto.TCPOpen
			if json.Unmarshal(env.Payload, &open) != nil {
				continue
			}
			dest := cfg.TCPTargets[open.TunnelID]
			if dest == "" {
				dest = localHTTP.Host
			}
			go func(streamID, id, dst string) {
				conn, err := net.DialTimeout("tcp", dst, 10*time.Second)
				if err != nil {
					cl := &proto.TCPClose{TunnelID: id, StreamID: streamID, Reason: err.Error()}
					env, _ := proto.Wrap("tcp_close", cl)
					_ = s.WriteJSON(env)
					return
				}
				tcpMap.Lock()
				tcpMap.m[streamID] = &tcpLocal{conn: conn, id: streamID, dest: dst}
				tcpMap.Unlock()
				buf := make([]byte, 32*1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						env, _ := proto.Wrap("tcp_data", &proto.TCPData{TunnelID: id, StreamID: streamID, Data: append([]byte(nil), buf[:n]...)})
						_ = s.WriteJSON(env)
					}
					if err != nil {
						_ = conn.Close()
						cl := &proto.TCPClose{TunnelID: id, StreamID: streamID, Reason: errString(err)}
						env, _ := proto.Wrap("tcp_close", cl)
						_ = s.WriteJSON(env)
						tcpMap.Lock()
						delete(tcpMap.m, streamID)
						tcpMap.Unlock()
						return
					}
				}
			}(open.StreamID, open.TunnelID, dest)
		case "tcp_data":
			var d proto.TCPData
			if json.Unmarshal(env.Payload, &d) != nil {
				continue
			}
			tcpMap.Lock()
			st := tcpMap.m[d.StreamID]
			tcpMap.Unlock()
			if st != nil {
				_, _ = st.conn.Write(d.Data)
			}
		case "tcp_close":
			var cl proto.TCPClose
			if json.Unmarshal(env.Payload, &cl) != nil {
				continue
			}
			tcpMap.Lock()
			st := tcpMap.m[cl.StreamID]
			delete(tcpMap.m, cl.StreamID)
			tcpMap.Unlock()
			if st != nil {
				_ = st.conn.Close()
			}
		case "udp":
			var d proto.UDPDatagram
			if json.Unmarshal(env.Payload, &d) != nil {
				continue
			}
			dst := cfg.UDPTargets[d.TunnelID]
			if dst == "" {
				continue
			}
			laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
			raddr, err := net.ResolveUDPAddr("udp", dst)
			if err != nil {
				continue
			}
			uc, err := net.DialUDP("udp", laddr, raddr)
			if err != nil {
				continue
			}
			_, _ = uc.Write(d.Data)
			_ = uc.SetReadDeadline(time.Now().Add(1 * time.Second))
			buf := make([]byte, 65535)
			n, _, err := uc.ReadFromUDP(buf)
			if err == nil && n > 0 {
				reply := &proto.UDPDatagram{TunnelID: d.TunnelID, Client: d.Client, Direction: "to_client", Data: append([]byte(nil), buf[:n]...)}
				env, _ := proto.Wrap("udp", reply)
				_ = s.WriteJSON(env)
			}
			_ = uc.Close()
		default:
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func handleHTTPRequest(ws *safeWS, req *proto.Request, localBase *url.URL, web map[string]*url.URL, log *util.Logger) {
	start := time.Now()
	resp := &proto.Response{TunnelID: req.TunnelID, RequestID: req.RequestID, Status: 502, Header: map[string][]string{}}
	defer func() {
		env, _ := proto.Wrap("response", resp)
		_ = ws.WriteJSON(env)
		log.Infof("%s %s -> %d (%s)", req.Method, req.Path, resp.Status, time.Since(start))
	}()
	base := localBase
	if req.Service != "" {
		if wu, ok := web[req.Service]; ok {
			base = wu
		}
	}
	u := *base
	u.Path = singleJoiningSlash(base.Path, req.Path)
	u.RawQuery = req.RawQuery
	httpReq, err := http.NewRequest(req.Method, u.String(), io.NopCloser(bytes.NewReader(req.Body)))
	if err != nil {
		resp.Error = err.Error()
		return
	}
	for k, v := range req.Header {
		for _, vv := range v {
			httpReq.Header.Add(k, vv)
		}
	}
	httpReq.Host = base.Host
	client := &http.Client{Timeout: 25 * time.Second}
	localResp, err := client.Do(httpReq)
	if err != nil {
		resp.Error = err.Error()
		return
	}
	defer localResp.Body.Close()
	resp.Status = localResp.StatusCode
	for k, v := range localResp.Header {
		resp.Header[k] = append([]string(nil), v...)
	}
	b, _ := io.ReadAll(localResp.Body)
	resp.Body = b
}
func singleJoiningSlash(a, b string) string {
	sa := strings.HasSuffix(a, "/")
	sb := strings.HasPrefix(b, "/")
	switch {
	case sa && sb:
		return a + b[1:]
	case !sa && !sb:
		return a + "/" + b
	default:
		return a + b
	}
}
