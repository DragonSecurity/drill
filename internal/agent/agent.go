package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DragonSecurity/drill/pkg/proto"
	"github.com/DragonSecurity/drill/pkg/util"
)

type Config struct {
	ID        string
	AuthToken string
	ServerURL string // e.g., http://localhost:8080 or https://getexposed.io
	LocalTo   string // e.g., http://127.0.0.1:3000
}

// safeWS serializes writes to a websocket.Conn
type safeWS struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (s *safeWS) WriteJSON(v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c.WriteJSON(v)
}

func Run(ctx context.Context, cfg Config, log *util.Logger) error {
	if cfg.ServerURL == "" {
		return errors.New("missing --server")
	}
	if cfg.LocalTo == "" {
		return errors.New("missing --to")
	}

	serverBase, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}
	localBase, err := url.Parse(cfg.LocalTo)
	if err != nil {
		return fmt.Errorf("invalid --to url: %w", err)
	}

	ctrl := *serverBase
	ctrl.Path = path.Join(ctrl.Path, "/_control")
	q := ctrl.Query()
	if cfg.ID != "" {
		q.Set("id", cfg.ID)
	}
	if cfg.AuthToken != "" {
		q.Set("auth", cfg.AuthToken)
	}
	ctrl.RawQuery = q.Encode()

	// WebSocket schemes must be ws/wss, not http/https.
	wsCtrl := ctrl
	if serverBase.Scheme == "https" {
		wsCtrl.Scheme = "wss"
	} else {
		wsCtrl.Scheme = "ws"
	}

	log.Infof("dialing control: %s", wsCtrl.String())

	tlsSkip := serverBase.Scheme == "https" && (strings.Contains(serverBase.Host, "localhost") || strings.HasSuffix(serverBase.Host, ".local"))
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: tlsSkip},
		HandshakeTimeout: 10 * time.Second,
	}
	c, _, err := dialer.DialContext(ctx, wsCtrl.String(), nil)
	if err != nil {
		return fmt.Errorf("ws dial failed: %w", err)
	}
	defer c.Close()

	s := &safeWS{c: c}

	// Identify (optional)
	if cfg.ID != "" || cfg.AuthToken != "" {
		reg := &proto.Register{ID: cfg.ID, Token: cfg.AuthToken}
		env, _ := proto.Wrap("register", reg)
		_ = s.WriteJSON(env)
	}

	log.Infof("connected. exposing local %s", localBase.String())

	// read loop for requests
	for {
		var env proto.Envelope
		if err := c.ReadJSON(&env); err != nil {
			return err
		}
		switch env.Type {
		case "request":
			var req proto.Request
			if err := json.Unmarshal(env.Payload, &req); err != nil {
				log.Errorf("bad request payload: %v", err)
				continue
			}
			go handleRequest(s, &req, localBase, log)
		default:
			// ignore
		}
	}
}

func handleRequest(ws *safeWS, req *proto.Request, localBase *url.URL, log *util.Logger) {
	start := time.Now()
	resp := &proto.Response{
		TunnelID:  req.TunnelID,
		RequestID: req.RequestID,
		Status:    502,
		Header:    map[string][]string{},
	}
	defer func() {
		env, _ := proto.Wrap("response", resp)
		_ = ws.WriteJSON(env)
		log.Infof("%s %s -> %d (%s)", req.Method, req.Path, resp.Status, time.Since(start))
	}()

	// Build local URL
	u := *localBase
	u.Path = singleJoiningSlash(localBase.Path, req.Path)
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
	// Always set Host to local target's host
	httpReq.Host = localBase.Host

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

// lifted from net/http/httputil to join path segments
func singleJoiningSlash(a, b string) string {
	slashA := strings.HasSuffix(a, "/")
	slashB := strings.HasPrefix(b, "/")
	switch {
	case slashA && slashB:
		return a + b[1:]
	case !slashA && !slashB:
		return a + "/" + b
	}
	return a + b
}
