package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	prom "github.com/prometheus/client_golang/prometheus"
	promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme/autocert"

	"github.com/DragonSecurity/drill/pkg/proto"
	"github.com/DragonSecurity/drill/pkg/util"
)

type ACMEConfig struct {
	Enable   bool
	Email    string
	CacheDir string
}

type AuthConfig struct {
	Enable bool
	Token  string // simple shared token for agents
}

type Config struct {
	PublicAddr string
	DomainBase string // e.g., "getexposed.io"
	ACME       ACMEConfig
	Auth       AuthConfig
}

// Metrics
var (
	metricActiveTunnels = prom.NewGauge(prom.GaugeOpts{
		Name: "drill_active_tunnels",
		Help: "Number of currently connected tunnels.",
	})
	metricRequestsTotal = prom.NewCounterVec(prom.CounterOpts{
		Name: "drill_requests_total",
		Help: "Total number of proxied requests to agents.",
	}, []string{"tunnel", "method"})
	metricRequestDuration = prom.NewHistogramVec(prom.HistogramOpts{
		Name:    "drill_request_seconds",
		Help:    "Duration of proxied requests.",
		Buckets: prom.DefBuckets,
	}, []string{"tunnel", "method", "status"})
)

func init() {
	prom.MustRegister(metricActiveTunnels, metricRequestsTotal, metricRequestDuration)
}

type wsConn struct {
	c   *websocket.Conn
	wmu sync.Mutex
}

func (w *wsConn) ReadEnvelope() (*proto.Envelope, error) {
	var env proto.Envelope
	if err := w.c.ReadJSON(&env); err != nil {
		return nil, err
	}
	return &env, nil
}
func (w *wsConn) WriteEnvelope(env *proto.Envelope) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteJSON(env)
}
func (w *wsConn) Close() error { return w.c.Close() }

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1 << 14,
	WriteBufferSize: 1 << 14,
	CheckOrigin:     func(r *http.Request) bool { return true }, // TODO: tighten allowed origins
}

func Run(ctx context.Context, cfg Config, log *util.Logger) error {
	mgr := NewManager()
	r := routes(cfg, mgr, log)

	if cfg.ACME.Enable {
		return runWithACME(ctx, cfg, r, log)
	}
	// Plain HTTP mode (dev)
	srv := &http.Server{
		Addr:              cfg.PublicAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return serveAndWait(ctx, srv, log)
}

func routes(cfg Config, mgr *Manager, log *util.Logger) http.Handler {
	r := chi.NewRouter()
	// Health and metrics
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	r.Handle("/metrics", promhttp.Handler())

	// Control plane (agent connects here)
	r.Get("/_control", func(w http.ResponseWriter, r *http.Request) {
		authOK := true
		if cfg.Auth.Enable {
			want := strings.TrimSpace(cfg.Auth.Token)
			got := strings.TrimSpace(r.URL.Query().Get("auth"))
			if want == "" || got != want {
				authOK = false
			}
		}
		if !authOK {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized: bad agent token"))
			return
		}

		id := r.URL.Query().Get("id")
		if id == "" {
			id = randomID()
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Errorf("ws upgrade: %v", err)
			return
		}
		conn := &wsConn{c: c}
		t := &Tunnel{ID: id, Conn: conn, pending: make(map[string]*pendingResp)}
		mgr.Add(t)
		metricActiveTunnels.Inc()
		log.Infof("agent connected: %s", id)

		go t.runReader(func() {
			mgr.Remove(id)
			metricActiveTunnels.Dec()
			log.Infof("agent disconnected: %s", id)
		})
	})

	// Path-based routing: /t/{id}/*
	r.Route("/t/{id}", func(rr chi.Router) {
		rr.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
			handlePublicRequest(r.Context(), w, r, mgr, cfg, log, chi.URLParam(r, "id"), true)
		})
		rr.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			handlePublicRequest(r.Context(), w, r, mgr, cfg, log, chi.URLParam(r, "id"), true)
		})
	})

	// Host-based routing: {id}.<domain-base>
	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		id := tunnelIDFromHost(r.Host, cfg.DomainBase)
		if id == "" {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body><h3>drill server</h3><ul>` +
				`<li>Health: <a href="/healthz">/healthz</a></li>` +
				`<li>Metrics: <a href="/metrics">/metrics</a></li>` +
				`</ul><p>Agent connected? Use <code>/t/{id}/</code> or host <code>{id}.` + cfg.DomainBase + `</code></p></body></html>`))
			return
		}
		handlePublicRequest(r.Context(), w, r, mgr, cfg, log, id, false)
	})
	return r
}

func runWithACME(ctx context.Context, cfg Config, h http.Handler, log *util.Logger) error {
	// Autocert manager: allow apex and any subdomain of DomainBase.
	policy := func(ctx context.Context, host string) error {
		if sameHost(host, cfg.DomainBase) {
			return nil
		}
		if strings.HasSuffix(host, "."+cfg.DomainBase) {
			return nil
		}
		return errors.New("host not allowed by policy")
	}
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: policy,
		Email:      cfg.ACME.Email,
		Cache:      autocert.DirCache(cfg.ACME.CacheDir),
	}

	// HTTP server on :80 for challenges + redirect to HTTPS.
	httpSrv := &http.Server{
		Addr: ":80",
		Handler: mgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			to := "https://" + hostOnly(r.Host) + r.URL.RequestURI()
			http.Redirect(w, r, to, http.StatusMovedPermanently)
		})),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Prepare a fallback self-signed cert for the apex to avoid noisy "missing server name" errors
	fallbackCert, err := selfSignedCert(cfg.DomainBase)
	if err != nil {
		log.Errorf("self-signed cert generation failed: %v", err)
	}

	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			if fallbackCert != nil {
				return fallbackCert, nil
			}
			return nil, errors.New("missing SNI (ServerName)")
		}
		return mgr.GetCertificate(hello)
	}

	// HTTPS server on cfg.PublicAddr (default :443)
	httpsSrv := &http.Server{
		Addr:    cfg.PublicAddr,
		Handler: h,
		TLSConfig: &tls.Config{
			GetCertificate: getCert,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Run both
	errCh := make(chan error, 2)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	go func() { errCh <- httpsSrv.ListenAndServeTLS("", "") }()

	log.Infof("ACME enabled: serving HTTP on :80 (redirect+challenges), HTTPS on %s; domainBase=%s", cfg.PublicAddr, cfg.DomainBase)

	select {
	case <-ctx.Done():
		_ = httpSrv.Shutdown(context.Background())
		_ = httpsSrv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func serveAndWait(ctx context.Context, srv *http.Server, log *util.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		log.Infof("listening on %s (domainBase=%s)", srv.Addr, "(dev)")
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Infof("shutting down...")
		_ = srv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func handlePublicRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, mgr *Manager, cfg Config, log *util.Logger, id string, stripPrefix bool) {
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing tunnel id"))
		return
	}
	tun, err := mgr.Get(id)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("no agent connected for tunnel: " + id))
		return
	}

	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
	_ = r.Body.Close()

	path := r.URL.Path
	if stripPrefix {
		prefix := "/t/" + id
		path = strings.TrimPrefix(path, prefix)
		if path == "" {
			path = "/"
		}
	}

	req := &proto.Request{
		TunnelID:  id,
		RequestID: randomID(),
		Method:    r.Method,
		Path:      path,
		RawQuery:  r.URL.RawQuery,
		Header:    filterHeaders(r.Header),
		Body:      body,
	}

	start := time.Now()
	resp, err := tun.sendRequest(req, 30*time.Second)
	dur := time.Since(start).Seconds()
	if err != nil {
		metricRequestsTotal.WithLabelValues(id, r.Method).Inc()
		metricRequestDuration.WithLabelValues(id, r.Method, "bad_gateway").Observe(dur)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("tunnel write failed: " + err.Error()))
		return
	}

	metricRequestsTotal.WithLabelValues(id, r.Method).Inc()
	metricRequestDuration.WithLabelValues(id, r.Method, fmt.Sprintf("%d", resp.Status)).Observe(dur)

	if resp.Error != "" {
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte(resp.Error))
		return
	}

	for k, vv := range sanitizeRespHeaders(resp.Header) {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if resp.Status == 0 {
		resp.Status = 200
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func filterHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		if hopByHop[lk] {
			continue
		}
		if lk == "host" {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func sanitizeRespHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		if hopByHop[lk] {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

var hopByHop = map[string]bool{
	"connection":        true,
	"proxy-connection":  true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"te":                true,
	"trailer":           true,
	"upgrade":           true,
}

func tunnelIDFromHost(hostport, base string) string {
	host := hostOnly(hostport)
	if !strings.HasSuffix(host, "."+base) {
		return ""
	}
	left := strings.TrimSuffix(host, "."+base)
	if left == "" {
		return ""
	}
	return left
}

func hostOnly(hostport string) string {
	h := hostport
	if i := strings.Index(hostport, ":"); i >= 0 {
		h = hostport[:i]
	}
	return h
}

func sameHost(a, b string) bool {
	return strings.EqualFold(hostOnly(a), hostOnly(b))
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// selfSignedCert creates a short-lived self-signed certificate for fallback/no-SNI handshakes.
func selfSignedCert(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

// Optional: debug helper to dump incoming requests through the server.
func dumpReq(r *http.Request) string {
	b, _ := httputil.DumpRequest(r, true)
	return string(b)
}
