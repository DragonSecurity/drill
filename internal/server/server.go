package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DragonSecurity/drill/internal/server/tenancy"
	"github.com/DragonSecurity/drill/pkg/proto"
	"github.com/DragonSecurity/drill/pkg/util"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	prom "github.com/prometheus/client_golang/prometheus"
	promhttp "github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type ACMEConfig struct {
	Enable          bool   `mapstructure:"enable"`
	Email           string `mapstructure:"email"`
	CacheDir        string `mapstructure:"cache"`
	Challenge       string `mapstructure:"challenge"`
	DNSProvider     string `mapstructure:"dns_provider"`
	CA              string `mapstructure:"ca"`
	CloudflareToken string `mapstructure:"cloudflare_token"`
}
type AuthConfig struct {
	Enable bool
	Token  string
}
type TenancyConfig struct {
	Enable  bool
	Storage string
}
type AdminConfig struct {
	Enable bool
	Token  string
}

type Config struct {
	PublicAddr string
	DomainBase string
	ACME       ACMEConfig
	Auth       AuthConfig
	Tenancy    TenancyConfig
	Admin      AdminConfig
	SNI        SNIConfig
}

var (
	metricActiveTunnels = prom.NewGauge(prom.GaugeOpts{Name: "drill_active_tunnels", Help: "active tunnels"})
	metricRequestsTotal = prom.NewCounterVec(prom.CounterOpts{Name: "drill_requests_total", Help: "HTTP requests"}, []string{"tunnel", "method"})
	metricRequestSecs   = prom.NewHistogramVec(prom.HistogramOpts{Name: "drill_request_seconds", Help: "HTTP duration"}, []string{"tunnel", "method", "status"})
)

func init() { prom.MustRegister(metricActiveTunnels, metricRequestsTotal, metricRequestSecs) }

type wsConn struct {
	c   *websocket.Conn
	wmu sync.Mutex
}

func (w *wsConn) ReadEnvelope() (*proto.Envelope, error) {
	var e proto.Envelope
	if err := w.c.ReadJSON(&e); err != nil {
		return nil, err
	}
	return &e, nil
}
func (w *wsConn) WriteEnvelope(e *proto.Envelope) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteJSON(e)
}
func (w *wsConn) Close() error { return w.c.Close() }

var upgrader = websocket.Upgrader{ReadBufferSize: 1 << 14, WriteBufferSize: 1 << 14, CheckOrigin: func(r *http.Request) bool { return true }}

type ServerDeps struct {
	ctx context.Context
	mgr *Manager
	log *util.Logger
}

func Run(ctx context.Context, cfg Config, log *util.Logger) error {
	mgr := NewManager()
	reg := NewBindRegistry(ctx, mgr, log)

	var store *tenancy.Store
	if cfg.Tenancy.Enable {
		store = tenancy.NewStore(cfg.Tenancy.Storage)
		if err := store.Load(); err != nil {
			return err
		}
	}

	r := routesWithRegistry(cfg, mgr, store, reg, log)

	deps := &ServerDeps{ctx: ctx, mgr: mgr, log: log}

	if cfg.SNI.Enable {
		go func() { _ = runSNIGateway(ctx, cfg, deps) }()
	}

	if cfg.ACME.Enable {
		if strings.EqualFold(cfg.ACME.Challenge, "dns-01") {
			return runWithCertMagic(ctx, cfg, r, log, store)
		}
		return runWithACME(ctx, cfg, r, log, store)
	}
	srv := &http.Server{Addr: cfg.PublicAddr, Handler: r, ReadHeaderTimeout: 10 * time.Second}
	return serveAndWait(ctx, srv, log)
}

func routesWithRegistry(cfg Config, mgr *Manager, store *tenancy.Store, reg *BindRegistry, log *util.Logger) http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	r.Handle("/metrics", promhttp.Handler())

	r.Get("/_control", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("tenant")
		if cfg.Tenancy.Enable {
			if tenant == "" || store == nil || !store.Validate(tenant, r.URL.Query().Get("auth")) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("unauthorized"))
				return
			}
		} else if cfg.Auth.Enable {
			if strings.TrimSpace(r.URL.Query().Get("auth")) != strings.TrimSpace(cfg.Auth.Token) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("unauthorized"))
				return
			}
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

		t := &Tunnel{Tenant: tenant, ID: id, Conn: &wsConn{c: c}}
		t.init()
		mgr.Add(t)
		metricActiveTunnels.Inc()
		log.Infof("agent connected: %s/%s", tenant, id)

		// Optional register frame
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var first proto.Envelope
		if err := c.ReadJSON(&first); err == nil && first.Type == "register" && first.Register != nil {
			// Could auto-create binds for TCP/UDP services if desired
			for sid := range first.Register.TCPTargets {
				if it, err := reg.EnsureTCP(tenant, sid, ":0"); err == nil {
					log.Infof("auto TCP bind %s/%s -> %s", tenant, sid, it.Addr)
				}
			}
			for sid := range first.Register.UDPTargets {
				if it, err := reg.EnsureUDP(tenant, sid, ":0"); err == nil {
					log.Infof("auto UDP bind %s/%s -> %s", tenant, sid, it.Addr)
				}
			}
		}
		_ = c.SetReadDeadline(time.Time{})

		go t.runReader(func() {
			mgr.RemoveWithTenant(tenant, id)
			metricActiveTunnels.Dec()
			reg.StopAllFor(tenant, id)
			log.Infof("agent disconnected: %s/%s", tenant, id)
		})
	})

	// /t/{tenant}/{id}[/*]
	r.Route("/t/{tenant}/{id}", func(rr chi.Router) {
		rr.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
			handlePublicRequest(r.Context(), w, r, mgr, cfg, log, chi.URLParam(r, "tenant"), chi.URLParam(r, "id"), true)
		})
		rr.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			handlePublicRequest(r.Context(), w, r, mgr, cfg, log, chi.URLParam(r, "tenant"), chi.URLParam(r, "id"), true)
		})
	})

	// Host-based {left}--{tenant}.{base}
	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		left, tenant := idTenantFromHost(r.Host, cfg.DomainBase)
		if left == "" || tenant == "" {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body><h3>drill</h3><ul><li><a href="/healthz">/healthz</a></li><li><a href="/metrics">/metrics</a></li></ul></body></html>`))
			return
		}
		handlePublicRequest(r.Context(), w, r, mgr, cfg, log, tenant, left, false)
	})

	// Admin + binds
	if cfg.Admin.Enable {
		routesAdmin(r, cfg, store, mgr, reg, log)
	}
	// Tenant self-service
	if cfg.Tenancy.Enable {
		r.Route("/api/tenant/{tenant}", func(tr chi.Router) {
			tr.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					tn := chi.URLParam(r, "tenant")
					tok := r.Header.Get("X-Tenant-Token")
					if tok == "" {
						tok = r.URL.Query().Get("token")
					}
					if store == nil || !store.Validate(tn, tok) {
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte("unauthorized"))
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			tr.Get("/binds", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, reg.List()) })
			tr.Post("/binds/tcp", func(w http.ResponseWriter, r *http.Request) {
				tn := chi.URLParam(r, "tenant")
				id := r.FormValue("id")
				addr := r.FormValue("addr")
				if addr == "" {
					addr = ":0"
				}
				it, err := reg.StartTCP(tn, id, addr)
				if err != nil {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(err.Error()))
					return
				}
				writeJSON(w, it)
			})
			tr.Post("/binds/udp", func(w http.ResponseWriter, r *http.Request) {
				tn := chi.URLParam(r, "tenant")
				id := r.FormValue("id")
				addr := r.FormValue("addr")
				if addr == "" {
					addr = ":0"
				}
				it, err := reg.StartUDP(tn, id, addr)
				if err != nil {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(err.Error()))
					return
				}
				writeJSON(w, it)
			})
			tr.Delete("/binds/{proto}", func(w http.ResponseWriter, r *http.Request) {
				proto := chi.URLParam(r, "proto")
				tn := chi.URLParam(r, "tenant")
				agent := r.URL.Query().Get("agent")
				id := r.URL.Query().Get("id")
				addr := r.URL.Query().Get("addr")
				if agent == "" {
					agent = id
				}
				if err := reg.Stop(proto, tn, agent, id, addr); err != nil {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(err.Error()))
					return
				}
				w.WriteHeader(204)
			})
		})
	}

	return r
}

// admin HTML + routes
const adminHTML = `<!doctype html><html><head><meta charset="utf-8"><title>drill admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:ui-sans-serif,system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}th,td{padding:.5rem;border-bottom:1px solid #ddd;vertical-align:top}
h1{font-size:1.5rem}code{background:#f5f5f5;padding:.1rem .3rem;border-radius:.2rem}
small{color:#666}
input,button{font:inherit;padding:.3rem .5rem;margin:.1rem}
kbd{border:1px solid #ccc;border-bottom-color:#bbb;border-radius:3px;padding:0 .2rem}
pre{background:#fafafa;border:1px solid #eee;border-radius:6px;padding:.5rem;overflow:auto}
.copy{cursor:pointer}
</style>
<script>
function copy(txt){navigator.clipboard.writeText(txt)}
</script>
</head><body>
<h1>drill admin</h1>

<h2>Tenants</h2>
<table><thead><tr><th>Slug</th><th>Name</th><th>Active</th><th>Token</th><th>Actions</th></tr></thead>
<tbody>
{{range .Tenants}}<tr>
<td><code>{{.Slug}}</code></td>
<td>{{.Name}}</td>
<td>{{.Active}}</td>
<td><code>{{.Token}}</code> <button class="copy" onclick="copy('{{.Token}}')">copy</button></td>
<td>
<form method="post" action="/admin/api/tenants/{{.Slug}}/rotate?token={{$.Token}}" onsubmit="fetch(this.action,{method:'POST',body:new FormData(this)}).then(()=>location.reload());return false;" style="display:inline">
  <input name="token" placeholder="(optional) new token"><button>Rotate</button>
</form>
<form method="post" action="/admin/api/tenants/{{.Slug}}?token={{$.Token}}" onsubmit="fetch('/admin/api/tenants/{{.Slug}}?token={{$.Token}}',{method:'DELETE'}).then(()=>location.reload());return false;" style="display:inline">
  <button>Delete</button>
</form>
</td>
</tr>{{end}}
</tbody></table>

<h3>Create tenant</h3>
<form method="post" action="/admin/api/tenants?token={{$.Token}}" onsubmit="fetch(this.action,{method:'POST',body:new FormData(this)}).then(()=>location.reload());return false;">
<input name="name" placeholder="tenant name" required>
<input name="token" placeholder="(optional) token">
<button>Create</button>
</form>

<h2>Active tunnels</h2>
<table><thead><tr><th>Tenant</th><th>Agent ID</th><th>HTTP host</th><th>TCP/SSH (SNI)</th><th>Actions</th></tr></thead><tbody>
{{range .Tunnels}}<tr>
<td><code>{{.Tenant}}</code></td>
<td><code>{{.ID}}</code></td>
<td>
<code>{{.ID}}--{{.Tenant}}.{{$.Base}}</code><br>
<small>Try: <code>https://{{.ID}}--{{.Tenant}}.{{$.Base}}</code></small>
</td>
<td>
<code>&lt;service&gt;.{{.ID}}.tcp--{{.Tenant}}.{{$.Base}}</code>
<pre>Host &lt;service&gt;.{{.ID}}.tcp--{{.Tenant}}.{{$.Base}}
  User &lt;user&gt;
  HostName {{$.Base}}
  Port {{$.SNIPort}}
  ProxyCommand openssl s_client -quiet -servername %n -alpn drill-tcp/1 -connect %h:%p</pre>
</td>
<td>
<form method="post" action="/admin/api/tunnels/{{.Tenant}}/{{.ID}}/disconnect?token={{$.Token}}" onsubmit="fetch(this.action,{method:'POST'}).then(()=>location.reload());return false;"><button>Disconnect</button></form>
</td>
</tr>{{end}}</tbody></table>

<h2>Dynamic binds</h2>
<table><thead><tr><th>Proto</th><th>Tenant</th><th>Agent</th><th>Service</th><th>Addr</th><th>Delete</th></tr></thead><tbody id="binds"></tbody></table>
<script>
fetch('/admin/api/binds?token={{$.Token}}').then(function(r){return r.json()}).then(function(rows){
  var tbody=document.getElementById('binds');
  rows.forEach(function(it){
    var tr=document.createElement('tr');
    var delURL='/admin/api/binds/'+it.proto+'?token={{$.Token}}&tenant='+encodeURIComponent(it.tenant)+'&agent='+encodeURIComponent(it.agent)+'&id='+encodeURIComponent(it.id)+'&addr='+encodeURIComponent(it.addr);
    tr.innerHTML =
      "<td><code>"+it.proto+"</code></td>" +
      "<td><code>"+it.tenant+"</code></td>" +
      "<td><code>"+it.agent+"</code></td>" +
      "<td><code>"+it.id+"</code></td>" +
      "<td><code>"+it.addr+"</code></td>" +
      "<td><button onclick=\\"fetch('"+delURL+"',{method:'DELETE'}).then(()=>location.reload())\\">Delete</button></td>";
    tbody.appendChild(tr);
  });
});
</script>

</body></html>`

func routesAdmin(r chi.Router, cfg Config, store *tenancy.Store, mgr *Manager, reg *BindRegistry, log *util.Logger) {
	r.Group(func(ar chi.Router) {
		ar.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tok := r.Header.Get("X-Admin-Token")
				if tok == "" {
					tok = r.URL.Query().Get("token")
				}
				if strings.TrimSpace(tok) != strings.TrimSpace(cfg.Admin.Token) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("admin unauthorized"))
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		ar.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			if store == nil {
				w.WriteHeader(500)
				_, _ = w.Write([]byte("tenancy not enabled"))
				return
			}
			tmpl := template.Must(template.New("admin").Parse(adminHTML))
			_ = tmpl.Execute(w, map[string]any{
				"Token": cfg.Admin.Token, "Base": cfg.DomainBase, "SNIPort": strings.TrimPrefix(cfg.SNI.Addr, ":"),
				"Tenants": store.List(), "Tunnels": mgr.List(),
			})
		})
		ar.Get("/admin/api/tenants", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, store.List()) })
		ar.Post("/admin/api/tenants", func(w http.ResponseWriter, r *http.Request) {
			name := r.FormValue("name")
			token := r.FormValue("token")
			if token == "" {
				token = randomID() + randomID()
			}
			t, err := store.Create(name, token)
			if err != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			writeJSON(w, t)
		})
		ar.Post("/admin/api/tenants/{slug}/rotate", func(w http.ResponseWriter, r *http.Request) {
			slug := chi.URLParam(r, "slug")
			token := r.FormValue("token")
			if token == "" {
				token = randomID() + randomID()
			}
			t, err := store.Rotate(slug, token)
			if err != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			writeJSON(w, t)
		})
		ar.Delete("/admin/api/tenants/{slug}", func(w http.ResponseWriter, r *http.Request) {
			slug := chi.URLParam(r, "slug")
			if err := store.Delete(slug); err != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(204)
		})
		ar.Post("/admin/api/tunnels/{tenant}/{id}/disconnect", func(w http.ResponseWriter, r *http.Request) {
			tn := chi.URLParam(r, "tenant")
			id := chi.URLParam(r, "id")
			if t, err := mgr.GetWithTenant(tn, id); err == nil {
				_ = t.Conn.Close()
			}
			w.WriteHeader(204)
		})
		ar.Get("/admin/api/binds", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, reg.List()) })
		ar.Post("/admin/api/binds/tcp", func(w http.ResponseWriter, r *http.Request) {
			tenant := r.FormValue("tenant")
			id := r.FormValue("id")
			addr := r.FormValue("addr")
			if addr == "" {
				addr = ":0"
			}
			it, err := reg.StartTCP(tenant, id, addr)
			if err != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			writeJSON(w, it)
		})
		ar.Post("/admin/api/binds/udp", func(w http.ResponseWriter, r *http.Request) {
			tenant := r.FormValue("tenant")
			id := r.FormValue("id")
			addr := r.FormValue("addr")
			if addr == "" {
				addr = ":0"
			}
			it, err := reg.StartUDP(tenant, id, addr)
			if err != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			writeJSON(w, it)
		})
		ar.Delete("/admin/api/binds/{proto}", func(w http.ResponseWriter, r *http.Request) {
			proto := chi.URLParam(r, "proto")
			tenant := r.URL.Query().Get("tenant")
			agent := r.URL.Query().Get("agent")
			id := r.URL.Query().Get("id")
			addr := r.URL.Query().Get("addr")
			if agent == "" {
				agent = id
			}
			if err := reg.Stop(proto, tenant, agent, id, addr); err != nil {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(204)
		})
	})
}

func runWithACME(ctx context.Context, cfg Config, h http.Handler, log *util.Logger, store *tenancy.Store) error {
	policy := func(ctx context.Context, host string) error {
		h := strings.ToLower(hostOnly(host))
		if sameHost(h, cfg.DomainBase) {
			return nil
		}
		if !strings.HasSuffix(h, "."+strings.ToLower(cfg.DomainBase)) {
			return errors.New("host not under base domain")
		}
		left, tenant := idTenantFromHost(h, cfg.DomainBase)
		if tenant == "" || left == "" {
			return errors.New("unrecognized host shape")
		}
		if store != nil && !store.ExistsActive(tenant) {
			return errors.New("unknown tenant")
		}
		return nil
	}
	mgr := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: policy, Email: cfg.ACME.Email, Cache: autocert.DirCache(cfg.ACME.CacheDir)}
	httpSrv := &http.Server{Addr: ":80", Handler: mgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		to := "https://" + hostOnly(r.Host) + r.URL.RequestURI()
		http.Redirect(w, r, to, http.StatusMovedPermanently)
	})), ReadHeaderTimeout: 10 * time.Second}
	fallback, _ := selfSignedCert(cfg.DomainBase)
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			if fallback != nil {
				return fallback, nil
			}
			return nil, errors.New("missing SNI")
		}
		return mgr.GetCertificate(hello)
	}
	httpsSrv := &http.Server{Addr: cfg.PublicAddr, Handler: h, TLSConfig: &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1", acme.ALPNProto}}, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 2)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	go func() { errCh <- httpsSrv.ListenAndServeTLS("", "") }()
	log.Infof("ACME (HTTP-01/TLS-ALPN): :80 redirect/challenge; HTTPS on %s", cfg.PublicAddr)
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

func runWithCertMagic(ctx context.Context, cfg Config, h http.Handler, log *util.Logger, store interface{}) error {
	tlsConf, err := makeCertMagic(ctx, cfg, nil)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Addr: ":80", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
	}), ReadHeaderTimeout: 10 * time.Second}
	httpsSrv := &http.Server{Addr: cfg.PublicAddr, Handler: h, TLSConfig: tlsConf, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 2)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	go func() { errCh <- httpsSrv.ListenAndServeTLS("", "") }()
	log.Infof("CertMagic (DNS-01): :80 redirect; HTTPS on %s (provider=%s)", cfg.PublicAddr, cfg.ACME.DNSProvider)
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
	go func() { log.Infof("listening on %s", srv.Addr); errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = srv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func handlePublicRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, mgr *Manager, cfg Config, log *util.Logger, tenant string, id string, strip bool) {
	if id == "" {
		w.WriteHeader(400)
		_, _ = w.Write([]byte("missing id"))
		return
	}
	service := ""
	agentID := id
	if dot := strings.Index(agentID, "."); dot > 0 {
		service = agentID[:dot]
		agentID = agentID[dot+1:]
	}
	tun, err := mgr.GetWithTenant(tenant, agentID)
	if err != nil {
		w.WriteHeader(502)
		_, _ = w.Write([]byte("no agent for " + html.EscapeString(tenant) + "/" + html.EscapeString(agentID)))
		return
	}
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
	_ = r.Body.Close()
	path := r.URL.Path
	if strip {
		prefix := "/t/" + tenant + "/" + id
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			if path == "" {
				path = "/"
			}
		}
	}
	req := &proto.Request{
		Method:   r.Method,
		Path:     path,
		RawQuery: r.URL.RawQuery,
		Header:   filterHeaders(r.Header),
		Body:     body,
	}
	start := time.Now()
	resp, err := tun.sendRequest(req, 30*time.Second, service)
	dur := time.Since(start).Seconds()
	if err != nil {
		metricRequestsTotal.WithLabelValues(agentID, r.Method).Inc()
		metricRequestSecs.WithLabelValues(agentID, r.Method, "bad_gateway").Observe(dur)
		w.WriteHeader(502)
		_, _ = w.Write([]byte("tunnel write failed: " + err.Error()))
		return
	}
	metricRequestsTotal.WithLabelValues(agentID, r.Method).Inc()
	metricRequestSecs.WithLabelValues(agentID, r.Method, fmt.Sprintf("%d", resp.Status)).Observe(dur)
	if resp.Error != "" {
		w.WriteHeader(504)
		_, _ = w.Write([]byte(resp.Error))
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var hopByHop = map[string]bool{"connection": true, "proxy-connection": true, "keep-alive": true, "transfer-encoding": true, "te": true, "trailer": true, "upgrade": true}

func filterHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "host" {
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
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func hostOnly(hp string) string {
	if i := strings.Index(hp, ":"); i >= 0 {
		return hp[:i]
	}
	return hp
}
func sameHost(a, b string) bool { return strings.EqualFold(hostOnly(a), hostOnly(b)) }
func randomID() string          { var b [6]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

func selfSignedCert(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
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

func idTenantFromHost(hostport, base string) (left, tenant string) {
	host := hostOnly(hostport)
	if !strings.HasSuffix(host, "."+base) {
		return "", ""
	}
	left = strings.TrimSuffix(host, "."+base)
	if left == "" {
		return "", ""
	}
	i := strings.LastIndex(left, "--")
	if i <= 0 || i >= len(left)-2 {
		return "", ""
	}
	return left[:i], left[i+2:]
}
