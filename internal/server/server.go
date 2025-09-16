package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	_ "github.com/DragonSecurity/drill/internal/ui/landing" // landing UI
	"github.com/dustin/go-humanize"
	"github.com/felixge/httpsnoop"
	"github.com/google/wire"
	"github.com/jkuri/statik/fs"
	"github.com/yhat/wsutil"
	"go.uber.org/zap"
)

var ProviderSet = wire.NewSet(
	NewConfig,
	NewOptions,
	NewDrillServer,
)

type DrillServer struct {
	opts       *Options
	sshServer  *SSHServer
	httpServer *HTTPServer
	UI         http.Handler
}

func NewDrillServer(opts *Options, logger *zap.Logger) *DrillServer {
	log := logger.Sugar()
	landingFS, _ := fs.New()

	return &DrillServer{
		opts:       opts,
		sshServer:  NewSSHServer(opts, log),
		httpServer: NewHTTPServer(log),
		UI:         http.FileServer(&statikWrapper{landingFS}),
	}
}

func (s *DrillServer) Run() error {
	errch := make(chan error)

	go func() {
		if err := s.httpServer.Run(s.opts.HTTPAddr, s.getHandler(s.handleHTTP())); err != nil {
			errch <- err
		}
	}()

	go func() {
		if err := s.sshServer.Run(); err != nil {
			errch <- err
		}
	}()

	go func() {
		if err := s.httpServer.Wait(); err != nil {
			errch <- err
		}
	}()

	go func() {
		if err := s.sshServer.Wait(); err != nil {
			errch <- err
		}
	}()

	return <-errch
}

func (s *DrillServer) getHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(handler, w, r)
		remote := r.Header.Get("X-Forwarded-For")
		if remote == "" {
			remote = r.RemoteAddr
		}
		log := fmt.Sprintf(
			"%s %s (code=%d dt=%s written=%s remote=%s)",
			r.Method,
			r.URL,
			m.Code,
			m.Duration,
			humanize.Bytes(uint64(m.Written)),
			remote,
		)
		s.httpServer.logger.Debug(log)

		userID := strings.Split(r.Host, ".")[0]
		if client, ok := s.sshServer.clients[userID]; ok {
			client.write(fmt.Sprintf("%s\n", log))
		}
	})
}

func (s *DrillServer) handleHTTP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		if host != s.opts.Domain {
			splitted := strings.Split(host, ".")
			userID := splitted[0]

			if client, ok := s.sshServer.clients[userID]; ok {
				w.Header().Set("X-Proxy", "drill")

				if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
					url := &url.URL{Scheme: "ws", Host: fmt.Sprintf("%s:%d", client.addr, client.port)}
					proxy := wsutil.NewSingleHostReverseProxy(url)
					proxy.ServeHTTP(w, r)
					return
				}

				url := &url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", client.addr, client.port)}
				proxy := httputil.NewSingleHostReverseProxy(url)
				proxy.ServeHTTP(w, r)
				return
			}

			url := &url.URL{Scheme: r.URL.Scheme, Host: s.opts.Domain, Path: "not-found", RawQuery: fmt.Sprintf("tunnelID=%s", userID)}
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
			return
		}

		s.UI.ServeHTTP(w, r)
	})
}
