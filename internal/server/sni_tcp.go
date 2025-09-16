package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"

	"github.com/DragonSecurity/drill/pkg/util"
)

type SNIConfig struct {
	Enable bool   `mapstructure:"enable"`
	Addr   string `mapstructure:"addr"`
}

func runSNIGateway(ctx context.Context, cfg Config, deps *ServerDeps) error {
	if cfg.SNI.Addr == "" {
		cfg.SNI.Addr = ":8443"
	}
	// Reuse ACME TLS config if dns-01 enabled; else self-signed fallback
	var tlsConf *tls.Config
	var err error
	if cfg.ACME.Enable && strings.EqualFold(cfg.ACME.Challenge, "dns-01") {
		tlsConf, err = makeCertMagic(ctx, cfg, nil)
		if err != nil {
			return err
		}
	} else {
		cert, _ := selfSignedCert(cfg.DomainBase)
		tlsConf = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	ln, err := tls.Listen("tcp", cfg.SNI.Addr, tlsConf)
	if err != nil {
		return err
	}
	deps.log.Infof("SNI TCP gateway listening on %s (DNS-01 via CertMagic)", cfg.SNI.Addr)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSNITCP(conn, cfg, deps.log, deps.mgr)
	}
}

func handleSNITCP(c net.Conn, cfg Config, log *util.Logger, mgr *Manager) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return
	}
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		return
	}
	st := tc.ConnectionState()
	sni := strings.ToLower(st.ServerName)
	// Expect <service>.<agent>.tcp--<tenant>.<base>
	host := hostOnly(sni)
	parts := strings.SplitN(host, ".tcp--", 2)
	if len(parts) != 2 {
		_ = tc.Close()
		return
	}
	left := parts[0] // service.agent
	tenantHost := parts[1]
	tenant := strings.TrimSuffix(tenantHost, "."+cfg.DomainBase)
	sa := strings.SplitN(left, ".", 2)
	if len(sa) != 2 {
		_ = tc.Close()
		return
	}
	service, agent := sa[0], sa[1]
	tun, err := mgr.GetWithTenant(tenant, agent)
	if err != nil {
		log.Errorf("tcp: no agent for %s/%s", tenant, agent)
		_ = tc.Close()
		return
	}
	connID := randomID() + randomID()
	if err := tun.openTCP(connID, service); err != nil {
		_ = tc.Close()
		return
	}
	// Pipe both ways
	remoteCh := tun.newTCPChan(connID)
	// remote -> local
	done := make(chan struct{})
	go func() {
		for data := range remoteCh {
			if len(data) == 0 {
				continue
			}
			if _, err := tc.Write(data); err != nil {
				break
			}
		}
		close(done)
	}()
	// local -> remote
	buf := make([]byte, 32<<10)
	for {
		n, err := tc.Read(buf)
		if n > 0 {
			_ = tun.writeTCP(connID, buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Errorf("sni read: %v", err)
			}
			break
		}
	}
	_ = tun.closeTCP(connID)
	<-done
	_ = tc.Close()
}
