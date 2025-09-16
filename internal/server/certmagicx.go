package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/DragonSecurity/drill/internal/server/tenancy"
	"github.com/caddyserver/certmagic"
	cloudflaredns "github.com/libdns/cloudflare"
	"golang.org/x/crypto/acme"
)

func acmeCAURL(which string) string {
	switch strings.ToLower(which) {
	case "staging":
		return certmagic.LetsEncryptStagingCA
	default:
		return certmagic.LetsEncryptProductionCA
	}
}

func makeCertMagic(ctx context.Context, cfg Config, store *tenancy.Store) (*tls.Config, error) {
	if strings.TrimSpace(cfg.ACME.Email) == "" {
		return nil, errors.New("acme.email is required for dns-01")
	}
	if strings.TrimSpace(cfg.ACME.CacheDir) == "" {
		cfg.ACME.CacheDir = "/var/lib/drill-acme"
	}
	if !strings.EqualFold(cfg.ACME.DNSProvider, "cloudflare") {
		return nil, fmt.Errorf("unsupported dns_provider %q (this build wires cloudflare only)", cfg.ACME.DNSProvider)
	}
	if strings.TrimSpace(cfg.ACME.CloudflareToken) == "" {
		return nil, errors.New("acme.cloudflare_token is required for cloudflare dns-01")
	}

	var magic *certmagic.Config

	cache := certmagic.NewCache(certmagic.CacheOptions{
		// NOTE: v0.25.0 expects a func(certmagic.Certificate) (*certmagic.Config, error)
		GetConfigForCert: func(_ certmagic.Certificate) (*certmagic.Config, error) {
			if magic == nil {
				return nil, errors.New("certmagic config not initialized yet")
			}
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.ACME.CacheDir},
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				h := strings.ToLower(hostOnly(name))

				if sameHost(h, cfg.DomainBase) {
					return nil
				}
				if !strings.HasSuffix(h, "."+strings.ToLower(cfg.DomainBase)) {
					return fmt.Errorf("reject host outside base: %s", h)
				}
				left, tenant := idTenantFromHost(h, cfg.DomainBase)
				if left == "" || tenant == "" {
					return fmt.Errorf("reject unrecognized host: %s", h)
				}
				if store != nil && !store.ExistsActive(tenant) {
					return fmt.Errorf("reject unknown tenant: %s", tenant)
				}
				return nil
			},
		},
	})

	// Use the constructor so internal locks are initialized
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      acmeCAURL(cfg.ACME.CA),
		Email:                   cfg.ACME.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	})
	issuer.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflaredns.Provider{APIToken: cfg.ACME.CloudflareToken},
		},
	}
	magic.Issuers = []certmagic.Issuer{issuer}

	tlsConf := magic.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12
	tlsConf.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	return tlsConf, nil
}
