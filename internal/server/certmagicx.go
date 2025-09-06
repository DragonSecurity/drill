package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
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
	if cfg.ACME.Email == "" {
		return nil, errors.New("acme.email is required for dns-01")
	}
	if cfg.ACME.CacheDir == "" {
		cfg.ACME.CacheDir = "cert-cache"
	}

	cache := certmagic.NewCache(certmagic.CacheOptions{})
	magic := certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.ACME.CacheDir},

		// This is the place to authorize on-demand names:
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				h := strings.ToLower(hostOnly(name))

				// allow apex
				if sameHost(h, cfg.DomainBase) {
					return nil
				}
				// allow only hosts under the configured base
				if !strings.HasSuffix(h, "."+strings.ToLower(cfg.DomainBase)) {
					return fmt.Errorf("reject host outside base: %s", h)
				}
				// must be {left}--{tenant}.{base}
				left, tenant := idTenantFromHost(h, cfg.DomainBase)
				if left == "" || tenant == "" {
					return fmt.Errorf("reject unrecognized host: %s", h)
				}
				// if tenancy enabled, tenant must exist+active
				if store != nil && !store.ExistsActive(tenant) {
					return fmt.Errorf("reject unknown tenant: %s", tenant)
				}
				return nil
			},
		},
	})

	issuer := &certmagic.ACMEIssuer{
		CA:                      acmeCAURL(cfg.ACME.CA),
		Email:                   cfg.ACME.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	}

	switch strings.ToLower(cfg.ACME.DNSProvider) {
	case "cloudflare":
		token := strings.TrimSpace(cfg.ACME.CloudflareToken)
		if token == "" {
			// fallback to env if you prefer
			token = os.Getenv("CLOUDFLARE_API_TOKEN")
		}
		if token == "" {
			return nil, errors.New("cloudflare token is empty (set acme.cloudflare_token or CLOUDFLARE_API_TOKEN)")
		}
		issuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflaredns.Provider{APIToken: token},
			},
		}
	default:
		return nil, fmt.Errorf("unsupported acme.dns_provider %q", cfg.ACME.DNSProvider)
	}

	magic.Issuers = []certmagic.Issuer{issuer}

	tlsConf := magic.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12
	tlsConf.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	return tlsConf, nil
}
