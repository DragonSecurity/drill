package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/DragonSecurity/drill/internal/server"
	"github.com/DragonSecurity/drill/pkg/util"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	// Flags (also available via config file and env)
	serverCmd.Flags().String("public", ":8080", "public HTTP(S) address; with --acme usually :443")
	serverCmd.Flags().String("domain-base", "localhost", "base domain for host-based routing, e.g. example.com")

	serverCmd.Flags().Bool("acme", false, "enable Let's Encrypt (autocert) and force HTTPS")
	serverCmd.Flags().String("acme-email", "", "email for Let's Encrypt registration/notifications")
	serverCmd.Flags().String("acme-cache", "cert-cache", "directory to cache certificates")

	serverCmd.Flags().Bool("auth", false, "require a shared token for agent control connections")
	serverCmd.Flags().String("auth-token", "", "shared token expected from agents")

	// Bind to viper keys
	viper.BindPFlag("server.public", serverCmd.Flags().Lookup("public"))
	viper.BindPFlag("server.domain_base", serverCmd.Flags().Lookup("domain-base"))
	viper.BindPFlag("server.acme.enable", serverCmd.Flags().Lookup("acme"))
	viper.BindPFlag("server.acme.email", serverCmd.Flags().Lookup("acme-email"))
	viper.BindPFlag("server.acme.cache", serverCmd.Flags().Lookup("acme-cache"))
	viper.BindPFlag("server.auth.enable", serverCmd.Flags().Lookup("auth"))
	viper.BindPFlag("server.auth.token", serverCmd.Flags().Lookup("auth-token"))

	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the reverse-tunnel server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := util.NewLogger("server")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		cfg := server.Config{
			PublicAddr: viper.GetString("server.public"),
			DomainBase: viper.GetString("server.domain_base"),
			ACME: server.ACMEConfig{
				Enable:   viper.GetBool("server.acme.enable"),
				Email:    viper.GetString("server.acme.email"),
				CacheDir: firstNonEmpty(viper.GetString("server.acme.cache"), viper.GetString("server.acme.cache_dir")),
			},
			Auth: server.AuthConfig{
				Enable: viper.GetBool("server.auth.enable"),
				Token:  viper.GetString("server.auth.token"),
			},
		}
		if cfg.ACME.Enable && (cfg.PublicAddr == ":8080" || cfg.PublicAddr == "") {
			cfg.PublicAddr = ":443"
		}
		return server.Run(ctx, cfg, log)
	},
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
