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
	serverCmd.Flags().String("public", ":8080", "public address")
	serverCmd.Flags().String("domain-base", "localhost", "base domain")
	serverCmd.Flags().Bool("acme", false, "enable Let's Encrypt")
	serverCmd.Flags().String("acme-email", "", "ACME email")
	serverCmd.Flags().String("acme-cache", "cert-cache", "ACME cache dir")
	serverCmd.Flags().Bool("auth", false, "enable shared token (single tenant)")
	serverCmd.Flags().String("auth-token", "", "shared token")
	serverCmd.Flags().Bool("tenancy", false, "enable multi-tenant mode")
	serverCmd.Flags().String("tenancy-storage", "tenants.json", "tenants JSON path")
	serverCmd.Flags().Bool("admin", true, "enable admin dashboard")
	serverCmd.Flags().String("admin-token", "", "admin dashboard token")

	_ = viper.BindPFlag("server.public", serverCmd.Flags().Lookup("public"))
	_ = viper.BindPFlag("server.domain_base", serverCmd.Flags().Lookup("domain-base"))
	_ = viper.BindPFlag("server.acme.enable", serverCmd.Flags().Lookup("acme"))
	_ = viper.BindPFlag("server.acme.email", serverCmd.Flags().Lookup("acme-email"))
	_ = viper.BindPFlag("server.acme.cache", serverCmd.Flags().Lookup("acme-cache"))
	_ = viper.BindPFlag("server.auth.enable", serverCmd.Flags().Lookup("auth"))
	_ = viper.BindPFlag("server.auth.token", serverCmd.Flags().Lookup("auth-token"))
	_ = viper.BindPFlag("server.tenancy.enable", serverCmd.Flags().Lookup("tenancy"))
	_ = viper.BindPFlag("server.tenancy.storage", serverCmd.Flags().Lookup("tenancy-storage"))
	_ = viper.BindPFlag("server.admin.enable", serverCmd.Flags().Lookup("admin"))
	_ = viper.BindPFlag("server.admin.token", serverCmd.Flags().Lookup("admin-token"))

	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "run server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := util.NewLogger("server")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		cfg := server.Config{
			PublicAddr: viper.GetString("server.public"),
			DomainBase: viper.GetString("server.domain_base"),
			ACME:       server.ACMEConfig{Enable: viper.GetBool("server.acme.enable"), Email: viper.GetString("server.acme.email"), CacheDir: viper.GetString("server.acme.cache")},
			Auth:       server.AuthConfig{Enable: viper.GetBool("server.auth.enable"), Token: viper.GetString("server.auth.token")},
			Tenancy:    server.TenancyConfig{Enable: viper.GetBool("server.tenancy.enable"), Storage: viper.GetString("server.tenancy.storage")},
			Admin:      server.AdminConfig{Enable: viper.GetBool("server.admin.enable"), Token: viper.GetString("server.admin.token")},
		}
		var tbs []server.TCPBind
		_ = viper.UnmarshalKey("server.tcp_binds", &tbs)
		cfg.TCPBinds = tbs
		var ubs []server.UDPBind
		_ = viper.UnmarshalKey("server.udp_binds", &ubs)
		cfg.UDPBinds = ubs
		if cfg.ACME.Enable && (cfg.PublicAddr == ":8080" || cfg.PublicAddr == "") {
			cfg.PublicAddr = ":443"
		}
		return server.Run(ctx, cfg, log)
	},
}
