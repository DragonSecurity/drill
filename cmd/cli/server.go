package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DragonSecurity/drill/internal/server"
	"github.com/DragonSecurity/drill/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the drill server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := util.NewLogger("server")

		type rootCfg struct {
			Server *server.Config `mapstructure:"server"`
			// squash lets flat keys decode directly into this embedded Config
			server.Config `mapstructure:",squash"`
			SNI           server.SNIConfig `mapstructure:"sni"`
		}

		var rc rootCfg
		if err := viper.Unmarshal(&rc); err != nil {
			return fmt.Errorf("config decode: %w", err)
		}

		// Choose nested if present; otherwise use flattened.
		var cfg server.Config
		if rc.Server != nil {
			cfg = *rc.Server
		} else {
			cfg = rc.Config
		}

		cfg.SNI = rc.SNI

		if cfg.PublicAddr == "" {
			cfg.PublicAddr = ":443"
		}
		if cfg.ACME.CacheDir == "" {
			cfg.ACME.CacheDir = "/var/lib/drill-acme"
		}

		log.Infof("boot: base=%s public=%s acme.enable=%v challenge=%s dns_provider=%s sni=%v@%s",
			cfg.DomainBase, cfg.PublicAddr, cfg.ACME.Enable, cfg.ACME.Challenge, cfg.ACME.DNSProvider, cfg.SNI.Enable, cfg.SNI.Addr)

		if strings.TrimSpace(cfg.DomainBase) == "" {
			return fmt.Errorf("domain_base must be set (e.g. getexposed.io)")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return server.Run(ctx, cfg, log)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
