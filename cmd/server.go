package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
		cfg := server.Config{}
		if err := viper.UnmarshalKey("server", &cfg); err != nil {
			return fmt.Errorf("decode server config: %w", err)
		}
		if cfg.PublicAddr == "" {
			cfg.PublicAddr = ":443"
		}
		if cfg.ACME.CacheDir == "" {
			cfg.ACME.CacheDir = "/var/lib/drill-acme"
		}
		log := util.NewLogger("[server] ")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return server.Run(ctx, cfg, log)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
