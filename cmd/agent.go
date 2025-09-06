package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/DragonSecurity/drill/internal/agent"
	"github.com/DragonSecurity/drill/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	agentCmd.Flags().String("tenant", "", "tenant slug (required when server.tenancy.enable=true)")
	agentCmd.Flags().String("id", "", "tunnel id")
	agentCmd.Flags().String("auth", "", "tenant token")
	agentCmd.Flags().String("server", "http://localhost:8080", "server base URL")
	agentCmd.Flags().String("to", "http://127.0.0.1:3000", "default HTTP target")

	viper.BindPFlag("agent.tenant", agentCmd.Flags().Lookup("tenant"))
	viper.BindPFlag("agent.id", agentCmd.Flags().Lookup("id"))
	viper.BindPFlag("agent.auth", agentCmd.Flags().Lookup("auth"))
	viper.BindPFlag("agent.server", agentCmd.Flags().Lookup("server"))
	viper.BindPFlag("agent.to", agentCmd.Flags().Lookup("to"))

	rootCmd.AddCommand(agentCmd)
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "run agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := util.NewLogger("agent")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		cfg := agent.Config{
			Tenant:     viper.GetString("agent.tenant"),
			ID:         viper.GetString("agent.id"),
			AuthToken:  viper.GetString("agent.auth"),
			ServerURL:  viper.GetString("agent.server"),
			LocalTo:    viper.GetString("agent.to"),
			WebTargets: map[string]string{},
			TCPTargets: map[string]string{},
			UDPTargets: map[string]string{},
		}
		if m := viper.GetStringMapString("agent.web_targets"); len(m) > 0 {
			cfg.WebTargets = m
		}
		if m := viper.GetStringMapString("agent.tcp_targets"); len(m) > 0 {
			cfg.TCPTargets = m
		}
		if m := viper.GetStringMapString("agent.udp_targets"); len(m) > 0 {
			cfg.UDPTargets = m
		}
		return agent.Run(ctx, cfg, log)
	},
}
