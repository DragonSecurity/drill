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
	agentCmd.Flags().String("id", "", "tunnel id (subdomain and path segment)")
	agentCmd.Flags().String("auth", "", "auth token (must match server --auth-token when --auth is enabled)")
	agentCmd.Flags().String("server", "http://localhost:8080", "server base URL, e.g. http://localhost:8080 or https://yourdomain")
	agentCmd.Flags().String("to", "http://127.0.0.1:3000", "local target base URL to forward to")

	viper.BindPFlag("agent.id", agentCmd.Flags().Lookup("id"))
	viper.BindPFlag("agent.auth", agentCmd.Flags().Lookup("auth"))
	viper.BindPFlag("agent.server", agentCmd.Flags().Lookup("server"))
	viper.BindPFlag("agent.to", agentCmd.Flags().Lookup("to"))

	rootCmd.AddCommand(agentCmd)
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the reverse-tunnel agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := util.NewLogger("agent")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		cfg := agent.Config{
			ID:        viper.GetString("agent.id"),
			AuthToken: viper.GetString("agent.auth"),
			ServerURL: viper.GetString("agent.server"),
			LocalTo:   viper.GetString("agent.to"),
		}
		return agent.Run(ctx, cfg, log)
	},
}
