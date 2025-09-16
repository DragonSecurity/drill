package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/DragonSecurity/drill/internal/agent"
	"github.com/DragonSecurity/drill/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type agentCfg struct {
	Agent agent.Config `mapstructure:"agent"`
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the drill agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg agentCfg
		if err := viper.Unmarshal(&cfg); err != nil {
			return fmt.Errorf("decode agent config: %w", err)
		}
		log := util.NewLogger("[agent] ")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return agent.Run(ctx, cfg.Agent, log)
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
}
