package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"

	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:     "drill",
	Short:   "A minimal reverse-tunnel scaffold (chi + cobra + websockets)",
	Version: fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date),
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (yaml/json/toml); defaults: ./drill.yaml, $HOME/.revtun/revtun.yaml, /etc/revtun/revtun.yaml")
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetEnvPrefix("DRILL")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("drill")
		viper.AddConfigPath(".")
		home, _ := os.UserHomeDir()
		if home != "" {
			viper.AddConfigPath(filepath.Join(home, ".drill"))
		}
		viper.AddConfigPath("/etc/drill")
	}

	_ = viper.ReadInConfig() // ignore missing; flags/env still work
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
