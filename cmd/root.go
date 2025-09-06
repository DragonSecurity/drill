package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Version = "dev"

var Commit = "none"

var Date = "unknown"
var cfgFile string

var rootCmd = &cobra.Command{
	Use:     "drill",
	Short:   "drill: reverse tunnels (HTTP + TCP/UDP) with multi-tenancy",
	Version: fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date),
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
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
		if home, _ := os.UserHomeDir(); home != "" {
			viper.AddConfigPath(filepath.Join(home, ".drill"))
		}
		viper.AddConfigPath("/etc/drill")
	}
	_ = viper.ReadInConfig()
}
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
