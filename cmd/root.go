package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "drill",
		Short: "drill – reverse tunnel server/agent",
		Long:  "drill – reverse tunnel server/agent",
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (yaml/json/toml)")
	rootCmd.Version = fmt.Sprintf("%s (%s) %s", Version, Commit, Date)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("server")
		viper.AddConfigPath("/etc/drill")
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
	}
	_ = viper.ReadInConfig()
}
