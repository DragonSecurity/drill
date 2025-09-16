package server

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/DragonSecurity/drill/pkg/fs"
	"github.com/DragonSecurity/drill/pkg/logger"
	"github.com/DragonSecurity/drill/pkg/rsa"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

type Options struct {
	Domain     string
	PrivateKey string
	PublicKey  string
	SSHAddr    string
	HTTPAddr   string
	Password   string
	Logger     *logger.Options
}

func NewConfig(configPath string) (*viper.Viper, error) {
	v := viper.New()

	dir := getConfigDir()
	v.AddConfigPath(dir)
	v.SetConfigName("drill-server")
	v.SetConfigType("yaml")

	v.SetDefault("domain", "getexposed.io")
	v.SetDefault("privatekey", filepath.Join(dir, "id_rsa"))
	v.SetDefault("publickey", filepath.Join(dir, "id_rsa.pub"))
	v.SetDefault("sshaddr", "0.0.0.0:2200")
	v.SetDefault("httpaddr", "0.0.0.0:2000")
	v.SetDefault("password", "")
	v.SetDefault("log.level", "debug")
	v.SetDefault("log.stdout", true)
	v.SetDefault("log.filename", filepath.Join(dir, "drill-server.log"))
	v.SetDefault("log.max_size", 500)
	v.SetDefault("log.max_backups", 3)
	v.SetDefault("log.max_age", 3)

	v.SetEnvPrefix("DRILL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if !fs.Exists(dir) {
		err := fs.MakeDir(dir)
		if err != nil {
			return nil, err
		}
	}

	if !strings.HasPrefix(configPath, "/") {
		configPath = path.Join(dir, configPath)
	}

	if fs.Exists(configPath) {
		v.SetConfigFile(configPath)
	} else {
		if err := v.SafeWriteConfigAs(configPath); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func NewOptions(v *viper.Viper) (*Options, error) {
	opts := &Options{}
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	err := v.Unmarshal(opts)
	if err != nil {
		return nil, err
	}

	rsa.GenerateRSA(opts.PrivateKey, opts.PublicKey)

	return opts, nil
}

func getConfigDir() string {
	home, err := homedir.Dir()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s/drill", home)
}
