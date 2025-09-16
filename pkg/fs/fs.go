package fs

import (
	"os"
	"runtime"

	"github.com/mitchellh/go-homedir"
)

func Exists(filePath string) bool {
	if _, err := os.Stat(filePath); err == nil {
		return true
	}
	return false
}

func MakeDir(dirPath string) error {
	return os.MkdirAll(dirPath, 0700)
}

func GetHomeDir() (string, error) {
	return homedir.Dir()
}

func TempDir() (string, error) {
	var tmp string
	if runtime.GOOS != "darwin" {
		tmp = os.TempDir()
	} else {
		tmp = "/tmp"
	}
	return os.MkdirTemp(tmp, "drill")
}
