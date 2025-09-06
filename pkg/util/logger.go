package util

import (
	"log"
	"os"
)

type Logger struct {
	prefix string
	*log.Logger
}

func NewLogger(p string) *Logger {
	return &Logger{prefix: p, Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)}
}
func (l *Logger) p() string {
	if l.prefix == "" {
		return ""
	}
	return "[" + l.prefix + "] "
}
func (l *Logger) Infof(f string, v ...any)  { l.Printf(l.p()+f, v...) }
func (l *Logger) Errorf(f string, v ...any) { l.Printf(l.p()+"ERROR: "+f, v...) }
