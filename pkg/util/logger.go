package util

import (
	"log"
	"os"
)

type Logger struct {
	prefix string
	*log.Logger
}

func NewLogger(prefix string) *Logger {
	return &Logger{
		prefix: prefix,
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
}

func (l *Logger) withPrefix() string {
	if l.prefix == "" {
		return ""
	}
	return "[" + l.prefix + "] "
}

func (l *Logger) Infof(format string, v ...any) {
	l.Printf(l.withPrefix()+format, v...)
}

func (l *Logger) Errorf(format string, v ...any) {
	l.Printf(l.withPrefix()+"ERROR: "+format, v...)
}
