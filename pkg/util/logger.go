package util

import "log"

type Logger struct {
	pfx string
}

func NewLogger(prefix string) *Logger { return &Logger{pfx: prefix} }

func (l *Logger) printf(level, f string, a ...any) {
	log.Printf("%s%s: "+f, append([]any{l.pfx, level}, a...)...)
}

func (l *Logger) Infof(f string, a ...any) {
	l.printf("", f, a...)
}

func (l *Logger) Errorf(f string, a ...any) {
	l.printf("ERROR: ", f, a...)
}
