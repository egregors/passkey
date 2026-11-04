package log

import (
	"log"
	"os"
)

var (
	debg = log.New(os.Stdout, "[DEBG] ", log.LstdFlags|log.Lshortfile)
	info = log.New(os.Stdout, "[INFO] ", log.LstdFlags|log.Lshortfile)
	warn = log.New(os.Stdout, "[WARN] ", log.LstdFlags|log.Lshortfile)
	erro = log.New(os.Stderr, "[ERRO] ", log.LstdFlags|log.Lshortfile)
)

type Level byte

const (
	DBG Level = 1 << iota
	INF
	WRN
	ERR
)

type Logger struct {
	lvl Level
}

func NewLogger() *Logger {
	return &Logger{
		lvl: INF | WRN | ERR,
	}
}

func (l *Logger) isEnabled(lvl Level) bool {
	return l.lvl&lvl != 0
}

func (l *Logger) Enable(levels Level) {
	l.lvl |= levels
}

func (l *Logger) Disable(levels Level) {
	l.lvl &^= levels
}

func (l *Logger) Debugf(format string, v ...any) {
	if l.isEnabled(DBG) {
		debg.Printf(format, v...)
	}
}

func (l *Logger) Infof(format string, v ...any) {
	if l.isEnabled(INF) {
		info.Printf(format, v...)
	}
}

func (l *Logger) Warnf(format string, v ...any) {
	if l.isEnabled(WRN) {
		warn.Printf(format, v...)
	}
}

func (l *Logger) Errorf(format string, v ...any) {
	if l.isEnabled(ERR) {
		erro.Printf(format, v...)
	}
}
