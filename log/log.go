package log

import (
	"io"
	"log"
	"os"
)

var (
	Debg = &Logger{log.New(os.Stdout, "[DEBG] ", log.LstdFlags|log.Lshortfile)}
	Info = &Logger{log.New(os.Stdout, "[INFO] ", log.LstdFlags|log.Lshortfile)}
	Warn = &Logger{log.New(os.Stdout, "[WARN] ", log.LstdFlags|log.Lshortfile)}
	Erro = &Logger{log.New(os.Stderr, "[ERRO] ", log.LstdFlags|log.Lshortfile)}
)

type Logger struct {
	*log.Logger
}

func (l *Logger) On() {
	l.SetOutput(os.Stdout)
}

func (l *Logger) Off() {
	l.SetOutput(io.Discard)
}

func NewLogger() *Logger {
	return &Logger{
		log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *Logger) Errorf(format string, v ...interface{}) {
	Erro.Printf(format, v...)
}

func (l *Logger) Debugf(format string, v ...interface{}) {
	Debg.Printf(format, v...)
}

func (l *Logger) Infof(format string, v ...interface{}) {
	Info.Printf(format, v...)
}

func (l *Logger) Warnf(format string, v ...interface{}) {
	Warn.Printf(format, v...)
}
