package main

import (
	"log"
	"os"
)

type Logger struct {
	logger *log.Logger
}

func NewLogger() Logger {
	return Logger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l Logger) Errorf(format string, v ...interface{}) {
	l.logger.Printf("ERROR: "+format, v...)
}

func (l Logger) Debugf(format string, v ...interface{}) {
	l.logger.Printf("DEBUG: "+format, v...)
}

func (l Logger) Infof(format string, v ...interface{}) {
	l.logger.Printf("INFO: "+format, v...)
}

func (l Logger) Warnf(format string, v ...interface{}) {
	l.logger.Printf("WARN: "+format, v...)
}
