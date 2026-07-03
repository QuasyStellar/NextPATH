package logger

import (
	"fmt"
	"time"
)

var debugMode bool

func Init(debug bool) {
	debugMode = debug
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[1;31m"
	colorGreen  = "\033[1;32m"
	colorYellow = "\033[1;33m"
	colorBlue   = "\033[1;34m"
	colorCyan   = "\033[1;36m"
)

func logMessage(level, phase, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	t := time.Now().Format("15:04:05")

	levelColor := colorReset
	switch level {
	case "INFO":
		levelColor = colorGreen
	case "DEBUG":
		levelColor = colorBlue
	case "WARN":
		levelColor = colorYellow
	case "ERROR":
		levelColor = colorRed
	}

	levelStr := fmt.Sprintf("[%s]", level)
	fmt.Printf("%s[%s] %s%-7s%s %s%-12s%s | %s\n", colorReset, t, levelColor, levelStr, colorReset, colorCyan, phase, colorReset, msg)
}

func Info(phase, format string, v ...interface{}) {
	logMessage("INFO", phase, format, v...)
}

func Debug(phase, format string, v ...interface{}) {
	if debugMode {
		logMessage("DEBUG", phase, format, v...)
	}
}

func Error(phase, format string, v ...interface{}) {
	logMessage("ERROR", phase, format, v...)
}

func Warn(phase, format string, v ...interface{}) {
	logMessage("WARN", phase, format, v...)
}
