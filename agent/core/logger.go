package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// LogLevel represents the severity of a log entry.
type LogLevel string

const (
	LevelInfo  LogLevel = "INFO"
	LevelWarn  LogLevel = "WARN"
	LevelError LogLevel = "ERROR"
	LevelDebug LogLevel = "DEBUG"
)

// LogEntry is a single structured log record written as JSON.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger writes structured JSON log entries to both a file and stdout.
type Logger struct {
	file   *os.File
	writer io.Writer
}

// NewLogger creates a Logger that writes to the given file path (and also to stdout).
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("could not open log file %q: %w", path, err)
	}

	return &Logger{
		file:   f,
		writer: io.MultiWriter(f, os.Stdout),
	}, nil
}

// Close flushes and closes the underlying log file.
func (l *Logger) Close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}

func (l *Logger) write(level LogLevel, msg string, fields map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Message:   msg,
		Fields:    fields,
	}
	data, _ := json.Marshal(entry)
	fmt.Fprintln(l.writer, string(data))
}

func (l *Logger) Info(msg string, fields map[string]interface{})  { l.write(LevelInfo, msg, fields) }
func (l *Logger) Warn(msg string, fields map[string]interface{})  { l.write(LevelWarn, msg, fields) }
func (l *Logger) Error(msg string, fields map[string]interface{}) { l.write(LevelError, msg, fields) }
func (l *Logger) Debug(msg string, fields map[string]interface{}) { l.write(LevelDebug, msg, fields) }
