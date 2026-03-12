package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PromptPrefix is a special line prefix that LogStreamWriter converts to a "prompt" level entry.
// This allows code writing to stdout (via a pipe) to signal the client without directly
// writing to the HTTP response writer, avoiding concurrent write corruption.
const PromptPrefix = "\x00PROMPT:"

// LogEntry represents a single log entry in NDJSON format
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"` // "info", "error", "warning", "prompt"
	Message string `json:"message"`
}

// LogStreamWriter is a writer that formats output as NDJSON and streams it
type LogStreamWriter struct {
	writer io.Writer
	level  string
}

// NewLogStreamWriter creates a new log stream writer
func NewLogStreamWriter(writer io.Writer, level string) *LogStreamWriter {
	return &LogStreamWriter{
		writer: writer,
		level:  level,
	}
}

// Write implements io.Writer interface
func (l *LogStreamWriter) Write(p []byte) (n int, err error) {
	// Split input by newlines to handle multi-line messages
	lines := strings.Split(strings.TrimSuffix(string(p), "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		level := l.level
		msg := line
		if strings.HasPrefix(line, PromptPrefix) {
			level = "prompt"
			msg = strings.TrimPrefix(line, PromptPrefix)
		}
		entry := LogEntry{
			Time:    time.Now().UTC().Format(time.RFC3339),
			Level:   level,
			Message: msg,
		}

		jsonData, err := json.Marshal(entry)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal log entry: %w", err)
		}

		// Write NDJSON (newline-delimited JSON)
		_, err = l.writer.Write(append(jsonData, '\n'))
		if err != nil {
			return 0, err
		}

		// Flush if the writer supports it
		if flusher, ok := l.writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	return len(p), nil
}

// WriteLogEntry writes a structured log entry
func WriteLogEntry(w io.Writer, level, message string) error {
	entry := LogEntry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   level,
		Message: message,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}

	_, err = w.Write(append(jsonData, '\n'))
	if err != nil {
		return err
	}

	// Flush if the writer supports it
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	return nil
}

