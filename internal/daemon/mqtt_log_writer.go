package daemon

import (
	"strings"
)

// MQTTLogWriter is a writer that publishes log messages to MQTT
type MQTTLogWriter struct {
	publisher *MQTTPublisher
	requestID string
	level     string
}

// NewMQTTLogWriter creates a new MQTT log writer
func NewMQTTLogWriter(publisher *MQTTPublisher, requestID, level string) *MQTTLogWriter {
	return &MQTTLogWriter{
		publisher: publisher,
		requestID: requestID,
		level:     level,
	}
}

// Write implements io.Writer interface
func (w *MQTTLogWriter) Write(p []byte) (n int, err error) {
	// Split input by newlines to handle multi-line messages
	lines := strings.Split(strings.TrimSuffix(string(p), "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Publish each line as a log message in a goroutine to avoid blocking
		// This ensures that even if MQTT publishing is slow or blocked, the writer doesn't block
		// Use a closure to capture the line value
		lineCopy := line
		go func() {
			w.publisher.publishLog(w.requestID, w.level, lineCopy)
		}()
	}
	// Always return immediately - don't wait for publishes to complete
	return len(p), nil
}
