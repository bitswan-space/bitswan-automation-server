package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/fluent/fluent-logger-golang/fluent"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
)

// The sink is a thin front-end over the local fluent-bit. Batching, retries,
// disk buffering, and fan-out to the actual SIEM all happen inside
// fluent-bit — we just push events to its forward-protocol input. The daemon
// container sits on bitswan_network alongside fluent-bit, so we address it
// by container name. Docker's fluentd log driver pushes container logs to
// the same fluent-bit via its localhost-bound host port.
const (
	fluentHost = "fluent-bit"
	fluentPort = 24224
	tagPrefix  = "bitswan"
)

// Stats is a snapshot of sink counters (what we can see from this side;
// fluent-bit has its own metrics for what leaves the host).
type Stats struct {
	Queued     uint64 `json:"queued"`
	Sent       uint64 `json:"sent"`
	Dropped    uint64 `json:"dropped"` // fluent client refused (buffer full, not connected)
	LastError  string `json:"last_error,omitempty"`
	Configured bool   `json:"configured"`
}

// Sink pushes events to a local fluent-bit via the forward protocol.
type Sink struct {
	clientMu sync.RWMutex
	client   *fluent.Fluent

	cfgMu sync.RWMutex
	cfg   Config

	queued  atomic.Uint64
	sent    atomic.Uint64
	dropped atomic.Uint64

	errMu   sync.Mutex
	lastErr string
}

var (
	defaultOnce sync.Once
	defaultSink *Sink
)

// Default returns the process-wide sink, initializing it on first call. The
// fluent client is created lazily on first Emit (so the daemon can start
// even if fluent-bit isn't up yet) and reconnects automatically.
func Default() *Sink {
	defaultOnce.Do(func() {
		defaultSink = &Sink{}
		cfg, err := Load()
		if err != nil {
			defaultSink.recordError(fmt.Sprintf("load config: %v", err))
		}
		defaultSink.setConfig(cfg)
	})
	return defaultSink
}

// Configure persists the SIEM config and rewrites fluent-bit.conf. The
// fluent-bit container reloads its own config (SIGHUP); this sink doesn't
// need to be restarted.
func (s *Sink) Configure(cfg Config) error {
	cfg.Defaults()
	if err := Save(cfg); err != nil {
		return err
	}
	s.setConfig(cfg)
	return nil
}

func (s *Sink) setConfig(cfg Config) {
	s.cfgMu.Lock()
	s.cfg = cfg
	s.cfgMu.Unlock()
}

// Config returns a snapshot of the current config.
func (s *Sink) Config() Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// Stats returns cumulative counters.
func (s *Sink) Stats() Stats {
	cfg := s.Config()
	s.errMu.Lock()
	le := s.lastErr
	s.errMu.Unlock()
	return Stats{
		Queued:     s.queued.Load(),
		Sent:       s.sent.Load(),
		Dropped:    s.dropped.Load(),
		LastError:  le,
		Configured: cfg.Enabled && cfg.URL != "",
	}
}

// Emit queues one event. Non-blocking: the underlying fluent client is in
// async mode and has its own bounded buffer; on overflow events are dropped
// and counted.
func (s *Sink) Emit(source string, payload any) {
	s.queued.Add(1)
	record := s.envelope(source, payload)

	client, err := s.getClient()
	if err != nil {
		s.dropped.Add(1)
		s.recordError(fmt.Sprintf("fluent dial: %v", err))
		return
	}

	tag := tagPrefix + "." + source
	if err := client.Post(tag, record); err != nil {
		s.dropped.Add(1)
		s.recordError(fmt.Sprintf("fluent post: %v", err))
		return
	}
	s.sent.Add(1)
}

// EmitTest pushes a synthetic test event so admins can verify connectivity
// end-to-end from the UI.
func (s *Sink) EmitTest() {
	s.Emit("siem.test", map[string]string{
		"message":  "SIEM connectivity test from bitswan-automation-server",
		"hostname": hostname(),
	})
}

func (s *Sink) getClient() (*fluent.Fluent, error) {
	s.clientMu.RLock()
	c := s.client
	s.clientMu.RUnlock()
	if c != nil {
		return c, nil
	}

	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.client != nil {
		return s.client, nil
	}

	logger, err := fluent.New(fluent.Config{
		FluentHost: fluentHost,
		FluentPort: fluentPort,
		Async:      true, // non-blocking Post(); internal buffer + reconnect
		// MaxRetry is per-write (library bug: -1 ⇒ zero retries). Leave it
		// at the library default (13) which is plenty given fluent-bit is
		// right next door.
	})
	if err != nil {
		return nil, err
	}
	s.client = logger
	return logger, nil
}

// envelope builds the record that fluent-bit sees. Marshaling any → map via
// JSON is slightly wasteful but keeps Payload arbitrary without reflection.
func (s *Sink) envelope(source string, payload any) map[string]any {
	out := map[string]any{
		"source": source,
	}
	if raw, err := json.Marshal(payload); err == nil {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err == nil {
			out["event"] = decoded
		} else {
			out["event"] = string(raw)
		}
	}
	fillIdentity(out)
	return out
}

func (s *Sink) recordError(msg string) {
	s.errMu.Lock()
	s.lastErr = msg
	s.errMu.Unlock()
}

// --- identity ---

func fillIdentity(record map[string]any) {
	cfg := config.NewAutomationServerConfig()
	sc, err := cfg.LoadConfig()
	if err != nil || sc == nil {
		return
	}
	if sc.Slug != "" {
		record["server_slug"] = sc.Slug
	}
	if sc.Name != "" {
		record["server_name"] = sc.Name
	}
	if sc.AutomationOperationsCenter.AutomationServerId != "" {
		record["server_id"] = sc.AutomationOperationsCenter.AutomationServerId
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
