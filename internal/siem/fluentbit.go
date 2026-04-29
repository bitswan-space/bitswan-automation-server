package siem

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// RenderFluentBitConfig generates a fluent-bit.conf from the admin-supplied
// SIEM config. The resulting config:
//   - Listens on 0.0.0.0:24224 for the forward protocol (reachable from the
//     host's Docker fluentd log driver and from our daemon via the
//     bitswan_network bridge).
//   - Tails container logs when Docker's log-driver is json-file.
//   - Ships everything to cfg.URL via the http output plugin, adding the
//     configured auth header if any. If cfg is disabled or URL is empty,
//     events are discarded (null output) so fluent-bit still starts cleanly.
func RenderFluentBitConfig(cfg Config) (string, error) {
	var b strings.Builder
	b.WriteString(`[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info
    HTTP_Server  On
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020
    storage.path /fluent-bit/state
    storage.sync normal

[INPUT]
    Name         forward
    Listen       0.0.0.0
    Port         24224
    storage.type filesystem

[FILTER]
    Name         record_modifier
    Match        *
    Record       ingested_at ${HOSTNAME}

`)

	if !cfg.Enabled || cfg.URL == "" {
		b.WriteString(`[OUTPUT]
    Name         null
    Match        *
`)
		return b.String(), nil
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url must be http:// or https://")
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	uri := u.Path
	if uri == "" {
		uri = "/"
	}
	if u.RawQuery != "" {
		uri = uri + "?" + u.RawQuery
	}
	tls := "off"
	if u.Scheme == "https" {
		tls = "on"
	}

	fmt.Fprintf(&b, `[OUTPUT]
    Name               http
    Match              *
    Host               %s
    Port               %s
    URI                %s
    tls                %s
    tls.verify         on
    Format             json_lines
    json_date_key      timestamp
    json_date_format   iso8601
    storage.total_limit_size 100M
    Retry_Limit        no_limits
`, host, port, uri, tls)

	if cfg.AuthHeader != "" {
		name, value := splitAuthHeader(cfg.AuthHeader)
		fmt.Fprintf(&b, "    header             %s %s\n", name, escapeConfValue(value))
	}
	return b.String(), nil
}

// splitAuthHeader allows the admin to paste a raw header line
// ("Authorization: Bearer xxx") or just the value, which defaults to
// Authorization.
func splitAuthHeader(h string) (string, string) {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		name := strings.TrimSpace(h[:i])
		value := strings.TrimSpace(h[i+1:])
		return name, value
	}
	return "Authorization", strings.TrimSpace(h)
}

func escapeConfValue(v string) string {
	// fluent-bit ini-ish parser treats newlines as record separators; strip.
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\r", " ")
	return v
}

// WriteFluentBitConfig writes the rendered config to disk so fluent-bit
// (which has the dir mounted) picks it up on SIGHUP.
func WriteFluentBitConfig(dir string, cfg Config) error {
	conf, err := RenderFluentBitConfig(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "fluent-bit.conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(conf), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

