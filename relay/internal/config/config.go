// Package config loads and validates relay configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	ListenAddr    string
	DatabaseURL   string
	AdminToken    string // bootstrap credential for registration/command APIs until Phase 3 (clients and scopes)
	PublicOrigin  string // e.g. wss://relay.example.com; bound into the device handshake signature
	TLSCertFile   string
	TLSKeyFile    string
	AllowInsecure bool // plain HTTP/WS; development only

	HandshakeTimeout time.Duration
	HeartbeatTimeout time.Duration // a device is dropped after this long without a valid message (3 x 25 s beats)
}

// Load reads configuration through getenv (os.Getenv in production) and returns every problem at once.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddr:       or(getenv("RELAY_LISTEN_ADDR"), ":8443"),
		DatabaseURL:      getenv("RELAY_DATABASE_URL"),
		AdminToken:       getenv("RELAY_ADMIN_TOKEN"),
		PublicOrigin:     strings.ToLower(strings.TrimRight(strings.TrimSpace(getenv("RELAY_PUBLIC_ORIGIN")), "/")), // scheme and host are case-insensitive; devices lower-case too
		TLSCertFile:      getenv("RELAY_TLS_CERT_FILE"),
		TLSKeyFile:       getenv("RELAY_TLS_KEY_FILE"),
		AllowInsecure:    getenv("RELAY_ALLOW_INSECURE_HTTP") == "true",
		HandshakeTimeout: 10 * time.Second,
		HeartbeatTimeout: 75 * time.Second,
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("RELAY_DATABASE_URL is required"))
	}
	if len(c.AdminToken) < 32 {
		errs = append(errs, errors.New("RELAY_ADMIN_TOKEN is required and must be at least 32 characters"))
	}
	if u, err := url.Parse(c.PublicOrigin); err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("RELAY_PUBLIC_ORIGIN is required and must look like wss://host[:port] (no path)"))
	} else if u.Scheme == "ws" && !c.AllowInsecure {
		errs = append(errs, errors.New("RELAY_PUBLIC_ORIGIN uses ws:// but RELAY_ALLOW_INSECURE_HTTP is not true"))
	}
	hasCert, hasKey := c.TLSCertFile != "", c.TLSKeyFile != ""
	switch {
	case hasCert != hasKey:
		errs = append(errs, errors.New("RELAY_TLS_CERT_FILE and RELAY_TLS_KEY_FILE must be set together"))
	case !hasCert && !c.AllowInsecure:
		errs = append(errs, errors.New("TLS is required: set RELAY_TLS_CERT_FILE and RELAY_TLS_KEY_FILE, or RELAY_ALLOW_INSECURE_HTTP=true for local development"))
	}
	if len(errs) > 0 {
		return Config{}, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return c, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
