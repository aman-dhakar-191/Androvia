// Package config loads and validates relay configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
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

	TokenTTL           time.Duration // lifetime of client access tokens
	AuditRetentionDays int

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
	c.TokenTTL = 10 * time.Minute
	c.AuditRetentionDays = 90
	var errs []error
	if v := getenv("RELAY_TOKEN_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 60 {
			errs = append(errs, errors.New("RELAY_TOKEN_TTL_MINUTES must be a whole number from 1 to 60"))
		} else {
			c.TokenTTL = time.Duration(n) * time.Minute
		}
	}
	if v := getenv("RELAY_AUDIT_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 3650 {
			errs = append(errs, errors.New("RELAY_AUDIT_RETENTION_DAYS must be a whole number from 1 to 3650"))
		} else {
			c.AuditRetentionDays = n
		}
	}
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

// PublicHTTPBase is the relay's public HTTP(S) base URL, derived from the public WebSocket origin
// (wss://host -> https://host, ws://host -> http://host).
func (c Config) PublicHTTPBase() string {
	switch {
	case strings.HasPrefix(c.PublicOrigin, "wss://"):
		return "https://" + strings.TrimPrefix(c.PublicOrigin, "wss://")
	case strings.HasPrefix(c.PublicOrigin, "ws://"):
		return "http://" + strings.TrimPrefix(c.PublicOrigin, "ws://")
	}
	return c.PublicOrigin
}
