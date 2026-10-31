package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var token = strings.Repeat("t", 32)

func valid() map[string]string {
	return map[string]string{
		"RELAY_DATABASE_URL":  "postgres://x",
		"RELAY_ADMIN_TOKEN":   token,
		"RELAY_PUBLIC_ORIGIN": "wss://relay.example.com",
		"RELAY_TLS_CERT_FILE": "/c.pem",
		"RELAY_TLS_KEY_FILE":  "/k.pem",
	}
}

func TestLoadValid(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8443" || c.PublicOrigin != "wss://relay.example.com" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadTrimsTrailingSlash(t *testing.T) {
	m := valid()
	m["RELAY_PUBLIC_ORIGIN"] = "wss://relay.example.com/"
	c, err := Load(env(m))
	if err != nil || c.PublicOrigin != "wss://relay.example.com" {
		t.Fatalf("%v %q", err, c.PublicOrigin)
	}
}

func TestLoadLowercasesOrigin(t *testing.T) {
	m := valid()
	m["RELAY_PUBLIC_ORIGIN"] = " WSS://Relay.Example.COM:8443/ "
	c, err := Load(env(m))
	if err != nil || c.PublicOrigin != "wss://relay.example.com:8443" {
		t.Fatalf("%v %q", err, c.PublicOrigin)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]func(map[string]string){
		"no database":           func(m map[string]string) { delete(m, "RELAY_DATABASE_URL") },
		"no admin token":        func(m map[string]string) { delete(m, "RELAY_ADMIN_TOKEN") },
		"short admin token":     func(m map[string]string) { m["RELAY_ADMIN_TOKEN"] = "short" },
		"no origin":             func(m map[string]string) { delete(m, "RELAY_PUBLIC_ORIGIN") },
		"https origin":          func(m map[string]string) { m["RELAY_PUBLIC_ORIGIN"] = "https://r.example.com" },
		"origin with path":      func(m map[string]string) { m["RELAY_PUBLIC_ORIGIN"] = "wss://r.example.com/ws" },
		"ws origin without dev": func(m map[string]string) { m["RELAY_PUBLIC_ORIGIN"] = "ws://r.example.com" },
		"cert without key":      func(m map[string]string) { delete(m, "RELAY_TLS_KEY_FILE") },
		"no TLS and no dev flag": func(m map[string]string) {
			delete(m, "RELAY_TLS_CERT_FILE")
			delete(m, "RELAY_TLS_KEY_FILE")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := valid()
			mutate(m)
			if _, err := Load(env(m)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestInsecureDevMode(t *testing.T) {
	m := map[string]string{
		"RELAY_DATABASE_URL": "postgres://x", "RELAY_ADMIN_TOKEN": token,
		"RELAY_PUBLIC_ORIGIN": "ws://localhost:8443", "RELAY_ALLOW_INSECURE_HTTP": "true",
	}
	if _, err := Load(env(m)); err != nil {
		t.Fatal(err)
	}
}

func TestErrorDoesNotEchoSecrets(t *testing.T) {
	m := valid()
	m["RELAY_DATABASE_URL"] = ""
	m["RELAY_ADMIN_TOKEN"] = "supersecret"
	_, err := Load(env(m))
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error must not contain the token: %v", err)
	}
}

func TestTokenAndRetentionSettings(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil || c.TokenTTL != 10*time.Minute || c.AuditRetentionDays != 90 {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	m := valid()
	m["RELAY_TOKEN_TTL_MINUTES"] = "30"
	m["RELAY_AUDIT_RETENTION_DAYS"] = "7"
	if c, err = Load(env(m)); err != nil || c.TokenTTL != 30*time.Minute || c.AuditRetentionDays != 7 {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range []map[string]string{
		{"RELAY_TOKEN_TTL_MINUTES": "0"}, {"RELAY_TOKEN_TTL_MINUTES": "61"}, {"RELAY_TOKEN_TTL_MINUTES": "ten"},
		{"RELAY_AUDIT_RETENTION_DAYS": "0"}, {"RELAY_AUDIT_RETENTION_DAYS": "99999"}, {"RELAY_AUDIT_RETENTION_DAYS": "-1"},
	} {
		m := valid()
		for k, v := range bad {
			m[k] = v
		}
		if _, err := Load(env(m)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
