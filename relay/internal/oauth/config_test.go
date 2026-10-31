package oauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/oauth"
)

func TestNewValidatesItsConfiguration(t *testing.T) {
	cs := clients.NewMemoryStore(nil)
	ok := oauth.Config{
		Issuer: "https://relay.example.com", AdminToken: strings.Repeat("t", 32), Devices: devices.NewMemoryStore(), Clients: cs,
		Auth: auth.New(cs, "wss://relay.example.com", time.Minute, nil), Store: oauth.NewMemoryStore(), Audit: audit.NewRecorder(audit.NewMemoryStore(), nil, nil),
	}
	if _, err := oauth.New(ok); err != nil {
		t.Fatal(err)
	}
	mod := func(f func(*oauth.Config)) oauth.Config { c := ok; f(&c); return c }
	for name, c := range map[string]oauth.Config{
		"http issuer":         mod(func(c *oauth.Config) { c.Issuer = "http://relay.example.com" }),
		"issuer with a path":  mod(func(c *oauth.Config) { c.Issuer = "https://relay.example.com/x" }),
		"issuer with a slash": mod(func(c *oauth.Config) { c.Issuer = "https://relay.example.com/" }),
		"issuer with a query": mod(func(c *oauth.Config) { c.Issuer = "https://relay.example.com?a=b" }),
		"no host":             mod(func(c *oauth.Config) { c.Issuer = "https://" }),
		"short admin token":   mod(func(c *oauth.Config) { c.AdminToken = "short" }),
		"no store":            mod(func(c *oauth.Config) { c.Store = nil }),
		"no audit":            mod(func(c *oauth.Config) { c.Audit = nil }),
	} {
		if _, err := oauth.New(c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// plain http is for development only, and only when asked for
	if _, err := oauth.New(mod(func(c *oauth.Config) { c.Issuer = "http://127.0.0.1:8443"; c.AllowInsecure = true })); err != nil {
		t.Errorf("insecure development mode refused: %v", err)
	}
}
