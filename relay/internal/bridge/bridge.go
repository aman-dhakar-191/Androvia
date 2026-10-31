// Package bridge lets an ordinary MCP host (anything that can start a local MCP server over stdio) use an Androvia relay
// without ever being handed a token.
//
// The host starts `mcpbridge run`, which speaks MCP on stdin/stdout. The bridge holds the client's private key, logs in to
// the relay with the signed-challenge exchange (docs/relay.md), keeps the short-lived access token fresh, and forwards every
// MCP message to the relay's /mcp endpoint. The host never sees the token or the key.
//
// Messages are piped at the connection level through the official MCP SDK's transports, so the protocol-version, method and
// header rules of each MCP revision are applied by the SDK, not re-implemented here. The bridge adds nothing to what a client
// may do: the relay still authorises every call against the grants of the client whose key the bridge holds.
package bridge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	KeyFile = "client-key.pem" // same names as deploy/examples/client-login.sh uses, so the two interoperate
	IDsFile = "client.json"

	refreshMargin = 30 * time.Second
	maxResponse   = 1 << 20
)

// Config says where the relay is and how this bridge proves who it is.
type Config struct {
	// RelayURL is the relay's HTTPS base, e.g. https://relay.example.com (no path).
	RelayURL string
	// Origin is what the client signs: exactly the relay's RELAY_PUBLIC_ORIGIN (e.g. wss://relay.example.com). If empty it is
	// derived from RelayURL (https -> wss).
	Origin string
	// Dir holds client-key.pem and client.json.
	Dir string
	// AllowInsecure permits plain http:// but ONLY to a loopback address (development).
	AllowInsecure bool
	// HTTPClient is the client used for login and (wrapped) for MCP; nil means a client with sane timeouts.
	HTTPClient *http.Client
	Now        func() time.Time
	// Logf receives diagnostics. It must go to stderr (stdout carries the protocol) and never receives secrets.
	Logf func(format string, args ...any)
}

func (c *Config) defaults() error {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 45 * time.Second}
	}
	u, err := url.Parse(strings.TrimRight(c.RelayURL, "/"))
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return errors.New("the relay address must look like https://relay.example.com (no path, no credentials)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !c.AllowInsecure || !isLoopback(u.Hostname()) {
			return errors.New("plain http:// is only allowed to a loopback address with -allow-insecure; use https://")
		}
	default:
		return errors.New("the relay address must start with https://")
	}
	c.RelayURL = strings.TrimRight(u.String(), "/")
	if c.Origin == "" {
		c.Origin = map[string]string{"https": "wss", "http": "ws"}[u.Scheme] + "://" + strings.ToLower(u.Host)
	}
	c.Origin = strings.ToLower(strings.TrimRight(c.Origin, "/"))
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Credentials are the client's identity: ids from client.json and the private key.
type Credentials struct {
	ClientID     string
	CredentialID string
	Key          *ecdsa.PrivateKey
}

// LoadCredentials reads the key and ids from dir. It refuses a private key that other users can read.
func LoadCredentials(dir string) (*Credentials, error) {
	keyPath := filepath.Join(dir, KeyFile)
	st, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("no client key in %s: pair first (mcpbridge pair ...): %w", dir, err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %o); run: chmod 600 %s", keyPath, st.Mode().Perm(), keyPath)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	ib, err := os.ReadFile(filepath.Join(dir, IDsFile))
	if err != nil {
		return nil, fmt.Errorf("no %s in %s: pair first: %w", IDsFile, dir, err)
	}
	var ids struct {
		ClientID     string `json:"client_id"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.Unmarshal(ib, &ids); err != nil || ids.ClientID == "" || ids.CredentialID == "" {
		return nil, fmt.Errorf("%s is not valid (need client_id and credential_id)", IDsFile)
	}
	return &Credentials{ClientID: strings.ToLower(ids.ClientID), CredentialID: strings.ToLower(ids.CredentialID), Key: key}, nil
}

// parseKey accepts an EC P-256 key as PKCS#8 or SEC1 PEM (what `openssl ecparam -genkey` writes).
func parseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("not a PEM file")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an EC key")
		}
		key = ek
	} else if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		key = k
	} else {
		return nil, errors.New("not a readable EC private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("the key must be EC P-256")
	}
	return key, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Pairing

// Pair redeems a one-time pairing code: it creates a new key pair, registers the public key with the relay, and writes the
// key (mode 0600) and the ids into dir. Nothing is written unless the relay accepted the code, and an existing key is never
// overwritten.
func Pair(ctx context.Context, cfg Config, code, label string) error {
	if err := cfg.defaults(); err != nil {
		return err
	}
	if strings.TrimSpace(code) == "" {
		return errors.New("a pairing code is required")
	}
	keyPath, idsPath := filepath.Join(cfg.Dir, KeyFile), filepath.Join(cfg.Dir, IDsFile)
	for _, p := range []string{keyPath, idsPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite an existing identity (move it away to pair again)", p)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	var out struct {
		ClientID     string `json:"client_id"`
		CredentialID string `json:"credential_id"`
	}
	status, err := postJSON(ctx, cfg.HTTPClient, cfg.RelayURL+"/v1/clients/redeem", "", map[string]string{
		"code": code, "label": label, "public_key": base64.StdEncoding.EncodeToString(spki),
	}, &out)
	switch {
	case err != nil:
		return fmt.Errorf("cannot reach the relay: %w", err)
	case status == http.StatusBadRequest:
		return errors.New("the relay refused the pairing code (invalid, expired or already used) or the label")
	case status == http.StatusTooManyRequests:
		return errors.New("too many attempts; wait a minute and try again")
	case status != http.StatusCreated:
		return fmt.Errorf("the relay answered HTTP %d", status)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return err
	}
	ids, _ := json.MarshalIndent(map[string]string{"client_id": out.ClientID, "credential_id": out.CredentialID}, "", "  ")
	if err := writeNew(idsPath, ids); err != nil {
		_ = os.Remove(keyPath) // never leave a key without its ids
		return err
	}
	cfg.Logf("paired as client %s; key saved to %s", out.ClientID, keyPath)
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func postJSON(ctx context.Context, hc *http.Client, url, bearer string, body any, out any) (int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unreadable response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Token source

// ErrRejected means the relay refused to log this client in (revoked, wrong key/credential, or a wrong origin).
var ErrRejected = errors.New("the relay rejected this client: it may have been revoked, or the key, credential or -origin does not match (the origin must equal the relay's RELAY_PUBLIC_ORIGIN)")

// TokenSource logs in when needed and caches the access token in memory only. Safe for concurrent use; concurrent callers
// share a single login.
type TokenSource struct {
	cfg   Config
	creds *Credentials

	mu      sync.Mutex
	token   string
	expires time.Time
}

func NewTokenSource(cfg Config, creds *Credentials) (*TokenSource, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &TokenSource{cfg: cfg, creds: creds}, nil
}

// Token returns a token valid for at least the refresh margin, logging in if necessary.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.cfg.Now().Add(refreshMargin).Before(t.expires) {
		return t.token, nil
	}
	return t.loginLocked(ctx)
}

// Reject forgets token if it is still the current one (the relay refused it), so the next Token call logs in again.
func (t *TokenSource) Reject(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token == token {
		t.token = ""
	}
}

func (t *TokenSource) loginLocked(ctx context.Context) (string, error) {
	var ch struct {
		Nonce string `json:"nonce"`
	}
	st, err := postJSON(ctx, t.cfg.HTTPClient, t.cfg.RelayURL+"/v1/auth/challenge", "", map[string]string{"client_id": t.creds.ClientID}, &ch)
	if err != nil {
		return "", fmt.Errorf("cannot reach the relay: %w", err)
	}
	if st != http.StatusOK {
		return "", fmt.Errorf("the relay refused the login request (HTTP %d)", st)
	}
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil || len(nonce) != 32 {
		return "", errors.New("the relay sent an invalid challenge")
	}
	digest := sha256.Sum256(auth.Message(nonce, t.creds.ClientID, t.creds.CredentialID, t.cfg.Origin))
	sig, err := ecdsa.SignASN1(rand.Reader, t.creds.Key, digest[:])
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string    `json:"access_token"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	st, err = postJSON(ctx, t.cfg.HTTPClient, t.cfg.RelayURL+"/v1/auth/token", "", map[string]string{
		"client_id": t.creds.ClientID, "credential_id": t.creds.CredentialID, "nonce": ch.Nonce, "signature": base64.StdEncoding.EncodeToString(sig),
	}, &tok)
	switch {
	case err != nil:
		return "", fmt.Errorf("cannot reach the relay: %w", err)
	case st == http.StatusUnauthorized:
		return "", ErrRejected
	case st != http.StatusOK || tok.AccessToken == "":
		return "", fmt.Errorf("the relay refused the login (HTTP %d)", st)
	}
	t.token, t.expires = tok.AccessToken, tok.ExpiresAt
	t.cfg.Logf("logged in; token valid until %s", tok.ExpiresAt.Format(time.RFC3339))
	return t.token, nil
}

// authTransport adds the bearer token to every request and, when the relay answers 401, logs in again and retries once.
type authTransport struct {
	base http.RoundTripper
	ts   *TokenSource
}

func (a *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	send := func(r *http.Request) (*http.Response, string, error) {
		tok, err := a.ts.Token(r.Context())
		if err != nil {
			return nil, "", err
		}
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+tok)
		resp, err := a.base.RoundTrip(r)
		return resp, tok, err
	}
	resp, tok, err := send(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || req.GetBody == nil {
		return resp, err
	}
	// The token was refused (expired early, or the relay restarted and forgot it). Log in again and retry exactly once.
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	resp.Body.Close()
	a.ts.Reject(tok)
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	resp, _, err = send(retry)
	return resp, err
}

// ---------------------------------------------------------------------------------------------------------------------
// The pipe

// Run bridges host (the stdio side) to the relay until ctx ends or either side closes.
func Run(ctx context.Context, cfg Config, host mcp.Transport) error {
	if err := cfg.defaults(); err != nil {
		return err
	}
	creds, err := LoadCredentials(cfg.Dir)
	if err != nil {
		return err
	}
	ts, err := NewTokenSource(cfg, creds)
	if err != nil {
		return err
	}
	// Fail fast and clearly at start-up rather than on the host's first request.
	if _, err := ts.Token(ctx); err != nil {
		return err
	}
	relay := &mcp.StreamableClientTransport{
		Endpoint:             cfg.RelayURL + "/mcp",
		HTTPClient:           &http.Client{Transport: &authTransport{base: http.DefaultTransport, ts: ts}},
		DisableStandaloneSSE: true,
	}
	return pipe(ctx, cfg, host, relay)
}

func pipe(ctx context.Context, cfg Config, host, relay mcp.Transport) error {
	hconn, err := host.Connect(ctx)
	if err != nil {
		return fmt.Errorf("host side: %w", err)
	}
	defer hconn.Close()
	rconn, err := relay.Connect(ctx)
	if err != nil {
		return fmt.Errorf("relay side: %w", err)
	}
	defer rconn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	// host -> relay. A request the relay cannot take must still get an answer, or the host would wait for ever.
	go func() {
		for {
			msg, err := hconn.Read(ctx)
			if err != nil {
				done <- ignoreClosed(err)
				return
			}
			if err := rconn.Write(ctx, msg); err != nil {
				cfg.Logf("forwarding to the relay failed: %v", err)
				if req, ok := msg.(*jsonrpc.Request); ok && req.IsCall() {
					reply := &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: -32000, Message: errorText(err)}}
					if werr := hconn.Write(ctx, reply); werr != nil {
						done <- werr
						return
					}
				}
			}
		}
	}()
	// relay -> host
	go func() {
		for {
			msg, err := rconn.Read(ctx)
			if err != nil {
				done <- ignoreClosed(err)
				return
			}
			if err := hconn.Write(ctx, msg); err != nil {
				done <- err
				return
			}
		}
	}()
	err = <-done
	cancel()
	return err
}

// errorText is what the host's user sees. It names the problem without echoing request data or credentials.
func errorText(err error) string {
	switch {
	case errors.Is(err, ErrRejected):
		return ErrRejected.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "the relay did not answer in time"
	default:
		return "androvia bridge: " + strings.TrimSpace(err.Error())
	}
}

func ignoreClosed(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, mcp.ErrConnectionClosed) {
		return nil
	}
	return err
}
