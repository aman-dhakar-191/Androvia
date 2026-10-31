package mcpgw_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/bridge"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------------------------------------------------
// harness: the bridge, paired through the real admin + redeem endpoints, with the host side in memory

func (e *env) adminPost(path string, body any) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) bridgeCfg(dir string) bridge.Config {
	return bridge.Config{RelayURL: e.srv.URL, Origin: origin, Dir: dir, AllowInsecure: true, Now: e.clk.now}
}

// pairedBridge issues a pairing code with the grants and redeems it with bridge.Pair into a fresh directory.
func (e *env) pairedBridge(gs ...grant) (cfg bridge.Config, clientID string) {
	e.t.Helper()
	grants := []map[string]any{}
	for _, g := range gs {
		grants = append(grants, map[string]any{"device_id": g.dev.ID, "scopes": g.scopes})
	}
	st, out := e.adminPost("/v1/admin/pairing-codes", map[string]any{"grants": grants})
	if st != http.StatusCreated {
		e.t.Fatalf("issue code: %d %v", st, out)
	}
	cfg = e.bridgeCfg(filepath.Join(e.t.TempDir(), "androvia"))
	if err := bridge.Pair(ctx0, cfg, out["code"].(string), "bridge-test"); err != nil {
		e.t.Fatal(err)
	}
	creds, err := bridge.LoadCredentials(cfg.Dir)
	if err != nil {
		e.t.Fatal(err)
	}
	return cfg, creds.ClientID
}

// host runs the bridge and returns an MCP client session connected to its host side.
func (e *env) host(cfg bridge.Config) (*mcp.ClientSession, <-chan error) {
	e.t.Helper()
	hostSide, clientSide := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(ctx0)
	e.t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- bridge.Run(ctx, cfg, hostSide) }()
	cl := mcp.NewClient(&mcp.Implementation{Name: "host", Version: "1"}, nil)
	cctx, ccancel := context.WithTimeout(ctx, 15*time.Second)
	defer ccancel()
	s, err := cl.Connect(cctx, clientSide, nil)
	if err != nil {
		e.t.Fatalf("connect through the bridge: %v", err)
	}
	e.t.Cleanup(func() { s.Close() })
	return s, done
}

// ---------------------------------------------------------------------------------------------------------------------

func TestBridgeServesToolsWithoutTheHostHoldingAToken(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, clientID := e.pairedBridge(grant{d, readAndInfo})
	s, _ := e.host(cfg)

	if got := strings.Join(toolNames(t, s), ","); got != "get_device_info,list_devices" {
		t.Fatalf("tools via bridge = %s", got)
	}
	r, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if err != nil || r.IsError {
		t.Fatalf("get_device_info: %v %v", err, r)
	}
	if structured(t, r)["model"] != "Phone 1" {
		t.Fatalf("unexpected result %v", r.StructuredContent)
	}
	if d.received.Load() != 1 {
		t.Fatalf("phone received %d commands, want 1", d.received.Load())
	}
	// The relay saw the paired client, not the bridge or the host.
	found := false
	for _, ev := range e.audit.All() {
		if ev.Action == "command.dispatch" && ev.ActorID == clientID {
			found = true
		}
	}
	if !found {
		t.Fatal("no command.dispatch audit event for the paired client")
	}
}

func TestBridgeAddsNoAuthorityBeyondTheClientsGrants(t *testing.T) {
	e := newEnv(t)
	granted, other := e.device(true), e.device(true)
	cfg, _ := e.pairedBridge(grant{granted, readOnly}) // no capability scope
	s, _ := e.host(cfg)

	if got := strings.Join(toolNames(t, s), ","); got != "list_devices" {
		t.Fatalf("tools = %s", got)
	}
	// Not listed for this client, so not callable: a protocol error or a tool error are both refusals.
	if r, err := call(t, s, "get_device_info", map[string]any{"device_id": granted.ID}); err == nil && (r == nil || !r.IsError) {
		t.Fatalf("a tool outside the client's grants succeeded: %v", r)
	}
	if r, err := call(t, s, "get_device_info", map[string]any{"device_id": other.ID}); err == nil && (r == nil || !r.IsError) {
		t.Fatalf("an ungranted device answered: %v", r)
	}
	if granted.received.Load()+other.received.Load() != 0 {
		t.Fatal("a denied call reached a phone")
	}
}

func TestBridgeRefreshesTheTokenBeforeItExpires(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	s, _ := e.host(cfg)
	if r, err := call(t, s, "list_devices", nil); err != nil || r.IsError {
		t.Fatalf("first call: %v %v", err, r)
	}
	e.clk.advance(11 * time.Minute) // the first token is now past its 10-minute life, at the relay and in the bridge
	r, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if err != nil || r.IsError {
		t.Fatalf("call after expiry: %v %v", err, r)
	}
}

func TestBridgeLogsInAgainWhenTheRelayForgotTheToken(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, clientID := e.pairedBridge(grant{d, readAndInfo})
	s, _ := e.host(cfg)
	if _, err := call(t, s, "list_devices", nil); err != nil {
		t.Fatal(err)
	}
	// The relay forgets the token while the client is still valid.
	e.authn.RevokeClient(clientID) // forgets the tokens only (as a relay restart would); the client stays valid in the store
	r, err := call(t, s, "list_devices", nil)
	if err != nil || r.IsError {
		t.Fatalf("expected a transparent re-login, got %v %v", err, r)
	}
}

func TestBridgeOfARevokedClientFailsClearlyAndDoesNotHang(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, clientID := e.pairedBridge(grant{d, readAndInfo})
	s, _ := e.host(cfg)
	if _, err := call(t, s, "list_devices", nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.adminPost("/v1/admin/clients/"+clientID+"/revoke", map[string]any{}); st != http.StatusOK {
		t.Fatalf("revoke: %d", st)
	}
	r, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if err == nil && (r == nil || !r.IsError) {
		t.Fatal("a revoked client's call succeeded through the bridge")
	}
	if err != nil && !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("error should explain the rejection, got: %v", err)
	}
	if d.received.Load() != 0 {
		t.Fatal("a revoked client reached the phone")
	}
}

func TestBridgeFailsAtStartupForARevokedClient(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, clientID := e.pairedBridge(grant{d, readAndInfo})
	e.adminPost("/v1/admin/clients/"+clientID+"/revoke", map[string]any{})
	host, _ := mcp.NewInMemoryTransports()
	err := bridge.Run(ctx0, cfg, host)
	if !errors.Is(err, bridge.ErrRejected) {
		t.Fatalf("Run = %v, want ErrRejected", err)
	}
}

func TestBridgeRefusesWrongOrigin(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	cfg.Origin = "wss://evil.test" // a signature over another origin must not be accepted
	host, _ := mcp.NewInMemoryTransports()
	if err := bridge.Run(ctx0, cfg, host); !errors.Is(err, bridge.ErrRejected) {
		t.Fatalf("Run = %v, want ErrRejected", err)
	}
}

func TestBridgeConcurrentCallsShareOneLogin(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	ts, err := bridge.NewTokenSource(cfg, mustCreds(t, cfg.Dir))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	toks := make([]string, 16)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], _ = ts.Token(ctx0)
		}()
	}
	wg.Wait()
	for _, tk := range toks {
		if tk == "" || tk != toks[0] {
			t.Fatalf("concurrent callers got different tokens: %v", toks)
		}
	}
}

func mustCreds(t *testing.T, dir string) *bridge.Credentials {
	t.Helper()
	c, err := bridge.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------------------------------------------------------------------------------------------------------------------
// configuration and local-file safety

func TestPairWritesTheKeyPrivately(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(cfg.Dir, bridge.KeyFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("key mode = %v err=%v, want 0600", st.Mode().Perm(), err)
		}
	}
}

func TestPairRefusesToOverwriteAnExistingIdentity(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	before, _ := os.ReadFile(filepath.Join(cfg.Dir, bridge.KeyFile))
	st, out := e.adminPost("/v1/admin/pairing-codes", map[string]any{"grants": []map[string]any{{"device_id": d.ID, "scopes": readOnly}}})
	if st != http.StatusCreated {
		t.Fatal(st)
	}
	if err := bridge.Pair(ctx0, cfg, out["code"].(string), "again"); err == nil {
		t.Fatal("Pair overwrote an existing identity")
	}
	after, _ := os.ReadFile(filepath.Join(cfg.Dir, bridge.KeyFile))
	if !bytes.Equal(before, after) {
		t.Fatal("the existing key changed")
	}
	// And the refused attempt must not have consumed the code.
	cfg2 := e.bridgeCfg(filepath.Join(t.TempDir(), "other"))
	if err := bridge.Pair(ctx0, cfg2, out["code"].(string), "second"); err != nil {
		t.Fatalf("code was burned by a refused local attempt: %v", err)
	}
}

func TestPairWithABadCodeWritesNothing(t *testing.T) {
	e := newEnv(t)
	cfg := e.bridgeCfg(filepath.Join(t.TempDir(), "androvia"))
	if err := bridge.Pair(ctx0, cfg, "not-a-real-code", "x"); err == nil {
		t.Fatal("bad code accepted")
	}
	if _, err := os.Stat(cfg.Dir); err == nil {
		entries, _ := os.ReadDir(cfg.Dir)
		if len(entries) != 0 {
			t.Fatalf("files written for a refused pairing: %v", entries)
		}
	}
}

func TestPairedCodeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	st, out := e.adminPost("/v1/admin/pairing-codes", map[string]any{"grants": []map[string]any{{"device_id": d.ID, "scopes": readOnly}}})
	if st != http.StatusCreated {
		t.Fatal(st)
	}
	code := out["code"].(string)
	if err := bridge.Pair(ctx0, e.bridgeCfg(filepath.Join(t.TempDir(), "a")), code, "a"); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Pair(ctx0, e.bridgeCfg(filepath.Join(t.TempDir(), "b")), code, "b"); err == nil {
		t.Fatal("a pairing code was accepted twice")
	}
}

func TestBridgeRefusesAKeyOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	if err := os.Chmod(filepath.Join(cfg.Dir, bridge.KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	host, _ := mcp.NewInMemoryTransports()
	err := bridge.Run(ctx0, cfg, host)
	if err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("Run = %v", err)
	}
}

func TestBridgeRefusesInsecureAndMalformedRelayAddresses(t *testing.T) {
	host, _ := mcp.NewInMemoryTransports()
	for name, c := range map[string]bridge.Config{
		"plain http without the flag": {RelayURL: "http://127.0.0.1:1", Dir: t.TempDir()},
		"plain http to a remote host": {RelayURL: "http://relay.example.com", AllowInsecure: true, Dir: t.TempDir()},
		"path in the address":         {RelayURL: "https://relay.example.com/mcp", Dir: t.TempDir()},
		"credentials in the address":  {RelayURL: "https://user:pw@relay.example.com", Dir: t.TempDir()},
		"unsupported scheme":          {RelayURL: "ftp://relay.example.com", Dir: t.TempDir()},
		"empty":                       {Dir: t.TempDir()},
	} {
		if err := bridge.Run(ctx0, c, host); err == nil || strings.Contains(err.Error(), "no client key") {
			t.Errorf("%s: Run = %v, want an address error before any key is read", name, err)
		}
	}
}

func TestBridgeNeverLogsTheTokenOrTheKey(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	var mu sync.Mutex
	var logged strings.Builder
	cfg.Logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged.WriteString(strings.TrimSpace(strings.ReplaceAll(f, "%", "")) + "|")
		for _, x := range a {
			if s, ok := x.(string); ok {
				logged.WriteString(s + "|")
			}
		}
	}
	s, _ := e.host(cfg)
	_, _ = call(t, s, "list_devices", nil)
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(logged.String(), "avt_") || strings.Contains(logged.String(), "PRIVATE KEY") {
		t.Fatalf("secret in bridge log: %s", logged.String())
	}
}

func TestTokenSourceRefreshesInsideTheMarginAndNotBefore(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	cfg, _ := e.pairedBridge(grant{d, readAndInfo})
	ts, err := bridge.NewTokenSource(cfg, mustCreds(t, cfg.Dir))
	if err != nil {
		t.Fatal(err)
	}
	first, err := ts.Token(ctx0)
	if err != nil {
		t.Fatal(err)
	}
	e.clk.advance(5 * time.Minute) // 5 of 10 minutes used: keep the same token
	if again, _ := ts.Token(ctx0); again != first {
		t.Fatal("logged in again while the token still had plenty of life")
	}
	e.clk.advance(4*time.Minute + 45*time.Second) // 15 s left: inside the 30 s margin, refresh before it can fail a request
	renewed, err := ts.Token(ctx0)
	if err != nil || renewed == first {
		t.Fatalf("token was not renewed inside the refresh margin (err=%v)", err)
	}
	// Reject only forgets the token it is told about.
	ts.Reject("avt_something_else")
	if same, _ := ts.Token(ctx0); same != renewed {
		t.Fatal("Reject of an unrelated token discarded the current one")
	}
}
