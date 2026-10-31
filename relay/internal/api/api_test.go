package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/api"
	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/coder/websocket"
)

const (
	origin = "wss://relay.test"
	admin  = "test-admin-token-0123456789abcdef0123456789"
)

// ---------------------------------------------------------------------------------------------------------------------
// harness

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type skewClock struct{ offset atomic.Int64 }

func (c *skewClock) now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *skewClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

type env struct {
	t       *testing.T
	srv     *httptest.Server
	devices *devices.MemoryStore
	clients *clients.MemoryStore
	audit   *audit.MemoryStore
	mgr     *connections.Manager
	logs    *syncBuf
	clk     *skewClock
}

func newEnv(t *testing.T, limits api.Limits) *env {
	t.Helper()
	if limits == (api.Limits{}) {
		limits = api.Limits{AuthPerMinute: 100000, RedeemPerMinute: 100000, FailuresPerMinute: 100000, ChallengePerClient: 100000}
	}
	logs := &syncBuf{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	clk := &skewClock{}
	ds := devices.NewMemoryStore()
	cs := clients.NewMemoryStore(func(id string) bool { _, err := ds.Get(context.Background(), id); return err == nil })
	as := audit.NewMemoryStore()
	rec := audit.NewRecorder(as, log, clk.now)
	rt := router.New(log, clk.now)
	rt.SetGrace(50 * time.Millisecond)
	mgr := connections.NewManager(connections.Config{PublicOrigin: origin, HandshakeTimeout: 2 * time.Second, HeartbeatTimeout: 10 * time.Second, Audit: rec}, ds, rt, log, clk.now)
	rt.Attach(mgr)
	srv := httptest.NewServer(api.New(api.Deps{
		AdminToken: admin, Devices: ds, Clients: cs, Auth: auth.New(cs, origin, 10*time.Minute, clk.now), Authz: policy.NewAuthorizer(cs),
		Audit: rec, AuditStore: as, Conns: mgr, Disp: rt, Log: log, Now: clk.now, Limits: limits,
	}).Handler(mgr.ServeWS))
	t.Cleanup(func() { mgr.CloseAll(); srv.Close() })
	return &env{t, srv, ds, cs, as, mgr, logs, clk}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

func (e *env) call(method, path, bearer string, body any) (int, map[string]any, http.Header) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (e *env) adm(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	c, o, _ := e.call(method, path, admin, body)
	return c, o
}

func errCode(out map[string]any) string {
	if m, ok := out["error"].(map[string]any); ok {
		s, _ := m["code"].(string)
		return s
	}
	return ""
}

// registerDevice registers a new simulated device through the admin API.
func (e *env) registerDevice() *testutil.Device {
	e.t.Helper()
	d := testutil.NewDevice(e.t)
	if code, out := e.adm("POST", "/v1/admin/devices", map[string]string{"label": "phone", "public_key": d.PublicKeyB64()}); code != 201 {
		e.t.Fatalf("register device: %d %v", code, out)
	}
	return d
}

type grant struct {
	Device *testutil.Device
	Scopes []string
}

func grantsBody(gs []grant) []map[string]any {
	out := []map[string]any{}
	for _, g := range gs {
		out = append(out, map[string]any{"device_id": g.Device.ID, "scopes": g.Scopes})
	}
	return out
}

// pairedClient is an API client with its own key.
type pairedClient struct {
	e      *env
	ID     string
	CredID string
	Key    *testutil.Device
	Token  string
}

func (e *env) issueCode(gs []grant, ttlMinutes int) string {
	e.t.Helper()
	body := map[string]any{"grants": grantsBody(gs)}
	if ttlMinutes != 0 {
		body["ttl_minutes"] = ttlMinutes
	}
	code, out := e.adm("POST", "/v1/admin/pairing-codes", body)
	if code != 201 {
		e.t.Fatalf("issue code: %d %v", code, out)
	}
	return out["code"].(string)
}

func (e *env) redeem(code string, key *testutil.Device) (int, map[string]any) {
	c, o, _ := e.call("POST", "/v1/clients/redeem", "", map[string]string{"code": code, "label": "agent", "public_key": key.PublicKeyB64()})
	return c, o
}

// pair issues a code with the grants, redeems it with a fresh key, and logs in.
func (e *env) pair(gs ...grant) *pairedClient {
	e.t.Helper()
	key := testutil.NewDevice(e.t)
	code, out := e.redeem(e.issueCode(gs, 0), key)
	if code != 201 {
		e.t.Fatalf("redeem: %d %v", code, out)
	}
	c := &pairedClient{e: e, ID: out["client_id"].(string), CredID: out["credential_id"].(string), Key: key}
	c.Token = c.login(c.CredID, key)
	return c
}

// signedExchange performs challenge + token with the given signer behaviour and returns the token response.
func (e *env) exchange(clientID, credID string, key *testutil.Device, org string) (int, map[string]any) {
	e.t.Helper()
	code, ch, _ := e.call("POST", "/v1/auth/challenge", "", map[string]string{"client_id": clientID})
	if code != 200 {
		return code, ch
	}
	nonce := ch["nonce"].(string)
	nb, _ := base64.StdEncoding.DecodeString(nonce)
	sig := key.Sign(auth.Message(nb, clientID, credID, org))
	c, o, _ := e.call("POST", "/v1/auth/token", "", map[string]string{"client_id": clientID, "credential_id": credID, "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(sig)})
	return c, o
}

func (c *pairedClient) login(credID string, key *testutil.Device) string {
	c.e.t.Helper()
	code, out := c.e.exchange(c.ID, credID, key, origin)
	if code != 200 {
		c.e.t.Fatalf("login: %d %v", code, out)
	}
	return out["access_token"].(string)
}

func (c *pairedClient) do(method, path string, body any) (int, map[string]any) {
	c.e.t.Helper()
	code, out, _ := c.e.call(method, path, c.Token, body)
	return code, out
}

func (c *pairedClient) command(d *testutil.Device, capability string) (int, map[string]any) {
	return c.do("POST", "/v1/devices/"+d.ID+"/commands", map[string]any{"capability": capability, "version": 1, "timeout_ms": 2000})
}

// answering makes a connected device reply to each command: result for known capabilities, silence otherwise.
func (e *env) connect(d *testutil.Device) *websocket.Conn {
	e.t.Helper()
	c := d.Connect(ctx(e.t), e.t, e.srv.URL, origin)
	go func() {
		for {
			m, err := testutil.Recv(context.Background(), c)
			if err != nil {
				return
			}
			if m.Type != protocol.TypeCommand {
				continue
			}
			var p protocol.CommandPayload
			_ = json.Unmarshal(m.Payload, &p)
			switch p.Capability {
			case "device.info":
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeResult, m.ID, map[string]any{"status": "ok", "data": map[string]any{"model": "Pixel"}}))
			case "files.read":
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeError, m.ID, map[string]any{"code": "permission_denied", "message": "capability is not enabled on this device"}))
			}
		}
	}()
	return c
}

var execInfo = []string{"capability:device.info:execute"}

// ---------------------------------------------------------------------------------------------------------------------
// authentication boundaries

func TestHealthzIsOpenAndResponsesAreNotCacheable(t *testing.T) {
	e := newEnv(t, api.Limits{})
	code, out, h := e.call("GET", "/healthz", "", nil)
	if code != 200 || out["status"] != "ok" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v %v", code, out, h)
	}
}

func TestEveryAdminRouteRequiresTheAdminToken(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := testutil.NewDevice(t)
	cid := protocol.NewID()
	routes := []struct{ method, path string }{
		{"POST", "/v1/admin/devices"}, {"GET", "/v1/admin/devices"}, {"GET", "/v1/admin/devices/" + d.ID}, {"POST", "/v1/admin/devices/" + d.ID + "/revoke"},
		{"POST", "/v1/admin/pairing-codes"}, {"GET", "/v1/admin/clients"}, {"GET", "/v1/admin/clients/" + cid}, {"POST", "/v1/admin/clients/" + cid + "/revoke"},
		{"PUT", "/v1/admin/clients/" + cid + "/grants/" + d.ID}, {"DELETE", "/v1/admin/clients/" + cid + "/grants/" + d.ID}, {"GET", "/v1/admin/audit"},
	}
	// A real client token must not work on the admin plane either.
	dev := e.registerDevice()
	c := e.pair(grant{dev, append(execInfo, "devices:read")})
	headers := map[string]string{
		"none": "", "wrong": strings.Repeat("x", len(admin)), "prefix": admin[:len(admin)-1], "extra": admin + "x", "client token": c.Token,
	}
	before, _ := e.devices.List(context.Background())
	for _, r := range routes {
		for name, tok := range headers {
			code, out, _ := e.call(r.method, r.path, tok, map[string]any{"label": "x", "public_key": d.PublicKeyB64(), "scopes": []string{"devices:read"}})
			if code != 401 || errCode(out) != "unauthorized" {
				t.Errorf("%s %s with %s: %d %v", r.method, r.path, name, code, out)
			}
		}
	}
	if after, _ := e.devices.List(context.Background()); len(after) != len(before) {
		t.Fatal("an unauthenticated admin request changed state")
	}
}

func TestEveryClientRouteRequiresAClientToken(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	routes := []struct{ method, path string }{
		{"GET", "/v1/me"}, {"POST", "/v1/me/credentials"}, {"DELETE", "/v1/me/credentials/" + protocol.NewID()},
		{"GET", "/v1/devices"}, {"GET", "/v1/devices/" + d.ID}, {"POST", "/v1/devices/" + d.ID + "/commands"},
	}
	for _, r := range routes {
		for name, tok := range map[string]string{"none": "", "garbage": "avt_" + strings.Repeat("A", 43), "no prefix": "abc", "admin token": admin} {
			code, out, _ := e.call(r.method, r.path, tok, map[string]any{"capability": "device.info", "version": 1})
			if code != 401 || errCode(out) != "unauthorized" {
				t.Errorf("%s %s with %s: %d %v", r.method, r.path, name, code, out)
			}
		}
	}
}

func TestTheAdminTokenCannotSendCommands(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	code, out, _ := e.call("POST", "/v1/devices/"+d.ID+"/commands", admin, map[string]any{"capability": "device.info", "version": 1})
	if code != 401 {
		t.Fatalf("the admin token must not reach the command plane: %d %v", code, out)
	}
	if code, _, _ := e.call("POST", "/v1/admin/devices/"+d.ID+"/commands", admin, map[string]any{"capability": "device.info", "version": 1}); code != 404 && code != 405 {
		t.Fatalf("there must be no admin command route: %d", code)
	}
}

func TestTokenNeverAppearsInLogsOrAuditEvents(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	code := e.issueCode([]grant{{d, append(execInfo, "devices:read")}}, 0)
	key := testutil.NewDevice(t)
	_, red := e.redeem(code, key)
	c := &pairedClient{e: e, ID: red["client_id"].(string), CredID: red["credential_id"].(string), Key: key}
	c.Token = c.login(c.CredID, key)
	e.connect(d)
	c.command(d, "device.info")
	e.call("GET", "/v1/admin/clients", "wrong-secret-value-should-not-be-logged", nil)

	_, aud := e.adm("GET", "/v1/admin/audit?limit=500", nil)
	auditJSON, _ := json.Marshal(aud)
	haystack := e.logs.String() + string(auditJSON)
	for name, secret := range map[string]string{
		"admin token": admin, "client token": c.Token, "pairing code": code, "pairing code (no dashes)": strings.ReplaceAll(code, "-", ""),
		"client public key": key.PublicKeyB64(), "failed bearer": "wrong-secret-value", "device public key": d.PublicKeyB64(),
	} {
		if strings.Contains(haystack, secret) {
			t.Errorf("%s leaked into logs or the audit log", name)
		}
	}
	if !strings.Contains(haystack, "admin.auth") {
		t.Error("the failed admin authentication was not audited")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// pairing

func TestPairingEndToEnd(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})

	code, me := c.do("GET", "/v1/me", nil)
	if code != 200 || me["client_id"] != c.ID || len(me["grants"].([]any)) != 1 || len(me["credentials"].([]any)) != 1 {
		t.Fatalf("%d %v", code, me)
	}
	code, list := c.do("GET", "/v1/devices", nil)
	if code != 200 || len(list["devices"].([]any)) != 1 {
		t.Fatalf("%d %v", code, list)
	}
	if _, dev := c.do("GET", "/v1/devices/"+d.ID, nil); dev["online"] != true {
		t.Fatalf("not online: %v", dev)
	}
	code, out := c.command(d, "device.info")
	if code != 200 || out["status"] != "ok" || !protocol.ValidID(out["request_id"].(string)) {
		t.Fatalf("%d %v", code, out)
	}

	// The audit trail tells the whole story, and the request id ties dispatch to completion.
	_, aud := e.adm("GET", "/v1/admin/audit?limit=500", nil)
	seen := map[string]int{}
	var dispatchID, completeID string
	for _, ev := range aud["events"].([]any) {
		m := ev.(map[string]any)
		seen[m["action"].(string)]++
		switch m["action"] {
		case "command.dispatch":
			dispatchID = m["request_id"].(string)
		case "command.complete":
			completeID = m["request_id"].(string)
		}
	}
	for _, want := range []string{"device.register", "pairing.issue", "pairing.redeem", "auth.token", "device.connect", "command.dispatch", "command.complete"} {
		if seen[want] == 0 {
			t.Errorf("audit log has no %q event (have %v)", want, seen)
		}
	}
	if dispatchID == "" || dispatchID != completeID || dispatchID != out["request_id"] {
		t.Errorf("request ids do not line up: %q %q %v", dispatchID, completeID, out["request_id"])
	}
}

func TestPairingCodeWorksOnceAndBadCodesAreIndistinguishable(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	code := e.issueCode([]grant{{d, []string{"devices:read"}}}, 0)
	if c, o := e.redeem(code, testutil.NewDevice(t)); c != 201 {
		t.Fatalf("%d %v", c, o)
	}
	// Reuse, junk, and a made-up code give the identical answer.
	var bodies []string
	for _, bad := range []string{code, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA", "", "x"} {
		c, o := e.redeem(bad, testutil.NewDevice(t))
		if c != 400 || errCode(o) != "invalid_code" {
			t.Errorf("%q: %d %v", bad, c, o)
		}
		b, _ := json.Marshal(o)
		bodies = append(bodies, string(b))
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("responses differ and leak why a code failed: %q vs %q", b, bodies[0])
		}
	}
}

func TestExpiredPairingCode(t *testing.T) {
	e := newEnv(t, api.Limits{})
	code := e.issueCode(nil, 5)
	e.clk.advance(6 * time.Minute)
	if c, o := e.redeem(code, testutil.NewDevice(t)); c != 400 || errCode(o) != "invalid_code" {
		t.Fatalf("expired code accepted: %d %v", c, o)
	}
}

func TestBadRedeemInputDoesNotBurnTheCode(t *testing.T) {
	e := newEnv(t, api.Limits{})
	code := e.issueCode(nil, 0)
	good := testutil.NewDevice(t)
	for name, body := range map[string]map[string]string{
		"not base64":  {"code": code, "label": "a", "public_key": "!!!"},
		"not a key":   {"code": code, "label": "a", "public_key": base64.StdEncoding.EncodeToString([]byte("hello"))},
		"empty label": {"code": code, "label": "", "public_key": good.PublicKeyB64()},
	} {
		if c, o, _ := e.call("POST", "/v1/clients/redeem", "", body); c != 400 || errCode(o) != "invalid_request" {
			t.Errorf("%s: %d %v", name, c, o)
		}
	}
	if c, o := e.redeem(code, good); c != 201 {
		t.Fatalf("the code was burned by invalid input: %d %v", c, o)
	}
}

func TestConcurrentRedemptionsOfOneCode(t *testing.T) {
	e := newEnv(t, api.Limits{})
	code := e.issueCode(nil, 0)
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, _ := e.redeem(code, testutil.NewDevice(t)); c == 201 {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d clients were created from one code", ok)
	}
	if _, out := e.adm("GET", "/v1/admin/clients", nil); len(out["clients"].([]any)) != 1 {
		t.Fatalf("clients: %v", out)
	}
}

func TestIssueCodeValidation(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	ghost := testutil.NewDevice(t)
	bad := map[string]any{
		"unknown device":   map[string]any{"grants": grantsBody([]grant{{ghost, []string{"devices:read"}}})},
		"unknown scope":    map[string]any{"grants": grantsBody([]grant{{d, []string{"root"}}})},
		"wildcard scope":   map[string]any{"grants": grantsBody([]grant{{d, []string{"capability:*:execute"}}})},
		"empty scopes":     map[string]any{"grants": grantsBody([]grant{{d, nil}})},
		"ttl too long":     map[string]any{"ttl_minutes": 100000},
		"negative ttl":     map[string]any{"ttl_minutes": -1},
		"unknown field":    map[string]any{"admin": true},
		"duplicate device": map[string]any{"grants": grantsBody([]grant{{d, []string{"devices:read"}}, {d, execInfo}})},
	}
	for name, body := range bad {
		if c, o := e.adm("POST", "/v1/admin/pairing-codes", body); c != 400 {
			t.Errorf("%s: %d %v", name, c, o)
		}
	}
	// A revoked device cannot be granted.
	e.adm("POST", "/v1/admin/devices/"+d.ID+"/revoke", nil)
	if c, _ := e.adm("POST", "/v1/admin/pairing-codes", map[string]any{"grants": grantsBody([]grant{{d, []string{"devices:read"}}})}); c != 400 {
		t.Errorf("a revoked device was grantable: %d", c)
	}
}

func TestRedeemIsRateLimited(t *testing.T) {
	e := newEnv(t, api.Limits{AuthPerMinute: 1000, RedeemPerMinute: 5, FailuresPerMinute: 1000, ChallengePerClient: 1000})
	limited := false
	for i := 0; i < 12; i++ {
		c, _ := e.redeem("AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA", testutil.NewDevice(t))
		if c == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("redeem guessing is not rate limited")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// login (challenge / token)

func TestLoginFailuresAreIdenticalAndLeakNothing(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, execInfo})
	other := testutil.NewDevice(t)
	ghostClient, ghostCred := protocol.NewID(), protocol.NewID()

	cases := map[string]func() (int, map[string]any){
		"unknown client":     func() (int, map[string]any) { return e.exchange(ghostClient, ghostCred, other, origin) },
		"wrong key":          func() (int, map[string]any) { return e.exchange(c.ID, c.CredID, other, origin) },
		"wrong relay":        func() (int, map[string]any) { return e.exchange(c.ID, c.CredID, c.Key, "wss://evil.example.com") },
		"unknown credential": func() (int, map[string]any) { return e.exchange(c.ID, protocol.NewID(), c.Key, origin) },
	}
	var first string
	for name, f := range cases {
		code, out := f()
		if code != 401 || errCode(out) != "unauthorized" {
			t.Errorf("%s: %d %v", name, code, out)
		}
		b, _ := json.Marshal(out)
		if first == "" {
			first = string(b)
		} else if string(b) != first {
			t.Errorf("%s answers differently (%s), which leaks why it failed", name, b)
		}
	}
	// The reasons are for the audit log only.
	_, aud := e.adm("GET", "/v1/admin/audit?limit=500", nil)
	reasons := map[string]bool{}
	for _, ev := range aud["events"].([]any) {
		m := ev.(map[string]any)
		if m["action"] == "auth.token" && m["outcome"] == "denied" {
			reasons[m["detail"].(map[string]any)["reason"].(string)] = true
		}
	}
	// "wrong key" and "wrong relay" are bad signatures; "unknown client" and "unknown credential" have no such credential.
	for _, want := range []string{"bad_signature", "unknown_credential"} {
		if !reasons[want] {
			t.Errorf("audit log lacks the %q reason: %v", want, reasons)
		}
	}
}

func TestAReplayedLoginIsRejected(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, execInfo})
	_, ch, _ := e.call("POST", "/v1/auth/challenge", "", map[string]string{"client_id": c.ID})
	nonce := ch["nonce"].(string)
	nb, _ := base64.StdEncoding.DecodeString(nonce)
	body := map[string]string{"client_id": c.ID, "credential_id": c.CredID, "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(c.Key.Sign(auth.Message(nb, c.ID, c.CredID, origin)))}
	if code, _, _ := e.call("POST", "/v1/auth/token", "", body); code != 200 {
		t.Fatalf("first exchange: %d", code)
	}
	if code, out, _ := e.call("POST", "/v1/auth/token", "", body); code != 401 {
		t.Fatalf("a recorded exchange was accepted twice: %d %v", code, out)
	}
}

func TestChallengeAndTokenInputValidation(t *testing.T) {
	e := newEnv(t, api.Limits{})
	for name, body := range map[string]any{"not a uuid": map[string]string{"client_id": "x"}, "empty": map[string]string{}, "unknown field": map[string]any{"client_id": protocol.NewID(), "x": 1}, "not json": "{"} {
		if c, o, _ := e.call("POST", "/v1/auth/challenge", "", body); c != 400 {
			t.Errorf("challenge %s: %d %v", name, c, o)
		}
	}
	for name, body := range map[string]any{
		"bad ids":                map[string]string{"client_id": "x", "credential_id": "y", "nonce": "n", "signature": "AA=="},
		"bad signature encoding": map[string]string{"client_id": protocol.NewID(), "credential_id": protocol.NewID(), "nonce": "n", "signature": "!!!"},
	} {
		if c, o, _ := e.call("POST", "/v1/auth/token", "", body); c != 400 {
			t.Errorf("token %s: %d %v", name, c, o)
		}
	}
}

func TestTokensExpire(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})
	if code, _ := c.do("GET", "/v1/me", nil); code != 200 {
		t.Fatal("fresh token refused")
	}
	e.clk.advance(11 * time.Minute)
	if code, _ := c.do("GET", "/v1/me", nil); code != 401 {
		t.Fatalf("an expired token still works: %d", code)
	}
	c.Token = c.login(c.CredID, c.Key) // logging in again works
	if code, _ := c.do("GET", "/v1/me", nil); code != 200 {
		t.Fatal("re-login failed")
	}
}

func TestFailedAuthenticationIsRateLimitedPerIP(t *testing.T) {
	e := newEnv(t, api.Limits{AuthPerMinute: 1000, RedeemPerMinute: 1000, FailuresPerMinute: 5, ChallengePerClient: 1000})
	limited := false
	for i := 0; i < 15; i++ {
		if c, _, _ := e.call("GET", "/v1/admin/clients", "guess", nil); c == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("admin token guessing is not rate limited")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// authorization

func TestScopesAreEnforcedPerCapability(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})

	if code, _ := c.command(d, "device.info"); code != 200 {
		t.Fatalf("the granted capability was refused: %d", code)
	}
	// The device would happily answer files.read, but this client was never granted it.
	code, out := c.command(d, "files.read")
	if code != 403 || errCode(out) != "forbidden" {
		t.Fatalf("scope escalation: %d %v", code, out)
	}
	// Only the request that was allowed reached the device.
	_, aud := e.adm("GET", "/v1/admin/audit?limit=500", nil)
	denied := 0
	for _, ev := range aud["events"].([]any) {
		if m := ev.(map[string]any); m["action"] == "command.denied" && m["outcome"] == "denied" {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("expected one command.denied event, saw %d", denied)
	}
}

func TestReadAndExecuteAreSeparate(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	reader := e.pair(grant{d, []string{"devices:read"}})
	runner := e.pair(grant{d, execInfo})

	if code, _ := reader.do("GET", "/v1/devices/"+d.ID, nil); code != 200 {
		t.Fatalf("reader cannot read: %d", code)
	}
	if code, out := reader.command(d, "device.info"); code != 403 {
		t.Fatalf("a read-only client could execute: %d %v", code, out)
	}
	if code, _ := runner.command(d, "device.info"); code != 200 {
		t.Fatal("runner cannot execute")
	}
	if code, out := runner.do("GET", "/v1/devices/"+d.ID, nil); code != 403 {
		t.Fatalf("an execute-only client could read the device: %d %v", code, out)
	}
	if _, list := runner.do("GET", "/v1/devices", nil); len(list["devices"].([]any)) != 0 {
		t.Fatalf("a device without devices:read was listed: %v", list)
	}
}

func TestACLientCannotReachDevicesItWasNotGranted(t *testing.T) {
	e := newEnv(t, api.Limits{})
	a, b := e.registerDevice(), e.registerDevice()
	e.connect(a)
	e.connect(b)
	c := e.pair(grant{a, append([]string{"devices:read"}, execInfo...)})

	if code, _ := c.command(a, "device.info"); code != 200 {
		t.Fatal("own device refused")
	}
	// Device B exists, is online, and is a perfectly good target: but this client has no relationship with it.
	for name, f := range map[string]func() (int, map[string]any){
		"command": func() (int, map[string]any) { return c.command(b, "device.info") },
		"get":     func() (int, map[string]any) { return c.do("GET", "/v1/devices/"+b.ID, nil) },
	} {
		code, out := f()
		if code != 404 || errCode(out) != "device_not_found" {
			t.Errorf("%s on another device: %d %v", name, code, out)
		}
	}
	ghost := testutil.NewDevice(t)
	_, existing := c.command(b, "device.info")
	_, missing := c.command(ghost, "device.info")
	e1, _ := json.Marshal(existing)
	e2, _ := json.Marshal(missing)
	if string(e1) != string(e2) {
		t.Errorf("an ungranted real device looks different from a non-existent one:\n%s\n%s", e1, e2)
	}
	if _, list := c.do("GET", "/v1/devices", nil); len(list["devices"].([]any)) != 1 {
		t.Fatalf("list leaked other devices: %v", list)
	}
}

func TestClientWithNoGrantsSeesNothing(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair() // no grants at all
	if code, _ := c.command(d, "device.info"); code != 404 {
		t.Fatalf("%d", code)
	}
	if _, list := c.do("GET", "/v1/devices", nil); len(list["devices"].([]any)) != 0 {
		t.Fatalf("%v", list)
	}
}

func TestGrantChangesTakeEffectImmediately(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair()
	path := "/v1/admin/clients/" + c.ID + "/grants/" + d.ID

	if code, _ := c.command(d, "device.info"); code != 404 {
		t.Fatal("access before any grant")
	}
	if code, out := e.adm("PUT", path, map[string]any{"scopes": execInfo}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := c.command(d, "device.info"); code != 200 {
		t.Fatal("grant not effective")
	}
	if code, _ := e.adm("PUT", path, map[string]any{"scopes": []string{"devices:read"}}); code != 200 { // narrowing replaces
		t.Fatal("narrow failed")
	}
	if code, _ := c.command(d, "device.info"); code != 403 {
		t.Fatalf("narrowed grant still allows execution: %d", code)
	}
	if code, _ := e.adm("DELETE", path, nil); code != 204 {
		t.Fatalf("delete grant: %d", code)
	}
	if code, _ := c.command(d, "device.info"); code != 404 {
		t.Fatal("removed grant still works")
	}
}

func TestGrantValidation(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair()
	path := "/v1/admin/clients/" + c.ID + "/grants/" + d.ID
	for name, body := range map[string]any{"unknown scope": map[string]any{"scopes": []string{"root"}}, "wildcard": map[string]any{"scopes": []string{"capability:*:execute"}}, "empty": map[string]any{"scopes": []string{}}, "unknown field": map[string]any{"scopes": []string{"devices:read"}, "x": 1}} {
		if code, _ := e.adm("PUT", path, body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	ok := map[string]any{"scopes": []string{"devices:read"}}
	if code, _ := e.adm("PUT", "/v1/admin/clients/"+protocol.NewID()+"/grants/"+d.ID, ok); code != 404 {
		t.Errorf("unknown client: %d", code)
	}
	if code, _ := e.adm("PUT", "/v1/admin/clients/"+c.ID+"/grants/"+testutil.NewDevice(t).ID, ok); code != 404 {
		t.Errorf("unknown device: %d", code)
	}
	if code, _ := e.adm("PUT", "/v1/admin/clients/"+c.ID+"/grants/not-a-device", ok); code != 404 {
		t.Errorf("malformed device: %d", code)
	}
	e.adm("POST", "/v1/admin/clients/"+c.ID+"/revoke", nil)
	if code, _ := e.adm("PUT", path, ok); code != 409 {
		t.Errorf("granting to a revoked client: %d", code)
	}
}

func TestACommandToARevokedDeviceIsRefused(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair(grant{d, execInfo})
	e.adm("POST", "/v1/admin/devices/"+d.ID+"/revoke", nil)
	if code, out := c.command(d, "device.info"); code != 409 || errCode(out) != "device_revoked" {
		t.Fatalf("%d %v", code, out)
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// revocation and rotation

func TestRevokingAClientEndsItsAccessAtOnce(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})
	if code, _ := c.command(d, "device.info"); code != 200 {
		t.Fatal("setup")
	}
	if code, out := e.adm("POST", "/v1/admin/clients/"+c.ID+"/revoke", nil); code != 200 || out["status"] != "revoked" {
		t.Fatalf("%d %v", code, out)
	}
	// The very same token, no waiting for it to expire.
	if code, _ := c.command(d, "device.info"); code != 401 {
		t.Fatalf("a revoked client's token still works: %d", code)
	}
	if code, _ := e.exchange(c.ID, c.CredID, c.Key, origin); code != 401 {
		t.Fatalf("a revoked client can log in again: %d", code)
	}
	if code, _ := e.adm("POST", "/v1/admin/clients/"+c.ID+"/revoke", nil); code != 200 { // idempotent
		t.Fatalf("second revoke: %d", code)
	}
	if code, _ := e.adm("POST", "/v1/admin/clients/"+protocol.NewID()+"/revoke", nil); code != 404 {
		t.Fatalf("unknown client: %d", code)
	}
	if _, g := e.adm("GET", "/v1/admin/clients/"+c.ID, nil); g["client"].(map[string]any)["status"] != "revoked" {
		t.Fatalf("%v", g)
	}
}

func TestCredentialRotation(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})
	oldToken := c.Token

	newKey := testutil.NewDevice(t)
	code, out := c.do("POST", "/v1/me/credentials", map[string]string{"public_key": newKey.PublicKeyB64()})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	newCred := out["credential_id"].(string)
	newToken := c.login(newCred, newKey) // the new key works

	// Retire the old one: its tokens die with it, and it can no longer log in.
	if code, o := c.do("DELETE", "/v1/me/credentials/"+c.CredID, nil); code != 200 {
		t.Fatalf("%d %v", code, o)
	}
	c.Token = oldToken
	if code, _ := c.do("GET", "/v1/me", nil); code != 401 {
		t.Fatalf("a retired credential's token still works: %d", code)
	}
	if code, _ := e.exchange(c.ID, c.CredID, c.Key, origin); code != 401 {
		t.Fatalf("a retired credential can log in: %d", code)
	}
	c.Token = newToken
	if code, _ := c.do("GET", "/v1/me", nil); code != 200 {
		t.Fatal("the new credential's token broke")
	}
	// Cannot lock yourself out.
	if code, o := c.do("DELETE", "/v1/me/credentials/"+newCred, nil); code != 409 || errCode(o) != "last_credential" {
		t.Fatalf("removed the last credential: %d %v", code, o)
	}
	if code, _ := c.do("DELETE", "/v1/me/credentials/"+protocol.NewID(), nil); code != 404 {
		t.Fatalf("unknown credential: %d", code)
	}
	if code, _ := c.do("POST", "/v1/me/credentials", map[string]string{"public_key": "!!!"}); code != 400 {
		t.Fatalf("bad key: %d", code)
	}
}

func TestCredentialLimit(t *testing.T) {
	e := newEnv(t, api.Limits{})
	c := e.pair()
	limited := false
	for i := 0; i < clients.MaxCredentialsPerClient+2; i++ {
		code, _ := c.do("POST", "/v1/me/credentials", map[string]string{"public_key": testutil.NewDevice(t).PublicKeyB64()})
		if code == 409 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unbounded credentials")
	}
}

func TestAClientCannotRemoveAnotherClientsCredential(t *testing.T) {
	e := newEnv(t, api.Limits{})
	a, b := e.pair(), e.pair()
	if code, _ := a.do("POST", "/v1/me/credentials", map[string]string{"public_key": testutil.NewDevice(t).PublicKeyB64()}); code != 201 {
		t.Fatal("setup")
	}
	if code, _ := a.do("DELETE", "/v1/me/credentials/"+b.CredID, nil); code != 404 {
		t.Fatalf("%d", code)
	}
	if code, _ := b.do("GET", "/v1/me", nil); code != 200 {
		t.Fatal("b's credential was touched")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// admin: devices, audit

func TestAdminDeviceEndpoints(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	if code, out := e.adm("POST", "/v1/admin/devices", map[string]string{"label": "again", "public_key": d.PublicKeyB64()}); code != 409 || errCode(out) != "device_exists" {
		t.Fatalf("%d %v", code, out)
	}
	for name, body := range map[string]any{"not json": "{", "bad key": map[string]string{"label": "x", "public_key": base64.StdEncoding.EncodeToString([]byte("k"))}, "no label": map[string]string{"label": "", "public_key": d.PublicKeyB64()}, "unknown field": `{"label":"x","public_key":"` + d.PublicKeyB64() + `","admin":true}`} {
		if code, _ := e.adm("POST", "/v1/admin/devices", body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	c := d.Connect(ctx(t), t, e.srv.URL, origin) // no responder goroutine: this test reads the close frame itself
	if _, out := e.adm("GET", "/v1/admin/devices/"+d.ID, nil); out["online"] != true || out["status"] != "active" {
		t.Fatalf("%v", out)
	}
	if _, out := e.adm("GET", "/v1/admin/devices", nil); len(out["devices"].([]any)) != 1 {
		t.Fatalf("%v", out)
	}
	if code, out := e.adm("POST", "/v1/admin/devices/"+d.ID+"/revoke", nil); code != 200 || out["status"] != "revoked" {
		t.Fatalf("%d %v", code, out)
	}
	for { // revoking disconnects with the dedicated code
		if _, _, err := c.Read(ctx(t)); err != nil {
			if websocket.CloseStatus(err) != 4002 {
				t.Fatalf("close %v", err)
			}
			break
		}
	}
	for _, id := range []string{strings.Repeat("0", 64), "short"} {
		if code, out := e.adm("GET", "/v1/admin/devices/"+id, nil); code != 404 || errCode(out) != "device_not_found" {
			t.Errorf("%s: %d %v", id, code, out)
		}
	}
}

func TestAuditPagingAndFilteringOfInput(t *testing.T) {
	e := newEnv(t, api.Limits{})
	for i := 0; i < 5; i++ {
		e.registerDevice()
	}
	_, p1 := e.adm("GET", "/v1/admin/audit?limit=3", nil)
	evs := p1["events"].([]any)
	if len(evs) != 3 || p1["next_before"] == nil {
		t.Fatalf("%v", p1)
	}
	next := fmt.Sprint(int64(p1["next_before"].(float64)))
	_, p2 := e.adm("GET", "/v1/admin/audit?limit=3&before="+next, nil)
	if got := len(p2["events"].([]any)); got != 2 {
		t.Fatalf("second page has %d events", got)
	}
	for _, bad := range []string{"limit=0", "limit=501", "limit=x", "before=-1", "before=x"} {
		if code, _ := e.adm("GET", "/v1/admin/audit?"+bad, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// the audit log is a precondition for privileged actions

func TestNoAuditNoCommand(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	dc := d.Connect(ctx(t), t, e.srv.URL, origin)
	c := e.pair(grant{d, execInfo})

	// Count what actually reaches the device, and answer so the recovery step can complete.
	var reached atomic.Int32
	go func() {
		for {
			m, err := testutil.Recv(context.Background(), dc)
			if err != nil {
				return
			}
			if m.Type == protocol.TypeCommand {
				reached.Add(1)
				_ = testutil.Send(context.Background(), dc, d.Env(protocol.TypeResult, m.ID, map[string]any{"status": "ok", "data": map[string]any{}}))
			}
		}
	}()

	e.audit.FailAppend = errors.New("disk full")
	code, out := c.command(d, "device.info")
	if code != 503 || errCode(out) != "audit_unavailable" {
		t.Fatalf("a command was sent without being audited: %d %v", code, out)
	}
	time.Sleep(300 * time.Millisecond) // give a wrongly-sent command time to arrive
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d command(s) reached the device although the audit write failed", n)
	}
	e.audit.FailAppend = nil
	for _, ev := range e.audit.All() {
		if ev.Action == "command.dispatch" {
			t.Fatal("a dispatch event exists although the write failed")
		}
	}
	if code, _ := c.command(d, "device.info"); code != 200 || reached.Load() != 1 {
		t.Fatalf("recovery after the audit log came back: %d (reached %d)", code, reached.Load())
	}
}

func TestNoAuditNoPrivilegeIncrease(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair()
	e.audit.FailAppend = errors.New("disk full")

	if code, out := e.adm("POST", "/v1/admin/pairing-codes", map[string]any{}); code != 503 || errCode(out) != "audit_unavailable" {
		t.Fatalf("a pairing code was issued unaudited: %d %v", code, out)
	}
	if code, out := e.adm("PUT", "/v1/admin/clients/"+c.ID+"/grants/"+d.ID, map[string]any{"scopes": execInfo}); code != 503 {
		t.Fatalf("a grant was set unaudited: %d %v", code, out)
	}
	e.audit.FailAppend = nil
	if gs, _ := e.clients.Grants(context.Background(), c.ID); len(gs) != 0 {
		t.Fatalf("the grant was applied although it could not be audited: %v", gs)
	}
}

func TestRevocationWorksEvenWhenTheAuditLogIsDown(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, append([]string{"devices:read"}, execInfo...)})
	e.audit.FailAppend = errors.New("disk full")
	if code, _ := e.adm("POST", "/v1/admin/clients/"+c.ID+"/revoke", nil); code != 200 {
		t.Fatalf("revocation was blocked by the audit log: %d", code)
	}
	if code, _ := e.adm("POST", "/v1/admin/devices/"+d.ID+"/revoke", nil); code != 200 {
		t.Fatalf("device revocation was blocked by the audit log: %d", code)
	}
	e.audit.FailAppend = nil
	if code, _ := c.do("GET", "/v1/me", nil); code != 401 {
		t.Fatal("the revoked client still has access")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// command outcomes (carried over from Phase 2, now through the client plane)

func TestCommandOutcomes(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := e.pair(grant{d, []string{"capability:device.info:execute", "capability:files.read:execute", "capability:clipboard.read:execute"}})

	if code, out := c.command(d, "device.info"); code != 409 || errCode(out) != "device_offline" {
		t.Fatalf("offline: %d %v", code, out)
	}
	e.connect(d)
	code, out := c.command(d, "device.info")
	data := out["result"].(map[string]any)["data"].(map[string]any)
	if code != 200 || data["model"] != "Pixel" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = c.command(d, "files.read")
	errObj, _ := out["error"].(map[string]any)
	if code != 422 || errObj["code"] != "permission_denied" || errObj["source"] != "device" {
		t.Fatalf("a device refusal must be reported as the device's own: %d %v", code, out)
	}
	if code, out := c.do("POST", "/v1/devices/"+d.ID+"/commands", map[string]any{"capability": "clipboard.read", "version": 1, "timeout_ms": 150}); code != 504 || errCode(out) != "timeout" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestCommandInputValidation(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	c := e.pair(grant{d, execInfo})
	for name, body := range map[string]any{
		"empty":              map[string]any{},
		"injection":          map[string]any{"capability": "shell; rm -rf /", "version": 1},
		"uppercase":          map[string]any{"capability": "Device.Info", "version": 1},
		"missing version":    map[string]any{"capability": "device.info"},
		"args not an object": map[string]any{"capability": "device.info", "version": 1, "args": []int{1}},
		"timeout too large":  map[string]any{"capability": "device.info", "version": 1, "timeout_ms": 3600000},
		"unknown field":      map[string]any{"capability": "device.info", "version": 1, "device": "other"},
	} {
		if code, out := c.do("POST", "/v1/devices/"+d.ID+"/commands", body); code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestDroppingMidCommandIsReported(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	c := d.Connect(ctx(t), t, e.srv.URL, origin)
	cl := e.pair(grant{d, execInfo})
	go func() {
		if m, err := testutil.Recv(context.Background(), c); err == nil && m.Type == protocol.TypeCommand {
			_ = c.Close(websocket.StatusNormalClosure, "bye")
		}
	}()
	if code, out := cl.command(d, "device.info"); code != 502 || errCode(out) != "device_disconnected" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestDeviceConnectionsAreAudited(t *testing.T) {
	e := newEnv(t, api.Limits{})
	d := e.registerDevice()
	e.connect(d)
	stranger := testutil.NewDevice(t)
	ws, _, _ := websocket.Dial(ctx(t), testutil.WSURL(e.srv.URL), nil)
	defer ws.CloseNow()
	_, _ = stranger.Handshake(ctx(t), ws, stranger.ProperSign(origin))
	_, _, _ = ws.Read(ctx(t))

	deadline := time.Now().Add(3 * time.Second)
	var connect, failed bool
	for time.Now().Before(deadline) && !(connect && failed) {
		for _, ev := range e.audit.All() {
			connect = connect || (ev.Action == "device.connect" && ev.DeviceID == d.ID)
			failed = failed || (ev.Action == "device.auth_failed" && ev.DeviceID == stranger.ID && ev.Outcome == audit.Denied)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !connect || !failed {
		t.Fatalf("connect audited=%v, failed login audited=%v", connect, failed)
	}
}
