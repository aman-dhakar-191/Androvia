package mcpgw_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/aman-dhakar-191/androvia/relay/internal/commands"
	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/mcpgw"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	origin     = "wss://relay.test"
	publicBase = "https://relay.test"
	adminToken = "test-admin-token-0123456789abcdef0123456789"
)

var ctx0 = context.Background()

// ---------------------------------------------------------------------------------------------------------------------
// harness: the real relay routes, in-memory stores

type skewClock struct{ offset atomic.Int64 }

func (c *skewClock) now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *skewClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t       *testing.T
	srv     *httptest.Server
	devices *devices.MemoryStore
	clients *clients.MemoryStore
	audit   *audit.MemoryStore
	authn   *auth.Authenticator
	clk     *skewClock
	logs    *syncBuf
}

func newEnv(t *testing.T) *env {
	t.Helper()
	logs := &syncBuf{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	clk := &skewClock{}
	ds := devices.NewMemoryStore()
	cs := clients.NewMemoryStore(func(id string) bool { _, err := ds.Get(ctx0, id); return err == nil })
	as := audit.NewMemoryStore()
	rec := audit.NewRecorder(as, log, clk.now)
	rt := router.New(log, clk.now)
	rt.SetGrace(50 * time.Millisecond)
	mgr := connections.NewManager(connections.Config{PublicOrigin: origin, HandshakeTimeout: 2 * time.Second, HeartbeatTimeout: 10 * time.Second, Audit: rec}, ds, rt, log, clk.now)
	rt.Attach(mgr)
	authn := auth.New(cs, origin, 10*time.Minute, clk.now)
	cmds := commands.New(commands.Deps{Devices: ds, Clients: cs, Authz: policy.NewAuthorizer(cs), Audit: rec, Disp: rt, Conns: mgr, Log: log, Now: clk.now})
	gw := mcpgw.New(mcpgw.Config{Commands: cmds, Auth: authn, Audit: rec, Log: log, Now: clk.now, PublicBase: publicBase, Version: "test"})
	srv := httptest.NewServer(api.New(api.Deps{
		AdminToken: adminToken, Devices: ds, Clients: cs, Auth: authn, Audit: rec, AuditStore: as, Conns: mgr, Commands: cmds, Log: log, Now: clk.now,
		MCP: gw.Handler(), MCPMetadata: gw.MetadataHandler(), MCPPath: gw.EndpointPath(), MCPMetaPath: gw.MetadataPath(),
		Limits: api.Limits{AuthPerMinute: 100000, RedeemPerMinute: 100000, FailuresPerMinute: 100000, ChallengePerClient: 100000},
	}).Handler(mgr.ServeWS))
	t.Cleanup(func() { mgr.CloseAll(); srv.Close() })
	return &env{t, srv, ds, cs, as, authn, clk, logs}
}

func (e *env) mcpURL() string { return e.srv.URL + "/mcp" }

// device registers a device and (optionally) connects a simulated phone that answers device.info and counts commands.
type phone struct {
	*testutil.Device
	received atomic.Int32
	refuse   atomic.Bool // behave like a phone whose owner has not switched the capability on
	silent   atomic.Bool // receive commands but never answer
	cancels  atomic.Int32
}

func (e *env) device(connect bool) *phone {
	e.t.Helper()
	d := testutil.NewDevice(e.t)
	dev, err := devices.New("Pixel", d.SPKI, e.clk.now())
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.devices.Create(ctx0, dev); err != nil {
		e.t.Fatal(err)
	}
	p := &phone{Device: d}
	if !connect {
		return p
	}
	c := d.Connect(ctx0, e.t, e.srv.URL, origin)
	go func() {
		for {
			m, err := testutil.Recv(context.Background(), c)
			if err != nil {
				return
			}
			if m.Type == protocol.TypeCancel {
				p.cancels.Add(1)
				continue
			}
			if m.Type != protocol.TypeCommand {
				continue
			}
			p.received.Add(1)
			if p.silent.Load() {
				continue
			}
			var cp protocol.CommandPayload
			_ = json.Unmarshal(m.Payload, &cp)
			if cp.Capability == "device.info" && !p.refuse.Load() {
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeResult, m.ID, map[string]any{"status": "ok", "data": map[string]any{
					"manufacturer": "Acme", "model": "Phone 1", "android_release": "16", "sdk_int": 36, "security_patch": "2026-10-01", "supported_abis": []string{"arm64-v8a"},
				}}))
			} else {
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeError, m.ID, map[string]any{"code": "permission_denied", "message": "capability is not enabled on this device"}))
			}
		}
	}()
	return p
}

type grant struct {
	dev    *phone
	scopes []string
}

type apiClient struct {
	id, credID string
	token      string
}

// client creates a paired client holding the grants and logs it in (through the real challenge/signature exchange).
func (e *env) client(gs ...grant) *apiClient {
	e.t.Helper()
	cg := []clients.Grant{}
	for _, g := range gs {
		cg = append(cg, clients.Grant{DeviceID: g.dev.ID, Scopes: g.scopes})
	}
	code, _ := clients.NewCode()
	_ = e.clients.IssueCode(ctx0, clients.PairingCode{ID: protocol.NewID(), CodeHash: clients.HashCode(code), Grants: cg, CreatedBy: "t", CreatedAt: e.clk.now(), ExpiresAt: e.clk.now().Add(time.Hour)})
	key := testutil.NewDevice(e.t)
	cl, cr, err := e.clients.Redeem(ctx0, clients.HashCode(code), "agent", key.SPKI, e.clk.now())
	if err != nil {
		e.t.Fatal(err)
	}
	nonce, _, err := e.authn.NewChallenge(cl.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	nb, _ := base64.StdEncoding.DecodeString(nonce)
	tok, _, err := e.authn.Exchange(ctx0, cl.ID, cr.ID, nonce, key.Sign(auth.Message(nb, cl.ID, cr.ID, origin)))
	if err != nil {
		e.t.Fatal(err)
	}
	return &apiClient{cl.ID, cr.ID, tok}
}

type bearerRT struct {
	token string
	extra http.Header
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	for k, v := range b.extra {
		r.Header[k] = v
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) session(token string) (*mcp.ClientSession, error) {
	c := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(ctx0, 15*time.Second)
	e.t.Cleanup(cancel)
	s, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.mcpURL(), HTTPClient: &http.Client{Transport: bearerRT{token: token}}, DisableStandaloneSSE: true}, nil)
	if err == nil {
		e.t.Cleanup(func() { s.Close() })
	}
	return s, err
}

func (e *env) mustSession(c *apiClient) *mcp.ClientSession {
	e.t.Helper()
	s, err := e.session(c.token)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func toolNames(t *testing.T, s *mcp.ClientSession) []string {
	t.Helper()
	res, err := s.ListTools(ctx0, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tl := range res.Tools {
		out = append(out, tl.Name)
	}
	return out
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx0, 15*time.Second)
	defer cancel()
	return s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}

func structured(t *testing.T, r *mcp.CallToolResult) map[string]any {
	t.Helper()
	m, ok := r.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T: %v", r.StructuredContent, r.StructuredContent)
	}
	return m
}

func errorCode(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	if !r.IsError {
		t.Fatalf("expected a tool error, got success: %v", r.StructuredContent)
	}
	return structured(t, r)["error"].(map[string]any)["code"].(string)
}

var (
	readAndInfo = []string{"devices:read", "capability:device.info:execute"}
	infoOnly    = []string{"capability:device.info:execute"}
	readOnly    = []string{"devices:read"}
)

// ---------------------------------------------------------------------------------------------------------------------
// the tools

func TestListToolsOffersOnlyWhatTheClientCanUse(t *testing.T) {
	e := newEnv(t)
	d := e.device(false)
	cases := map[string]struct {
		c    *apiClient
		want []string
	}{
		"read and execute": {e.client(grant{d, readAndInfo}), []string{"get_device_info", "list_devices"}},
		"read only":        {e.client(grant{d, readOnly}), []string{"list_devices"}},
		"execute only":     {e.client(grant{d, infoOnly}), []string{"get_device_info"}},
		"no grants":        {e.client(), nil},
	}
	for name, tc := range cases {
		got := toolNames(t, e.mustSession(tc.c))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: tools = %v, want %v", name, got, tc.want)
		}
	}
}

func TestToolDefinitions(t *testing.T) {
	e := newEnv(t)
	d := e.device(false)
	s := e.mustSession(e.client(grant{d, readAndInfo}))
	res, err := s.ListTools(ctx0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 2 || res.Tools[0].Name != "get_device_info" || res.Tools[1].Name != "list_devices" {
		t.Fatalf("not the explicit allowlist in deterministic order: %v", res.Tools)
	}
	for _, tl := range res.Tools {
		if tl.Description == "" || tl.InputSchema == nil || tl.OutputSchema == nil || tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("incomplete definition: %+v", tl)
		}
		schema, _ := json.Marshal(tl.InputSchema)
		if !strings.Contains(string(schema), `"additionalProperties":false`) {
			t.Errorf("%s accepts unknown properties: %s", tl.Name, schema)
		}
	}
	if got := ToolNamesForTest(); strings.Join(got, ",") != "get_device_info,list_devices" {
		t.Fatalf("allowlist changed: %v", got)
	}
	// 2026-07-28 requires cache hints; the list depends on the caller, so it must be private and never fresh.
	if res.CacheScope != "private" || res.TTLMs != 0 {
		t.Errorf("cache hints: scope=%q ttl=%d", res.CacheScope, res.TTLMs)
	}
}

func ToolNamesForTest() []string { return mcpgw.ToolNames() }

func TestListDevicesReturnsOnlyGrantedDevices(t *testing.T) {
	e := newEnv(t)
	mine, other := e.device(true), e.device(true)
	_ = other
	s := e.mustSession(e.client(grant{mine, readAndInfo}))
	res, err := call(t, s, "list_devices", nil)
	if err != nil || res.IsError {
		t.Fatalf("%v %v", err, res)
	}
	devs := structured(t, res)["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["device_id"] != mine.ID || devs[0].(map[string]any)["online"] != true {
		t.Fatalf("%v", devs)
	}
}

func TestGetDeviceInfoRunsOnTheDeviceAndIsAudited(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	c := e.client(grant{d, readAndInfo})
	res, err := call(t, e.mustSession(c), "get_device_info", map[string]any{"device_id": d.ID})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	sc := structured(t, res)
	if sc["manufacturer"] != "Acme" || sc["model"] != "Phone 1" || sc["sdk_int"] != float64(36) {
		t.Fatalf("%v", sc)
	}
	if len(res.Content) == 0 {
		t.Fatal("no text content for clients that ignore structuredContent")
	}
	if d.received.Load() != 1 {
		t.Fatalf("device received %d commands", d.received.Load())
	}

	// Same audit trail as REST, tagged with the channel, one request id across dispatch and completion.
	var dispatch, complete audit.Event
	for _, ev := range e.audit.All() {
		switch ev.Action {
		case "command.dispatch":
			dispatch = ev
		case "command.complete":
			complete = ev
		}
	}
	if dispatch.ActorID != c.id || dispatch.Detail["channel"] != "mcp" || dispatch.Detail["capability"] != "device.info" || dispatch.RequestID == "" {
		t.Fatalf("dispatch event: %+v", dispatch)
	}
	if complete.RequestID != dispatch.RequestID || complete.Outcome != audit.Allowed || complete.Detail["channel"] != "mcp" {
		t.Fatalf("complete event: %+v", complete)
	}
}

func TestFailuresAreToolErrorsWithStableCodes(t *testing.T) {
	e := newEnv(t)
	online, offline := e.device(true), e.device(false)
	s := e.mustSession(e.client(grant{online, readAndInfo}, grant{offline, readAndInfo}))

	res, err := call(t, s, "get_device_info", map[string]any{"device_id": offline.ID})
	if err != nil {
		t.Fatalf("a domain failure must be a tool error, not a protocol error: %v", err)
	}
	if code := errorCode(t, res); code != "device_offline" {
		t.Fatalf("offline: %s", code)
	}
	if len(res.Content) == 0 {
		t.Fatal("an error with no text for the model to read")
	}

	// The phone's owner has not switched the capability on: the device refuses and the answer is reported as the device's.
	online.refuse.Store(true)
	res, err = call(t, s, "get_device_info", map[string]any{"device_id": online.ID})
	if err != nil {
		t.Fatal(err)
	}
	e1 := structured(t, res)["error"].(map[string]any)
	if errorCode(t, res) != "permission_denied" || e1["source"] != "device" {
		t.Fatalf("%v", res.StructuredContent)
	}
	if rid, _ := structured(t, res)["request_id"].(string); !protocol.ValidID(rid) {
		t.Fatalf("a dispatched command should carry its request id: %v", res.StructuredContent)
	}
}

func TestToolsOutsideTheAllowlistAreNotCallable(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	s := e.mustSession(e.client(grant{d, readAndInfo}))
	for _, name := range []string{"files_read", "run_shell", "exec", "device.info", "get_device_info ", "GET_DEVICE_INFO", "", "../list_devices"} {
		if res, err := call(t, s, name, map[string]any{"device_id": d.ID}); err == nil && (res == nil || !res.IsError) {
			t.Errorf("tool %q was callable", name)
		}
	}
	if d.received.Load() != 0 {
		t.Fatal("a call outside the allowlist reached the device")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// authorization at call time

func TestAnUnlistedToolIsAlsoNotCallable(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	readerOnly := e.client(grant{d, readOnly})
	s := e.mustSession(readerOnly)
	res, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("a client without the execute scope ran the tool: %+v", res)
	}
	if d.received.Load() != 0 {
		t.Fatal("the command reached the device")
	}
}

func TestOtherDevicesLookLikeNonExistentOnes(t *testing.T) {
	e := newEnv(t)
	mine, theirs := e.device(true), e.device(true)
	ghost := testutil.NewDevice(t)
	s := e.mustSession(e.client(grant{mine, readAndInfo}))

	a, _ := call(t, s, "get_device_info", map[string]any{"device_id": theirs.ID})
	b, _ := call(t, s, "get_device_info", map[string]any{"device_id": ghost.ID})
	if errorCode(t, a) != "device_not_found" || errorCode(t, b) != "device_not_found" {
		t.Fatalf("%v / %v", a.StructuredContent, b.StructuredContent)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("an ungranted real device answers differently from a missing one:\n%s\n%s", ja, jb)
	}
	if theirs.received.Load() != 0 {
		t.Fatal("a command reached a device the client has no grant on")
	}
}

func TestGrantsAreRecheckedOnEveryCall(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	c := e.client(grant{d, readAndInfo})
	s := e.mustSession(c)
	if res, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID}); err != nil || res.IsError {
		t.Fatalf("%v %v", err, res)
	}
	// The administrator removes the grant; the same open session must stop working at once.
	if err := e.clients.SetGrant(ctx0, c.id, d.ID, nil, e.clk.now()); err != nil {
		t.Fatal(err)
	}
	res, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if err == nil && !res.IsError {
		t.Fatalf("a revoked grant still works: %+v", res)
	}
	if d.received.Load() != 1 {
		t.Fatalf("device saw %d commands, want exactly the first", d.received.Load())
	}
}

func TestIdentityCannotBeSuppliedThroughArguments(t *testing.T) {
	e := newEnv(t)
	mine, victim := e.device(true), e.device(true)
	attacker := e.client(grant{mine, readAndInfo})
	victimClient := e.client(grant{victim, readAndInfo})
	s := e.mustSession(attacker)

	for name, args := range map[string]map[string]any{
		"client_id": {"device_id": victim.ID, "client_id": victimClient.id},
		"role":      {"device_id": mine.ID, "role": "admin"},
		"scopes":    {"device_id": victim.ID, "scopes": []string{"capability:device.info:execute"}},
		"token":     {"device_id": victim.ID, "access_token": victimClient.token},
		"as_user":   {"device_id": victim.ID, "user": victimClient.id},
	} {
		res, err := call(t, s, "get_device_info", args)
		if err == nil && !res.IsError {
			t.Errorf("%s: extra property accepted and the call succeeded: %v", name, res.StructuredContent)
		}
	}
	if victim.received.Load() != 0 || mine.received.Load() != 0 {
		t.Fatalf("commands ran: victim=%d mine=%d", victim.received.Load(), mine.received.Load())
	}
	for _, ev := range e.audit.All() {
		if ev.Action == "command.dispatch" {
			t.Fatalf("a rejected call was dispatched: %+v", ev)
		}
	}
}

func TestArgumentsAreValidatedAgainstTheSchema(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	s := e.mustSession(e.client(grant{d, readAndInfo}))
	for name, args := range map[string]map[string]any{
		"missing":        {},
		"wrong type":     {"device_id": 42},
		"too short":      {"device_id": "abc"},
		"upper case":     {"device_id": strings.ToUpper(d.ID)},
		"path traversal": {"device_id": "../../etc/passwd"},
		"null":           {"device_id": nil},
		"too long":       {"device_id": d.ID + "00"},
	} {
		res, err := call(t, s, "get_device_info", args)
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("%s accepted", name)
		}
	}
	if d.received.Load() != 0 {
		t.Fatal("an invalid call reached the device")
	}
}

func TestNoAuditNoCommandOverMCP(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	s := e.mustSession(e.client(grant{d, readAndInfo}))
	e.audit.FailAppend = errors.New("disk full")
	res, _ := call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	if code := errorCode(t, res); code != "audit_unavailable" {
		t.Fatalf("%s", code)
	}
	time.Sleep(300 * time.Millisecond)
	if d.received.Load() != 0 {
		t.Fatal("a command was sent although it could not be audited")
	}
	e.audit.FailAppend = nil
	if res, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID}); err != nil || res.IsError {
		t.Fatalf("no recovery: %v %v", err, res)
	}
}

func TestAClientThatGivesUpCancelsTheCommandOnThePhone(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	d.silent.Store(true)
	s := e.mustSession(e.client(grant{d, readAndInfo}))

	ctx, cancel := context.WithTimeout(ctx0, 600*time.Millisecond)
	defer cancel()
	_, err := s.CallTool(ctx, &mcp.CallToolParams{Name: "get_device_info", Arguments: map[string]any{"device_id": d.ID}})
	if err == nil {
		t.Fatal("the call should have been abandoned")
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if d.received.Load() != 1 || d.cancels.Load() != 1 {
		t.Fatalf("phone saw %d command(s) and %d cancel(s); an abandoned call must be cancelled on the phone", d.received.Load(), d.cancels.Load())
	}
}

func TestClientsAreIsolatedFromEachOther(t *testing.T) {
	e := newEnv(t)
	d1, d2 := e.device(true), e.device(true)
	c1, c2 := e.client(grant{d1, readAndInfo}), e.client(grant{d2, readAndInfo})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for _, tc := range []struct {
			c   *apiClient
			own *phone
		}{{c1, d1}, {c2, d2}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := e.session(tc.c.token)
				if err != nil {
					t.Error(err)
					return
				}
				res, err := call(t, s, "list_devices", nil)
				if err != nil {
					t.Error(err)
					return
				}
				devs := structured(t, res)["devices"].([]any)
				if len(devs) != 1 || devs[0].(map[string]any)["device_id"] != tc.own.ID {
					t.Errorf("a client saw another client's devices: %v", devs)
				}
			}()
		}
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------------------------------------------------
// authentication and transport

func rawPost(t *testing.T, e *env, token string, headers map[string]string, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.mcpURL(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`

func TestUnauthenticatedRequestsAreRefusedWithAChallenge(t *testing.T) {
	e := newEnv(t)
	d := e.device(false)
	c := e.client(grant{d, readAndInfo})
	bad := map[string]string{"none": "", "garbage": "avt_" + strings.Repeat("A", 43), "no prefix": "abc", "the admin token": adminToken}
	for name, tok := range bad {
		resp, _ := rawPost(t, e, tok, nil, strings.Replace(initBody, "%s", "2025-06-18", 1))
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		wa := resp.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(wa, "Bearer") || !strings.Contains(wa, `resource_metadata="`+publicBase+`/.well-known/oauth-protected-resource/mcp"`) {
			t.Errorf("%s: WWW-Authenticate = %q", name, wa)
		}
	}
	if resp, _ := rawPost(t, e, c.token, nil, strings.Replace(initBody, "%s", "2025-06-18", 1)); resp.StatusCode != 200 {
		t.Fatalf("a valid token was refused: %d", resp.StatusCode)
	}
	// Failures are audited with a reason, without the credential itself.
	seen := false
	for _, ev := range e.audit.All() {
		if ev.Action == "auth.rejected" && ev.Detail["channel"] == "mcp" {
			seen = true
		}
	}
	if !seen {
		t.Error("failed MCP authentication was not audited")
	}
	if strings.Contains(e.logs.String(), c.token) || strings.Contains(e.logs.String(), adminToken) {
		t.Error("a credential leaked into the logs")
	}
}

func TestTokenLifecycleIsEnforcedOnTheMCPEndpoint(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	expiring := e.client(grant{d, readAndInfo})
	revoked := e.client(grant{d, readAndInfo})

	if _, err := e.session(expiring.token); err != nil {
		t.Fatal(err)
	}
	// A revoked client's token stops working on its very next request.
	if err := e.clients.RevokeClient(ctx0, revoked.id, e.clk.now()); err != nil {
		t.Fatal(err)
	}
	if resp, _ := rawPost(t, e, revoked.token, nil, strings.Replace(initBody, "%s", "2025-06-18", 1)); resp.StatusCode != 401 {
		t.Errorf("revoked client: %d", resp.StatusCode)
	}
	e.clk.advance(11 * time.Minute)
	if resp, _ := rawPost(t, e, expiring.token, nil, strings.Replace(initBody, "%s", "2025-06-18", 1)); resp.StatusCode != 401 {
		t.Errorf("expired token: %d", resp.StatusCode)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode != 200 || m["resource"] != publicBase+"/mcp" {
		t.Fatalf("%d %v", resp.StatusCode, m)
	}
	if _, has := m["authorization_servers"]; has {
		t.Error("metadata advertises an authorization server this relay does not run")
	}
	if bm, _ := m["bearer_methods_supported"].([]any); len(bm) != 1 || bm[0] != "header" {
		t.Errorf("bearer methods: %v", m["bearer_methods_supported"])
	}
}

func TestOriginIsValidated(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	body := strings.Replace(initBody, "%s", "2025-06-18", 1)
	for name, tc := range map[string]struct {
		origin string
		want   int
	}{
		"no Origin (non-browser client)": {"", 200},
		"the relay's own origin":         {publicBase, 200},
		"another site":                   {"https://evil.example.com", 403},
		"DNS rebinding style":            {"http://relay.test.evil.example.com", 403},
		"null origin":                    {"null", 403},
		"same host, wrong scheme":        {"http://relay.test", 403},
	} {
		h := map[string]string{}
		if tc.origin != "" {
			h["Origin"] = tc.origin
		}
		if resp, _ := rawPost(t, e, c.token, h, body); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
}

func TestStatelessTransport(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	for _, method := range []string{"GET", "DELETE"} {
		req, _ := http.NewRequest(method, e.mcpURL(), nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d (a stateless server has no session stream to open or close)", method, resp.StatusCode)
		}
	}
	resp, _ := rawPost(t, e, c.token, nil, strings.Replace(initBody, "%s", "2025-06-18", 1))
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		t.Errorf("a session id was issued: %q", id)
	}
}

func TestOversizedRequestsAreRefused(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", 80*1024) + `"}}`
	resp, _ := rawPost(t, e, c.token, nil, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an 80 KiB request was accepted: %d", resp.StatusCode)
	}
}

func TestOlderProtocolVersionsStillWork(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	c := e.client(grant{d, readAndInfo})
	for _, v := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"} {
		resp, body := rawPost(t, e, c.token, nil, strings.Replace(initBody, "%s", v, 1))
		if resp.StatusCode != 200 || !strings.Contains(body, `"protocolVersion":"`+v+`"`) {
			t.Errorf("%s: %d %s", v, resp.StatusCode, body)
			continue
		}
		// No session: the next request carries only the version header and the credential.
		resp, body = rawPost(t, e, c.token, map[string]string{"MCP-Protocol-Version": v}, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		if resp.StatusCode != 200 || !strings.Contains(body, `"get_device_info"`) {
			t.Errorf("%s tools/list: %d %s", v, resp.StatusCode, body)
		}
		resp, body = rawPost(t, e, c.token, map[string]string{"MCP-Protocol-Version": v},
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_device_info","arguments":{"device_id":"`+d.ID+`"}}}`)
		if resp.StatusCode != 200 || !strings.Contains(body, `Acme`) || strings.Contains(body, `"isError":true`) {
			t.Errorf("%s tools/call: %d %s", v, resp.StatusCode, body)
		}
	}
}

func TestCapabilitiesAreHonest(t *testing.T) {
	e := newEnv(t)
	c := e.client() // even a client with no grants gets a well-formed (empty) tools capability
	_, body := rawPost(t, e, c.token, nil, strings.Replace(initBody, "%s", "2025-11-25", 1))
	var r struct {
		Result struct {
			Capabilities map[string]map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	caps := r.Result.Capabilities
	if _, ok := caps["tools"]; !ok {
		t.Errorf("no tools capability: %v", caps)
	}
	if lc, _ := caps["tools"]["listChanged"].(bool); lc {
		t.Error("listChanged advertised, but a stateless server can never send list_changed notifications")
	}
	for _, unclaimed := range []string{"logging", "prompts", "resources", "completions"} {
		if _, ok := caps[unclaimed]; ok {
			t.Errorf("capability %q advertised but not provided", unclaimed)
		}
	}
}

func TestUnsupportedProtocolVersionIsNegotiatedNotAccepted(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	resp, body := rawPost(t, e, c.token, nil, strings.Replace(initBody, "%s", "1999-01-01", 1))
	// Per the spec the server answers with a version it supports; it must never echo a version it does not.
	if resp.StatusCode == 200 && strings.Contains(body, `"protocolVersion":"1999-01-01"`) {
		t.Fatalf("an unknown protocol version was echoed: %s", body)
	}
}

func TestSecretsNeverReachTheAuditLogOrLogs(t *testing.T) {
	e := newEnv(t)
	d := e.device(true)
	c := e.client(grant{d, readAndInfo})
	s := e.mustSession(c)
	_, _ = call(t, s, "get_device_info", map[string]any{"device_id": d.ID})
	_, _ = call(t, s, "get_device_info", map[string]any{"device_id": strings.Repeat("e", 64)})
	var all strings.Builder
	for _, ev := range e.audit.All() {
		b, _ := json.Marshal(ev)
		all.Write(b)
	}
	all.WriteString(e.logs.String())
	for name, secret := range map[string]string{"client token": c.token, "admin token": adminToken} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("%s leaked", name)
		}
	}
}
