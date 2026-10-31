package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/api"
	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/coder/websocket"
)

const (
	origin = "wss://relay.test"
	token  = "test-admin-token-0123456789abcdef0123456789"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	srv   *httptest.Server
	store *devices.MemoryStore
	logs  *syncBuf
}

func newEnv(t *testing.T) *env {
	t.Helper()
	logs := &syncBuf{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	store := devices.NewMemoryStore()
	rt := router.New(log, nil)
	rt.SetGrace(50 * time.Millisecond)
	mgr := connections.NewManager(connections.Config{PublicOrigin: origin, HandshakeTimeout: 2 * time.Second, HeartbeatTimeout: 10 * time.Second}, store, rt, log, nil)
	rt.Attach(mgr)
	srv := httptest.NewServer(api.New(token, store, mgr, rt, log, nil).Handler(mgr.ServeWS))
	t.Cleanup(func() { mgr.CloseAll(); srv.Close() })
	return &env{srv, store, logs}
}

func (e *env) do(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
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
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) admin(t *testing.T, method, path string, body any) (int, map[string]any) {
	return e.do(t, method, path, "Bearer "+token, body)
}

func (e *env) register(t *testing.T, d *testutil.Device) {
	t.Helper()
	if code, out := e.admin(t, "POST", "/v1/devices", map[string]string{"label": "test", "public_key": d.PublicKeyB64()}); code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func errCode(out map[string]any) string {
	if m, ok := out["error"].(map[string]any); ok {
		s, _ := m["code"].(string)
		return s
	}
	return ""
}

func TestHealthzIsOpen(t *testing.T) {
	e := newEnv(t)
	if code, out := e.do(t, "GET", "/healthz", "", nil); code != 200 || out["status"] != "ok" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestEveryAdminRouteRequiresTheToken(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	id := d.ID
	routes := []struct{ method, path string }{
		{"POST", "/v1/devices"}, {"GET", "/v1/devices"}, {"GET", "/v1/devices/" + id},
		{"POST", "/v1/devices/" + id + "/revoke"}, {"POST", "/v1/devices/" + id + "/commands"},
	}
	headers := map[string]string{
		"missing":          "",
		"wrong token":      "Bearer " + strings.Repeat("x", len(token)),
		"prefix of token":  "Bearer " + token[:len(token)-1],
		"token plus extra": "Bearer " + token + "x",
		"empty bearer":     "Bearer ",
		"basic scheme":     "Basic " + token,
		"no scheme":        token,
		"lowercase scheme": "bearer " + token,
	}
	body := map[string]string{"label": "x", "public_key": d.PublicKeyB64()}
	for _, r := range routes {
		for name, h := range headers {
			code, out := e.do(t, r.method, r.path, h, body)
			if code != 401 || errCode(out) != "unauthorized" {
				t.Errorf("%s %s with %s: %d %v", r.method, r.path, name, code, out)
			}
		}
	}
	if ds, _ := e.store.List(context.Background()); len(ds) != 0 {
		t.Fatal("an unauthenticated request changed state")
	}
}

func TestTokenNeverAppearsInLogs(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	e.do(t, "GET", "/v1/devices", "Bearer wrong-secret-value-should-not-be-logged", nil)
	e.admin(t, "GET", "/v1/devices", nil)
	logs := e.logs.String()
	if strings.Contains(logs, token) || strings.Contains(logs, "wrong-secret-value") || strings.Contains(logs, d.PublicKeyB64()) {
		t.Fatalf("secret material in logs:\n%s", logs)
	}
	if !strings.Contains(logs, "unauthorized request") {
		t.Fatal("failed authentication was not logged")
	}
}

func TestRegisterListGetRevoke(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)

	code, out := e.admin(t, "GET", "/v1/devices/"+d.ID, nil)
	if code != 200 || out["id"] != d.ID || out["status"] != "active" || out["online"] != false || out["label"] != "test" {
		t.Fatalf("%d %v", code, out)
	}
	if _, leaked := out["public_key"]; leaked {
		t.Fatal("public key echoed in device JSON")
	}
	if code, out = e.admin(t, "GET", "/v1/devices", nil); code != 200 || len(out["devices"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out = e.admin(t, "POST", "/v1/devices/"+d.ID+"/revoke", nil); code != 200 || out["status"] != "revoked" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out = e.admin(t, "GET", "/v1/devices/"+d.ID, nil); out["status"] != "revoked" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	good := testutil.NewDevice(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsader, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	b64 := base64.StdEncoding.EncodeToString

	bad := map[string]any{
		"not json":           "{",
		"unknown field":      `{"label":"x","public_key":"` + good.PublicKeyB64() + `","admin":true}`,
		"not base64":         map[string]string{"label": "x", "public_key": "!!!"},
		"not a key":          map[string]string{"label": "x", "public_key": b64([]byte("hello"))},
		"P-384":              map[string]string{"label": "x", "public_key": b64(p384der)},
		"RSA":                map[string]string{"label": "x", "public_key": b64(rsader)},
		"empty label":        map[string]string{"label": "", "public_key": good.PublicKeyB64()},
		"label too long":     map[string]string{"label": strings.Repeat("a", 65), "public_key": good.PublicKeyB64()},
		"oversized body":     `{"label":"` + strings.Repeat("a", 70000) + `"}`,
		"missing public_key": map[string]string{"label": "x"},
	}
	for name, body := range bad {
		if code, out := e.admin(t, "POST", "/v1/devices", body); code != 400 || errCode(out) != "invalid_request" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if ds, _ := e.store.List(context.Background()); len(ds) != 0 {
		t.Fatal("a rejected registration was stored")
	}
	e.register(t, good)
	if code, out := e.admin(t, "POST", "/v1/devices", map[string]string{"label": "again", "public_key": good.PublicKeyB64()}); code != 409 || errCode(out) != "device_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
}

func TestUnknownAndMalformedDeviceIDs(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{strings.Repeat("0", 64), "short", "../etc/passwd", strings.Repeat("A", 64)} {
		for _, r := range [][2]string{{"GET", ""}, {"POST", "/revoke"}, {"POST", "/commands"}} {
			code, out := e.admin(t, r[0], "/v1/devices/"+id+r[1], map[string]any{"capability": "device.info", "version": 1})
			if strings.Contains(id, "..") {
				// Go's router cleans/rejects traversal paths before any handler runs: 404 without our JSON body.
				if code != 404 {
					t.Errorf("%s %s%s: %d %v", r[0], id, r[1], code, out)
				}
				continue
			}
			if code != 404 || errCode(out) != "device_not_found" {
				t.Errorf("%s %s%s: %d %v", r[0], id, r[1], code, out)
			}
		}
	}
}

func command(capability string) map[string]any {
	return map[string]any{"capability": capability, "version": 1, "timeout_ms": 2000}
}

func TestCommandEndToEnd(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	c := d.Connect(ctx(t), t, e.srv.URL, origin)

	go func() {
		for {
			msg, err := testutil.Recv(context.Background(), c)
			if err != nil {
				return
			}
			if msg.Type != protocol.TypeCommand {
				continue
			}
			var p protocol.CommandPayload
			_ = json.Unmarshal(msg.Payload, &p)
			switch p.Capability {
			case "device.info":
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeResult, msg.ID, map[string]any{"status": "ok", "data": map[string]any{"model": "Pixel"}}))
			case "files.read":
				_ = testutil.Send(context.Background(), c, d.Env(protocol.TypeError, msg.ID, map[string]any{"code": "permission_denied", "message": "capability is not enabled on this device"}))
			}
			// any other capability: stay silent so the request times out
		}
	}()

	// Online status is visible.
	if _, out := e.admin(t, "GET", "/v1/devices/"+d.ID, nil); out["online"] != true {
		t.Fatalf("not reported online: %v", out)
	}

	code, out := e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", command("device.info"))
	if code != 200 || out["status"] != "ok" || !protocol.ValidID(out["request_id"].(string)) {
		t.Fatalf("%d %v", code, out)
	}
	if data := out["result"].(map[string]any)["data"].(map[string]any); data["model"] != "Pixel" {
		t.Fatalf("%v", out)
	}

	code, out = e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", command("files.read"))
	errObj, _ := out["error"].(map[string]any)
	if code != 422 || errObj["code"] != "permission_denied" || errObj["source"] != "device" {
		t.Fatalf("device error not reported as-is: %d %v", code, out)
	}

	req := command("clipboard.read")
	req["timeout_ms"] = 150
	if code, out = e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", req); code != 504 || errCode(out) != "timeout" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestCommandValidation(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	d.Connect(ctx(t), t, e.srv.URL, origin)
	bad := map[string]any{
		"empty":             map[string]any{},
		"bad capability":    map[string]any{"capability": "shell; rm -rf /", "version": 1},
		"missing version":   map[string]any{"capability": "device.info"},
		"args not object":   map[string]any{"capability": "device.info", "version": 1, "args": []int{1}},
		"timeout too large": map[string]any{"capability": "device.info", "version": 1, "timeout_ms": 3600000},
		"negative timeout":  map[string]any{"capability": "device.info", "version": 1, "timeout_ms": -5},
		"unknown field":     map[string]any{"capability": "device.info", "version": 1, "device": "other"},
	}
	for name, body := range bad {
		if code, out := e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", body); code != 400 || errCode(out) != "invalid_request" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestCommandToOfflineAndRevokedDevices(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	if code, out := e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", command("device.info")); code != 409 || errCode(out) != "device_offline" {
		t.Fatalf("%d %v", code, out)
	}
	e.admin(t, "POST", "/v1/devices/"+d.ID+"/revoke", nil)
	if code, out := e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", command("device.info")); code != 409 || errCode(out) != "device_revoked" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestRevokeDisconnectsAndBlocksReconnect(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	c := d.Connect(ctx(t), t, e.srv.URL, origin)

	e.admin(t, "POST", "/v1/devices/"+d.ID+"/revoke", nil)
	for {
		_, _, err := c.Read(ctx(t))
		if err != nil {
			if websocket.CloseStatus(err) != 4002 {
				t.Fatalf("close %v", err)
			}
			break
		}
	}
	if _, out := e.admin(t, "GET", "/v1/devices/"+d.ID, nil); out["online"] != false {
		t.Fatalf("revoked device reported online: %v", out)
	}
	c2, _, err := websocket.Dial(ctx(t), testutil.WSURL(e.srv.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.CloseNow()
	if _, err := d.Handshake(ctx(t), c2, d.ProperSign(origin)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, _, err := c2.Read(ctx(t)); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
				t.Fatalf("close %v", err)
			}
			break
		}
	}
}

func TestDeviceDroppingMidCommandIsReported(t *testing.T) {
	e := newEnv(t)
	d := testutil.NewDevice(t)
	e.register(t, d)
	c := d.Connect(ctx(t), t, e.srv.URL, origin)
	go func() {
		if msg, err := testutil.Recv(context.Background(), c); err == nil && msg.Type == protocol.TypeCommand {
			_ = c.Close(websocket.StatusNormalClosure, "bye")
		}
	}()
	if code, out := e.admin(t, "POST", "/v1/devices/"+d.ID+"/commands", command("device.info")); code != 502 || errCode(out) != "device_disconnected" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestResponsesAreNotCacheable(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", resp.Header)
	}
}
