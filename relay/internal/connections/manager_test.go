package connections_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/coder/websocket"
)

const origin = "wss://relay.test"

type harness struct {
	store *devices.MemoryStore
	mgr   *connections.Manager
	rt    *router.Router
	srv   *httptest.Server
}

func newHarness(t *testing.T, mutate func(*connections.Config)) *harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := devices.NewMemoryStore()
	rt := router.New(log, nil)
	rt.SetGrace(50 * time.Millisecond)
	cfg := connections.Config{PublicOrigin: origin, HandshakeTimeout: 2 * time.Second, HeartbeatTimeout: 5 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	mgr := connections.NewManager(cfg, store, rt, log, nil)
	rt.Attach(mgr)
	srv := httptest.NewServer(http.HandlerFunc(mgr.ServeWS))
	t.Cleanup(func() { mgr.CloseAll(); srv.Close() })
	return &harness{store, mgr, rt, srv}
}

func (h *harness) register(t *testing.T, d *testutil.Device) {
	t.Helper()
	dev, err := devices.New("test", d.SPKI, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.Create(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func dial(t *testing.T, h *harness) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx(t), testutil.WSURL(h.srv.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c
}

// closeInfo reads until the connection ends and reports how.
func closeInfo(t *testing.T, c *websocket.Conn) (websocket.StatusCode, string) {
	t.Helper()
	for {
		_, _, err := c.Read(ctx(t))
		if err == nil {
			continue
		}
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			return ce.Code, ce.Reason
		}
		t.Fatalf("connection ended without a close frame: %v", err)
	}
}

func TestHandshakeHeartbeatAndOnline(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	if h.mgr.Online(d.ID) {
		t.Fatal("online before connecting")
	}
	d.Connect(ctx(t), t, h.srv.URL, origin)
	if !h.mgr.Online(d.ID) {
		t.Fatal("not online after handshake")
	}
	got, _ := h.store.Get(context.Background(), d.ID)
	if got.LastSeenAt == nil {
		t.Fatal("last_seen not recorded")
	}
}

func TestAuthFailuresAreIndistinguishable(t *testing.T) {
	h := newHarness(t, nil)
	registered := testutil.NewDevice(t)
	h.register(t, registered)
	revoked := testutil.NewDevice(t)
	h.register(t, revoked)
	_ = h.store.Revoke(context.Background(), revoked.ID)
	unknown := testutil.NewDevice(t)
	attacker := testutil.NewDevice(t)

	cases := map[string]struct {
		dev  *testutil.Device
		sign testutil.SignFunc
	}{
		"unknown device (valid signature)": {unknown, unknown.ProperSign(origin)},
		"revoked device (valid signature)": {revoked, revoked.ProperSign(origin)},
		"wrong key":                        {registered, func(n []byte) []byte { return attacker.Sign(protocol.AuthMessage(n, registered.ID, origin)) }},
		"wrong origin":                     {registered, registered.ProperSign("wss://evil.test")},
		"signed a different nonce": {registered, func(n []byte) []byte {
			return registered.Sign(protocol.AuthMessage(make([]byte, 32), registered.ID, origin))
		}},
		"missing domain prefix":    {registered, func(n []byte) []byte { return registered.Sign(append(append(n, registered.ID...), origin...)) }},
		"signed another device id": {registered, func(n []byte) []byte { return registered.Sign(protocol.AuthMessage(n, unknown.ID, origin)) }},
		"empty signature":          {registered, func([]byte) []byte { return nil }},
		"garbage signature":        {registered, func([]byte) []byte { return []byte("not a signature") }},
	}
	var first struct {
		code   websocket.StatusCode
		reason string
	}
	i := 0
	for name, tc := range cases {
		c := dial(t, h)
		if _, err := tc.dev.Handshake(ctx(t), c, tc.sign); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		code, reason := closeInfo(t, c)
		if code != websocket.StatusPolicyViolation || reason != "authentication failed" {
			t.Errorf("%s: closed with %d %q", name, code, reason)
		}
		if i == 0 {
			first.code, first.reason = code, reason
		} else if code != first.code || reason != first.reason {
			t.Errorf("%s: close differs from the others (%d %q)", name, code, reason)
		}
		i++
	}
	if h.mgr.Online(registered.ID) || h.mgr.Online(revoked.ID) || h.mgr.Online(unknown.ID) {
		t.Fatal("a failed handshake left a device online")
	}
}

func TestSignatureCannotBeReplayedOnAnotherConnection(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)

	// Connection 1: a legitimate handshake whose signature an eavesdropper records.
	c1 := dial(t, h)
	var captured []byte
	if _, err := d.Handshake(ctx(t), c1, func(n []byte) []byte {
		captured = d.Sign(protocol.AuthMessage(n, d.ID, origin))
		return captured
	}); err != nil {
		t.Fatal(err)
	}
	// Connection 2: relay issues a fresh nonce, so the recorded signature must fail.
	c2 := dial(t, h)
	if _, err := d.Handshake(ctx(t), c2, func([]byte) []byte { return captured }); err != nil {
		t.Fatal(err)
	}
	if code, _ := closeInfo(t, c2); code != websocket.StatusPolicyViolation {
		t.Fatalf("replayed signature accepted (close %d)", code)
	}
}

func TestHandshakeProtocolViolations(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)

	t.Run("first message is not hello", func(t *testing.T) {
		c := dial(t, h)
		_ = testutil.Send(ctx(t), c, d.Env(protocol.TypeHeartbeat, "", struct{}{}))
		if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
			t.Fatalf("close %d", code)
		}
	})
	t.Run("unsupported protocol version in hello", func(t *testing.T) {
		c := dial(t, h)
		_ = testutil.Send(ctx(t), c, d.Env(protocol.TypeHello, "", protocol.HelloPayload{Versions: []int{99}}))
		if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
			t.Fatalf("close %d", code)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		c := dial(t, h)
		_ = c.Write(ctx(t), websocket.MessageText, []byte("{"))
		if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
			t.Fatalf("close %d", code)
		}
	})
	t.Run("binary frame", func(t *testing.T) {
		c := dial(t, h)
		_ = c.Write(ctx(t), websocket.MessageBinary, []byte{1, 2, 3})
		if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
			t.Fatalf("close %d", code)
		}
	})
	t.Run("auth sent as a different device", func(t *testing.T) {
		c := dial(t, h)
		other := testutil.NewDevice(t)
		_ = testutil.Send(ctx(t), c, d.Env(protocol.TypeHello, "", protocol.HelloPayload{Versions: []int{1}}))
		_, _ = testutil.Recv(ctx(t), c)
		bad := other.Env(protocol.TypeAuth, "", protocol.AuthPayload{Signature: base64.StdEncoding.EncodeToString([]byte("x"))})
		_ = testutil.Send(ctx(t), c, bad)
		if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
			t.Fatalf("close %d", code)
		}
	})
}

func TestHandshakeTimeout(t *testing.T) {
	h := newHarness(t, func(c *connections.Config) { c.HandshakeTimeout = 200 * time.Millisecond })
	c := dial(t, h)
	start := time.Now()
	code, _ := closeInfo(t, c)
	if code != websocket.StatusPolicyViolation || time.Since(start) > 3*time.Second {
		t.Fatalf("close %d after %v", code, time.Since(start))
	}
}

func TestHeartbeatTimeoutDropsDevice(t *testing.T) {
	h := newHarness(t, func(c *connections.Config) { c.HeartbeatTimeout = 300 * time.Millisecond })
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	code, reason := closeInfo(t, c)
	if code != 4003 {
		t.Fatalf("close %d %q", code, reason)
	}
	time.Sleep(50 * time.Millisecond)
	if h.mgr.Online(d.ID) {
		t.Fatal("idle device still online")
	}
}

func TestHeartbeatKeepsConnectionAlive(t *testing.T) {
	h := newHarness(t, func(c *connections.Config) { c.HeartbeatTimeout = 400 * time.Millisecond })
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	for i := 0; i < 4; i++ {
		time.Sleep(200 * time.Millisecond)
		if err := testutil.Send(ctx(t), c, d.Env(protocol.TypeHeartbeat, "", struct{}{})); err != nil {
			t.Fatal(err)
		}
		if e, err := testutil.Recv(ctx(t), c); err != nil || e.Type != protocol.TypeHeartbeat {
			t.Fatalf("beat %d: %v %v", i, e, err)
		}
	}
	if !h.mgr.Online(d.ID) {
		t.Fatal("device dropped despite heartbeats")
	}
}

func TestOversizeMessageClosesConnection(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	_ = c.Write(ctx(t), websocket.MessageText, []byte(strings.Repeat("x", protocol.MaxMessageBytes+1)))
	if code, _ := closeInfo(t, c); code != websocket.StatusMessageTooBig {
		t.Fatalf("close %d", code)
	}
}

func TestRepeatedViolationsCloseConnection(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	for i := 0; i < 5; i++ {
		_ = c.Write(ctx(t), websocket.MessageText, []byte(`{}`))
	}
	errorsSeen := 0
	for {
		_, data, err := c.Read(ctx(t))
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
				t.Fatalf("close %v", err)
			}
			break
		}
		e, perr := protocol.Parse(data)
		if perr != nil || e.Type != protocol.TypeError {
			t.Fatalf("expected a parseable error envelope: %v %v", e, perr)
		}
		errorsSeen++
	}
	if errorsSeen != 5 {
		t.Fatalf("saw %d error replies, want 5", errorsSeen)
	}
}

func TestUnexpectedTypesAreRejectedNotRouted(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	// A device must not be able to send commands to the relay or to other devices.
	_ = testutil.Send(ctx(t), c, d.Env(protocol.TypeCommand, "", protocol.CommandPayload{Capability: "device.info", Version: 1}))
	e, err := testutil.Recv(ctx(t), c)
	if err != nil || e.Type != protocol.TypeError {
		t.Fatalf("%v %v", e, err)
	}
	var p protocol.ErrorPayload
	_ = json.Unmarshal(e.Payload, &p)
	if p.Code != string(protocol.CodeUnsupportedMessage) {
		t.Fatalf("code %s", p.Code)
	}
}

func TestDeviceCannotSpeakAsAnotherDevice(t *testing.T) {
	h := newHarness(t, nil)
	d, victim := testutil.NewDevice(t), testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	spoof := victim.Env(protocol.TypeResult, protocol.NewID(), map[string]any{"status": "ok", "data": map[string]any{}})
	_ = testutil.Send(ctx(t), c, spoof)
	e, err := testutil.Recv(ctx(t), c)
	if err != nil || e.Type != protocol.TypeError {
		t.Fatalf("%v %v", e, err)
	}
	if code, _ := closeInfo(t, c); code != websocket.StatusPolicyViolation {
		t.Fatalf("close %d", code)
	}
}

func TestSecondConnectionReplacesFirst(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	first := d.Connect(ctx(t), t, h.srv.URL, origin)
	second := d.Connect(ctx(t), t, h.srv.URL, origin)
	if code, _ := closeInfo(t, first); code != 4001 {
		t.Fatalf("first connection closed with %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	if !h.mgr.Online(d.ID) {
		t.Fatal("the replaced connection removed its successor")
	}
	_ = testutil.Send(ctx(t), second, d.Env(protocol.TypeHeartbeat, "", struct{}{}))
	if e, err := testutil.Recv(ctx(t), second); err != nil || e.Type != protocol.TypeHeartbeat {
		t.Fatalf("second connection unusable: %v %v", e, err)
	}
}

func TestDisconnectClosesWithRevokedCode(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	h.mgr.Disconnect(d.ID)
	if code, _ := closeInfo(t, c); code != 4002 {
		t.Fatalf("close %d", code)
	}
}

// answerLoop makes a simulated device reply to every command with reply(command).
func answerLoop(t *testing.T, d *testutil.Device, c *websocket.Conn, reply func(*protocol.Envelope) *protocol.Envelope) {
	go func() {
		for {
			e, err := testutil.Recv(context.Background(), c)
			if err != nil {
				return
			}
			if e.Type == protocol.TypeCommand {
				if r := reply(e); r != nil {
					_ = testutil.Send(context.Background(), c, r)
				}
			}
		}
	}()
}

func TestCommandRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	answerLoop(t, d, c, func(cmd *protocol.Envelope) *protocol.Envelope {
		return d.Env(protocol.TypeResult, cmd.ID, map[string]any{"status": "ok", "data": map[string]any{"model": "Pixel"}})
	})
	resp, err := h.rt.Dispatch(ctx(t), d.ID, router.Request{Capability: "device.info", Version: 1})
	if err != nil || resp.Err != nil || !strings.Contains(string(resp.Result), "Pixel") {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestDeviceCannotAnswerAnotherDevicesCommand(t *testing.T) {
	h := newHarness(t, nil)
	a, b := testutil.NewDevice(t), testutil.NewDevice(t)
	h.register(t, a)
	h.register(t, b)
	ca := a.Connect(ctx(t), t, h.srv.URL, origin)
	cb := b.Connect(ctx(t), t, h.srv.URL, origin)
	// A receives the command but stays silent; B tries to answer it.
	answerLoop(t, a, ca, func(cmd *protocol.Envelope) *protocol.Envelope {
		_ = testutil.Send(context.Background(), cb, b.Env(protocol.TypeResult, cmd.ID, map[string]any{"status": "ok", "data": map[string]any{"forged": true}}))
		return nil
	})
	_, err := h.rt.Dispatch(ctx(t), a.ID, router.Request{Capability: "device.info", Version: 1, Timeout: 300 * time.Millisecond})
	if !errors.Is(err, router.ErrTimeout) {
		t.Fatalf("forged answer from another device was accepted: %v", err)
	}
}

func TestCommandFailsWhenDeviceDisconnectsMidFlight(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	c := d.Connect(ctx(t), t, h.srv.URL, origin)
	answerLoop(t, d, c, func(*protocol.Envelope) *protocol.Envelope {
		_ = c.Close(websocket.StatusNormalClosure, "bye")
		return nil
	})
	_, err := h.rt.Dispatch(ctx(t), d.ID, router.Request{Capability: "device.info", Version: 1, Timeout: 5 * time.Second})
	if !errors.Is(err, router.ErrDisconnected) {
		t.Fatalf("%v", err)
	}
}

func TestCommandToOfflineDevice(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	if _, err := h.rt.Dispatch(ctx(t), d.ID, router.Request{Capability: "device.info", Version: 1}); !errors.Is(err, router.ErrDeviceOffline) {
		t.Fatalf("%v", err)
	}
}

func TestRevokedDeviceCannotReconnect(t *testing.T) {
	h := newHarness(t, nil)
	d := testutil.NewDevice(t)
	h.register(t, d)
	d.Connect(ctx(t), t, h.srv.URL, origin).CloseNow()
	_ = h.store.Revoke(context.Background(), d.ID)
	c := dial(t, h)
	if _, err := d.Handshake(ctx(t), c, d.ProperSign(origin)); err != nil {
		t.Fatal(err)
	}
	if code, reason := closeInfo(t, c); code != websocket.StatusPolicyViolation || reason != "authentication failed" {
		t.Fatalf("close %d %q", code, reason)
	}
}

func TestBrowserOriginIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	_, resp, err := websocket.Dial(ctx(t), testutil.WSURL(h.srv.URL), &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}},
	})
	if err == nil {
		t.Fatal("cross-origin browser connection accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("response %v", resp)
	}
}
