package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
)

var dev = strings.Repeat("a", 64)
var other = strings.Repeat("b", 64)

type fakeSender struct {
	mu      sync.Mutex
	sent    []*protocol.Envelope
	offline bool
	onSend  func(*protocol.Envelope)
}

func (f *fakeSender) Send(_ context.Context, deviceID string, e *protocol.Envelope) error {
	if f.offline {
		return ErrDeviceOffline
	}
	f.mu.Lock()
	f.sent = append(f.sent, e)
	cb := f.onSend
	f.mu.Unlock()
	if cb != nil && e.Type == protocol.TypeCommand {
		go cb(e)
	}
	return nil
}

func (f *fakeSender) types() []protocol.MessageType {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []protocol.MessageType
	for _, e := range f.sent {
		out = append(out, e.Type)
	}
	return out
}

func newRouter(s *fakeSender) *Router {
	r := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	r.Attach(s)
	r.SetGrace(50 * time.Millisecond)
	return r
}

func reply(typ protocol.MessageType, corr, device, payload string) *protocol.Envelope {
	return &protocol.Envelope{V: 1, Type: typ, ID: protocol.NewID(), Corr: corr, Device: device, Payload: json.RawMessage(payload)}
}

func TestDispatchResult(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	s.onSend = func(e *protocol.Envelope) {
		r.HandleResponse(dev, reply(protocol.TypeResult, e.ID, dev, `{"status":"ok","data":{"x":1}}`))
	}

	resp, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Err != nil || !strings.Contains(string(resp.Result), `"x":1`) || !protocol.ValidID(resp.RequestID) {
		t.Fatalf("%+v", resp)
	}
	// The command the device saw must be valid under the protocol rules.
	cmd := s.sent[0]
	b, _ := cmd.Marshal()
	parsed, perr := protocol.Parse(b)
	if perr != nil {
		t.Fatal(perr)
	}
	if err := parsed.CheckWindow(time.Now()); err != nil {
		t.Fatal(err)
	}
	var p protocol.CommandPayload
	_ = json.Unmarshal(parsed.Payload, &p)
	if p.Capability != "device.info" || p.Version != 1 || string(p.Args) != "{}" {
		t.Fatalf("payload %+v", p)
	}
}

func TestDispatchDeviceError(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	s.onSend = func(e *protocol.Envelope) {
		r.HandleResponse(dev, reply(protocol.TypeError, e.ID, dev, `{"code":"permission_denied","message":"nope"}`))
	}
	resp, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1})
	if err != nil || resp.Err == nil || resp.Err.Code != "permission_denied" {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestDispatchUnreadableDeviceError(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	s.onSend = func(e *protocol.Envelope) {
		r.HandleResponse(dev, reply(protocol.TypeError, e.ID, dev, `{"unexpected":1}`))
	}
	resp, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1})
	if err != nil || resp.Err == nil || resp.Err.Code != "internal" {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestDispatchOffline(t *testing.T) {
	r := newRouter(&fakeSender{offline: true})
	if _, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1}); !errors.Is(err, ErrDeviceOffline) {
		t.Fatalf("%v", err)
	}
	if len(r.pending) != 0 {
		t.Fatal("pending entry leaked")
	}
}

func TestDispatchTimeoutSendsCancel(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	_, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1, Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("%v", err)
	}
	ts := s.types()
	if len(ts) != 2 || ts[0] != protocol.TypeCommand || ts[1] != protocol.TypeCancel {
		t.Fatalf("sent %v", ts)
	}
	if s.sent[1].Corr != s.sent[0].ID {
		t.Fatal("cancel does not reference the command")
	}
	if len(r.pending) != 0 {
		t.Fatal("pending entry leaked")
	}
}

func TestDispatchContextCancelled(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_, err := r.Dispatch(ctx, dev, Request{Capability: "device.info", Version: 1, Timeout: 5 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if ts := s.types(); len(ts) != 2 || ts[1] != protocol.TypeCancel {
		t.Fatalf("sent %v", ts)
	}
}

func TestDisconnectFailsPending(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	s.onSend = func(*protocol.Envelope) { time.Sleep(20 * time.Millisecond); r.DeviceDisconnected(dev) }
	_, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1, Timeout: 5 * time.Second})
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("%v", err)
	}
}

func TestOtherDeviceCannotAnswer(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	// A different authenticated device replies using the command's id.
	s.onSend = func(e *protocol.Envelope) {
		r.HandleResponse(other, reply(protocol.TypeResult, e.ID, other, `{"status":"ok","data":{}}`))
	}
	_, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1, Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("spoofed answer was accepted: %v", err)
	}
}

func TestDuplicateAndUnmatchedResponsesDropped(t *testing.T) {
	s := &fakeSender{}
	r := newRouter(s)
	s.onSend = func(e *protocol.Envelope) {
		r.HandleResponse(dev, reply(protocol.TypeResult, e.ID, dev, `{"status":"ok","data":{"n":1}}`))
		r.HandleResponse(dev, reply(protocol.TypeResult, e.ID, dev, `{"status":"ok","data":{"n":2}}`)) // duplicate
		r.HandleResponse(dev, reply(protocol.TypeResult, protocol.NewID(), dev, `{}`))                 // unknown corr
	}
	resp, err := r.Dispatch(context.Background(), dev, Request{Capability: "device.info", Version: 1})
	if err != nil || !strings.Contains(string(resp.Result), `"n":1`) {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]Request{
		"empty capability":     {Version: 1},
		"uppercase capability": {Capability: "Device.Info", Version: 1},
		"no dot":               {Capability: "deviceinfo", Version: 1},
		"injection":            {Capability: "device.info; rm", Version: 1},
		"zero version":         {Capability: "device.info"},
		"args array":           {Capability: "device.info", Version: 1, Args: json.RawMessage(`[1]`)},
		"args scalar":          {Capability: "device.info", Version: 1, Args: json.RawMessage(`"x"`)},
		"args null":            {Capability: "device.info", Version: 1, Args: json.RawMessage(`null`)},
		"args too big":         {Capability: "device.info", Version: 1, Args: json.RawMessage(`{"a":"` + strings.Repeat("x", MaxArgsBytes) + `"}`)},
		"negative timeout":     {Capability: "device.info", Version: 1, Timeout: -1},
		"huge timeout":         {Capability: "device.info", Version: 1, Timeout: time.Hour},
	}
	for name, q := range bad {
		t.Run(name, func(t *testing.T) {
			r := newRouter(&fakeSender{})
			if _, err := r.Dispatch(context.Background(), dev, q); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("want ErrInvalidRequest, got %v", err)
			}
		})
	}
	r := newRouter(&fakeSender{})
	if _, err := r.Dispatch(context.Background(), "nope", Request{Capability: "device.info", Version: 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad device id accepted: %v", err)
	}
}
