// Package connections owns the device WebSocket endpoint: handshake, heartbeat and message routing.
package connections

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/coder/websocket"
)

const (
	closeAuthFailed websocket.StatusCode = websocket.StatusPolicyViolation
	closeReplaced   websocket.StatusCode = 4001
	closeRevoked    websocket.StatusCode = 4002
	closeIdle       websocket.StatusCode = 4003
)

const authFailedReason = "authentication failed" // identical for unknown, revoked and bad-signature devices

type Config struct {
	PublicOrigin     string
	HandshakeTimeout time.Duration
	HeartbeatTimeout time.Duration
	WriteTimeout     time.Duration
	MaxViolations    int // protocol violations tolerated per connection before it is closed
	// Audit, if set, records device connections and failed device logins.
	Audit *audit.Recorder
}

// Handler receives traffic from authenticated devices. *router.Router implements it.
type Handler interface {
	HandleResponse(deviceID string, env *protocol.Envelope)
	DeviceDisconnected(deviceID string)
}

type Manager struct {
	cfg     Config
	store   devices.Store
	handler Handler
	log     *slog.Logger
	now     func() time.Time

	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct {
	id       string // unique per connection
	deviceID string
	ws       *websocket.Conn
	wmu      sync.Mutex
	timeout  time.Duration
}

func NewManager(cfg Config, store devices.Store, h Handler, log *slog.Logger, now func() time.Time) *Manager {
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.MaxViolations == 0 {
		cfg.MaxViolations = 5
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{cfg: cfg, store: store, handler: h, log: log, now: now, conns: map[string]*conn{}}
}

func (c *conn) write(ctx context.Context, env *protocol.Envelope) error {
	b, err := env.Marshal()
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

// Send implements router.Sender.
func (m *Manager) Send(ctx context.Context, deviceID string, env *protocol.Envelope) error {
	m.mu.Lock()
	c := m.conns[deviceID]
	m.mu.Unlock()
	if c == nil {
		return router.ErrDeviceOffline
	}
	if err := c.write(ctx, env); err != nil {
		return err
	}
	return nil
}

// Online reports whether deviceID currently has an authenticated connection.
func (m *Manager) Online(deviceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[deviceID] != nil
}

// Disconnect closes the device's connection, if any (used when a device is revoked).
func (m *Manager) Disconnect(deviceID string) {
	m.mu.Lock()
	c := m.conns[deviceID]
	m.mu.Unlock()
	if c != nil {
		_ = c.ws.Close(closeRevoked, "device revoked")
	}
}

// CloseAll closes every device connection (graceful shutdown; http.Server.Shutdown does not touch hijacked connections).
func (m *Manager) CloseAll() {
	m.mu.Lock()
	cs := make([]*conn, 0, len(m.conns))
	for _, c := range m.conns {
		cs = append(cs, c)
	}
	m.mu.Unlock()
	for _, c := range cs {
		_ = c.ws.Close(websocket.StatusGoingAway, "relay shutting down")
	}
}

func (m *Manager) note(deviceID, action string, oc audit.Outcome, detail map[string]string) {
	if m.cfg.Audit == nil {
		return
	}
	m.cfg.Audit.Note(context.Background(), audit.Event{ActorType: audit.ActorDevice, ActorID: deviceID, DeviceID: deviceID, Action: action, Outcome: oc, Detail: detail})
}

// ServeWS is the HTTP handler for GET /v1/device/ws.
func (m *Manager) ServeWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil) // default: browsers from other origins are rejected; devices send no Origin
	if err != nil {
		return // Accept already wrote the HTTP error
	}
	ws.SetReadLimit(protocol.MaxMessageBytes)
	c := &conn{id: protocol.NewID(), ws: ws, timeout: m.cfg.WriteTimeout}

	deviceID, ok := m.handshake(r.Context(), c)
	if !ok {
		return
	}
	c.deviceID = deviceID
	m.register(c)
	m.log.Info("device connected", "device", deviceID, "conn", c.id)
	m.note(deviceID, "device.connect", audit.Info, nil)
	_ = m.store.TouchLastSeen(context.Background(), deviceID, m.now())

	m.readLoop(r.Context(), c)

	m.unregister(c)
	m.handler.DeviceDisconnected(deviceID)
	_ = m.store.TouchLastSeen(context.Background(), deviceID, m.now())
	m.log.Info("device disconnected", "device", deviceID, "conn", c.id)
}

// handshake: hello -> hello_ack(nonce) -> auth(signature). Unknown, revoked and badly-signed devices all get
// the same hello_ack and the same close, so the endpoint does not reveal which device ids are registered.
func (m *Manager) handshake(parent context.Context, c *conn) (string, bool) {
	// A context deadline would make the websocket library drop the TCP connection without a close frame, so the
	// handshake time limit is a timer that closes cleanly instead.
	ctx := parent
	timer := time.AfterFunc(m.cfg.HandshakeTimeout, func() { _ = c.ws.Close(closeAuthFailed, "handshake timeout") })
	defer timer.Stop()
	fail := func(reason string) (string, bool) {
		_ = c.ws.Close(closeAuthFailed, reason)
		return "", false
	}

	env, err := m.read(ctx, c)
	if err != nil || env.Type != protocol.TypeHello {
		return fail("handshake failed")
	}
	var hello protocol.HelloPayload
	if json.Unmarshal(env.Payload, &hello) != nil || !contains(hello.Versions, protocol.Version) {
		return fail("unsupported protocol version")
	}
	deviceID := env.Device

	dev, derr := m.store.Get(ctx, deviceID)
	known := derr == nil && dev.Status == devices.StatusActive
	if derr != nil && !errors.Is(derr, devices.ErrNotFound) {
		m.log.Error("device lookup failed", "error", derr.Error())
		return fail("handshake failed")
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fail("handshake failed")
	}
	ackPayload, _ := json.Marshal(protocol.HelloAckPayload{Nonce: base64.StdEncoding.EncodeToString(nonce), Version: protocol.Version})
	now := m.now().UTC()
	ack := &protocol.Envelope{V: protocol.Version, Type: protocol.TypeHelloAck, ID: protocol.NewID(), Corr: env.ID, Device: deviceID, TS: &now, Payload: ackPayload}
	if err := c.write(ctx, ack); err != nil {
		return fail("handshake failed")
	}

	authEnv, err := m.read(ctx, c)
	if err != nil || authEnv.Type != protocol.TypeAuth || authEnv.Device != deviceID {
		return fail(authFailedReason)
	}
	var ap protocol.AuthPayload
	sig, serr := []byte(nil), error(nil)
	if json.Unmarshal(authEnv.Payload, &ap) == nil {
		sig, serr = base64.StdEncoding.DecodeString(ap.Signature)
	} else {
		serr = errors.New("bad payload")
	}
	if !known || serr != nil || !dev.Verify(protocol.AuthMessage(nonce, deviceID, m.cfg.PublicOrigin), sig) {
		m.log.Warn("device authentication failed", "device", deviceID, "known", known)
		reason := "bad_signature"
		if !known {
			reason = "unknown_or_revoked_device" // the audit log may say so; the device is only ever told "authentication failed"
		}
		m.note(deviceID, "device.auth_failed", audit.Denied, map[string]string{"reason": reason})
		return fail(authFailedReason)
	}
	return deviceID, true
}

func (m *Manager) register(c *conn) {
	m.mu.Lock()
	old := m.conns[c.deviceID]
	m.conns[c.deviceID] = c
	m.mu.Unlock()
	if old != nil {
		_ = old.ws.Close(closeReplaced, "replaced by a newer connection")
	}
}

func (m *Manager) unregister(c *conn) {
	m.mu.Lock()
	if m.conns[c.deviceID] == c { // a replaced connection must not remove its successor
		delete(m.conns, c.deviceID)
	}
	m.mu.Unlock()
}

func (m *Manager) read(ctx context.Context, c *conn) (*protocol.Envelope, error) {
	typ, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, &protocol.Error{Code: protocol.CodeMalformed, Msg: "text frames only"}
	}
	return protocol.Parse(data)
}

func (m *Manager) readLoop(parent context.Context, c *conn) {
	violations := 0
	violate := func(id string, code protocol.Code, msg string) bool {
		violations++
		_ = c.write(parent, protocol.NewError(c.deviceID, id, code, msg, m.now().UTC()))
		if violations >= m.cfg.MaxViolations {
			_ = c.ws.Close(websocket.StatusPolicyViolation, "too many protocol violations")
			return false
		}
		return true
	}
	for {
		idle := time.AfterFunc(m.cfg.HeartbeatTimeout, func() { _ = c.ws.Close(closeIdle, "heartbeat timeout") })
		typ, data, err := c.ws.Read(parent)
		idle.Stop()
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			if !violate("", protocol.CodeMalformed, "text frames only") {
				return
			}
			continue
		}
		env, perr := protocol.Parse(data)
		if perr != nil {
			var pe *protocol.Error
			if !errors.As(perr, &pe) {
				return
			}
			if !violate(pe.ID, pe.Code, pe.Msg) {
				return
			}
			continue
		}
		if env.Device != c.deviceID {
			// A device may only speak as itself.
			_ = c.write(parent, protocol.NewError(c.deviceID, env.ID, protocol.CodePermissionDenied, "device id does not match this connection", m.now().UTC()))
			_ = c.ws.Close(websocket.StatusPolicyViolation, "device id mismatch")
			return
		}
		switch env.Type {
		case protocol.TypeHeartbeat:
			now := m.now().UTC()
			_ = c.write(parent, &protocol.Envelope{V: protocol.Version, Type: protocol.TypeHeartbeat, ID: protocol.NewID(), Corr: env.ID, Device: c.deviceID, TS: &now, Payload: json.RawMessage(`{}`)})
		case protocol.TypeResult, protocol.TypeError:
			m.handler.HandleResponse(c.deviceID, env)
		default:
			if !violate(env.ID, protocol.CodeUnsupportedMessage, "message type not accepted from a device") {
				return
			}
		}
	}
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
