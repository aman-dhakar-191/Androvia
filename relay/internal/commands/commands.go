// Package commands is the one place where "may this client do this to that device, and record it" is decided and a
// command is sent. REST and MCP are thin adapters over it, so they cannot drift apart: same policy engine, same audit
// rules, same routing (spec §9).
//
// Order for Execute: no grant on the device (looks exactly like a missing device) -> unknown device -> invalid capability
// -> missing scope -> revoked device -> AUDIT (no record, no command) -> dispatch -> audit the outcome.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
)

// Channel says how the request arrived; it is recorded in the audit log.
type Channel string

const (
	ChannelREST Channel = "rest"
	ChannelMCP  Channel = "mcp"
)

type Kind int

const (
	KindNotFound Kind = iota + 1
	KindForbidden
	KindInvalid
	KindRevoked
	KindOffline
	KindTimeout
	KindDisconnected
	KindAuditUnavailable
	KindInternal
	KindDevice // the device answered with an error (e.g. permission_denied)
)

// Failure is a request that did not succeed. Adapters translate Kind into their own error vocabulary.
type Failure struct {
	Kind          Kind
	Message       string
	RequestID     string // set once a command was dispatched (or audited)
	DeviceCode    string // KindDevice only
	DeviceMessage string // KindDevice only
}

func (f *Failure) Error() string { return f.Message }

type Result struct {
	RequestID string
	// Payload is the device's whole result payload: {"status":"ok","data":{...}}.
	Payload json.RawMessage
}

// Data returns the "data" object of the device result (or the whole payload if it has none).
func (r *Result) Data() json.RawMessage {
	var p struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(r.Payload, &p); err == nil && len(p.Data) > 0 {
		return p.Data
	}
	return r.Payload
}

type Dispatcher interface {
	Dispatch(ctx context.Context, deviceID string, q router.Request) (*router.Response, error)
}

type Connections interface{ Online(deviceID string) bool }

type Deps struct {
	Devices devices.Store
	Clients clients.Store
	Authz   *policy.Authorizer
	Audit   *audit.Recorder
	Disp    Dispatcher
	Conns   Connections
	Log     *slog.Logger
	Now     func() time.Time
}

type Service struct{ d Deps }

func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d}
}

type DeviceView struct {
	ID         string
	Label      string
	Status     string
	Online     bool
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

func (s *Service) view(d devices.Device) DeviceView {
	return DeviceView{ID: d.ID, Label: d.Label, Status: string(d.Status), Online: s.d.Conns.Online(d.ID) && d.Status == devices.StatusActive, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt}
}

func (s *Service) internal(what string, err error) *Failure {
	s.d.Log.Error("internal error", "op", what, "error", err.Error())
	return &Failure{Kind: KindInternal, Message: "internal error"}
}

// Grants returns what the client has been granted (used to decide which tools to offer; every call is still checked).
func (s *Service) Grants(ctx context.Context, clientID string) ([]clients.Grant, *Failure) {
	gs, err := s.d.Clients.Grants(ctx, clientID)
	if err != nil {
		return nil, s.internal("grants", err)
	}
	return gs, nil
}

// ListDevices returns the devices the client may read (it holds devices:read on them).
func (s *Service) ListDevices(ctx context.Context, clientID string) ([]DeviceView, *Failure) {
	grants, err := s.d.Clients.Grants(ctx, clientID)
	if err != nil {
		return nil, s.internal("list grants", err)
	}
	out := []DeviceView{}
	for _, g := range grants {
		if !contains(g.Scopes, policy.ScopeDevicesRead) {
			continue
		}
		d, err := s.d.Devices.Get(ctx, g.DeviceID)
		if errors.Is(err, devices.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, s.internal("get device", err)
		}
		out = append(out, s.view(d))
	}
	return out, nil
}

// visible resolves a device for a client. A device the client has no grant on looks exactly like one that does not exist.
func (s *Service) visible(ctx context.Context, clientID, deviceID string, ch Channel) (devices.Device, *Failure) {
	notFound := &Failure{Kind: KindNotFound, Message: "no such device"}
	if !protocol.ValidDeviceID(deviceID) {
		return devices.Device{}, notFound
	}
	has, err := s.d.Authz.HasAny(ctx, clientID, deviceID)
	if err != nil {
		return devices.Device{}, s.internal("authorize", err)
	}
	if !has {
		s.d.Audit.Note(ctx, audit.Event{ActorType: audit.ActorClient, ActorID: clientID, DeviceID: deviceID, Action: "device.access", Outcome: audit.Denied,
			Detail: map[string]string{"reason": "no_grant", "channel": string(ch)}})
		return devices.Device{}, notFound
	}
	d, err := s.d.Devices.Get(ctx, deviceID)
	if errors.Is(err, devices.ErrNotFound) {
		return devices.Device{}, notFound
	}
	if err != nil {
		return devices.Device{}, s.internal("get device", err)
	}
	return d, nil
}

// require checks a scope and audits a refusal.
func (s *Service) require(ctx context.Context, clientID, deviceID, scope, action, capability string, ch Channel) *Failure {
	err := s.d.Authz.Require(ctx, clientID, deviceID, scope)
	if err == nil {
		return nil
	}
	if errors.Is(err, policy.ErrForbidden) {
		detail := map[string]string{"reason": "missing_scope", "channel": string(ch)}
		if capability != "" {
			detail["capability"] = capability
		}
		s.d.Audit.Note(ctx, audit.Event{ActorType: audit.ActorClient, ActorID: clientID, DeviceID: deviceID, Action: action, Outcome: audit.Denied, Detail: detail})
		return &Failure{Kind: KindForbidden, Message: "this client has no permission for that on this device"}
	}
	return s.internal("authorize", err)
}

// GetDevice returns one device the client may read.
func (s *Service) GetDevice(ctx context.Context, clientID, deviceID string, ch Channel) (DeviceView, *Failure) {
	d, f := s.visible(ctx, clientID, deviceID, ch)
	if f != nil {
		return DeviceView{}, f
	}
	if f := s.require(ctx, clientID, d.ID, policy.ScopeDevicesRead, "device.access", "", ch); f != nil {
		return DeviceView{}, f
	}
	return s.view(d), nil
}

type Request struct {
	ClientID   string
	DeviceID   string
	Capability string
	Version    int
	Args       json.RawMessage
	Timeout    time.Duration
	Channel    Channel
}

// Execute runs one capability on one device on behalf of an authenticated client. The caller has already authenticated
// the client; everything else is decided here.
func (s *Service) Execute(ctx context.Context, q Request) (*Result, *Failure) {
	d, f := s.visible(ctx, q.ClientID, q.DeviceID, q.Channel)
	if f != nil {
		return nil, f
	}
	scope := policy.ExecuteScope(q.Capability)
	if scope == "" {
		return nil, &Failure{Kind: KindInvalid, Message: "capability must look like 'device.info'"}
	}
	if f := s.require(ctx, q.ClientID, d.ID, scope, "command.denied", q.Capability, q.Channel); f != nil {
		return nil, f
	}
	if d.Status != devices.StatusActive {
		return nil, &Failure{Kind: KindRevoked, Message: "device is revoked"}
	}

	reqID := protocol.NewID()
	// Audit first: no record, no command.
	if err := s.d.Audit.Record(ctx, audit.Event{ActorType: audit.ActorClient, ActorID: q.ClientID, DeviceID: d.ID, Action: "command.dispatch",
		Outcome: audit.Allowed, RequestID: reqID, Detail: map[string]string{"capability": q.Capability, "channel": string(q.Channel)}}); err != nil {
		return nil, &Failure{Kind: KindAuditUnavailable, Message: "the audit log is unavailable, so the command was not sent"}
	}
	resp, err := s.d.Disp.Dispatch(ctx, d.ID, router.Request{Capability: q.Capability, Version: q.Version, Args: q.Args, Timeout: q.Timeout, ID: reqID})

	done := func(oc audit.Outcome, code string) {
		s.d.Audit.Note(ctx, audit.Event{ActorType: audit.ActorClient, ActorID: q.ClientID, DeviceID: d.ID, Action: "command.complete", Outcome: oc, RequestID: reqID,
			Detail: map[string]string{"capability": q.Capability, "result_code": code, "channel": string(q.Channel)}})
	}
	fail := func(k Kind, code, msg string) (*Result, *Failure) {
		done(audit.Error, code)
		return nil, &Failure{Kind: k, Message: msg, RequestID: reqID}
	}
	switch {
	case errors.Is(err, router.ErrInvalidRequest):
		return fail(KindInvalid, "invalid_request", strings.TrimPrefix(err.Error(), router.ErrInvalidRequest.Error()+"\n"))
	case errors.Is(err, router.ErrDeviceOffline):
		return fail(KindOffline, "device_offline", "device is not connected")
	case errors.Is(err, router.ErrTimeout):
		return fail(KindTimeout, "timeout", "device did not answer in time")
	case errors.Is(err, router.ErrDisconnected):
		return fail(KindDisconnected, "device_disconnected", "device disconnected before answering")
	case err != nil:
		done(audit.Error, "internal")
		f := s.internal("dispatch", err)
		f.RequestID = reqID
		return nil, f
	case resp.Err != nil:
		// The device answered with an error (e.g. permission_denied): a normal outcome, reported as-is.
		done(audit.Denied, resp.Err.Code)
		return nil, &Failure{Kind: KindDevice, Message: resp.Err.Message, RequestID: reqID, DeviceCode: resp.Err.Code, DeviceMessage: resp.Err.Message}
	default:
		done(audit.Allowed, "ok")
		return &Result{RequestID: reqID, Payload: resp.Result}, nil
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
