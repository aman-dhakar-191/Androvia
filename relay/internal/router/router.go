// Package router sends commands to connected devices and correlates their responses.
package router

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
)

var (
	ErrDeviceOffline  = errors.New("device is not connected")
	ErrTimeout        = errors.New("device did not answer in time")
	ErrDisconnected   = errors.New("device disconnected before answering")
	ErrInvalidRequest = errors.New("invalid command request")
)

const (
	DefaultTimeout = 10 * time.Second
	MaxTimeout     = 55 * time.Second // below protocol.MaxLifetime so exp-ts stays valid
	MaxArgsBytes   = 32 * 1024
	answerGrace    = 2 * time.Second
)

var capabilityRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Sender delivers an envelope to a connected device. It returns ErrDeviceOffline if there is none.
type Sender interface {
	Send(ctx context.Context, deviceID string, env *protocol.Envelope) error
}

type Request struct {
	Capability string
	Version    int
	Args       json.RawMessage // JSON object; nil means {}
	Timeout    time.Duration   // 0 means DefaultTimeout
}

// Response is the device's answer. Exactly one of Result or Err is set.
type Response struct {
	RequestID string
	Result    json.RawMessage // payload of a "result" message
	Err       *protocol.ErrorPayload
}

type outcome struct {
	env *protocol.Envelope
	err error
}

type key struct{ device, id string }

type Router struct {
	sender  Sender
	now     func() time.Time
	log     *slog.Logger
	mu      sync.Mutex
	pending map[key]chan outcome
	grace   time.Duration
}

func New(log *slog.Logger, now func() time.Time) *Router {
	if now == nil {
		now = time.Now
	}
	return &Router{now: now, log: log, pending: map[key]chan outcome{}, grace: answerGrace}
}

// SetGrace changes how long past the command timeout the router waits for an answer (tests).
func (r *Router) SetGrace(d time.Duration) { r.grace = d }

// Attach sets the sender (the connection manager). It is separate from New because the manager also needs the router.
func (r *Router) Attach(s Sender) { r.sender = s }

// Validate checks a request without sending it.
func (q *Request) Validate() error {
	if !capabilityRE.MatchString(q.Capability) {
		return errors.Join(ErrInvalidRequest, errors.New("capability must look like 'device.info'"))
	}
	if q.Version < 1 {
		return errors.Join(ErrInvalidRequest, errors.New("version must be >= 1"))
	}
	if len(q.Args) > MaxArgsBytes {
		return errors.Join(ErrInvalidRequest, errors.New("args too large"))
	}
	if len(q.Args) > 0 {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(q.Args, &m); err != nil || m == nil {
			return errors.Join(ErrInvalidRequest, errors.New("args must be a JSON object"))
		}
	}
	if q.Timeout < 0 || q.Timeout > MaxTimeout {
		return errors.Join(ErrInvalidRequest, errors.New("timeout out of range"))
	}
	return nil
}

// Dispatch sends one command to deviceID and waits for its result or error.
// The caller is responsible for having authorised the request; the router only routes.
func (r *Router) Dispatch(ctx context.Context, deviceID string, q Request) (*Response, error) {
	if !protocol.ValidDeviceID(deviceID) {
		return nil, errors.Join(ErrInvalidRequest, errors.New("bad device id"))
	}
	if err := q.Validate(); err != nil {
		return nil, err
	}
	timeout := q.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	args := q.Args
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	payload, _ := json.Marshal(protocol.CommandPayload{Capability: q.Capability, Version: q.Version, Args: args})
	now := r.now().UTC()
	exp := now.Add(timeout)
	env := &protocol.Envelope{
		V: protocol.Version, Type: protocol.TypeCommand, ID: protocol.NewID(), Device: deviceID,
		TS: &now, Exp: &exp, Payload: payload,
	}

	k := key{deviceID, env.ID}
	ch := make(chan outcome, 1)
	r.mu.Lock()
	r.pending[k] = ch
	r.mu.Unlock()
	defer r.forget(k)

	r.log.Info("command dispatch", "device", deviceID, "request_id", env.ID, "capability", q.Capability)
	if err := r.sender.Send(ctx, deviceID, env); err != nil {
		if errors.Is(err, ErrDeviceOffline) {
			r.log.Info("command denied: device offline", "device", deviceID, "request_id", env.ID)
			return nil, ErrDeviceOffline
		}
		return nil, err
	}

	timer := time.NewTimer(timeout + r.grace)
	defer timer.Stop()
	select {
	case o := <-ch:
		if o.err != nil {
			r.log.Info("command failed", "device", deviceID, "request_id", env.ID, "error", o.err.Error())
			return nil, o.err
		}
		resp := &Response{RequestID: env.ID}
		if o.env.Type == protocol.TypeResult {
			resp.Result = o.env.Payload
		} else {
			var ep protocol.ErrorPayload
			if err := json.Unmarshal(o.env.Payload, &ep); err != nil || ep.Code == "" {
				ep = protocol.ErrorPayload{Code: "internal", Message: "device sent an unreadable error"}
			}
			resp.Err = &ep
		}
		r.log.Info("command completed", "device", deviceID, "request_id", env.ID, "type", string(o.env.Type))
		return resp, nil
	case <-timer.C:
		r.cancel(deviceID, env.ID)
		r.log.Info("command timed out", "device", deviceID, "request_id", env.ID)
		return nil, ErrTimeout
	case <-ctx.Done():
		r.cancel(deviceID, env.ID)
		return nil, ctx.Err()
	}
}

// cancel tells the device to stop work on a command (best effort).
func (r *Router) cancel(deviceID, corr string) {
	now := r.now().UTC()
	exp := now.Add(10 * time.Second)
	env := &protocol.Envelope{
		V: protocol.Version, Type: protocol.TypeCancel, ID: protocol.NewID(), Corr: corr, Device: deviceID,
		TS: &now, Exp: &exp, Payload: json.RawMessage(`{}`),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = r.sender.Send(ctx, deviceID, env)
}

func (r *Router) forget(k key) {
	r.mu.Lock()
	delete(r.pending, k)
	r.mu.Unlock()
}

// HandleResponse is called by the connection manager for a result/error received from an authenticated device.
// The key includes the authenticated device id, so one device can never answer another device's command.
func (r *Router) HandleResponse(deviceID string, env *protocol.Envelope) {
	k := key{deviceID, env.Corr}
	r.mu.Lock()
	ch, ok := r.pending[k]
	if ok {
		delete(r.pending, k) // first answer wins; later duplicates are dropped
	}
	r.mu.Unlock()
	if !ok {
		r.log.Warn("dropping unmatched response", "device", deviceID, "corr", env.Corr)
		return
	}
	ch <- outcome{env: env}
}

// DeviceDisconnected fails every command still waiting on deviceID.
func (r *Router) DeviceDisconnected(deviceID string) {
	r.mu.Lock()
	var chans []chan outcome
	for k, ch := range r.pending {
		if k.device == deviceID {
			chans = append(chans, ch)
			delete(r.pending, k)
		}
	}
	r.mu.Unlock()
	for _, ch := range chans {
		ch <- outcome{err: ErrDisconnected}
	}
}
