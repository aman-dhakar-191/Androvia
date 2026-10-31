// Package audit records security-relevant events: pairing, authentication failures, grants, revocation, and command
// dispatch / denial / completion.
//
// Secrets and payloads never enter the log. Detail fields come from a fixed allow-list, values are short, and values
// that look like a token or pairing code are refused. An event that cannot be recorded cleanly is an error, not a
// silent drop, so mistakes show up in tests.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"sync"
	"time"
)

type Outcome string

const (
	Allowed Outcome = "allowed"
	Denied  Outcome = "denied"
	Error   Outcome = "error"
	Info    Outcome = "info"
)

// Actor types.
const (
	ActorAdmin     = "admin"
	ActorClient    = "client"
	ActorDevice    = "device"
	ActorAnonymous = "anonymous"
	ActorSystem    = "system"
)

type Event struct {
	ID        int64             `json:"id"`
	At        time.Time         `json:"at"`
	ActorType string            `json:"actor_type"`
	ActorID   string            `json:"actor_id"`
	DeviceID  string            `json:"device_id"`
	Action    string            `json:"action"`
	Outcome   Outcome           `json:"outcome"`
	RequestID string            `json:"request_id"`
	Detail    map[string]string `json:"detail"`
}

// allowedDetail is the complete list of detail keys. Deliberately absent: anything that could carry a secret or a
// payload (token, nonce, signature, code, args, key).
var allowedDetail = map[string]bool{
	"capability": true, "reason": true, "result_code": true, "remote": true, "scopes": true, "label": true,
	"target_client": true, "target_device": true, "credential_id": true, "count": true, "expires_at": true, "limit": true, "channel": true, "oauth_client": true,
}

const (
	maxDetailKeys  = 12
	maxDetailValue = 200
)

var (
	ErrDetail = errors.New("audit detail rejected")

	secretShapes = []*regexp.Regexp{
		regexp.MustCompile(`avt_`), // access token prefix
		regexp.MustCompile(`\b[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{6}\b`), // pairing code
		regexp.MustCompile(`[A-Za-z0-9+/_-]{48,}`),                                            // long opaque blob (key, signature, nonce)
	}
	nameRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)
)

// Validate checks that e is safe to store.
func Validate(e Event) error {
	if !nameRE.MatchString(e.Action) {
		return fmt.Errorf("%w: bad action %q", ErrDetail, e.Action)
	}
	switch e.Outcome {
	case Allowed, Denied, Error, Info:
	default:
		return fmt.Errorf("%w: bad outcome", ErrDetail)
	}
	if len(e.Detail) > maxDetailKeys {
		return fmt.Errorf("%w: too many fields", ErrDetail)
	}
	for k, v := range e.Detail {
		if !allowedDetail[k] {
			return fmt.Errorf("%w: field %q is not allowed", ErrDetail, k)
		}
		if len(v) > maxDetailValue {
			return fmt.Errorf("%w: field %q is too long", ErrDetail, k)
		}
		for _, re := range secretShapes {
			if re.MatchString(v) {
				return fmt.Errorf("%w: field %q looks like a secret", ErrDetail, k)
			}
		}
	}
	for _, v := range []string{e.ActorID, e.DeviceID, e.RequestID} {
		if len(v) > maxDetailValue {
			return fmt.Errorf("%w: identifier too long", ErrDetail)
		}
	}
	return nil
}

type Store interface {
	Append(ctx context.Context, e Event) error
	// List returns events newest first. beforeID 0 means from the newest; otherwise only events with id < beforeID.
	List(ctx context.Context, limit int, beforeID int64) ([]Event, error)
	// Purge deletes events older than before and reports how many.
	Purge(ctx context.Context, before time.Time) (int64, error)
}

// Recorder writes events and mirrors them to the structured log (without detail values beyond the allow-list).
type Recorder struct {
	store Store
	log   *slog.Logger
	now   func() time.Time
}

func NewRecorder(s Store, log *slog.Logger, now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{store: s, log: log, now: now}
}

// Record stores the event. Callers on a security-critical path (a command about to be sent) must treat an error as
// "do not proceed".
func (r *Recorder) Record(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = r.now().UTC()
	}
	if e.Detail == nil {
		e.Detail = map[string]string{}
	}
	if err := Validate(e); err != nil {
		r.log.Error("audit event refused", "action", e.Action, "error", err.Error())
		return err
	}
	if err := r.store.Append(ctx, e); err != nil {
		r.log.Error("audit write failed", "action", e.Action, "error", err.Error())
		return err
	}
	r.log.Info("audit", "actor_type", e.ActorType, "actor", e.ActorID, "device", e.DeviceID, "action", e.Action, "outcome", string(e.Outcome), "request_id", e.RequestID)
	return nil
}

// Note is Record for events where failing the user's action would be worse than missing the line (e.g. a rejected
// login). The failure is still logged.
func (r *Recorder) Note(ctx context.Context, e Event) { _ = r.Record(ctx, e) }

// RunRetention deletes events older than keep, once at start and then every interval, until ctx ends.
func RunRetention(ctx context.Context, s Store, keep, interval time.Duration, log *slog.Logger, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	purge := func() {
		n, err := s.Purge(ctx, now().Add(-keep))
		if err != nil {
			log.Error("audit retention failed", "error", err.Error())
		} else if n > 0 {
			log.Info("audit retention", "deleted", n)
		}
	}
	purge()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------

// MemoryStore is for tests.
type MemoryStore struct {
	mu     sync.Mutex
	events []Event
	next   int64
	// FailAppend makes Append fail, to test fail-closed behaviour.
	FailAppend error
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{next: 1} }

func (s *MemoryStore) Append(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailAppend != nil {
		return s.FailAppend
	}
	e.ID = s.next
	s.next++
	s.events = append(s.events, e)
	return nil
}

func (s *MemoryStore) List(_ context.Context, limit int, beforeID int64) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		if beforeID == 0 || s.events[i].ID < beforeID {
			out = append(out, s.events[i])
		}
	}
	return out, nil
}

func (s *MemoryStore) Purge(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	var n int64
	for _, e := range s.events {
		if e.At.Before(before) {
			n++
		} else {
			kept = append(kept, e)
		}
	}
	s.events = kept
	return n, nil
}

// All returns every stored event, oldest first (tests).
func (s *MemoryStore) All() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Event(nil), s.events...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func detailJSON(d map[string]string) (string, error) {
	b, err := json.Marshal(d)
	return string(b), err
}
