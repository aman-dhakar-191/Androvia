package audit_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
)

var ctx = context.Background()

func ev(action string, at time.Time) audit.Event {
	return audit.Event{At: at, ActorType: audit.ActorClient, ActorID: "c1", DeviceID: strings.Repeat("a", 64), Action: action,
		Outcome: audit.Allowed, RequestID: "r1", Detail: map[string]string{"capability": "device.info"}}
}

func storeContract(t *testing.T, s audit.Store) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, a := range []string{"one", "two", "three", "four"} {
		if err := s.Append(ctx, ev(a, now.Add(time.Duration(i-10)*24*time.Hour))); err != nil { // 10..7 days old
			t.Fatal(err)
		}
	}
	got, err := s.List(ctx, 10, 0)
	if err != nil || len(got) != 4 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].Action != "four" || got[3].Action != "one" || got[0].ID <= got[1].ID {
		t.Fatalf("not newest first: %v", got)
	}
	if got[0].Detail["capability"] != "device.info" || got[0].ActorID != "c1" || got[0].Outcome != audit.Allowed {
		t.Fatalf("fields lost: %+v", got[0])
	}
	page, _ := s.List(ctx, 2, 0)
	rest, _ := s.List(ctx, 10, page[1].ID)
	if len(page) != 2 || len(rest) != 2 || rest[0].Action != "two" {
		t.Fatalf("paging: %v / %v", page, rest)
	}
	n, err := s.Purge(ctx, now.Add(-8*24*time.Hour)) // removes the two oldest
	if err != nil || n != 2 {
		t.Fatalf("purged %d %v", n, err)
	}
	if left, _ := s.List(ctx, 10, 0); len(left) != 2 || left[1].Action != "three" {
		t.Fatalf("after purge: %v", left)
	}
}

func TestMemoryStore(t *testing.T) { storeContract(t, audit.NewMemoryStore()) }

func TestPostgresStore(t *testing.T) {
	pool := testutil.PGPool(t)
	storeContract(t, audit.NewPostgresStore(pool))
}

func TestValidateRejectsSecretsAndUnknownFields(t *testing.T) {
	ok := ev("command.dispatch", time.Now())
	if err := audit.Validate(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*audit.Event){
		"unknown field":         func(e *audit.Event) { e.Detail["args"] = "{}" },
		"token field":           func(e *audit.Event) { e.Detail["token"] = "x" },
		"signature field":       func(e *audit.Event) { e.Detail["signature"] = "x" },
		"token in a value":      func(e *audit.Event) { e.Detail["reason"] = "bad avt_abcdef" },
		"pairing code in value": func(e *audit.Event) { e.Detail["reason"] = "code ABCDE-23456-ABCDE-23456-ABCDEF" },
		"long opaque blob":      func(e *audit.Event) { e.Detail["reason"] = strings.Repeat("Ab1+", 14) },
		"long value":            func(e *audit.Event) { e.Detail["reason"] = strings.Repeat("x ", 101) },
		"too many fields": func(e *audit.Event) {
			e.Detail = map[string]string{"capability": "a", "reason": "b", "result_code": "c", "remote": "d", "scopes": "e", "label": "f", "target_client": "g", "target_device": "h", "credential_id": "i", "count": "j", "expires_at": "k", "limit": "l", "x": "m"}
		},
		"bad action":      func(e *audit.Event) { e.Action = "Bad Action!" },
		"empty action":    func(e *audit.Event) { e.Action = "" },
		"bad outcome":     func(e *audit.Event) { e.Outcome = "maybe" },
		"huge request id": func(e *audit.Event) { e.RequestID = strings.Repeat("r", 300) },
	}
	for name, mutate := range bad {
		e := ev("command.dispatch", time.Now())
		mutate(&e)
		if err := audit.Validate(e); !errors.Is(err, audit.ErrDetail) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRecorder(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := audit.NewMemoryStore()
	r := audit.NewRecorder(s, log, nil)
	if err := r.Record(ctx, audit.Event{ActorType: audit.ActorAdmin, ActorID: "admin", Action: "device.register", Outcome: audit.Allowed}); err != nil {
		t.Fatal(err)
	}
	all := s.All()
	if len(all) != 1 || all[0].At.IsZero() || all[0].Detail == nil {
		t.Fatalf("defaults not filled: %+v", all)
	}
	if err := r.Record(ctx, audit.Event{Action: "x y", Outcome: audit.Allowed}); err == nil {
		t.Fatal("invalid event stored")
	}
	if len(s.All()) != 1 {
		t.Fatal("an invalid event reached the store")
	}
	s.FailAppend = errors.New("disk full")
	if err := r.Record(ctx, ev("command.dispatch", time.Now())); err == nil {
		t.Fatal("a write failure was swallowed: callers could not fail closed")
	}
	r.Note(ctx, ev("auth.failed", time.Now())) // best-effort variant must not panic
}

func TestRetentionPurgesOldEvents(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := audit.NewMemoryStore()
	now := time.Now().UTC()
	_ = s.Append(ctx, ev("old", now.Add(-100*24*time.Hour)))
	_ = s.Append(ctx, ev("new", now.Add(-1*time.Hour)))
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { audit.RunRetention(c, s, 90*24*time.Hour, time.Hour, log, nil); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(s.All()) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if all := s.All(); len(all) != 1 || all[0].Action != "new" {
		t.Fatalf("retention kept the wrong events: %v", all)
	}
}
