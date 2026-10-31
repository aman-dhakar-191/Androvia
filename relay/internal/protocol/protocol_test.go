package protocol

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	dev = strings.Repeat("a", 64)
	id1 = "8f1c4a2e-1111-4222-8333-944455556666"
	id2 = "9a1c4a2e-1111-4222-8333-944455556666"
)

func cmd(extra string) string {
	return fmt.Sprintf(`{"v":1,"type":"command","id":"%s","device":"%s","ts":"2026-10-31T12:00:00Z","exp":"2026-10-31T12:00:30Z","payload":{"capability":"device.info","version":1}%s}`, id1, dev, extra)
}

func TestParseValid(t *testing.T) {
	e, err := Parse([]byte(cmd("")))
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeCommand || e.ID != id1 || e.Device != dev || e.TS == nil || e.Exp == nil {
		t.Fatalf("bad parse: %+v", e)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code Code
	}{
		{"not json", "nope", CodeMalformed},
		{"array", "[]", CodeMalformed},
		{"empty", "", CodeMalformed},
		{"trailing data", cmd("") + "{}", CodeMalformed},
		{"unknown top-level field", strings.Replace(cmd(""), `{"v":1`, `{"evil":1,"v":1`, 1), CodeMalformed},
		{"v as string", strings.Replace(cmd(""), `"v":1`, `"v":"1"`, 1), CodeMalformed},
		{"v fractional", strings.Replace(cmd(""), `"v":1`, `"v":1.5`, 1), CodeMalformed},
		{"v missing", strings.Replace(cmd(""), `"v":1,`, ``, 1), CodeMalformed},
		{"wrong version", strings.Replace(cmd(""), `"v":1`, `"v":2`, 1), CodeUnsupportedVersion},
		{"unknown type", strings.Replace(cmd(""), `"command"`, `"shell"`, 1), CodeUnsupportedMessage},
		{"non-uuid id", strings.Replace(cmd(""), id1, "not-a-uuid", 1), CodeMalformed},
		{"short device", strings.Replace(cmd(""), dev, "abc", 1), CodeMalformed},
		{"uppercase device", strings.Replace(cmd(""), dev, strings.Repeat("A", 64), 1), CodeMalformed},
		{"command with corr", strings.Replace(cmd(""), `"device"`, fmt.Sprintf(`"corr":"%s","device"`, id2), 1), CodeMalformed},
		{"result without corr", fmt.Sprintf(`{"v":1,"type":"result","id":"%s","device":"%s","payload":{}}`, id1, dev), CodeMalformed},
		{"command without ts", strings.Replace(cmd(""), `"ts":"2026-10-31T12:00:00Z",`, ``, 1), CodeMalformed},
		{"bad exp", strings.Replace(cmd(""), `2026-10-31T12:00:30Z`, `yesterday`, 1), CodeMalformed},
		{"payload not object", strings.Replace(cmd(""), `"payload":{"capability":"device.info","version":1}`, `"payload":[1]`, 1), CodeMalformed},
		{"payload missing", fmt.Sprintf(`{"v":1,"type":"heartbeat","id":"%s","device":"%s"}`, id1, dev), CodeMalformed},
		{"too large", cmd(`,"x":"` + strings.Repeat("y", MaxMessageBytes) + `"`), CodeTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			pe, ok := err.(*Error)
			if !ok {
				t.Fatalf("expected *Error, got %v", err)
			}
			if pe.Code != tc.code {
				t.Fatalf("code = %s, want %s (%s)", pe.Code, tc.code, pe.Msg)
			}
		})
	}
}

func TestParseKeepsIDOnLaterFailure(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(cmd(""), `"v":1`, `"v":2`, 1)))
	if pe := err.(*Error); pe.ID != id1 {
		t.Fatalf("id not carried: %q", pe.ID)
	}
}

func TestCheckWindow(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 10, 0, time.UTC)
	mk := func(ts, exp string) *Envelope {
		e, err := Parse([]byte(strings.NewReplacer("2026-10-31T12:00:00Z", ts, "2026-10-31T12:00:30Z", exp).Replace(cmd(""))))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	check := func(e *Envelope, want Code) {
		t.Helper()
		err := e.CheckWindow(now)
		if want == "" {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if err == nil || err.(*Error).Code != want {
			t.Fatalf("want %s, got %v", want, err)
		}
	}
	check(mk("2026-10-31T12:00:00Z", "2026-10-31T12:00:30Z"), "")
	check(mk("2026-10-31T11:59:50Z", "2026-10-31T12:00:05Z"), CodeExpired)
	check(mk("2026-10-31T12:02:00Z", "2026-10-31T12:02:30Z"), CodeExpired)
	check(mk("2026-10-31T12:00:00Z", "2026-10-31T12:01:01Z"), CodeMalformed)
	check(mk("2026-10-31T12:00:30Z", "2026-10-31T12:00:00Z"), CodeMalformed)
}

func TestMarshalRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Second)
	in := &Envelope{V: 1, Type: TypeCommand, ID: NewID(), Device: dev, TS: &now, Exp: &exp, Payload: []byte(`{"a":1}`)}
	b, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.Type != in.Type {
		t.Fatal("round trip mismatch")
	}
}

func TestNewIDIsV4UUID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewID()
		if !ValidID(id) || id[14] != '4' || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestNewErrorAlwaysHasCorr(t *testing.T) {
	e := NewError(dev, "", CodeMalformed, "x", time.Now())
	if !ValidID(e.Corr) {
		t.Fatalf("corr = %q", e.Corr)
	}
	b, _ := e.Marshal()
	if _, err := Parse(b); err != nil {
		t.Fatalf("own error envelope does not parse: %v", err)
	}
}

func TestAuthMessageDomainSeparated(t *testing.T) {
	m := AuthMessage(make([]byte, 32), dev, "wss://r")
	if !strings.HasPrefix(string(m), AuthPrefix) || !strings.HasSuffix(string(m), "wss://r") {
		t.Fatal("unexpected auth message layout")
	}
}
