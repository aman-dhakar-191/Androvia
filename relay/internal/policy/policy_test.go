package policy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
)

type fakeSource map[string][]string // "client|device" -> scopes

func (f fakeSource) ScopesFor(_ context.Context, c, d string) ([]string, error) {
	return f[c+"|"+d], nil
}

type failingSource struct{}

func (failingSource) ScopesFor(context.Context, string, string) ([]string, error) {
	return nil, errors.New("database down")
}

func TestValidScope(t *testing.T) {
	good := []string{"devices:read", "capability:device.info:execute", "capability:files.read_text:execute", "capability:a.b.c:execute"}
	bad := []string{
		"", "*", "admin", "devices:write", "devices:read ", "DEVICES:READ", "capability:*:execute", "capability:device.info:*",
		"capability:device:execute", "capability::execute", "capability:device.info:read", "capability:Device.Info:execute",
		"capability:device.info:execute:extra", "capability:device.info", "capability:../etc:execute", "execute",
	}
	for _, s := range good {
		if !policy.ValidScope(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range bad {
		if policy.ValidScope(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestExecuteScope(t *testing.T) {
	if policy.ExecuteScope("device.info") != "capability:device.info:execute" {
		t.Fatal("wrong scope")
	}
	for _, bad := range []string{"", "device", "Device.Info", "a.b:execute", "x y.z"} {
		if got := policy.ExecuteScope(bad); got != "" {
			t.Errorf("%q produced %q", bad, got)
		}
	}
	// An invalid capability must never produce something that could match a grant.
	if policy.ValidScope(policy.ExecuteScope("nope")) {
		t.Fatal("empty scope considered valid")
	}
}

func TestNormalizeScopes(t *testing.T) {
	got, err := policy.NormalizeScopes([]string{"devices:read", "capability:b.c:execute", "devices:read", "capability:a.c:execute"})
	if err != nil || strings.Join(got, ",") != "capability:a.c:execute,capability:b.c:execute,devices:read" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := policy.NormalizeScopes([]string{"devices:read", "root"}); err == nil {
		t.Fatal("unknown scope silently accepted")
	}
	tooMany := make([]string, policy.MaxScopesPerGrant+1)
	for i := range tooMany {
		tooMany[i] = "devices:read"
	}
	if _, err := policy.NormalizeScopes(tooMany); err == nil {
		t.Fatal("too many scopes accepted")
	}
}

func TestAuthorizeDeniesByDefault(t *testing.T) {
	ctx := context.Background()
	src := fakeSource{"alice|devA": {"devices:read", "capability:device.info:execute"}}
	a := policy.NewAuthorizer(src)

	if err := a.Require(ctx, "alice", "devA", "capability:device.info:execute"); err != nil {
		t.Fatalf("granted action refused: %v", err)
	}
	denied := map[string][3]string{
		"other capability":          {"alice", "devA", "capability:files.read:execute"},
		"same scope, other device":  {"alice", "devB", "capability:device.info:execute"},
		"same scope, other client":  {"bob", "devA", "capability:device.info:execute"},
		"empty scope":               {"alice", "devA", ""},
		"empty client":              {"", "devA", "devices:read"},
		"empty device":              {"alice", "", "devices:read"},
		"wildcard is not a grant":   {"alice", "devA", "capability:*:execute"},
		"prefix of a granted scope": {"alice", "devA", "capability:device.info"},
	}
	for name, c := range denied {
		if err := a.Require(ctx, c[0], c[1], c[2]); !errors.Is(err, policy.ErrForbidden) {
			t.Errorf("%s: got %v, want ErrForbidden", name, err)
		}
	}
}

func TestAuthorizeFailsClosedWhenTheLookupFails(t *testing.T) {
	a := policy.NewAuthorizer(failingSource{})
	err := a.Require(context.Background(), "alice", "devA", "devices:read")
	if err == nil || errors.Is(err, policy.ErrForbidden) {
		t.Fatalf("a lookup failure must be an error, never an allow: %v", err)
	}
}

func TestHasAny(t *testing.T) {
	a := policy.NewAuthorizer(fakeSource{"alice|devA": {"devices:read"}})
	if ok, _ := a.HasAny(context.Background(), "alice", "devA"); !ok {
		t.Fatal("grant not seen")
	}
	if ok, _ := a.HasAny(context.Background(), "alice", "devB"); ok {
		t.Fatal("relationship with a device that has no grant")
	}
	if ok, _ := a.HasAny(context.Background(), "", "devA"); ok {
		t.Fatal("empty client")
	}
}
