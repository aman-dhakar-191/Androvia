package devices_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/aman-dhakar-191/androvia/relay/migrations"
)

func TestNewValidates(t *testing.T) {
	good := testutil.NewDevice(t)
	now := time.Now()

	d, err := devices.New("Pixel", good.SPKI, now)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != good.ID || d.Status != devices.StatusActive {
		t.Fatalf("id/status wrong: %+v", d)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsader, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)

	bad := map[string]struct {
		label string
		key   []byte
	}{
		"garbage key":       {"x", []byte("not a key")},
		"empty key":         {"x", nil},
		"P-384 key":         {"x", p384der},
		"RSA key":           {"x", rsader},
		"empty label":       {"", good.SPKI},
		"long label":        {strings.Repeat("a", 65), good.SPKI},
		"control character": {"a\x00b", good.SPKI},
	}
	for name, tc := range bad {
		if _, err := devices.New(tc.label, tc.key, now); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestVerify(t *testing.T) {
	a, b := testutil.NewDevice(t), testutil.NewDevice(t)
	d, _ := devices.New("a", a.SPKI, time.Now())
	msg := []byte("hello")
	if !d.Verify(msg, a.Sign(msg)) {
		t.Fatal("valid signature rejected")
	}
	if d.Verify([]byte("other"), a.Sign(msg)) {
		t.Fatal("signature accepted for different message")
	}
	if d.Verify(msg, b.Sign(msg)) {
		t.Fatal("signature from another key accepted")
	}
	if d.Verify(msg, []byte("junk")) || d.Verify(msg, nil) {
		t.Fatal("junk signature accepted")
	}
}

// storeContract is run against every Store implementation.
func storeContract(t *testing.T, s devices.Store) {
	ctx := context.Background()
	d1, _ := devices.New("one", testutil.NewDevice(t).SPKI, time.Now().Add(-time.Minute))
	d2, _ := devices.New("two", testutil.NewDevice(t).SPKI, time.Now())

	if _, err := s.Get(ctx, d1.ID); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := s.Create(ctx, d1); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, d1); !errors.Is(err, devices.ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	if err := s.Create(ctx, d2); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, d1.ID)
	if err != nil || got.Label != "one" || got.Status != devices.StatusActive || string(got.PublicKey) != string(d1.PublicKey) {
		t.Fatalf("get: %+v %v", got, err)
	}
	if got.LastSeenAt != nil {
		t.Fatal("last_seen should start empty")
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range list {
		ids = append(ids, d.ID)
	}
	i1, i2 := indexOf(ids, d1.ID), indexOf(ids, d2.ID)
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("list order wrong: %v", ids)
	}

	seen := time.Now().UTC().Truncate(time.Second)
	if err := s.TouchLastSeen(ctx, d1.ID, seen); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(ctx, d1.ID)
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
		t.Fatalf("last seen = %v", got.LastSeenAt)
	}
	if err := s.TouchLastSeen(ctx, strings.Repeat("0", 64), seen); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("touch missing: %v", err)
	}

	if err := s.Revoke(ctx, d1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, d1.ID); err != nil { // idempotent
		t.Fatal(err)
	}
	got, _ = s.Get(ctx, d1.ID)
	if got.Status != devices.StatusRevoked {
		t.Fatal("not revoked")
	}
	if err := s.Revoke(ctx, strings.Repeat("0", 64)); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
}

func indexOf(xs []string, v string) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	return -1
}

func TestMemoryStore(t *testing.T) { storeContract(t, devices.NewMemoryStore()) }

// TestPostgresStore runs only when RELAY_TEST_DATABASE_URL points at a disposable database.
func TestPostgresStore(t *testing.T) {
	ctx := context.Background()
	pool := testutil.PGPool(t)
	if err := migrations.Apply(ctx, pool); err != nil { // re-running must be a no-op
		t.Fatalf("second Apply: %v", err)
	}
	storeContract(t, devices.NewPostgresStore(pool))

	// The CHECK constraints are the last line of defence against bad rows.
	if _, err := pool.Exec(ctx, `INSERT INTO devices VALUES ('short','x','\x00','active',now(),NULL)`); err == nil {
		t.Fatal("bad id accepted by database")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO devices VALUES ('`+strings.Repeat("c", 64)+`','x','\x00','pending',now(),NULL)`); err == nil {
		t.Fatal("bad status accepted by database")
	}
}
