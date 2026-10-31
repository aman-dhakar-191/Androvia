package clients_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
	"github.com/aman-dhakar-191/androvia/relay/migrations"
)

var ctx = context.Background()

type fixture struct {
	store     clients.Store
	newDevice func(t *testing.T) string // registers a real device (the grants table has a foreign key to devices)
}

func issue(t *testing.T, s clients.Store, grants []clients.Grant, ttl time.Duration, now time.Time) string {
	t.Helper()
	code, err := clients.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.IssueCode(ctx, clients.PairingCode{
		ID: protocol.NewID(), CodeHash: clients.HashCode(code), Grants: grants, CreatedBy: "test",
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}); err != nil {
		t.Fatal(err)
	}
	return code
}

func contract(t *testing.T, f fixture) {
	s := f.store
	now := time.Now().UTC().Truncate(time.Millisecond)
	dev1, dev2 := f.newDevice(t), f.newDevice(t)
	key := testutil.NewDevice(t).SPKI

	t.Run("redeem creates client, credential and the code's grants", func(t *testing.T) {
		code := issue(t, s, []clients.Grant{{DeviceID: dev1, Scopes: []string{"capability:device.info:execute", "devices:read"}}}, time.Minute, now)
		cl, cr, err := s.Redeem(ctx, clients.HashCode(code), "agent-1", key, now)
		if err != nil {
			t.Fatal(err)
		}
		if cl.Status != clients.StatusActive || cl.Label != "agent-1" || cr.ClientID != cl.ID || !protocol.ValidID(cl.ID) {
			t.Fatalf("%+v %+v", cl, cr)
		}
		if !cr.Usable(now) || cr.ExpiresAt.Sub(now) != clients.CredentialLifetime {
			t.Fatalf("credential lifetime: %+v", cr)
		}
		got, err := s.GetCredential(ctx, cr.ID)
		if err != nil || string(got.PublicKey) != string(key) {
			t.Fatalf("stored key differs: %v", err)
		}
		sc, _ := s.ScopesFor(ctx, cl.ID, dev1)
		if strings.Join(sc, ",") != "capability:device.info:execute,devices:read" {
			t.Fatalf("scopes %v", sc)
		}
		if sc, _ := s.ScopesFor(ctx, cl.ID, dev2); len(sc) != 0 {
			t.Fatalf("grant leaked to another device: %v", sc)
		}
	})

	t.Run("a code works exactly once", func(t *testing.T) {
		code := issue(t, s, nil, time.Minute, now)
		if _, _, err := s.Redeem(ctx, clients.HashCode(code), "a", key, now); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Redeem(ctx, clients.HashCode(code), "b", key, now); !errors.Is(err, clients.ErrCodeInvalid) {
			t.Fatalf("second use: %v", err)
		}
	})

	t.Run("unknown, expired and malformed codes all fail the same way", func(t *testing.T) {
		expired := issue(t, s, nil, time.Minute, now.Add(-time.Hour))
		for name, c := range map[string]string{"unknown": "AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA", "expired": expired, "empty": "", "junk": "!!!"} {
			if _, _, err := s.Redeem(ctx, clients.HashCode(c), "x", key, now); !errors.Is(err, clients.ErrCodeInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})

	t.Run("code entry tolerates case, dashes and spaces", func(t *testing.T) {
		code := issue(t, s, nil, time.Minute, now)
		sloppy := " " + strings.ToLower(strings.ReplaceAll(code, "-", " ")) + " "
		if _, _, err := s.Redeem(ctx, clients.HashCode(sloppy), "x", key, now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("concurrent redemption: exactly one winner", func(t *testing.T) {
		code := issue(t, s, []clients.Grant{{DeviceID: dev1, Scopes: []string{"devices:read"}}}, time.Minute, now)
		var wins, invalid int32
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := s.Redeem(ctx, clients.HashCode(code), "racer", key, now)
				switch {
				case err == nil:
					atomic.AddInt32(&wins, 1)
				case errors.Is(err, clients.ErrCodeInvalid):
					atomic.AddInt32(&invalid, 1)
				default:
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if wins != 1 || invalid != 19 {
			t.Fatalf("wins=%d invalid=%d", wins, invalid)
		}
	})

	t.Run("a code granting a device that does not exist cannot be redeemed", func(t *testing.T) {
		code := issue(t, s, []clients.Grant{{DeviceID: strings.Repeat("9", 64), Scopes: []string{"devices:read"}}}, time.Minute, now)
		if _, _, err := s.Redeem(ctx, clients.HashCode(code), "x", key, now); !errors.Is(err, clients.ErrCodeInvalid) {
			t.Fatalf("%v", err)
		}
	})

	cl, cr := func() (clients.Client, clients.Credential) {
		c, k, err := s.Redeem(ctx, clients.HashCode(issue(t, s, nil, time.Minute, now)), "main", key, now)
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}()

	t.Run("grants: replace, remove, per device, list", func(t *testing.T) {
		if err := s.SetGrant(ctx, cl.ID, dev1, []string{"devices:read"}, now); err != nil {
			t.Fatal(err)
		}
		if err := s.SetGrant(ctx, cl.ID, dev2, []string{"capability:device.info:execute"}, now); err != nil {
			t.Fatal(err)
		}
		if err := s.SetGrant(ctx, cl.ID, dev1, []string{"capability:device.info:execute"}, now); err != nil { // replaces, not adds
			t.Fatal(err)
		}
		if sc, _ := s.ScopesFor(ctx, cl.ID, dev1); strings.Join(sc, ",") != "capability:device.info:execute" {
			t.Fatalf("replace failed: %v", sc)
		}
		gs, err := s.Grants(ctx, cl.ID)
		if err != nil || len(gs) != 2 {
			t.Fatalf("%v %v", gs, err)
		}
		if err := s.SetGrant(ctx, cl.ID, dev1, nil, now); err != nil {
			t.Fatal(err)
		}
		if sc, _ := s.ScopesFor(ctx, cl.ID, dev1); len(sc) != 0 {
			t.Fatalf("grant not removed: %v", sc)
		}
		if sc, _ := s.ScopesFor(ctx, cl.ID, dev2); len(sc) != 1 {
			t.Fatal("removing one device's grant touched another")
		}
	})

	t.Run("grants for unknown clients, devices and ids", func(t *testing.T) {
		if err := s.SetGrant(ctx, protocol.NewID(), dev1, []string{"devices:read"}, now); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("unknown client: %v", err)
		}
		if err := s.SetGrant(ctx, cl.ID, strings.Repeat("8", 64), []string{"devices:read"}, now); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("unknown device: %v", err)
		}
		if err := s.SetGrant(ctx, "not-a-uuid", dev1, []string{"devices:read"}, now); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("malformed client id: %v", err)
		}
		if sc, err := s.ScopesFor(ctx, "not-a-uuid", "nope"); err != nil || len(sc) != 0 {
			t.Fatalf("malformed ids must mean no access: %v %v", sc, err)
		}
		if _, err := s.Grants(ctx, protocol.NewID()); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("credentials: add, limit, expiry and revoked ones do not count", func(t *testing.T) {
		c2, _, err := s.Redeem(ctx, clients.HashCode(issue(t, s, nil, time.Minute, now)), "cred-test", key, now)
		if err != nil {
			t.Fatal(err)
		}
		add := func(exp time.Time) (clients.Credential, error) {
			c := clients.Credential{ID: protocol.NewID(), ClientID: c2.ID, PublicKey: key, CreatedAt: now, ExpiresAt: exp}
			return c, s.AddCredential(ctx, c)
		}
		var added []clients.Credential
		for i := 0; i < clients.MaxCredentialsPerClient-1; i++ { // the redeemed one is already 1
			c, err := add(now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			added = append(added, c)
		}
		if _, err := add(now.Add(time.Hour)); !errors.Is(err, clients.ErrCredentialLimit) {
			t.Fatalf("limit not enforced: %v", err)
		}
		if err := s.RevokeCredential(ctx, c2.ID, added[0].ID, now); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeCredential(ctx, c2.ID, added[0].ID, now); err != nil { // idempotent
			t.Fatal(err)
		}
		if _, err := add(now.Add(time.Hour)); err != nil {
			t.Fatalf("a revoked credential should free a slot: %v", err)
		}
		got, _ := s.GetCredential(ctx, added[0].ID)
		if got.Usable(now) {
			t.Fatal("revoked credential still usable")
		}
		if err := s.RevokeCredential(ctx, cl.ID, added[1].ID, now); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("revoking another client's credential: %v", err)
		}
		if _, err := s.GetCredential(ctx, protocol.NewID()); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("credentials can be listed per client", func(t *testing.T) {
		list, err := s.Credentials(ctx, cl.ID)
		if err != nil || len(list) != 1 || list[0].ID != cr.ID || list[0].ClientID != cl.ID {
			t.Fatalf("%v %v", list, err)
		}
		if _, err := s.Credentials(ctx, protocol.NewID()); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("an expired credential is not usable", func(t *testing.T) {
		c := clients.Credential{ExpiresAt: now.Add(-time.Second)}
		if c.Usable(now) {
			t.Fatal("expired credential usable")
		}
	})

	t.Run("revoking a client revokes it and every credential, and blocks new ones", func(t *testing.T) {
		c3, k3, err := s.Redeem(ctx, clients.HashCode(issue(t, s, nil, time.Minute, now)), "to-revoke", key, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeClient(ctx, c3.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeClient(ctx, c3.ID, now.Add(time.Hour)); err != nil { // idempotent, keeps the first time
			t.Fatal(err)
		}
		got, _ := s.GetClient(ctx, c3.ID)
		if got.Status != clients.StatusRevoked || got.RevokedAt == nil || got.RevokedAt.After(now.Add(time.Minute)) {
			t.Fatalf("%+v", got)
		}
		if cr, _ := s.GetCredential(ctx, k3.ID); cr.Usable(now) {
			t.Fatal("credential of a revoked client is still usable")
		}
		add := clients.Credential{ID: protocol.NewID(), ClientID: c3.ID, PublicKey: key, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := s.AddCredential(ctx, add); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("revoked client got a new credential: %v", err)
		}
		if err := s.RevokeClient(ctx, protocol.NewID(), now); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("list and get", func(t *testing.T) {
		all, err := s.ListClients(ctx)
		if err != nil || len(all) < 3 {
			t.Fatalf("%d %v", len(all), err)
		}
		if _, err := s.GetClient(ctx, cl.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetClient(ctx, "nope"); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})
	_ = cr
}

func TestMemoryStore(t *testing.T) {
	ds := devices.NewMemoryStore()
	contract(t, fixture{
		store: clients.NewMemoryStore(func(id string) bool { _, err := ds.Get(ctx, id); return err == nil }),
		newDevice: func(t *testing.T) string {
			d, err := devices.New("d", testutil.NewDevice(t).SPKI, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := ds.Create(ctx, d); err != nil {
				t.Fatal(err)
			}
			return d.ID
		},
	})
}

// TestPostgresStore runs only when RELAY_TEST_DATABASE_URL points at a disposable database.
func TestPostgresStore(t *testing.T) {
	pool := testutil.PGPool(t)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	ds := devices.NewPostgresStore(pool)
	contract(t, fixture{
		store: clients.NewPostgresStore(pool),
		newDevice: func(t *testing.T) string {
			d, err := devices.New("d", testutil.NewDevice(t).SPKI, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := ds.Create(ctx, d); err != nil {
				t.Fatal(err)
			}
			return d.ID
		},
	})

	// The database itself must refuse inconsistent rows.
	bad := map[string]string{
		"client with bad status":  `INSERT INTO clients VALUES ('` + protocol.NewID() + `','x','pending',now(),NULL)`,
		"grant to unknown device": `INSERT INTO grants SELECT id, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'devices:read', now() FROM clients LIMIT 1`,
	}
	for name, q := range bad {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s accepted by the database", name)
		}
	}
}

func TestCodes(t *testing.T) {
	a, _ := clients.NewCode()
	b, _ := clients.NewCode()
	if a == b || len(a) != 30 || strings.Count(a, "-") != 4 {
		t.Fatalf("codes: %q %q", a, b)
	}
	if clients.HashCode(a) == clients.HashCode(b) {
		t.Fatal("hash collision")
	}
	if clients.HashCode(a) != clients.HashCode(strings.ToLower(strings.ReplaceAll(a, "-", ""))) {
		t.Fatal("normalisation differs")
	}
}

func TestValidateGrants(t *testing.T) {
	dev := strings.Repeat("a", 64)
	ok, err := clients.ValidateGrants([]clients.Grant{{DeviceID: dev, Scopes: []string{"devices:read", "devices:read", "capability:device.info:execute"}}})
	if err != nil || len(ok) != 1 || len(ok[0].Scopes) != 2 {
		t.Fatalf("%v %v", ok, err)
	}
	bad := map[string][]clients.Grant{
		"bad device":       {{DeviceID: "x", Scopes: []string{"devices:read"}}},
		"no scopes":        {{DeviceID: dev}},
		"unknown scope":    {{DeviceID: dev, Scopes: []string{"admin"}}},
		"wildcard scope":   {{DeviceID: dev, Scopes: []string{"capability:*:execute"}}},
		"duplicate device": {{DeviceID: dev, Scopes: []string{"devices:read"}}, {DeviceID: dev, Scopes: []string{"devices:read"}}},
		"execute w/o cap":  {{DeviceID: dev, Scopes: []string{"capability::execute"}}},
	}
	for name, g := range bad {
		if _, err := clients.ValidateGrants(g); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	many := make([]clients.Grant, clients.MaxGrantsPerCode+1)
	if _, err := clients.ValidateGrants(many); err == nil {
		t.Error("too many grants accepted")
	}
}
