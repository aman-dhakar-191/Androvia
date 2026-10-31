package oauth_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/oauth"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
)

var ctx = context.Background()

// storeEnv gives each implementation a way to create the Androvia client a refresh token points at.
type storeEnv struct {
	store    oauth.Store
	newOwner func(t *testing.T) string // creates an OAuth-derived client and returns its id
}

func implementations(t *testing.T) map[string]func(*testing.T) storeEnv {
	return map[string]func(*testing.T) storeEnv{
		"memory": func(t *testing.T) storeEnv {
			cs := clients.NewMemoryStore(nil)
			return storeEnv{oauth.NewMemoryStore(), func(t *testing.T) string {
				c, err := cs.CreateOAuthClient(ctx, "oauth: t", nil, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				return c.ID
			}}
		},
		"postgres": func(t *testing.T) storeEnv {
			pool := testutil.PGPool(t)
			cs := clients.NewPostgresStore(pool)
			return storeEnv{oauth.NewPostgresStore(pool), func(t *testing.T) string {
				c, err := cs.CreateOAuthClient(ctx, "oauth: t", nil, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				return c.ID
			}}
		},
	}
}

func eachStore(t *testing.T, f func(t *testing.T, e storeEnv)) {
	for name, mk := range implementations(t) {
		t.Run(name, func(t *testing.T) { f(t, mk(t)) })
	}
}

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func mkApp(t *testing.T, e storeEnv, id string) oauth.App {
	t.Helper()
	a := oauth.App{ID: id, Name: "Claude", RedirectURIs: []string{"https://claude.ai/cb", "http://127.0.0.1:1/x"}, CreatedAt: t0}
	if err := e.store.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	return a
}

func mkRefresh(t *testing.T, e storeEnv, app, owner, family, secret string) oauth.Refresh {
	t.Helper()
	r := oauth.Refresh{Hash: sha256.Sum256([]byte(secret)), FamilyID: family, AppID: app, SubjectClientID: owner, Resource: "https://relay.test/mcp",
		CreatedAt: t0, ExpiresAt: t0.Add(oauth.RefreshTTL), FamilyExpiresAt: t0.Add(oauth.RefreshFamilyTTL)}
	if err := e.store.SaveRefresh(ctx, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAppsRoundTrip(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		a := mkApp(t, e, "0123456789abcdef0123456789abcdef")
		got, err := e.store.GetApp(ctx, a.ID)
		if err != nil || got.Name != "Claude" || len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != "https://claude.ai/cb" {
			t.Fatalf("%+v %v", got, err)
		}
		if _, err := e.store.GetApp(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, oauth.ErrNotFound) {
			t.Fatalf("unknown app: %v", err)
		}
	})
}

func TestAppRegistrationIsCapped(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		for i := 0; i < oauth.MaxApps; i++ {
			id := make([]byte, 32)
			for j := range id {
				id[j] = "0123456789abcdef"[(i>>(4*(j%8)))&15]
			}
			if err := e.store.CreateApp(ctx, oauth.App{ID: string(id), Name: "x", RedirectURIs: []string{"https://a.example/cb"}, CreatedAt: t0}); err != nil {
				t.Fatalf("app %d: %v", i, err)
			}
		}
		err := e.store.CreateApp(ctx, oauth.App{ID: "ffffffffffffffffffffffffffffffff", Name: "x", RedirectURIs: []string{"https://a.example/cb"}, CreatedAt: t0})
		if !errors.Is(err, oauth.ErrTooMany) {
			t.Fatalf("beyond the cap: %v", err)
		}
	})
}

func TestRefreshTokenWorksOnceEvenUnderConcurrency(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		app := mkApp(t, e, "0123456789abcdef0123456789abcdef")
		r := mkRefresh(t, e, app.ID, e.newOwner(t), "fam1", "secret-1")
		var ok, reused, other atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch _, err := e.store.UseRefresh(ctx, r.Hash, t0.Add(time.Hour)); {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, oauth.ErrReused):
					reused.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || reused.Load() != 15 || other.Load() != 0 {
			t.Fatalf("ok=%d reused=%d other=%d, want exactly one success", ok.Load(), reused.Load(), other.Load())
		}
	})
}

func TestReuseReportsTheFamilyAndRevocationRemovesIt(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		app := mkApp(t, e, "0123456789abcdef0123456789abcdef")
		owner := e.newOwner(t)
		old := mkRefresh(t, e, app.ID, owner, "famA", "old")
		newer := mkRefresh(t, e, app.ID, owner, "famA", "new")
		other := mkRefresh(t, e, app.ID, e.newOwner(t), "famB", "unrelated")
		if _, err := e.store.UseRefresh(ctx, old.Hash, t0); err != nil {
			t.Fatal(err)
		}
		rec, err := e.store.UseRefresh(ctx, old.Hash, t0)
		if !errors.Is(err, oauth.ErrReused) || rec.FamilyID != "famA" || rec.SubjectClientID != owner {
			t.Fatalf("reuse: %+v %v", rec, err)
		}
		if err := e.store.RevokeFamily(ctx, "famA"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.UseRefresh(ctx, newer.Hash, t0); !errors.Is(err, oauth.ErrNotFound) {
			t.Fatalf("family member survived revocation: %v", err)
		}
		if _, err := e.store.UseRefresh(ctx, other.Hash, t0); err != nil {
			t.Fatalf("revoking one family touched another: %v", err)
		}
	})
}

func TestRefreshTokensExpireAndUnknownOnesAreNotFound(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		app := mkApp(t, e, "0123456789abcdef0123456789abcdef")
		owner := e.newOwner(t)
		r := mkRefresh(t, e, app.ID, owner, "fam", "s")
		if _, err := e.store.UseRefresh(ctx, r.Hash, t0.Add(oauth.RefreshTTL+time.Second)); !errors.Is(err, oauth.ErrNotFound) {
			t.Fatalf("expired: %v", err)
		}
		if _, err := e.store.UseRefresh(ctx, sha256.Sum256([]byte("nope")), t0); !errors.Is(err, oauth.ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		// family lifetime caps a token that would otherwise still be valid
		r2 := oauth.Refresh{Hash: sha256.Sum256([]byte("capped")), FamilyID: "fam2", AppID: app.ID, SubjectClientID: owner, Resource: "r",
			CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour), FamilyExpiresAt: t0.Add(24 * time.Hour)}
		if err := e.store.SaveRefresh(ctx, r2); err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.UseRefresh(ctx, r2.Hash, t0.Add(48*time.Hour)); !errors.Is(err, oauth.ErrNotFound) {
			t.Fatalf("past the family lifetime: %v", err)
		}
	})
}

func TestPurgeRemovesOnlyExpiredTokens(t *testing.T) {
	eachStore(t, func(t *testing.T, e storeEnv) {
		app := mkApp(t, e, "0123456789abcdef0123456789abcdef")
		owner := e.newOwner(t)
		live := mkRefresh(t, e, app.ID, owner, "live", "live")
		mkRefresh(t, e, app.ID, owner, "dead", "dead")
		n, err := e.store.PurgeExpired(ctx, t0.Add(oauth.RefreshTTL+time.Hour))
		if err != nil || n != 2 { // both expire at the same moment here
			t.Fatalf("purged %d, %v", n, err)
		}
		_ = live
		n, _ = e.store.PurgeExpired(ctx, t0.Add(time.Hour))
		if n != 0 {
			t.Fatalf("purged %d fresh tokens", n)
		}
	})
}

// The Androvia client behind an OAuth connection: created with its grants all-or-nothing, and no credential.
func TestCreateOAuthClientIsAtomicAndHasNoCredential(t *testing.T) {
	pool := testutil.PGPool(t)
	cs := clients.NewPostgresStore(pool)
	ds := devices.NewPostgresStore(pool)
	d := testutil.NewDevice(t)
	dev, err := devices.New("Pixel", d.SPKI, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ds.Create(ctx, dev); err != nil {
		t.Fatal(err)
	}
	cl, err := cs.CreateOAuthClient(ctx, "oauth: Claude", []clients.Grant{{DeviceID: dev.ID, Scopes: []string{"devices:read"}}}, t0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cs.GetClient(ctx, cl.ID)
	if err != nil || got.Status != clients.StatusActive || got.Label != "oauth: Claude" {
		t.Fatalf("%+v %v", got, err)
	}
	if gs, _ := cs.Grants(ctx, cl.ID); len(gs) != 1 || gs[0].Scopes[0] != "devices:read" {
		t.Fatalf("grants: %v", gs)
	}
	if cr, _ := cs.Credentials(ctx, cl.ID); len(cr) != 0 {
		t.Fatalf("an OAuth client must have no key credential, has %d", len(cr))
	}
	before, _ := cs.ListClients(ctx)
	_, err = cs.CreateOAuthClient(ctx, "oauth: broken", []clients.Grant{
		{DeviceID: dev.ID, Scopes: []string{"devices:read"}},
		{DeviceID: protocol.NewID() + protocol.NewID()[:28], Scopes: []string{"devices:read"}}, // a device that does not exist
	}, t0)
	if !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("grant for an unknown device: %v", err)
	}
	if after, _ := cs.ListClients(ctx); len(after) != len(before) {
		t.Fatal("a failed creation left a client behind")
	}
}
