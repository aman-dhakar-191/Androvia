package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
)

const origin = "wss://relay.example.com"

var ctx = context.Background()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is one relay with one paired client holding one key.
type env struct {
	t      *testing.T
	clk    *clock
	store  *clients.MemoryStore
	a      *auth.Authenticator
	client clients.Client
	cred   clients.Credential
	key    *testutil.Device // the client's private key (same EC P-256 helper as devices)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
	store := clients.NewMemoryStore(nil)
	key := testutil.NewDevice(t)
	code, _ := clients.NewCode()
	_ = store.IssueCode(ctx, clients.PairingCode{ID: protocol.NewID(), CodeHash: clients.HashCode(code), CreatedBy: "t", CreatedAt: clk.now(), ExpiresAt: clk.now().Add(time.Hour)})
	cl, cr, err := store.Redeem(ctx, clients.HashCode(code), "agent", key.SPKI, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	return &env{t, clk, store, auth.New(store, origin, 10*time.Minute, clk.now), cl, cr, key}
}

func (e *env) sign(nonce, clientID, credID, org string) []byte {
	nb, _ := base64.StdEncoding.DecodeString(nonce)
	return e.key.Sign(auth.Message(nb, clientID, credID, org))
}

// login runs the whole exchange with a correct signature.
func (e *env) login() string {
	e.t.Helper()
	n, _, err := e.a.NewChallenge(e.client.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	tok, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, e.sign(n, e.client.ID, e.cred.ID, origin))
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func wantFail(t *testing.T, err error, reason auth.Reason) {
	t.Helper()
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if got := auth.ReasonOf(err); got != reason {
		t.Fatalf("reason = %q, want %q", got, reason)
	}
	if err.Error() != "unauthorized" {
		t.Fatalf("the error text must reveal nothing: %q", err.Error())
	}
}

func TestLoginAndVerify(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	if !strings.HasPrefix(tok, "avt_") || len(tok) < 40 {
		t.Fatalf("token shape: %q", tok)
	}
	p, err := e.a.Verify(ctx, tok)
	if err != nil || p.ClientID != e.client.ID || p.CredentialID != e.cred.ID {
		t.Fatalf("%+v %v", p, err)
	}
	if tok2 := e.login(); tok2 == tok {
		t.Fatal("two logins produced the same token")
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	n, _, _ := e.a.NewChallenge(e.client.ID)
	sig := e.sign(n, e.client.ID, e.cred.ID, origin)
	if _, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, sig); err != nil {
		t.Fatal(err)
	}
	// A recorded, perfectly valid exchange replayed: must fail.
	_, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, sig)
	wantFail(t, err, auth.ReasonUnknownChallenge)
}

func TestAFailedAttemptStillConsumesTheChallenge(t *testing.T) {
	e := newEnv(t)
	n, _, _ := e.a.NewChallenge(e.client.ID)
	_, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, []byte("garbage"))
	wantFail(t, err, auth.ReasonBadSignature)
	_, _, err = e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, e.sign(n, e.client.ID, e.cred.ID, origin))
	wantFail(t, err, auth.ReasonUnknownChallenge) // no second guess on the same nonce
}

func TestConcurrentExchangesOfOneChallenge(t *testing.T) {
	e := newEnv(t)
	n, _, _ := e.a.NewChallenge(e.client.ID)
	sig := e.sign(n, e.client.ID, e.cred.ID, origin)
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, sig); err == nil {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent exchanges succeeded; want exactly 1", ok)
	}
}

func TestChallengeExpires(t *testing.T) {
	e := newEnv(t)
	n, exp, _ := e.a.NewChallenge(e.client.ID)
	if exp.Sub(e.clk.now()) != auth.ChallengeTTL {
		t.Fatalf("ttl %v", exp.Sub(e.clk.now()))
	}
	e.clk.advance(auth.ChallengeTTL + time.Second)
	_, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, e.sign(n, e.client.ID, e.cred.ID, origin))
	wantFail(t, err, auth.ReasonExpiredChallenge)
}

func TestSignatureProblems(t *testing.T) {
	e := newEnv(t)
	other := testutil.NewDevice(t)
	otherClient := protocol.NewID()
	cases := map[string]func(n string) []byte{
		"another key": func(n string) []byte {
			nb, _ := base64.StdEncoding.DecodeString(n)
			return other.Sign(auth.Message(nb, e.client.ID, e.cred.ID, origin))
		},
		"another relay": func(n string) []byte { return e.sign(n, e.client.ID, e.cred.ID, "wss://evil.example.com") },
		"another nonce": func(n string) []byte {
			return e.sign(base64.StdEncoding.EncodeToString(make([]byte, 32)), e.client.ID, e.cred.ID, origin)
		},
		"another client id":  func(n string) []byte { return e.sign(n, otherClient, e.cred.ID, origin) },
		"another credential": func(n string) []byte { return e.sign(n, e.client.ID, protocol.NewID(), origin) },
		"no domain prefix": func(n string) []byte {
			nb, _ := base64.StdEncoding.DecodeString(n)
			return e.key.Sign(append(append(append(append([]byte{}, nb...), e.client.ID...), e.cred.ID...), origin...))
		},
		"a device-handshake signature": func(n string) []byte {
			nb, _ := base64.StdEncoding.DecodeString(n)
			return e.key.Sign(protocol.AuthMessage(nb, strings.Repeat("a", 64), origin))
		},
		"empty":     func(string) []byte { return nil },
		"truncated": func(n string) []byte { return e.sign(n, e.client.ID, e.cred.ID, origin)[:20] },
	}
	for name, mk := range cases {
		n, _, _ := e.a.NewChallenge(e.client.ID)
		_, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, mk(n))
		if !errors.Is(err, auth.ErrUnauthorized) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAChallengeForOneClientCannotBeUsedByAnother(t *testing.T) {
	e := newEnv(t)
	// A second, legitimate client with its own key.
	key2 := testutil.NewDevice(t)
	code, _ := clients.NewCode()
	_ = e.store.IssueCode(ctx, clients.PairingCode{ID: protocol.NewID(), CodeHash: clients.HashCode(code), CreatedBy: "t", CreatedAt: e.clk.now(), ExpiresAt: e.clk.now().Add(time.Hour)})
	cl2, cr2, _ := e.store.Redeem(ctx, clients.HashCode(code), "second", key2.SPKI, e.clk.now())

	n, _, _ := e.a.NewChallenge(e.client.ID) // issued to client 1
	nb, _ := base64.StdEncoding.DecodeString(n)
	sig := key2.Sign(auth.Message(nb, cl2.ID, cr2.ID, origin)) // client 2 signs it correctly for itself
	_, _, err := e.a.Exchange(ctx, cl2.ID, cr2.ID, n, sig)
	wantFail(t, err, auth.ReasonWrongClient)
}

func TestCredentialsOfOtherClientsAndUnknownOnesAreRejected(t *testing.T) {
	e := newEnv(t)
	n, _, _ := e.a.NewChallenge(e.client.ID)
	_, _, err := e.a.Exchange(ctx, e.client.ID, protocol.NewID(), n, e.sign(n, e.client.ID, e.cred.ID, origin))
	wantFail(t, err, auth.ReasonUnknownCredential)

	// Unknown client id: indistinguishable at the surface from a bad signature.
	ghost := protocol.NewID()
	n, _, err = e.a.NewChallenge(ghost)
	if err != nil {
		t.Fatalf("challenge for an unknown client must look like any other: %v", err)
	}
	_, _, err = e.a.Exchange(ctx, ghost, e.cred.ID, n, nil)
	if !errors.Is(err, auth.ErrUnauthorized) || err.Error() != "unauthorized" {
		t.Fatalf("%v", err)
	}
}

func TestRevokedAndExpiredCredentials(t *testing.T) {
	e := newEnv(t)
	short := clients.Credential{ID: protocol.NewID(), ClientID: e.client.ID, PublicKey: e.key.SPKI, CreatedAt: e.clk.now(), ExpiresAt: e.clk.now().Add(time.Hour)}
	if err := e.store.AddCredential(ctx, short); err != nil {
		t.Fatal(err)
	}
	try := func(credID string) error {
		n, _, _ := e.a.NewChallenge(e.client.ID)
		_, _, err := e.a.Exchange(ctx, e.client.ID, credID, n, e.sign(n, e.client.ID, credID, origin))
		return err
	}
	if err := try(short.ID); err != nil {
		t.Fatal(err)
	}
	e.clk.advance(2 * time.Hour)
	wantFail(t, try(short.ID), auth.ReasonCredentialUnusable) // expired
	if err := try(e.cred.ID); err != nil {                    // the other credential is unaffected
		t.Fatal(err)
	}
	_ = e.store.RevokeCredential(ctx, e.client.ID, e.cred.ID, e.clk.now())
	wantFail(t, try(e.cred.ID), auth.ReasonCredentialUnusable) // revoked
}

func TestRevokingTheClientEndsEverythingImmediately(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	if _, err := e.a.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	// Revoked only in the store (e.g. by another process): the very next request must still fail.
	_ = e.store.RevokeClient(ctx, e.client.ID, e.clk.now())
	_, err := e.a.Verify(ctx, tok)
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("a revoked client's token still works: %v", err)
	}
	n, _, _ := e.a.NewChallenge(e.client.ID)
	_, _, err = e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, e.sign(n, e.client.ID, e.cred.ID, origin))
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("a revoked client can log in: %v", err)
	}
}

func TestRevokeClientPurgesTokens(t *testing.T) {
	e := newEnv(t)
	a, b := e.login(), e.login()
	e.a.RevokeClient(e.client.ID)
	for _, tok := range []string{a, b} {
		if _, err := e.a.Verify(ctx, tok); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatalf("token survived RevokeClient: %v", err)
		}
	}
}

func TestRevokingACredentialKillsOnlyItsTokens(t *testing.T) {
	e := newEnv(t)
	second := clients.Credential{ID: protocol.NewID(), ClientID: e.client.ID, PublicKey: e.key.SPKI, CreatedAt: e.clk.now(), ExpiresAt: e.clk.now().Add(24 * time.Hour)}
	_ = e.store.AddCredential(ctx, second)
	tokOld := e.login()
	n, _, _ := e.a.NewChallenge(e.client.ID)
	tokNew, _, err := e.a.Exchange(ctx, e.client.ID, second.ID, n, e.sign(n, e.client.ID, second.ID, origin))
	if err != nil {
		t.Fatal(err)
	}
	// Rotation: the old credential is revoked after the new one works.
	_ = e.store.RevokeCredential(ctx, e.client.ID, e.cred.ID, e.clk.now())
	if _, err := e.a.Verify(ctx, tokOld); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("token of a revoked credential still works: %v", err)
	}
	if p, err := e.a.Verify(ctx, tokNew); err != nil || p.CredentialID != second.ID {
		t.Fatalf("token of the surviving credential broke: %v", err)
	}
}

func TestTokensExpire(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	e.clk.advance(9 * time.Minute)
	if _, err := e.a.Verify(ctx, tok); err != nil {
		t.Fatalf("token died early: %v", err)
	}
	e.clk.advance(2 * time.Minute)
	_, err := e.a.Verify(ctx, tok)
	wantFail(t, err, auth.ReasonBadToken)
}

func TestTokenCapPerClientEvictsTheOldest(t *testing.T) {
	e := newEnv(t)
	var toks []string
	for i := 0; i < auth.MaxTokensPerClient+3; i++ {
		toks = append(toks, e.login())
	}
	for i, tok := range toks {
		_, err := e.a.Verify(ctx, tok)
		if i < 3 && err == nil {
			t.Errorf("token %d should have been evicted", i)
		}
		if i >= 3 && err != nil {
			t.Errorf("token %d should still work: %v", i, err)
		}
	}
}

func TestChallengeCapRecoversAfterExpiry(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < auth.MaxChallenges; i++ {
		if _, _, err := e.a.NewChallenge(e.client.ID); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	if _, _, err := e.a.NewChallenge(e.client.ID); !errors.Is(err, auth.ErrBusy) {
		t.Fatalf("cap not enforced: %v", err)
	}
	e.clk.advance(auth.ChallengeTTL + time.Second)
	if _, _, err := e.a.NewChallenge(e.client.ID); err != nil {
		t.Fatalf("expired challenges were not reclaimed: %v", err)
	}
}

func TestMalformedClientIDsAreRefusedAtTheDoor(t *testing.T) {
	e := newEnv(t)
	for _, bad := range []string{"", "x", "../../etc", strings.Repeat("a", 500), "00000000-0000-0000-0000-00000000000g"} {
		if _, _, err := e.a.NewChallenge(bad); !errors.Is(err, auth.ErrBadInput) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestGarbageBearerTokens(t *testing.T) {
	e := newEnv(t)
	real := e.login()
	for name, tok := range map[string]string{
		"empty": "", "no prefix": real[4:], "wrong token": "avt_" + strings.Repeat("A", 43), "just the prefix": "avt_",
		"huge": "avt_" + strings.Repeat("A", 5000), "modified last char": real[:len(real)-1] + "x", "upper-cased": strings.ToUpper(real),
	} {
		if _, err := e.a.Verify(ctx, tok); !errors.Is(err, auth.ErrUnauthorized) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestChallengeLookupIsCaseSafeForIDs(t *testing.T) {
	e := newEnv(t)
	n, _, _ := e.a.NewChallenge(strings.ToUpper(e.client.ID))
	// The signature is over the canonical (lower-case) ids, as clients always send them.
	if _, _, err := e.a.Exchange(ctx, strings.ToUpper(e.client.ID), strings.ToUpper(e.cred.ID), n, e.sign(n, e.client.ID, e.cred.ID, origin)); err != nil {
		t.Fatalf("upper-case ids should be treated as the same ids: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// audience-bound (OAuth) tokens

func TestAudienceBoundTokenNeedsNoCredentialButIsBoundToItsResource(t *testing.T) {
	e := newEnv(t)
	oc, err := e.store.CreateOAuthClient(ctx, "oauth: x", nil, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	tok, exp, err := e.a.IssueForResource(ctx, oc.ID, "https://relay.example.com/mcp")
	if err != nil || !strings.HasPrefix(tok, auth.TokenPrefix) || !exp.After(e.clk.now()) {
		t.Fatalf("%q %v %v", tok, exp, err)
	}
	p, err := e.a.Verify(ctx, tok)
	if err != nil || p.ClientID != oc.ID || p.Audience != "https://relay.example.com/mcp" || p.CredentialID != "" {
		t.Fatalf("%+v %v", p, err)
	}
	// a key-login token has no audience
	n, _, _ := e.a.NewChallenge(e.client.ID)
	nb, _ := base64.StdEncoding.DecodeString(n)
	login, _, err := e.a.Exchange(ctx, e.client.ID, e.cred.ID, n, e.key.Sign(auth.Message(nb, e.client.ID, e.cred.ID, origin)))
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := e.a.Verify(ctx, login); p.Audience != "" {
		t.Errorf("key-login token has audience %q", p.Audience)
	}
}

func TestAudienceBoundTokenDiesWithItsClient(t *testing.T) {
	e := newEnv(t)
	oc, _ := e.store.CreateOAuthClient(ctx, "oauth: x", nil, e.clk.now())
	tok, _, _ := e.a.IssueForResource(ctx, oc.ID, "https://relay.example.com/mcp")
	if err := e.store.RevokeClient(ctx, oc.ID, e.clk.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.Verify(ctx, tok); !errors.Is(err, auth.ErrUnauthorized) || auth.ReasonOf(err) != auth.ReasonClientInactive {
		t.Fatalf("revoked client's OAuth token: %v", err)
	}
	if _, _, err := e.a.IssueForResource(ctx, oc.ID, "https://relay.example.com/mcp"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("issued a token for a revoked client: %v", err)
	}
}

func TestIssueForResourceRefusesBadInput(t *testing.T) {
	e := newEnv(t)
	oc, _ := e.store.CreateOAuthClient(ctx, "oauth: x", nil, e.clk.now())
	if _, _, err := e.a.IssueForResource(ctx, oc.ID, ""); !errors.Is(err, auth.ErrBadInput) {
		t.Errorf("empty audience: %v", err)
	}
	if _, _, err := e.a.IssueForResource(ctx, "not-a-uuid", "r"); !errors.Is(err, auth.ErrBadInput) {
		t.Errorf("malformed client id: %v", err)
	}
	if _, _, err := e.a.IssueForResource(ctx, protocol.NewID(), "r"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("unknown client: %v", err)
	}
}

func TestAudienceBoundTokenExpiresAndRevokeClientDropsIt(t *testing.T) {
	e := newEnv(t)
	oc, _ := e.store.CreateOAuthClient(ctx, "oauth: x", nil, e.clk.now())
	tok, _, _ := e.a.IssueForResource(ctx, oc.ID, "r")
	e.a.RevokeClient(oc.ID)
	if _, err := e.a.Verify(ctx, tok); !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("RevokeClient left an OAuth token alive: %v", err)
	}
	tok, _, _ = e.a.IssueForResource(ctx, oc.ID, "r")
	e.clk.advance(11 * time.Minute)
	if _, err := e.a.Verify(ctx, tok); !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expired OAuth token accepted: %v", err)
	}
}
