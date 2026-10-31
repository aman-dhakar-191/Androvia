// Package auth authenticates API clients without shared secrets.
//
//  1. The client asks for a challenge (a random nonce, valid 60 s, usable once, bound to that client id).
//  2. It signs prefix || nonce || clientID || credentialID || relayOrigin with its EC P-256 key and sends the signature.
//  3. If it verifies against a usable credential of an active client, the relay issues a short-lived bearer token.
//
// The bearer token is what REST (and later MCP) requests carry. Tokens live in memory only and are checked against the
// client and credential records on every use, so revoking a client or credential takes effect on the very next request.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
)

const (
	ChallengeTTL       = 60 * time.Second
	DefaultTokenTTL    = 10 * time.Minute
	MaxChallenges      = 2000
	MaxTokens          = 10000
	MaxTokensPerClient = 20
	TokenPrefix        = "avt_"
	// SignaturePrefix domain-separates client signatures from device handshake signatures.
	SignaturePrefix = "androvia/client-auth/v1\x00"
)

var (
	// ErrUnauthorized is the only thing a caller ever learns about a failed authentication.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrBusy means too many challenges or tokens are outstanding.
	ErrBusy = errors.New("busy")
	// ErrBadInput is for malformed identifiers (format errors reveal nothing about which clients exist).
	ErrBadInput = errors.New("bad input")
)

// Reason says why an authentication failed. It is for the audit log only and must never be shown to the caller.
type Reason string

const (
	ReasonUnknownChallenge   Reason = "unknown_challenge"
	ReasonExpiredChallenge   Reason = "expired_challenge"
	ReasonWrongClient        Reason = "challenge_for_other_client"
	ReasonUnknownCredential  Reason = "unknown_credential"
	ReasonCredentialUnusable Reason = "credential_revoked_or_expired"
	ReasonClientInactive     Reason = "client_revoked"
	ReasonBadSignature       Reason = "bad_signature"
	ReasonBadToken           Reason = "bad_token"
	ReasonTokenExpired       Reason = "token_expired"
)

// Failure is a failed authentication. errors.Is(err, ErrUnauthorized) is true for every Failure.
type Failure struct{ Reason Reason }

func (f *Failure) Error() string        { return "unauthorized" }
func (f *Failure) Is(target error) bool { return target == ErrUnauthorized }

// ReasonOf extracts the audit reason from an error ("" if it is not a Failure).
func ReasonOf(err error) Reason {
	var f *Failure
	if errors.As(err, &f) {
		return f.Reason
	}
	return ""
}

type Principal struct {
	ClientID     string
	CredentialID string
	Expires      time.Time // when the access token stops working
}

// Message is exactly what a client signs. nonce, clientID and credentialID have fixed lengths (32 bytes, 36 and 36
// ASCII characters), so the concatenation is unambiguous. origin is the relay's public origin as the client configured it.
func Message(nonce []byte, clientID, credentialID, origin string) []byte {
	m := make([]byte, 0, len(SignaturePrefix)+len(nonce)+len(clientID)+len(credentialID)+len(origin))
	m = append(m, SignaturePrefix...)
	m = append(m, nonce...)
	m = append(m, clientID...)
	m = append(m, credentialID...)
	m = append(m, origin...)
	return m
}

type challenge struct {
	clientID string
	expires  time.Time
}

type tokenRec struct {
	clientID, credentialID string
	expires                time.Time
}

type Authenticator struct {
	store    clients.Store
	origin   string
	tokenTTL time.Duration
	now      func() time.Time

	mu         sync.Mutex
	challenges map[string]challenge // by nonce (base64)
	tokens     map[[32]byte]tokenRec
	order      map[string][][32]byte // per client, oldest first
}

// New creates an authenticator. origin must equal the relay's RELAY_PUBLIC_ORIGIN; clients sign it.
func New(store clients.Store, origin string, tokenTTL time.Duration, now func() time.Time) *Authenticator {
	if now == nil {
		now = time.Now
	}
	if tokenTTL <= 0 {
		tokenTTL = DefaultTokenTTL
	}
	return &Authenticator{
		store: store, origin: origin, tokenTTL: tokenTTL, now: now,
		challenges: map[string]challenge{}, tokens: map[[32]byte]tokenRec{}, order: map[string][][32]byte{},
	}
}

// NewChallenge issues a nonce for clientID. It answers the same way for unknown and revoked clients, so it cannot be
// used to find out which client ids exist.
func (a *Authenticator) NewChallenge(clientID string) (nonce string, expires time.Time, err error) {
	if !protocol.ValidID(clientID) {
		return "", time.Time{}, ErrBadInput
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	nonce = base64.StdEncoding.EncodeToString(b)
	now := a.now()
	expires = now.Add(ChallengeTTL)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.challenges) >= MaxChallenges {
		for k, c := range a.challenges {
			if !now.Before(c.expires) {
				delete(a.challenges, k)
			}
		}
		if len(a.challenges) >= MaxChallenges {
			return "", time.Time{}, ErrBusy
		}
	}
	a.challenges[nonce] = challenge{clientID: strings.ToLower(clientID), expires: expires}
	return nonce, expires, nil
}

// Exchange verifies a signed challenge and issues a token. The challenge is consumed first, whatever happens next, so a
// recorded exchange can never be replayed.
func (a *Authenticator) Exchange(ctx context.Context, clientID, credentialID, nonce string, sig []byte) (string, time.Time, error) {
	clientID, credentialID = strings.ToLower(clientID), strings.ToLower(credentialID)
	a.mu.Lock()
	ch, ok := a.challenges[nonce]
	delete(a.challenges, nonce)
	a.mu.Unlock()

	now := a.now()
	switch {
	case !ok:
		return "", time.Time{}, &Failure{ReasonUnknownChallenge}
	case !now.Before(ch.expires):
		return "", time.Time{}, &Failure{ReasonExpiredChallenge}
	case ch.clientID != clientID:
		return "", time.Time{}, &Failure{ReasonWrongClient}
	}
	nb, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil || len(nb) != 32 {
		return "", time.Time{}, &Failure{ReasonUnknownChallenge}
	}

	cred, err := a.store.GetCredential(ctx, credentialID)
	if errors.Is(err, clients.ErrNotFound) || (err == nil && cred.ClientID != clientID) {
		return "", time.Time{}, &Failure{ReasonUnknownCredential}
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if !cred.Usable(now) {
		return "", time.Time{}, &Failure{ReasonCredentialUnusable}
	}
	cl, err := a.store.GetClient(ctx, clientID)
	if errors.Is(err, clients.ErrNotFound) || (err == nil && cl.Status != clients.StatusActive) {
		return "", time.Time{}, &Failure{ReasonClientInactive}
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if !cred.Verify(Message(nb, clientID, credentialID, a.origin), sig) {
		return "", time.Time{}, &Failure{ReasonBadSignature}
	}
	return a.issue(clientID, credentialID, now)
}

func (a *Authenticator) issue(clientID, credentialID string, now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	exp := now.Add(a.tokenTTL)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropExpiredLocked(clientID, now)
	if len(a.tokens) >= MaxTokens {
		return "", time.Time{}, ErrBusy
	}
	for len(a.order[clientID]) >= MaxTokensPerClient { // evict the oldest
		old := a.order[clientID][0]
		a.order[clientID] = a.order[clientID][1:]
		delete(a.tokens, old)
	}
	a.tokens[h] = tokenRec{clientID: clientID, credentialID: credentialID, expires: exp}
	a.order[clientID] = append(a.order[clientID], h)
	return token, exp, nil
}

func (a *Authenticator) dropExpiredLocked(clientID string, now time.Time) {
	kept := a.order[clientID][:0]
	for _, h := range a.order[clientID] {
		if t, ok := a.tokens[h]; ok && now.Before(t.expires) {
			kept = append(kept, h)
		} else {
			delete(a.tokens, h)
		}
	}
	a.order[clientID] = kept
}

// Verify turns a bearer token into a Principal. It re-checks the client and credential records every time.
func (a *Authenticator) Verify(ctx context.Context, bearer string) (Principal, error) {
	if !strings.HasPrefix(bearer, TokenPrefix) || len(bearer) > 128 {
		return Principal{}, &Failure{ReasonBadToken}
	}
	h := sha256.Sum256([]byte(bearer))
	now := a.now()
	a.mu.Lock()
	rec, ok := a.tokens[h]
	if ok && !now.Before(rec.expires) {
		delete(a.tokens, h)
		ok = false
	}
	a.mu.Unlock()
	if !ok {
		return Principal{}, &Failure{ReasonBadToken}
	}
	cl, err := a.store.GetClient(ctx, rec.clientID)
	if errors.Is(err, clients.ErrNotFound) || (err == nil && cl.Status != clients.StatusActive) {
		a.RevokeClient(rec.clientID)
		return Principal{}, &Failure{ReasonClientInactive}
	}
	if err != nil {
		return Principal{}, err
	}
	cred, err := a.store.GetCredential(ctx, rec.credentialID)
	if errors.Is(err, clients.ErrNotFound) || (err == nil && !cred.Usable(now)) {
		a.RevokeCredential(rec.credentialID)
		return Principal{}, &Failure{ReasonCredentialUnusable}
	}
	if err != nil {
		return Principal{}, err
	}
	return Principal{ClientID: rec.clientID, CredentialID: rec.credentialID, Expires: rec.expires}, nil
}

// RevokeClient forgets every token of the client (call after revoking it in the store).
func (a *Authenticator) RevokeClient(clientID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, h := range a.order[clientID] {
		delete(a.tokens, h)
	}
	delete(a.order, clientID)
}

// RevokeCredential forgets every token issued under the credential.
func (a *Authenticator) RevokeCredential(credentialID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for h, t := range a.tokens {
		if t.credentialID == credentialID {
			delete(a.tokens, h)
		}
	}
}
