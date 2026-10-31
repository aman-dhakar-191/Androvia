// Package clients holds client identities (agents, scripts, apps that call the relay), their credentials, the scope
// grants that say what they may do on which device, and the single-use pairing codes that create them.
package clients

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/keys"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

const (
	CredentialLifetime      = 365 * 24 * time.Hour
	MaxCredentialsPerClient = 5
	MaxGrantsPerCode        = 32
)

var (
	ErrNotFound        = errors.New("not found")
	ErrCodeInvalid     = errors.New("pairing code is invalid, expired or already used") // one error for all three, on purpose
	ErrCredentialLimit = errors.New("too many active credentials")
)

type Client struct {
	ID        string
	Label     string
	Status    Status
	CreatedAt time.Time
	RevokedAt *time.Time
}

type Credential struct {
	ID        string
	ClientID  string
	PublicKey []byte // X.509 SubjectPublicKeyInfo DER, EC P-256
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Usable reports whether the credential may authenticate at time now.
func (c Credential) Usable(now time.Time) bool { return c.RevokedAt == nil && now.Before(c.ExpiresAt) }

func (c Credential) Verify(msg, sig []byte) bool { return keys.Verify(c.PublicKey, msg, sig) }

type Grant struct {
	DeviceID string   `json:"device_id"`
	Scopes   []string `json:"scopes"`
}

type PairingCode struct {
	ID        string
	CodeHash  [32]byte
	Grants    []Grant
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewCode returns a fresh pairing code: 128 random bits, shown once, grouped for readability.
func NewCode() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]) // 26 chars
	return s[0:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20] + "-" + s[20:], nil
}

// HashCode normalises user input (case, dashes, spaces) and hashes it; only the hash is ever stored.
func HashCode(code string) [32]byte {
	n := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	return sha256.Sum256([]byte(n))
}

// ValidateGrants normalises scopes and rejects duplicates, bad device ids and unknown scopes.
func ValidateGrants(in []Grant) ([]Grant, error) {
	if len(in) > MaxGrantsPerCode {
		return nil, errors.New("too many grants")
	}
	seen := map[string]bool{}
	out := make([]Grant, 0, len(in))
	for _, g := range in {
		if !protocol.ValidDeviceID(g.DeviceID) {
			return nil, errors.New("grant has an invalid device_id")
		}
		if seen[g.DeviceID] {
			return nil, errors.New("duplicate device_id in grants")
		}
		seen[g.DeviceID] = true
		sc, err := policy.NormalizeScopes(g.Scopes)
		if err != nil {
			return nil, err
		}
		if len(sc) == 0 {
			return nil, errors.New("a grant needs at least one scope")
		}
		out = append(out, Grant{DeviceID: g.DeviceID, Scopes: sc})
	}
	return out, nil
}

// Store persists clients. Implementations must be safe for concurrent use.
type Store interface {
	IssueCode(ctx context.Context, c PairingCode) error
	// Redeem atomically consumes the code and creates the client, its first credential and the code's grants.
	// A code can succeed at most once, even under concurrent attempts.
	Redeem(ctx context.Context, codeHash [32]byte, label string, spki []byte, now time.Time) (Client, Credential, error)

	// CreateOAuthClient creates a client with the given grants and NO credential: it is reached only through an OAuth
	// authorization the owner approved (internal/oauth). All of it happens or none of it does. ErrNotFound if a granted
	// device does not exist.
	CreateOAuthClient(ctx context.Context, label string, grants []Grant, now time.Time) (Client, error)

	GetClient(ctx context.Context, id string) (Client, error)
	ListClients(ctx context.Context) ([]Client, error)
	// RevokeClient revokes the client and all its credentials. Idempotent; ErrNotFound if unknown.
	RevokeClient(ctx context.Context, id string, now time.Time) error

	GetCredential(ctx context.Context, id string) (Credential, error)
	// Credentials lists all of a client's credentials, including revoked and expired ones, oldest first.
	Credentials(ctx context.Context, clientID string) ([]Credential, error)
	// AddCredential adds a key (rotation). ErrCredentialLimit if the client already has MaxCredentialsPerClient usable keys.
	AddCredential(ctx context.Context, c Credential) error
	RevokeCredential(ctx context.Context, clientID, credentialID string, now time.Time) error

	Grants(ctx context.Context, clientID string) ([]Grant, error)
	ScopesFor(ctx context.Context, clientID, deviceID string) ([]string, error) // implements policy.Source
	// SetGrant replaces the scopes for (client, device); empty scopes removes the grant.
	SetGrant(ctx context.Context, clientID, deviceID string, scopes []string, now time.Time) error
}

// ---------------------------------------------------------------------------------------------------------------------

// MemoryStore is for tests; the relay binary uses PostgreSQL.
type MemoryStore struct {
	mu      sync.Mutex
	clients map[string]Client
	creds   map[string]Credential
	grants  map[string]map[string][]string // client -> device -> scopes
	codes   map[[32]byte]*memCode
	devices func(string) bool // optional: does the device exist (mirrors the foreign key)
}

type memCode struct {
	PairingCode
	redeemed bool
}

// NewMemoryStore creates a store; deviceExists (may be nil) mirrors the foreign key to devices.
func NewMemoryStore(deviceExists func(string) bool) *MemoryStore {
	return &MemoryStore{
		clients: map[string]Client{}, creds: map[string]Credential{},
		grants: map[string]map[string][]string{}, codes: map[[32]byte]*memCode{}, devices: deviceExists,
	}
}

func (s *MemoryStore) CreateOAuthClient(_ context.Context, label string, grants []Grant, now time.Time) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devices != nil {
		for _, g := range grants {
			if !s.devices(g.DeviceID) {
				return Client{}, ErrNotFound
			}
		}
	}
	cl := Client{ID: protocol.NewID(), Label: label, Status: StatusActive, CreatedAt: now.UTC()}
	s.clients[cl.ID] = cl
	s.grants[cl.ID] = map[string][]string{}
	for _, g := range grants {
		s.grants[cl.ID][g.DeviceID] = append([]string(nil), g.Scopes...)
	}
	return cl, nil
}

func (s *MemoryStore) IssueCode(_ context.Context, c PairingCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.CodeHash] = &memCode{PairingCode: c}
	return nil
}

func (s *MemoryStore) Redeem(_ context.Context, h [32]byte, label string, spki []byte, now time.Time) (Client, Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[h]
	if !ok || c.redeemed || !now.Before(c.ExpiresAt) {
		return Client{}, Credential{}, ErrCodeInvalid
	}
	if s.devices != nil {
		for _, g := range c.Grants {
			if !s.devices(g.DeviceID) {
				return Client{}, Credential{}, ErrCodeInvalid
			}
		}
	}
	c.redeemed = true
	cl := Client{ID: protocol.NewID(), Label: label, Status: StatusActive, CreatedAt: now.UTC()}
	cr := Credential{ID: protocol.NewID(), ClientID: cl.ID, PublicKey: append([]byte(nil), spki...), CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(CredentialLifetime)}
	s.clients[cl.ID] = cl
	s.creds[cr.ID] = cr
	s.grants[cl.ID] = map[string][]string{}
	for _, g := range c.Grants {
		s.grants[cl.ID][g.DeviceID] = append([]string(nil), g.Scopes...)
	}
	return cl, cr, nil
}

func (s *MemoryStore) GetClient(_ context.Context, id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return c, nil
}

func (s *MemoryStore) ListClients(_ context.Context) ([]Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	sortClients(out)
	return out, nil
}

func (s *MemoryStore) RevokeClient(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return ErrNotFound
	}
	if c.Status != StatusRevoked {
		t := now.UTC()
		c.Status, c.RevokedAt = StatusRevoked, &t
		s.clients[id] = c
	}
	for k, cr := range s.creds {
		if cr.ClientID == id && cr.RevokedAt == nil {
			t := now.UTC()
			cr.RevokedAt = &t
			s.creds[k] = cr
		}
	}
	return nil
}

func (s *MemoryStore) GetCredential(_ context.Context, id string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[id]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c, nil
}

func (s *MemoryStore) Credentials(_ context.Context, clientID string) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return nil, ErrNotFound
	}
	var out []Credential
	for _, c := range s.creds {
		if c.ClientID == clientID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) AddCredential(_ context.Context, c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cl, ok := s.clients[c.ClientID]
	if !ok || cl.Status != StatusActive {
		return ErrNotFound
	}
	n := 0
	for _, x := range s.creds {
		if x.ClientID == c.ClientID && x.Usable(c.CreatedAt) {
			n++
		}
	}
	if n >= MaxCredentialsPerClient {
		return ErrCredentialLimit
	}
	s.creds[c.ID] = c
	return nil
}

func (s *MemoryStore) RevokeCredential(_ context.Context, clientID, credentialID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[credentialID]
	if !ok || c.ClientID != clientID {
		return ErrNotFound
	}
	if c.RevokedAt == nil {
		t := now.UTC()
		c.RevokedAt = &t
		s.creds[credentialID] = c
	}
	return nil
}

func (s *MemoryStore) Grants(_ context.Context, clientID string) ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return nil, ErrNotFound
	}
	var out []Grant
	for d, sc := range s.grants[clientID] {
		out = append(out, Grant{DeviceID: d, Scopes: append([]string(nil), sc...)})
	}
	sortGrants(out)
	return out, nil
}

func (s *MemoryStore) ScopesFor(_ context.Context, clientID, deviceID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.grants[clientID][deviceID]...), nil
}

func (s *MemoryStore) SetGrant(_ context.Context, clientID, deviceID string, scopes []string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return ErrNotFound
	}
	if s.devices != nil && !s.devices(deviceID) {
		return ErrNotFound
	}
	if s.grants[clientID] == nil {
		s.grants[clientID] = map[string][]string{}
	}
	if len(scopes) == 0 {
		delete(s.grants[clientID], deviceID)
		return nil
	}
	s.grants[clientID][deviceID] = append([]string(nil), scopes...)
	return nil
}
