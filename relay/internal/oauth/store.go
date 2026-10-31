package oauth

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// MaxApps bounds open client registration: the endpoint is reachable by anyone, so the table must not grow without limit.
	MaxApps = 200

	RefreshTTL       = 30 * 24 * time.Hour // a refresh token is valid this long...
	RefreshFamilyTTL = 90 * 24 * time.Hour // ...but a connection must be re-approved by the owner after this long
)

var (
	ErrNotFound = errors.New("not found")
	ErrTooMany  = errors.New("too many registered applications")
	// ErrReused means a refresh token that was already used was presented again: someone holds a copy.
	ErrReused = errors.New("refresh token reused")
)

// App is a registered OAuth application (an MCP host). Public client: there is no client secret.
type App struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
}

// Refresh is a stored refresh token (by hash only).
type Refresh struct {
	Hash            [32]byte
	FamilyID        string
	AppID           string
	SubjectClientID string // the Androvia client (and its grants) the owner approved
	Resource        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	FamilyExpiresAt time.Time
}

// Store persists registered applications and refresh tokens. Implementations must be safe for concurrent use.
type Store interface {
	CreateApp(ctx context.Context, a App) error // ErrTooMany when MaxApps is reached
	GetApp(ctx context.Context, id string) (App, error)
	SaveRefresh(ctx context.Context, r Refresh) error
	// UseRefresh consumes a refresh token exactly once, even under concurrent attempts. ErrNotFound if it is unknown or
	// expired; ErrReused (with the record) if it was already used.
	UseRefresh(ctx context.Context, hash [32]byte, now time.Time) (Refresh, error)
	// RevokeFamily deletes every refresh token of the family.
	RevokeFamily(ctx context.Context, familyID string) error
	PurgeExpired(ctx context.Context, now time.Time) (int64, error)
}

// MemoryStore is for tests.
type MemoryStore struct {
	mu      sync.Mutex
	apps    map[string]App
	refresh map[[32]byte]*memRefresh
}

type memRefresh struct {
	Refresh
	used bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{apps: map[string]App{}, refresh: map[[32]byte]*memRefresh{}}
}

func (s *MemoryStore) CreateApp(_ context.Context, a App) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.apps) >= MaxApps {
		return ErrTooMany
	}
	a.RedirectURIs = append([]string(nil), a.RedirectURIs...)
	s.apps[a.ID] = a
	return nil
}

func (s *MemoryStore) GetApp(_ context.Context, id string) (App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[id]
	if !ok {
		return App{}, ErrNotFound
	}
	a.RedirectURIs = append([]string(nil), a.RedirectURIs...)
	return a, nil
}

func (s *MemoryStore) SaveRefresh(_ context.Context, r Refresh) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[r.Hash] = &memRefresh{Refresh: r}
	return nil
}

func (s *MemoryStore) UseRefresh(_ context.Context, h [32]byte, now time.Time) (Refresh, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refresh[h]
	if !ok {
		return Refresh{}, ErrNotFound
	}
	if r.used {
		return r.Refresh, ErrReused
	}
	if !now.Before(r.ExpiresAt) || !now.Before(r.FamilyExpiresAt) {
		return Refresh{}, ErrNotFound
	}
	r.used = true
	return r.Refresh, nil
}

func (s *MemoryStore) RevokeFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, r := range s.refresh {
		if r.FamilyID == familyID {
			delete(s.refresh, h)
		}
	}
	return nil
}

func (s *MemoryStore) PurgeExpired(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for h, r := range s.refresh {
		if !now.Before(r.ExpiresAt) || !now.Before(r.FamilyExpiresAt) {
			delete(s.refresh, h)
			n++
		}
	}
	return n, nil
}
