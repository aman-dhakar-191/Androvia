// Package devices holds device registration records and the stores that persist them.
package devices

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/keys"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

var (
	ErrNotFound = errors.New("device not found")
	ErrExists   = errors.New("device already registered")
)

type Device struct {
	ID         string // hex SHA-256 of PublicKey (SPKI DER)
	Label      string
	PublicKey  []byte // X.509 SubjectPublicKeyInfo DER, EC P-256
	Status     Status
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

// New validates the inputs and derives the device id from the key, so an id cannot be claimed without the key.
func New(label string, spki []byte, now time.Time) (Device, error) {
	if err := keys.ValidLabel(label); err != nil {
		return Device{}, err
	}
	if _, err := keys.ParseP256(spki); err != nil {
		return Device{}, err
	}
	return Device{
		ID: keys.ID(spki), Label: label, PublicKey: append([]byte(nil), spki...),
		Status: StatusActive, CreatedAt: now.UTC(),
	}, nil
}

// Verify checks an ASN.1 DER ECDSA/SHA-256 signature over msg with the device key.
func (d Device) Verify(msg, sig []byte) bool { return keys.Verify(d.PublicKey, msg, sig) }

// Store persists devices. Implementations must be safe for concurrent use.
type Store interface {
	Create(ctx context.Context, d Device) error // ErrExists if the id is taken
	Get(ctx context.Context, id string) (Device, error)
	List(ctx context.Context) ([]Device, error)
	Revoke(ctx context.Context, id string) error // idempotent; ErrNotFound if unknown
	TouchLastSeen(ctx context.Context, id string, t time.Time) error
}

// MemoryStore is for tests and local experiments; the relay binary only uses PostgreSQL.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]Device
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]Device{}} }

func (s *MemoryStore) Create(_ context.Context, d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[d.ID]; ok {
		return ErrExists
	}
	s.m[d.ID] = d
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[id]
	if !ok {
		return Device{}, ErrNotFound
	}
	return d, nil
}

func (s *MemoryStore) List(_ context.Context) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, 0, len(s.m))
	for _, d := range s.m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[id]
	if !ok {
		return ErrNotFound
	}
	d.Status = StatusRevoked
	s.m[id] = d
	return nil
}

func (s *MemoryStore) TouchLastSeen(_ context.Context, id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.m[id]
	if !ok {
		return ErrNotFound
	}
	t = t.UTC()
	d.LastSeenAt = &t
	s.m[id] = d
	return nil
}
