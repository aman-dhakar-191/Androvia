package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store on PostgreSQL (migration 0003).
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) CreateApp(ctx context.Context, a App) error {
	uris, err := json.Marshal(a.RedirectURIs)
	if err != nil {
		return err
	}
	// The count and the insert are one statement, so concurrent registrations cannot overshoot the cap by much more than
	// the number of racing requests; the per-IP rate limit bounds those.
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_clients (id, name, redirect_uris, created_at)
		 SELECT $1, $2, $3::jsonb, $4 WHERE (SELECT count(*) FROM oauth_clients) < $5`,
		a.ID, a.Name, string(uris), a.CreatedAt.UTC(), MaxApps)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTooMany
	}
	return nil
}

func (s *PostgresStore) GetApp(ctx context.Context, id string) (App, error) {
	var a App
	var uris string
	err := s.pool.QueryRow(ctx, `SELECT id, name, redirect_uris::text, created_at FROM oauth_clients WHERE id = $1`, id).
		Scan(&a.ID, &a.Name, &uris, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return App{}, ErrNotFound
	}
	if err != nil {
		return App{}, err
	}
	if err := json.Unmarshal([]byte(uris), &a.RedirectURIs); err != nil {
		return App{}, err
	}
	return a, nil
}

func (s *PostgresStore) SaveRefresh(ctx context.Context, r Refresh) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_refresh_tokens (token_hash, family_id, oauth_client_id, subject_client_id, resource, created_at, expires_at, family_expires_at)
		 VALUES ($1, $2, $3, $4::text::uuid, $5, $6, $7, $8)`,
		r.Hash[:], r.FamilyID, r.AppID, r.SubjectClientID, r.Resource, r.CreatedAt.UTC(), r.ExpiresAt.UTC(), r.FamilyExpiresAt.UTC())
	return err
}

func (s *PostgresStore) UseRefresh(ctx context.Context, h [32]byte, now time.Time) (Refresh, error) {
	now = now.UTC()
	r := Refresh{Hash: h}
	// One UPDATE makes a refresh token work once, even under concurrent attempts.
	err := s.pool.QueryRow(ctx,
		`UPDATE oauth_refresh_tokens SET used_at = $2
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2 AND family_expires_at > $2
		 RETURNING family_id, oauth_client_id, subject_client_id::text, resource, created_at, expires_at, family_expires_at`,
		h[:], now).Scan(&r.FamilyID, &r.AppID, &r.SubjectClientID, &r.Resource, &r.CreatedAt, &r.ExpiresAt, &r.FamilyExpiresAt)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Refresh{}, err
	}
	// Nothing was consumed: either it never existed / expired, or it was already used.
	var used *time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT family_id, oauth_client_id, subject_client_id::text, resource, created_at, expires_at, family_expires_at, used_at
		 FROM oauth_refresh_tokens WHERE token_hash = $1`, h[:]).
		Scan(&r.FamilyID, &r.AppID, &r.SubjectClientID, &r.Resource, &r.CreatedAt, &r.ExpiresAt, &r.FamilyExpiresAt, &used)
	if errors.Is(err, pgx.ErrNoRows) {
		return Refresh{}, ErrNotFound
	}
	if err != nil {
		return Refresh{}, err
	}
	if used != nil {
		return r, ErrReused
	}
	return Refresh{}, ErrNotFound
}

func (s *PostgresStore) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE family_id = $1`, familyID)
	return err
}

func (s *PostgresStore) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE expires_at <= $1 OR family_expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
