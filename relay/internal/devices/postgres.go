package devices

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists devices in PostgreSQL (schema: migrations/0001_devices.sql).
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

const cols = "id, label, public_key, status, created_at, last_seen_at"

func scan(row pgx.Row) (Device, error) {
	var d Device
	var st string
	if err := row.Scan(&d.ID, &d.Label, &d.PublicKey, &st, &d.CreatedAt, &d.LastSeenAt); err != nil {
		return Device{}, err
	}
	d.Status = Status(st)
	return d, nil
}

func (s *PostgresStore) Create(ctx context.Context, d Device) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO devices (id, label, public_key, status, created_at) VALUES ($1,$2,$3,$4,$5)`,
		d.ID, d.Label, d.PublicKey, string(d.Status), d.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrExists
	}
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Device, error) {
	d, err := scan(s.pool.QueryRow(ctx, `SELECT `+cols+` FROM devices WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return d, err
}

func (s *PostgresStore) List(ctx context.Context) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM devices ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Revoke(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET status='revoked' WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) TouchLastSeen(ctx context.Context, id string, t time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET last_seen_at=$2 WHERE id=$1`, id, t.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
