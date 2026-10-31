package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore keeps the audit log in audit_events (migrations/0002_clients_audit.sql).
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) Append(ctx context.Context, e Event) error {
	d, err := detailJSON(e.Detail)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_events (at, actor_type, actor_id, device_id, action, outcome, request_id, detail)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
		e.At.UTC(), e.ActorType, e.ActorID, e.DeviceID, e.Action, string(e.Outcome), e.RequestID, d)
	return err
}

func (s *PostgresStore) List(ctx context.Context, limit int, beforeID int64) ([]Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, at, actor_type, actor_id, device_id, action, outcome, request_id, detail::text
		 FROM audit_events WHERE ($2::bigint = 0 OR id < $2) ORDER BY id DESC LIMIT $1`, limit, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var oc, d string
		if err := rows.Scan(&e.ID, &e.At, &e.ActorType, &e.ActorID, &e.DeviceID, &e.Action, &oc, &e.RequestID, &d); err != nil {
			return nil, err
		}
		e.Outcome = Outcome(oc)
		if err := json.Unmarshal([]byte(d), &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Purge(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE at < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
