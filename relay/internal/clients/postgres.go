package clients

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists clients (schema: migrations/0002_clients_audit.sql).
// Ids are passed as text and cast in SQL, and validated first, so a malformed id can never reach a cast error.
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

const (
	pgFKViolation = "23503"
	clientCols    = "id::text, label, status, created_at, revoked_at"
	credCols      = "id::text, client_id::text, public_key, created_at, expires_at, revoked_at"
)

func isPG(err error, code string) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == code
}

func (s *PostgresStore) IssueCode(ctx context.Context, c PairingCode) error {
	g, err := json.Marshal(c.Grants)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO pairing_codes (id, code_hash, grants, created_by, created_at, expires_at)
		 VALUES ($1::text::uuid, $2, $3::jsonb, $4, $5, $6)`,
		c.ID, c.CodeHash[:], string(g), c.CreatedBy, c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	return err
}

func (s *PostgresStore) Redeem(ctx context.Context, h [32]byte, label string, spki []byte, now time.Time) (Client, Credential, error) {
	now = now.UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Client{}, Credential{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// The single UPDATE is what makes a code work once, even under concurrent attempts.
	var codeID, grantsJSON string
	err = tx.QueryRow(ctx,
		`UPDATE pairing_codes SET redeemed_at = $2
		 WHERE code_hash = $1 AND redeemed_at IS NULL AND expires_at > $2
		 RETURNING id::text, grants::text`, h[:], now).Scan(&codeID, &grantsJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, Credential{}, ErrCodeInvalid
	}
	if err != nil {
		return Client{}, Credential{}, err
	}
	var grants []Grant
	if err := json.Unmarshal([]byte(grantsJSON), &grants); err != nil {
		return Client{}, Credential{}, err
	}

	cl := Client{ID: protocol.NewID(), Label: label, Status: StatusActive, CreatedAt: now}
	cr := Credential{ID: protocol.NewID(), ClientID: cl.ID, PublicKey: append([]byte(nil), spki...), CreatedAt: now, ExpiresAt: now.Add(CredentialLifetime)}
	if _, err := tx.Exec(ctx, `INSERT INTO clients (id, label, status, created_at) VALUES ($1::text::uuid, $2, 'active', $3)`, cl.ID, cl.Label, now); err != nil {
		return Client{}, Credential{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO client_credentials (id, client_id, public_key, created_at, expires_at) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5)`,
		cr.ID, cl.ID, cr.PublicKey, cr.CreatedAt, cr.ExpiresAt); err != nil {
		return Client{}, Credential{}, err
	}
	for _, g := range grants {
		for _, sc := range g.Scopes {
			if _, err := tx.Exec(ctx, `INSERT INTO grants (client_id, device_id, scope, created_at) VALUES ($1::text::uuid, $2, $3, $4)`, cl.ID, g.DeviceID, sc, now); err != nil {
				if isPG(err, pgFKViolation) { // a granted device no longer exists
					return Client{}, Credential{}, ErrCodeInvalid
				}
				return Client{}, Credential{}, err
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE pairing_codes SET redeemed_by = $2::text::uuid WHERE id = $1::text::uuid`, codeID, cl.ID); err != nil {
		return Client{}, Credential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Client{}, Credential{}, err
	}
	return cl, cr, nil
}

func (s *PostgresStore) CreateOAuthClient(ctx context.Context, label string, grants []Grant, now time.Time) (Client, error) {
	now = now.UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Client{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	cl := Client{ID: protocol.NewID(), Label: label, Status: StatusActive, CreatedAt: now}
	if _, err := tx.Exec(ctx, `INSERT INTO clients (id, label, status, created_at) VALUES ($1::text::uuid, $2, 'active', $3)`, cl.ID, cl.Label, now); err != nil {
		return Client{}, err
	}
	for _, g := range grants {
		for _, sc := range g.Scopes {
			if _, err := tx.Exec(ctx, `INSERT INTO grants (client_id, device_id, scope, created_at) VALUES ($1::text::uuid, $2, $3, $4)`, cl.ID, g.DeviceID, sc, now); err != nil {
				if isPG(err, pgFKViolation) { // a granted device does not exist
					return Client{}, ErrNotFound
				}
				return Client{}, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Client{}, err
	}
	return cl, nil
}

func scanClient(row pgx.Row) (Client, error) {
	var c Client
	var st string
	if err := row.Scan(&c.ID, &c.Label, &st, &c.CreatedAt, &c.RevokedAt); err != nil {
		return Client{}, err
	}
	c.Status = Status(st)
	return c, nil
}

func (s *PostgresStore) GetClient(ctx context.Context, id string) (Client, error) {
	if !protocol.ValidID(id) {
		return Client{}, ErrNotFound
	}
	c, err := scanClient(s.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE id = $1::text::uuid`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

func (s *PostgresStore) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clientCols+` FROM clients ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeClient(ctx context.Context, id string, now time.Time) error {
	if !protocol.ValidID(id) {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE clients SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2) WHERE id = $1::text::uuid`, id, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE client_credentials SET revoked_at = $2 WHERE client_id = $1::text::uuid AND revoked_at IS NULL`, id, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) GetCredential(ctx context.Context, id string) (Credential, error) {
	if !protocol.ValidID(id) {
		return Credential{}, ErrNotFound
	}
	var c Credential
	err := s.pool.QueryRow(ctx, `SELECT `+credCols+` FROM client_credentials WHERE id = $1::text::uuid`, id).
		Scan(&c.ID, &c.ClientID, &c.PublicKey, &c.CreatedAt, &c.ExpiresAt, &c.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	return c, err
}

func (s *PostgresStore) Credentials(ctx context.Context, clientID string) ([]Credential, error) {
	if _, err := s.GetClient(ctx, clientID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+credCols+` FROM client_credentials WHERE client_id = $1::text::uuid ORDER BY created_at, id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.ClientID, &c.PublicKey, &c.CreatedAt, &c.ExpiresAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddCredential(ctx context.Context, c Credential) error {
	if !protocol.ValidID(c.ClientID) || !protocol.ValidID(c.ID) {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM clients WHERE id = $1::text::uuid FOR UPDATE`, c.ClientID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != string(StatusActive)) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM client_credentials WHERE client_id = $1::text::uuid AND revoked_at IS NULL AND expires_at > $2`,
		c.ClientID, c.CreatedAt.UTC()).Scan(&n); err != nil {
		return err
	}
	if n >= MaxCredentialsPerClient {
		return ErrCredentialLimit
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO client_credentials (id, client_id, public_key, created_at, expires_at) VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5)`,
		c.ID, c.ClientID, c.PublicKey, c.CreatedAt.UTC(), c.ExpiresAt.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) RevokeCredential(ctx context.Context, clientID, credentialID string, now time.Time) error {
	if !protocol.ValidID(clientID) || !protocol.ValidID(credentialID) {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE client_credentials SET revoked_at = COALESCE(revoked_at, $3) WHERE id = $1::text::uuid AND client_id = $2::text::uuid`,
		credentialID, clientID, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Grants(ctx context.Context, clientID string) ([]Grant, error) {
	if _, err := s.GetClient(ctx, clientID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT device_id, scope FROM grants WHERE client_id = $1::text::uuid ORDER BY device_id, scope`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var d, sc string
		if err := rows.Scan(&d, &sc); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].DeviceID == d {
			out[n-1].Scopes = append(out[n-1].Scopes, sc)
		} else {
			out = append(out, Grant{DeviceID: d, Scopes: []string{sc}})
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) ScopesFor(ctx context.Context, clientID, deviceID string) ([]string, error) {
	if !protocol.ValidID(clientID) || !protocol.ValidDeviceID(deviceID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT scope FROM grants WHERE client_id = $1::text::uuid AND device_id = $2 ORDER BY scope`, clientID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetGrant(ctx context.Context, clientID, deviceID string, scopes []string, now time.Time) error {
	if !protocol.ValidID(clientID) || !protocol.ValidDeviceID(deviceID) {
		return ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM clients WHERE id = $1::text::uuid FOR UPDATE`, clientID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM grants WHERE client_id = $1::text::uuid AND device_id = $2`, clientID, deviceID); err != nil {
		return err
	}
	for _, sc := range scopes {
		if _, err := tx.Exec(ctx, `INSERT INTO grants (client_id, device_id, scope, created_at) VALUES ($1::text::uuid, $2, $3, $4)`, clientID, deviceID, sc, now.UTC()); err != nil {
			if isPG(err, pgFKViolation) { // no such device
				return ErrNotFound
			}
			return err
		}
	}
	return tx.Commit(ctx)
}
