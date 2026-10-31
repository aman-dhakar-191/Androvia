package testutil

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGPool returns a pool on a private, freshly migrated schema that is dropped when the test ends, so PostgreSQL tests
// in different packages can run in parallel against one database. It skips the test unless RELAY_TEST_DATABASE_URL is
// set (point it at a disposable database).
func PGPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("RELAY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RELAY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "t_" + strings.ReplaceAll(protocol.NewID(), "-", "")

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
		admin.Close()
	})
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}
