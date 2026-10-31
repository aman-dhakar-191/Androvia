// Command relay is the Androvia relay: device WebSocket endpoint plus the HTTPS API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/api"
	"github.com/aman-dhakar-191/androvia/relay/internal/config"
	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("relay stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("cannot reach the database: " + err.Error()) // not the original error: it can echo the URL
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		return err
	}

	store := devices.NewPostgresStore(pool)
	rt := router.New(log, nil)
	mgr := connections.NewManager(connections.Config{
		PublicOrigin: cfg.PublicOrigin, HandshakeTimeout: cfg.HandshakeTimeout, HeartbeatTimeout: cfg.HeartbeatTimeout,
	}, store, rt, log, nil)
	rt.Attach(mgr)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.New(cfg.AdminToken, store, mgr, rt, log, nil).Handler(mgr.ServeWS),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("relay listening", "addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "")
		if cfg.TLSCertFile != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Warn("serving plain HTTP: RELAY_ALLOW_INSECURE_HTTP is set; development only")
			errc <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mgr.CloseAll()
	return srv.Shutdown(shutdownCtx)
}
