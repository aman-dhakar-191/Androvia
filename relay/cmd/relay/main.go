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
	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/commands"
	"github.com/aman-dhakar-191/androvia/relay/internal/config"
	"github.com/aman-dhakar-191/androvia/relay/internal/connections"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/mcpgw"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
	"github.com/aman-dhakar-191/androvia/relay/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

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

	deviceStore := devices.NewPostgresStore(pool)
	clientStore := clients.NewPostgresStore(pool)
	auditStore := audit.NewPostgresStore(pool)
	recorder := audit.NewRecorder(auditStore, log, nil)
	go audit.RunRetention(ctx, auditStore, time.Duration(cfg.AuditRetentionDays)*24*time.Hour, time.Hour, log, nil)

	rt := router.New(log, nil)
	mgr := connections.NewManager(connections.Config{
		PublicOrigin: cfg.PublicOrigin, HandshakeTimeout: cfg.HandshakeTimeout, HeartbeatTimeout: cfg.HeartbeatTimeout, Audit: recorder,
	}, deviceStore, rt, log, nil)
	rt.Attach(mgr)

	cmds := commands.New(commands.Deps{
		Devices: deviceStore, Clients: clientStore, Authz: policy.NewAuthorizer(clientStore), Audit: recorder, Disp: rt, Conns: mgr, Log: log,
	})
	authn := auth.New(clientStore, cfg.PublicOrigin, cfg.TokenTTL, nil)
	gw := mcpgw.New(mcpgw.Config{Commands: cmds, Auth: authn, Audit: recorder, Log: log, PublicBase: cfg.PublicHTTPBase(), Version: version})
	handler := api.New(api.Deps{
		AdminToken: cfg.AdminToken, Devices: deviceStore, Clients: clientStore, Auth: authn,
		Audit: recorder, AuditStore: auditStore, Conns: mgr, Commands: cmds, Log: log,
		MCP: gw.Handler(), MCPMetadata: gw.MetadataHandler(), MCPPath: gw.EndpointPath(), MCPMetaPath: gw.MetadataPath(),
	}).Handler(mgr.ServeWS)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
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
