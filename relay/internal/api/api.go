// Package api is the HTTPS surface of the relay. Handlers stay thin: parsing, auth, then a call into a service.
//
// Phase 2 authentication is a single bootstrap admin bearer token (RELAY_ADMIN_TOKEN). It is deliberately
// coarse and is replaced in Phase 3 by per-client credentials and scopes. Every route except /healthz requires it.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/router"
)

const maxBody = 64 * 1024

// Connections is what the API needs from the WebSocket manager.
type Connections interface {
	Online(deviceID string) bool
	Disconnect(deviceID string)
}

// Dispatcher is what the API needs from the router.
type Dispatcher interface {
	Dispatch(ctx context.Context, deviceID string, q router.Request) (*router.Response, error)
}

type Server struct {
	adminDigest [32]byte
	store       devices.Store
	conns       Connections
	disp        Dispatcher
	log         *slog.Logger
	now         func() time.Time
}

func New(adminToken string, store devices.Store, conns Connections, disp Dispatcher, log *slog.Logger, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{adminDigest: sha256.Sum256([]byte(adminToken)), store: store, conns: conns, disp: disp, log: log, now: now}
}

// Handler returns the HTTP routes. ws is mounted at /v1/device/ws and does its own (signature) authentication.
func (s *Server) Handler(ws http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /v1/device/ws", ws)
	mux.Handle("POST /v1/devices", s.admin(s.registerDevice))
	mux.Handle("GET /v1/devices", s.admin(s.listDevices))
	mux.Handle("GET /v1/devices/{id}", s.admin(s.getDevice))
	mux.Handle("POST /v1/devices/{id}/revoke", s.admin(s.revokeDevice))
	mux.Handle("POST /v1/devices/{id}/commands", s.admin(s.sendCommand))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// admin enforces the bearer token in constant time. The token is never logged.
func (s *Server) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		digest := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(digest[:], s.adminDigest[:]) != 1 {
			s.log.Warn("unauthorized request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="androvia-relay"`)
			writeError(w, 401, "unauthorized", "missing or invalid bearer token")
			return
		}
		next(w, r)
	})
}

type deviceJSON struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Status     string     `json:"status"`
	Online     bool       `json:"online"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

func (s *Server) toJSON(d devices.Device) deviceJSON {
	return deviceJSON{ID: d.ID, Label: d.Label, Status: string(d.Status), Online: s.conns.Online(d.ID) && d.Status == devices.StatusActive, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, 400, "invalid_request", "request body must be valid JSON with only known fields")
		return false
	}
	return true
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label     string `json:"label"`
		PublicKey string `json:"public_key"` // base64 (std) X.509 SubjectPublicKeyInfo DER, EC P-256
	}
	if !decode(w, r, &req) {
		return
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, 400, "invalid_request", "public_key must be base64")
		return
	}
	d, err := devices.New(req.Label, spki, s.now())
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	switch err := s.store.Create(r.Context(), d); {
	case errors.Is(err, devices.ErrExists):
		writeError(w, 409, "device_exists", "a device with this key is already registered")
	case err != nil:
		s.internal(w, "create device", err)
	default:
		s.log.Info("device registered", "device", d.ID)
		writeJSON(w, 201, s.toJSON(d))
	}
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.List(r.Context())
	if err != nil {
		s.internal(w, "list devices", err)
		return
	}
	out := make([]deviceJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, s.toJSON(d))
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookup(w, r)
	if ok {
		writeJSON(w, 200, s.toJSON(d))
	}
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if err := s.store.Revoke(r.Context(), d.ID); err != nil {
		s.internal(w, "revoke device", err)
		return
	}
	s.conns.Disconnect(d.ID)
	s.log.Info("device revoked", "device", d.ID)
	d.Status = devices.StatusRevoked
	writeJSON(w, 200, s.toJSON(d))
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) (devices.Device, bool) {
	id := r.PathValue("id")
	if !protocol.ValidDeviceID(id) {
		writeError(w, 404, "device_not_found", "no such device")
		return devices.Device{}, false
	}
	d, err := s.store.Get(r.Context(), id)
	switch {
	case errors.Is(err, devices.ErrNotFound):
		writeError(w, 404, "device_not_found", "no such device")
		return devices.Device{}, false
	case err != nil:
		s.internal(w, "get device", err)
		return devices.Device{}, false
	}
	return d, true
}

func (s *Server) sendCommand(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if d.Status != devices.StatusActive {
		writeError(w, 409, "device_revoked", "device is revoked")
		return
	}
	var req struct {
		Capability string          `json:"capability"`
		Version    int             `json:"version"`
		Args       json.RawMessage `json:"args"`
		TimeoutMS  int             `json:"timeout_ms"`
	}
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.disp.Dispatch(r.Context(), d.ID, router.Request{
		Capability: req.Capability, Version: req.Version, Args: req.Args, Timeout: time.Duration(req.TimeoutMS) * time.Millisecond,
	})
	switch {
	case errors.Is(err, router.ErrInvalidRequest):
		writeError(w, 400, "invalid_request", strings.TrimPrefix(err.Error(), router.ErrInvalidRequest.Error()+"\n"))
	case errors.Is(err, router.ErrDeviceOffline):
		writeError(w, 409, "device_offline", "device is not connected")
	case errors.Is(err, router.ErrTimeout):
		writeError(w, 504, "timeout", "device did not answer in time")
	case errors.Is(err, router.ErrDisconnected):
		writeError(w, 502, "device_disconnected", "device disconnected before answering")
	case err != nil:
		s.internal(w, "dispatch", err)
	case resp.Err != nil:
		// The device answered with an error (e.g. permission_denied): a normal outcome, reported as-is.
		writeJSON(w, 422, map[string]any{"request_id": resp.RequestID, "status": "error", "error": map[string]string{"code": resp.Err.Code, "message": resp.Err.Message, "source": "device"}})
	default:
		writeJSON(w, 200, map[string]any{"request_id": resp.RequestID, "status": "ok", "result": json.RawMessage(resp.Result)})
	}
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error("internal error", "op", what, "error", err.Error())
	writeError(w, 500, "internal", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
