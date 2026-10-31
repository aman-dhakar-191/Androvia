// Package api is the HTTPS surface of the relay. Handlers stay thin: parse, authenticate, authorize through the policy
// engine, call a service, audit.
//
// Two planes that never overlap:
//
//   - Admin plane (/v1/admin/...): the bootstrap admin token (RELAY_ADMIN_TOKEN) manages devices, issues pairing codes,
//     grants scopes, revokes, reads the audit log. It cannot send commands.
//   - Client plane (everything else under /v1): a client authenticates by signing a challenge with its own key
//     (/v1/auth/*) and then uses a short-lived bearer token. Every action needs an explicit grant on that device.
//
// Audit rules: actions that raise privilege or cannot be undone (issuing a pairing code, setting a grant, dispatching a
// command) are recorded BEFORE they happen and refused if the record cannot be written. Revocations are recorded after,
// best effort, so a broken audit log can never stop an operator from revoking access.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/commands"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/keys"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/aman-dhakar-191/androvia/relay/internal/ratelimit"
)

const (
	maxBody         = 64 * 1024
	adminActorID    = "bootstrap-token"
	defaultCodeTTL  = 15 // minutes
	maxCodeTTL      = 24 * 60
	maxAuditPage    = 500
	defaultAuditLen = 100
)

// Connections is what the API needs from the WebSocket manager.
type Connections interface {
	Online(deviceID string) bool
	Disconnect(deviceID string)
}

// Limits are per-IP (and per-client) request budgets for the unauthenticated endpoints.
type Limits struct {
	AuthPerMinute      int // /v1/auth/* and /v1/clients/redeem, per IP
	RedeemPerMinute    int // /v1/clients/redeem, per IP
	FailuresPerMinute  int // failed bearer/admin authentication, per IP
	ChallengePerClient int // challenges per client id per minute
}

func DefaultLimits() Limits {
	return Limits{AuthPerMinute: 60, RedeemPerMinute: 10, FailuresPerMinute: 30, ChallengePerClient: 20}
}

type Deps struct {
	AdminToken string
	Devices    devices.Store
	Clients    clients.Store
	Auth       *auth.Authenticator
	Audit      *audit.Recorder
	AuditStore audit.Store
	Conns      Connections
	Commands   *commands.Service // the shared authorization + audit + dispatch path (also used by MCP)
	// MCP, if set, is mounted at /mcp with its RFC 9728 metadata at MCPMetadata (see internal/mcpgw).
	MCP         http.Handler
	MCPMetadata http.Handler
	MCPPath     string
	MCPMetaPath string
	// OAuth, if set, mounts the OAuth authorization server's endpoints (internal/oauth).
	OAuth  interface{ Mount(*http.ServeMux) }
	Log    *slog.Logger
	Now    func() time.Time
	Limits Limits // zero value means DefaultLimits
}

type Server struct {
	d           Deps
	adminDigest [32]byte
	authIP      *ratelimit.Limiter
	redeemIP    *ratelimit.Limiter
	failIP      *ratelimit.Limiter
	challengeBy *ratelimit.Limiter
}

func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Limits == (Limits{}) {
		d.Limits = DefaultLimits()
	}
	lim := func(n int) *ratelimit.Limiter { return ratelimit.New(n, time.Minute, 10000, d.Now) }
	return &Server{
		d: d, adminDigest: sha256.Sum256([]byte(d.AdminToken)),
		authIP: lim(d.Limits.AuthPerMinute), redeemIP: lim(d.Limits.RedeemPerMinute),
		failIP: lim(d.Limits.FailuresPerMinute), challengeBy: lim(d.Limits.ChallengePerClient),
	}
}

// Handler returns the routes. ws is mounted at /v1/device/ws and does its own (signature) authentication.
func (s *Server) Handler(ws http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /v1/device/ws", ws)

	if s.d.MCP != nil {
		mux.Handle(s.d.MCPPath, s.d.MCP)
		mux.Handle("GET "+s.d.MCPMetaPath, s.d.MCPMetadata)
	}

	if s.d.OAuth != nil {
		s.d.OAuth.Mount(mux)
	}

	// Unauthenticated entry points (rate limited).
	mux.HandleFunc("POST /v1/auth/challenge", s.challenge)
	mux.HandleFunc("POST /v1/auth/token", s.token)
	mux.HandleFunc("POST /v1/clients/redeem", s.redeem)

	// Client plane.
	mux.Handle("GET /v1/me", s.client(s.me))
	mux.Handle("POST /v1/me/credentials", s.client(s.addCredential))
	mux.Handle("DELETE /v1/me/credentials/{id}", s.client(s.removeCredential))
	mux.Handle("GET /v1/devices", s.client(s.listDevices))
	mux.Handle("GET /v1/devices/{id}", s.client(s.getDevice))
	mux.Handle("POST /v1/devices/{id}/commands", s.client(s.sendCommand))

	// Admin plane.
	mux.Handle("POST /v1/admin/devices", s.admin(s.adminRegisterDevice))
	mux.Handle("GET /v1/admin/devices", s.admin(s.adminListDevices))
	mux.Handle("GET /v1/admin/devices/{id}", s.admin(s.adminGetDevice))
	mux.Handle("POST /v1/admin/devices/{id}/revoke", s.admin(s.adminRevokeDevice))
	mux.Handle("POST /v1/admin/pairing-codes", s.admin(s.adminIssueCode))
	mux.Handle("GET /v1/admin/clients", s.admin(s.adminListClients))
	mux.Handle("GET /v1/admin/clients/{id}", s.admin(s.adminGetClient))
	mux.Handle("POST /v1/admin/clients/{id}/revoke", s.admin(s.adminRevokeClient))
	mux.Handle("PUT /v1/admin/clients/{id}/grants/{device}", s.admin(s.adminSetGrant))
	mux.Handle("DELETE /v1/admin/clients/{id}/grants/{device}", s.admin(s.adminRemoveGrant))
	mux.Handle("GET /v1/admin/audit", s.admin(s.adminAudit))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------------------------------------------------
// Authentication middleware

type principalKey struct{}

func principalFrom(ctx context.Context) auth.Principal {
	p, _ := ctx.Value(principalKey{}).(auth.Principal)
	return p
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h // X-Forwarded-For is deliberately ignored: it is client-controlled unless a trusted proxy sets it
}

func bearer(r *http.Request) (string, bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// admin enforces the bootstrap token in constant time. The token is never logged.
func (s *Server) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := bearer(r)
		digest := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(digest[:], s.adminDigest[:]) != 1 {
			s.authFailed(w, r, audit.ActorAdmin, "admin.auth", "bad_admin_token")
			return
		}
		next(w, r)
	})
}

// client authenticates a bearer access token. The admin token does not work here, and client tokens do not work on
// admin routes: the two planes share no credential.
func (s *Server) client(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if !ok {
			s.authFailed(w, r, audit.ActorClient, "auth.rejected", "missing_token")
			return
		}
		p, err := s.d.Auth.Verify(r.Context(), tok)
		if err != nil {
			if !errors.Is(err, auth.ErrUnauthorized) {
				s.internal(w, "verify token", err)
				return
			}
			s.authFailed(w, r, audit.ActorClient, "auth.rejected", string(auth.ReasonOf(err)))
			return
		}
		if p.Audience != "" { // an OAuth token is bound to /mcp; it must not unlock the REST API
			s.authFailed(w, r, audit.ActorClient, "auth.rejected", "wrong_audience")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// authFailed answers 401 (or 429 when one IP keeps failing) and audits the failure, bounded by the same limiter.
func (s *Server) authFailed(w http.ResponseWriter, r *http.Request, actor, action, reason string) {
	ip := remoteIP(r)
	if !s.failIP.Allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "rate_limited", "too many failed attempts")
		return
	}
	s.d.Audit.Note(r.Context(), audit.Event{ActorType: actor, ActorID: audit.ActorAnonymous, Action: action, Outcome: audit.Denied,
		Detail: map[string]string{"reason": reason, "remote": ip}})
	w.Header().Set("WWW-Authenticate", `Bearer realm="androvia-relay"`)
	writeError(w, 401, "unauthorized", "missing or invalid credentials")
}

func (s *Server) tooMany(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeError(w, 429, "rate_limited", "too many requests")
}

// ---------------------------------------------------------------------------------------------------------------------
// Unauthenticated: login and pairing

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.authIP.Allow(remoteIP(r)) {
		s.tooMany(w)
		return
	}
	var req struct {
		ClientID string `json:"client_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.challengeBy.Allow(strings.ToLower(req.ClientID)) {
		s.tooMany(w)
		return
	}
	nonce, exp, err := s.d.Auth.NewChallenge(req.ClientID)
	switch {
	case errors.Is(err, auth.ErrBadInput):
		writeError(w, 400, "invalid_request", "client_id must be a UUID")
	case errors.Is(err, auth.ErrBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, 503, "busy", "too many logins in progress; try again shortly")
	case err != nil:
		s.internal(w, "challenge", err)
	default:
		writeJSON(w, 200, map[string]any{"nonce": nonce, "expires_at": exp})
	}
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.authIP.Allow(ip) {
		s.tooMany(w)
		return
	}
	var req struct {
		ClientID     string `json:"client_id"`
		CredentialID string `json:"credential_id"`
		Nonce        string `json:"nonce"`
		Signature    string `json:"signature"` // base64 (std), ASN.1 DER ECDSA P-256 / SHA-256
	}
	if !decode(w, r, &req) {
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || !protocol.ValidID(req.ClientID) || !protocol.ValidID(req.CredentialID) {
		writeError(w, 400, "invalid_request", "client_id and credential_id must be UUIDs and signature base64")
		return
	}
	tok, exp, err := s.d.Auth.Exchange(r.Context(), req.ClientID, req.CredentialID, req.Nonce, sig)
	if err != nil {
		if !errors.Is(err, auth.ErrUnauthorized) {
			s.internal(w, "token exchange", err)
			return
		}
		// The caller learns nothing about why; the audit log does.
		s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: strings.ToLower(req.ClientID), Action: "auth.token", Outcome: audit.Denied,
			Detail: map[string]string{"reason": string(auth.ReasonOf(err)), "remote": ip}})
		w.Header().Set("WWW-Authenticate", `Bearer realm="androvia-relay"`)
		writeError(w, 401, "unauthorized", "authentication failed")
		return
	}
	s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: strings.ToLower(req.ClientID), Action: "auth.token", Outcome: audit.Allowed,
		Detail: map[string]string{"credential_id": strings.ToLower(req.CredentialID), "remote": ip}})
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_at": exp})
}

func (s *Server) redeem(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.authIP.Allow(ip) || !s.redeemIP.Allow(ip) {
		s.tooMany(w)
		return
	}
	var req struct {
		Code      string `json:"code"`
		Label     string `json:"label"`
		PublicKey string `json:"public_key"` // base64 (std) X.509 SubjectPublicKeyInfo DER, EC P-256
	}
	if !decode(w, r, &req) {
		return
	}
	// Validate everything the caller controls BEFORE consuming the code, so a typo does not burn it.
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, 400, "invalid_request", "public_key must be base64")
		return
	}
	if err := keys.ValidLabel(req.Label); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	if _, err := keys.ParseP256(spki); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	cl, cr, err := s.d.Clients.Redeem(r.Context(), clients.HashCode(req.Code), req.Label, spki, s.d.Now())
	if errors.Is(err, clients.ErrCodeInvalid) {
		s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAnonymous, ActorID: audit.ActorAnonymous, Action: "pairing.redeem", Outcome: audit.Denied,
			Detail: map[string]string{"reason": "invalid_code", "remote": ip}})
		writeError(w, 400, "invalid_code", "the pairing code is invalid, expired or already used")
		return
	}
	if err != nil {
		s.internal(w, "redeem", err)
		return
	}
	grants, _ := s.d.Clients.Grants(r.Context(), cl.ID)
	s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: cl.ID, Action: "pairing.redeem", Outcome: audit.Allowed,
		Detail: map[string]string{"label": cl.Label, "credential_id": cr.ID, "count": strconv.Itoa(len(grants)), "remote": ip}})
	writeJSON(w, 201, map[string]any{"client_id": cl.ID, "credential_id": cr.ID, "expires_at": cr.ExpiresAt, "grants": grantsJSON(grants)})
}

// ---------------------------------------------------------------------------------------------------------------------
// Client plane

type deviceJSON struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Status     string     `json:"status"`
	Online     bool       `json:"online"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

func (s *Server) toJSON(d devices.Device) deviceJSON {
	return deviceJSON{ID: d.ID, Label: d.Label, Status: string(d.Status), Online: s.d.Conns.Online(d.ID) && d.Status == devices.StatusActive, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt}
}

func grantsJSON(gs []clients.Grant) []clients.Grant {
	if gs == nil {
		return []clients.Grant{}
	}
	return gs
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	cl, err := s.d.Clients.GetClient(r.Context(), p.ClientID)
	if err != nil {
		s.internal(w, "get client", err)
		return
	}
	grants, err := s.d.Clients.Grants(r.Context(), p.ClientID)
	if err != nil {
		s.internal(w, "get grants", err)
		return
	}
	creds, err := s.d.Clients.Credentials(r.Context(), p.ClientID)
	if err != nil {
		s.internal(w, "get credentials", err)
		return
	}
	writeJSON(w, 200, map[string]any{"client_id": cl.ID, "label": cl.Label, "credential_id": p.CredentialID, "grants": grantsJSON(grants), "credentials": credsJSON(creds)})
}

func credsJSON(cs []clients.Credential) []map[string]any {
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, map[string]any{"id": c.ID, "created_at": c.CreatedAt, "expires_at": c.ExpiresAt, "revoked": c.RevokedAt != nil})
	}
	return out
}

// addCredential is key rotation: a client that can authenticate may add a replacement key, then remove the old one.
func (s *Server) addCredential(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, 400, "invalid_request", "public_key must be base64")
		return
	}
	if _, err := keys.ParseP256(spki); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	now := s.d.Now().UTC()
	cr := clients.Credential{ID: protocol.NewID(), ClientID: p.ClientID, PublicKey: spki, CreatedAt: now, ExpiresAt: now.Add(clients.CredentialLifetime)}
	switch err := s.d.Clients.AddCredential(r.Context(), cr); {
	case errors.Is(err, clients.ErrCredentialLimit):
		writeError(w, 409, "credential_limit", "too many active credentials; remove one first")
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, 401, "unauthorized", "missing or invalid credentials")
	case err != nil:
		s.internal(w, "add credential", err)
	default:
		s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: p.ClientID, Action: "credential.add", Outcome: audit.Allowed, Detail: map[string]string{"credential_id": cr.ID}})
		writeJSON(w, 201, map[string]any{"credential_id": cr.ID, "expires_at": cr.ExpiresAt})
	}
}

func (s *Server) removeCredential(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	id := strings.ToLower(r.PathValue("id"))
	creds, err := s.d.Clients.Credentials(r.Context(), p.ClientID)
	if err != nil {
		s.internal(w, "list credentials", err)
		return
	}
	now := s.d.Now()
	found, othersUsable := false, 0
	for _, c := range creds {
		if c.ID == id {
			found = true
		} else if c.Usable(now) {
			othersUsable++
		}
	}
	if !found {
		writeError(w, 404, "credential_not_found", "no such credential")
		return
	}
	if othersUsable == 0 {
		writeError(w, 409, "last_credential", "this is the only usable credential; add a replacement first or ask an administrator to re-pair")
		return
	}
	if err := s.d.Clients.RevokeCredential(r.Context(), p.ClientID, id, now); err != nil {
		s.internal(w, "revoke credential", err)
		return
	}
	s.d.Auth.RevokeCredential(id)
	s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: p.ClientID, Action: "credential.revoke", Outcome: audit.Allowed, Detail: map[string]string{"credential_id": id}})
	writeJSON(w, 200, map[string]any{"credential_id": id, "revoked": true})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	views, f := s.d.Commands.ListDevices(r.Context(), p.ClientID)
	if f != nil {
		s.writeFailure(w, f)
		return
	}
	out := make([]deviceJSON, 0, len(views))
	for _, v := range views {
		out = append(out, viewJSON(v))
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	v, f := s.d.Commands.GetDevice(r.Context(), p.ClientID, r.PathValue("id"), commands.ChannelREST)
	if f != nil {
		s.writeFailure(w, f)
		return
	}
	writeJSON(w, 200, viewJSON(v))
}

func viewJSON(v commands.DeviceView) deviceJSON {
	return deviceJSON{ID: v.ID, Label: v.Label, Status: v.Status, Online: v.Online, CreatedAt: v.CreatedAt, LastSeenAt: v.LastSeenAt}
}

func (s *Server) sendCommand(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req struct {
		Capability string          `json:"capability"`
		Version    int             `json:"version"`
		Args       json.RawMessage `json:"args"`
		TimeoutMS  int             `json:"timeout_ms"`
	}
	if !decode(w, r, &req) {
		return
	}
	res, f := s.d.Commands.Execute(r.Context(), commands.Request{
		ClientID: p.ClientID, DeviceID: r.PathValue("id"), Capability: req.Capability, Version: req.Version, Args: req.Args,
		Timeout: time.Duration(req.TimeoutMS) * time.Millisecond, Channel: commands.ChannelREST,
	})
	if f != nil {
		s.writeFailure(w, f)
		return
	}
	writeJSON(w, 200, map[string]any{"request_id": res.RequestID, "status": "ok", "result": json.RawMessage(res.Payload)})
}

// writeFailure is the REST vocabulary for the shared service's failures.
func (s *Server) writeFailure(w http.ResponseWriter, f *commands.Failure) {
	switch f.Kind {
	case commands.KindNotFound:
		writeError(w, 404, "device_not_found", "no such device")
	case commands.KindForbidden:
		writeError(w, 403, "forbidden", f.Message)
	case commands.KindInvalid:
		writeError(w, 400, "invalid_request", f.Message)
	case commands.KindRevoked:
		writeError(w, 409, "device_revoked", f.Message)
	case commands.KindOffline:
		writeError(w, 409, "device_offline", f.Message)
	case commands.KindTimeout:
		writeError(w, 504, "timeout", f.Message)
	case commands.KindDisconnected:
		writeError(w, 502, "device_disconnected", f.Message)
	case commands.KindAuditUnavailable:
		writeError(w, 503, "audit_unavailable", f.Message)
	case commands.KindDevice:
		// The device answered with an error (e.g. permission_denied): a normal outcome, reported as-is.
		writeJSON(w, 422, map[string]any{"request_id": f.RequestID, "status": "error", "error": map[string]string{"code": f.DeviceCode, "message": f.DeviceMessage, "source": "device"}})
	default:
		writeError(w, 500, "internal", "internal error")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// Admin plane

func (s *Server) adminAct(r *http.Request, action string, oc audit.Outcome, device string, detail map[string]string) {
	s.d.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, DeviceID: device, Action: action, Outcome: oc, Detail: detail})
}

func (s *Server) adminRegisterDevice(w http.ResponseWriter, r *http.Request) {
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
	d, err := devices.New(req.Label, spki, s.d.Now())
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	switch err := s.d.Devices.Create(r.Context(), d); {
	case errors.Is(err, devices.ErrExists):
		writeError(w, 409, "device_exists", "a device with this key is already registered")
	case err != nil:
		s.internal(w, "create device", err)
	default:
		s.adminAct(r, "device.register", audit.Allowed, d.ID, map[string]string{"label": d.Label})
		writeJSON(w, 201, s.toJSON(d))
	}
}

func (s *Server) adminListDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.d.Devices.List(r.Context())
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

func (s *Server) adminDevice(w http.ResponseWriter, r *http.Request) (devices.Device, bool) {
	id := r.PathValue("id")
	if !protocol.ValidDeviceID(id) {
		writeError(w, 404, "device_not_found", "no such device")
		return devices.Device{}, false
	}
	d, err := s.d.Devices.Get(r.Context(), id)
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

func (s *Server) adminGetDevice(w http.ResponseWriter, r *http.Request) {
	if d, ok := s.adminDevice(w, r); ok {
		writeJSON(w, 200, s.toJSON(d))
	}
}

func (s *Server) adminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.adminDevice(w, r)
	if !ok {
		return
	}
	if err := s.d.Devices.Revoke(r.Context(), d.ID); err != nil {
		s.internal(w, "revoke device", err)
		return
	}
	s.d.Conns.Disconnect(d.ID)
	s.adminAct(r, "device.revoke", audit.Allowed, d.ID, nil) // best effort: revocation is never blocked by the audit log
	d.Status = devices.StatusRevoked
	writeJSON(w, 200, s.toJSON(d))
}

func (s *Server) adminIssueCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Grants     []clients.Grant `json:"grants"`
		TTLMinutes int             `json:"ttl_minutes"`
	}
	if !decode(w, r, &req) {
		return
	}
	grants, err := clients.ValidateGrants(req.Grants)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	ttl := req.TTLMinutes
	if ttl == 0 {
		ttl = defaultCodeTTL
	}
	if ttl < 1 || ttl > maxCodeTTL {
		writeError(w, 400, "invalid_request", "ttl_minutes must be from 1 to 1440")
		return
	}
	for _, g := range grants {
		d, err := s.d.Devices.Get(r.Context(), g.DeviceID)
		if errors.Is(err, devices.ErrNotFound) || (err == nil && d.Status != devices.StatusActive) {
			writeError(w, 400, "unknown_device", "a grant names a device that is not registered or is revoked")
			return
		}
		if err != nil {
			s.internal(w, "get device", err)
			return
		}
	}
	code, err := clients.NewCode()
	if err != nil {
		s.internal(w, "new code", err)
		return
	}
	now := s.d.Now().UTC()
	pc := clients.PairingCode{ID: protocol.NewID(), CodeHash: clients.HashCode(code), Grants: grants, CreatedBy: adminActorID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Minute)}
	// Audit first: a code must never exist without a record of who issued it. The code itself is never recorded.
	if err := s.d.Audit.Record(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, Action: "pairing.issue", Outcome: audit.Allowed,
		Detail: map[string]string{"count": strconv.Itoa(len(grants)), "expires_at": pc.ExpiresAt.Format(time.RFC3339)}}); err != nil {
		writeError(w, 503, "audit_unavailable", "the audit log is unavailable, so no code was issued")
		return
	}
	if err := s.d.Clients.IssueCode(r.Context(), pc); err != nil {
		s.internal(w, "issue code", err)
		return
	}
	writeJSON(w, 201, map[string]any{"code": code, "expires_at": pc.ExpiresAt, "grants": grantsJSON(grants)})
}

type clientJSON struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func toClientJSON(c clients.Client) clientJSON {
	return clientJSON{ID: c.ID, Label: c.Label, Status: string(c.Status), CreatedAt: c.CreatedAt, RevokedAt: c.RevokedAt}
}

func (s *Server) adminListClients(w http.ResponseWriter, r *http.Request) {
	cs, err := s.d.Clients.ListClients(r.Context())
	if err != nil {
		s.internal(w, "list clients", err)
		return
	}
	out := make([]clientJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toClientJSON(c))
	}
	writeJSON(w, 200, map[string]any{"clients": out})
}

func (s *Server) adminClient(w http.ResponseWriter, r *http.Request) (clients.Client, bool) {
	id := strings.ToLower(r.PathValue("id"))
	c, err := s.d.Clients.GetClient(r.Context(), id)
	switch {
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, 404, "client_not_found", "no such client")
		return clients.Client{}, false
	case err != nil:
		s.internal(w, "get client", err)
		return clients.Client{}, false
	}
	return c, true
}

func (s *Server) adminGetClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	grants, err := s.d.Clients.Grants(r.Context(), c.ID)
	if err != nil {
		s.internal(w, "grants", err)
		return
	}
	creds, err := s.d.Clients.Credentials(r.Context(), c.ID)
	if err != nil {
		s.internal(w, "credentials", err)
		return
	}
	writeJSON(w, 200, map[string]any{"client": toClientJSON(c), "grants": grantsJSON(grants), "credentials": credsJSON(creds)})
}

func (s *Server) adminRevokeClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	if err := s.d.Clients.RevokeClient(r.Context(), c.ID, s.d.Now()); err != nil {
		s.internal(w, "revoke client", err)
		return
	}
	s.d.Auth.RevokeClient(c.ID) // tokens stop working now, not at their expiry
	s.adminAct(r, "client.revoke", audit.Allowed, "", map[string]string{"target_client": c.ID})
	c.Status = clients.StatusRevoked
	writeJSON(w, 200, toClientJSON(c))
}

func (s *Server) adminSetGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	if c.Status != clients.StatusActive {
		writeError(w, 409, "client_revoked", "the client is revoked")
		return
	}
	deviceID := r.PathValue("device")
	if !protocol.ValidDeviceID(deviceID) {
		writeError(w, 404, "device_not_found", "no such device")
		return
	}
	var req struct {
		Scopes []string `json:"scopes"`
	}
	if !decode(w, r, &req) {
		return
	}
	scopes, err := policy.NormalizeScopes(req.Scopes)
	if err != nil || len(scopes) == 0 {
		msg := "scopes must be a non-empty list (use DELETE to remove a grant)"
		if err != nil {
			msg = err.Error()
		}
		writeError(w, 400, "invalid_request", msg)
		return
	}
	switch d, err := s.d.Devices.Get(r.Context(), deviceID); {
	case errors.Is(err, devices.ErrNotFound) || (err == nil && d.Status != devices.StatusActive):
		writeError(w, 404, "device_not_found", "no such active device")
		return
	case err != nil:
		s.internal(w, "get device", err)
		return
	}
	// Audit first: a privilege increase never happens unrecorded.
	if err := s.d.Audit.Record(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, DeviceID: deviceID, Action: "grant.set", Outcome: audit.Allowed,
		Detail: map[string]string{"target_client": c.ID, "count": strconv.Itoa(len(scopes)), "scopes": short(strings.Join(scopes, " "), 190)}}); err != nil {
		writeError(w, 503, "audit_unavailable", "the audit log is unavailable, so the grant was not changed")
		return
	}
	switch err := s.d.Clients.SetGrant(r.Context(), c.ID, deviceID, scopes, s.d.Now()); {
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, 404, "not_found", "no such client or device")
	case err != nil:
		s.internal(w, "set grant", err)
	default:
		writeJSON(w, 200, clients.Grant{DeviceID: deviceID, Scopes: scopes})
	}
}

func (s *Server) adminRemoveGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	deviceID := r.PathValue("device")
	if !protocol.ValidDeviceID(deviceID) {
		writeError(w, 404, "device_not_found", "no such device")
		return
	}
	switch err := s.d.Clients.SetGrant(r.Context(), c.ID, deviceID, nil, s.d.Now()); {
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, 404, "not_found", "no such client or device")
	case err != nil:
		s.internal(w, "remove grant", err)
	default:
		s.adminAct(r, "grant.remove", audit.Allowed, deviceID, map[string]string{"target_client": c.ID}) // best effort
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	limit, before := defaultAuditLen, int64(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxAuditPage {
			writeError(w, 400, "invalid_request", "limit must be from 1 to 500")
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, 400, "invalid_request", "before must be a non-negative integer")
			return
		}
		before = n
	}
	evs, err := s.d.AuditStore.List(r.Context(), limit, before)
	if err != nil {
		s.internal(w, "list audit", err)
		return
	}
	if evs == nil {
		evs = []audit.Event{}
	}
	out := map[string]any{"events": evs}
	if len(evs) == limit {
		out["next_before"] = evs[len(evs)-1].ID
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, 400, "invalid_request", "request body must be valid JSON with only known fields")
		return false
	}
	return true
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.d.Log.Error("internal error", "op", what, "error", err.Error())
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
