// Package oauth is a small OAuth 2.1 authorization server so that remote MCP hosts (Claude and others) can connect to the
// relay's /mcp endpoint by URL, with no software installed on the user's computer.
//
// It follows the MCP authorization specification (2026-07-28; 2025-11-25 is compatible):
//   - RFC 9728 protected resource metadata points at this server (the gateway publishes it);
//   - RFC 8414 authorization server metadata, with PKCE S256 advertised and required;
//   - public clients only (token_endpoint_auth_method "none"), registered with RFC 7591 dynamic registration;
//   - the authorization code flow with exact redirect-URI matching, RFC 8707 resource binding and RFC 9207 "iss";
//   - single-use authorization codes (60 s) and rotating refresh tokens whose reuse revokes the whole family.
//
// Who approves: the owner of the relay, on a consent page that asks for the relay admin token and lets them choose
// exactly which devices and scopes the application gets. Approving creates a dedicated Androvia client holding only those
// grants, so everything downstream (authorization, audit, revocation) is the existing machinery. Nothing is granted by
// default, and the access token is bound to /mcp: it is useless on the REST API.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	"github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/clients"
	"github.com/aman-dhakar-191/androvia/relay/internal/devices"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/ratelimit"
)

const (
	AuthorizePath = "/oauth/authorize"
	TokenPath     = "/oauth/token"
	RegisterPath  = "/oauth/register"
	MetadataPath  = "/.well-known/oauth-authorization-server"

	adminActorID = "bootstrap-token"

	codeTTL     = 60 * time.Second
	pendingTTL  = 10 * time.Minute
	maxPending  = 500
	maxCodes    = 2000
	maxAttempts = 5
	maxForm     = 16 * 1024
	maxState    = 512
	maxURIs     = 5
	maxURILen   = 512
	maxDevices  = 50
)

// Config wires the server to the relay.
type Config struct {
	// Issuer is the relay's public base URL (https://relay.example.com, no trailing slash). The resource is Issuer+"/mcp".
	Issuer     string
	Resource   string
	AdminToken string
	Devices    devices.Store
	Clients    clients.Store
	Auth       *auth.Authenticator
	Store      Store
	Audit      *audit.Recorder
	Log        *slog.Logger
	Now        func() time.Time
	// AllowInsecure permits an http:// issuer (development and tests only).
	AllowInsecure bool
	// Per-address request budgets per minute. Zero means the default (registration 10, token 60, wrong admin token 10).
	RegisterPerMinute, TokenPerMinute, FailuresPerMinute int
}

// Server implements the endpoints. Create it with New and attach it with Mount.
type Server struct {
	c           Config
	adminDigest [32]byte

	regIP, tokenIP, failIP *ratelimit.Limiter

	mu      sync.Mutex
	pending map[string]*pendingReq
	codes   map[[32]byte]*authCode
}

type pendingReq struct {
	app                 App
	redirectURI, state  string
	challenge, resource string
	expires             time.Time
	attempts            int
}

type authCode struct {
	appID, redirectURI, challenge, resource string
	subjectClientID                         string
	expires                                 time.Time
}

func New(c Config) (*Server, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(c.Issuer, "/") {
		return nil, errors.New("oauth: issuer must be a bare base URL such as https://relay.example.com")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.AllowInsecure) {
		return nil, errors.New("oauth: the issuer must be https (every OAuth endpoint has to be served over HTTPS)")
	}
	if len(c.AdminToken) < 32 || c.Devices == nil || c.Clients == nil || c.Auth == nil || c.Store == nil || c.Audit == nil {
		return nil, errors.New("oauth: incomplete configuration")
	}
	if c.Resource == "" {
		c.Resource = c.Issuer + "/mcp"
	}
	lim := func(n, def int) *ratelimit.Limiter {
		if n <= 0 {
			n = def
		}
		return ratelimit.New(n, time.Minute, 10000, c.Now)
	}
	return &Server{
		c: c, adminDigest: sha256.Sum256([]byte(c.AdminToken)),
		regIP: lim(c.RegisterPerMinute, 10), tokenIP: lim(c.TokenPerMinute, 60), failIP: lim(c.FailuresPerMinute, 10),
		pending: map[string]*pendingReq{}, codes: map[[32]byte]*authCode{},
	}, nil
}

// Mount registers the endpoints.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+MetadataPath, s.metadata)
	mux.HandleFunc("POST "+RegisterPath, s.register)
	mux.HandleFunc("GET "+AuthorizePath, s.authorizeGET)
	mux.HandleFunc("POST "+AuthorizePath, s.authorizePOST)
	mux.HandleFunc("POST "+TokenPath, s.token)
}

// ---------------------------------------------------------------------------------------------------------------------
// Metadata (RFC 8414)

func (s *Server) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.c.Issuer,
		"authorization_endpoint":                         s.c.Issuer + AuthorizePath,
		"token_endpoint":                                 s.c.Issuer + TokenPath,
		"registration_endpoint":                          s.c.Issuer + RegisterPath,
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          "https://github.com/aman-dhakar-191/Androvia/blob/main/docs/oauth.md",
	})
}

// ---------------------------------------------------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.regIP.Allow(ip) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations; wait a minute")
		return
	}
	var req struct {
		ClientName    string   `json:"client_name"`
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be a JSON object")
		return
	}
	if n := len(req.RedirectURIs); n < 1 || n > maxURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("give 1 to %d redirect_uris", maxURIs))
		return
	}
	for _, u := range req.RedirectURIs {
		if err := s.validRedirect(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	grants := []string{"authorization_code", "refresh_token"}
	if len(req.GrantTypes) > 0 {
		for _, g := range req.GrantTypes {
			if g != "authorization_code" && g != "refresh_token" {
				oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type "+quote(g))
				return
			}
		}
		grants = req.GrantTypes
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only the code response type is supported")
			return
		}
	}
	id, err := randHex(16)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	app := App{ID: id, Name: cleanName(req.ClientName), RedirectURIs: dedupe(req.RedirectURIs), CreatedAt: s.c.Now().UTC()}
	switch err := s.c.Store.CreateApp(r.Context(), app); {
	case errors.Is(err, ErrTooMany):
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "this relay accepts no more application registrations")
		return
	case err != nil:
		s.c.Log.Error("oauth: create app", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAnonymous, ActorID: audit.ActorAnonymous, Action: "oauth.register", Outcome: audit.Info,
		Detail: map[string]string{"oauth_client": app.ID, "label": app.Name, "remote": ip}})
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  app.ID,
		"client_id_issued_at":        app.CreatedAt.Unix(),
		"client_name":                app.Name,
		"redirect_uris":              app.RedirectURIs,
		"grant_types":                grants,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // public client: whatever the application asked for, there is no secret
	})
}

// validRedirect enforces the spec's rule: https, or http to a loopback host. Custom schemes, fragments and credentials are refused.
func (s *Server) validRedirect(raw string) error {
	if raw == "" || len(raw) > maxURILen {
		return errors.New("redirect_uri is empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil || strings.Contains(raw, "#") {
		return errors.New("redirect_uri must be an absolute URL without a fragment or credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
	}
	return errors.New("redirect_uri must be https, or http to localhost / 127.0.0.1 / [::1]")
}

// ---------------------------------------------------------------------------------------------------------------------
// Authorization endpoint

func (s *Server) authorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	app, redirectURI, ok := s.appAndRedirect(w, r, q.Get("client_id"), q.Get("redirect_uri"))
	if !ok {
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) { s.redirectError(w, r, redirectURI, state, code, desc) }
	switch {
	case len(state) > maxState:
		fail("invalid_request", "state is too long")
		return
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	case q.Get("code_challenge_method") != "S256" || !validChallenge(q.Get("code_challenge")):
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		resource = s.c.Resource
	}
	if resource != s.c.Resource {
		fail("invalid_target", "this server only issues tokens for "+s.c.Resource)
		return
	}
	id, err := randHex(16)
	if err != nil {
		fail("server_error", "")
		return
	}
	s.mu.Lock()
	s.sweepLocked()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		s.page(w, http.StatusServiceUnavailable, errorTmpl, map[string]any{"Message": "Too many sign-ins are in progress. Try again in a minute."})
		return
	}
	s.pending[id] = &pendingReq{app: app, redirectURI: redirectURI, state: state, challenge: q.Get("code_challenge"), resource: resource, expires: s.c.Now().Add(pendingTTL)}
	s.mu.Unlock()
	s.renderConsent(w, r, http.StatusOK, id, app, redirectURI, "")
}

func (s *Server) authorizePOST(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if s.failIP.Blocked(ip) {
		w.Header().Set("Retry-After", "60")
		s.page(w, http.StatusTooManyRequests, errorTmpl, map[string]any{"Message": "Too many wrong attempts from this address. Wait a minute."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, errorTmpl, map[string]any{"Message": "That form could not be read."})
		return
	}
	id := r.PostForm.Get("req")
	s.mu.Lock()
	p, ok := s.pending[id]
	if ok && !s.c.Now().Before(p.expires) {
		delete(s.pending, id)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		s.page(w, http.StatusBadRequest, errorTmpl, map[string]any{"Message": "This sign-in request has expired. Go back to the application and start the connection again."})
		return
	}

	if r.PostForm.Get("action") == "deny" {
		s.forget(id)
		s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, Action: "oauth.authorize", Outcome: audit.Denied,
			Detail: map[string]string{"oauth_client": p.app.ID, "reason": "owner_denied"}})
		s.redirectError(w, r, p.redirectURI, p.state, "access_denied", "the owner declined")
		return
	}

	// Authenticate the owner: constant time, bounded attempts per request and per address.
	s.mu.Lock()
	p.attempts++
	tooMany := p.attempts > maxAttempts
	if tooMany {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if tooMany {
		s.page(w, http.StatusBadRequest, errorTmpl, map[string]any{"Message": "Too many wrong attempts. Start the connection again."})
		return
	}
	digest := sha256.Sum256([]byte(r.PostForm.Get("admin_token")))
	if subtle.ConstantTimeCompare(digest[:], s.adminDigest[:]) != 1 {
		s.failIP.Allow(ip)
		s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: audit.ActorAnonymous, Action: "oauth.authorize", Outcome: audit.Denied,
			Detail: map[string]string{"oauth_client": p.app.ID, "reason": "bad_admin_token", "remote": ip}})
		s.renderConsent(w, r, http.StatusUnauthorized, id, p.app, p.redirectURI, "That is not the relay admin token.")
		return
	}

	grants, msg := s.parseGrants(r, r.PostForm["grant"])
	if msg != "" {
		s.renderConsent(w, r, http.StatusBadRequest, id, p.app, p.redirectURI, msg)
		return
	}

	// Audit first: an approval that cannot be recorded does not happen.
	if err := s.c.Audit.Record(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, Action: "oauth.authorize", Outcome: audit.Allowed,
		Detail: map[string]string{"oauth_client": p.app.ID, "label": p.app.Name, "count": fmt.Sprint(len(grants))}}); err != nil {
		s.page(w, http.StatusServiceUnavailable, errorTmpl, map[string]any{"Message": "The audit log is unavailable, so nothing was approved."})
		return
	}
	cl, err := s.c.Clients.CreateOAuthClient(r.Context(), "oauth: "+p.app.Name, grants, s.c.Now())
	if err != nil {
		s.c.Log.Error("oauth: create client", "error", err.Error())
		s.page(w, http.StatusInternalServerError, errorTmpl, map[string]any{"Message": "Could not create the connection. A device may have been removed; start again."})
		return
	}
	code, hash, err := newSecret("")
	if err != nil {
		s.page(w, http.StatusInternalServerError, errorTmpl, map[string]any{"Message": "Could not create a code."})
		return
	}
	s.mu.Lock()
	s.sweepLocked()
	if len(s.codes) >= maxCodes {
		s.mu.Unlock()
		s.page(w, http.StatusServiceUnavailable, errorTmpl, map[string]any{"Message": "Busy. Try again in a minute."})
		return
	}
	s.codes[hash] = &authCode{appID: p.app.ID, redirectURI: p.redirectURI, challenge: p.challenge, resource: p.resource, subjectClientID: cl.ID, expires: s.c.Now().Add(codeTTL)}
	delete(s.pending, id)
	s.mu.Unlock()
	s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorAdmin, ActorID: adminActorID, Action: "oauth.connected", Outcome: audit.Info,
		Detail: map[string]string{"oauth_client": p.app.ID, "target_client": cl.ID}})
	s.redirect(w, r, p.redirectURI, url.Values{"code": {code}, "state": nonEmpty(p.state), "iss": {s.c.Issuer}})
}

// parseGrants turns the posted checkboxes ("<device id>|<scope>") into grants. Anything unexpected is an error: nothing is dropped silently.
func (s *Server) parseGrants(r *http.Request, posted []string) ([]clients.Grant, string) {
	if len(posted) == 0 {
		return nil, "Tick at least one permission, or choose Deny."
	}
	if len(posted) > maxDevices*len(offeredScopes) {
		return nil, "Too many permissions in one request."
	}
	byDev := map[string][]string{}
	for _, v := range posted {
		dev, scope, ok := strings.Cut(v, "|")
		if !ok || !offered(scope) {
			return nil, "That form contained a permission this server does not offer."
		}
		byDev[dev] = append(byDev[dev], scope)
	}
	var out []clients.Grant
	for dev, scopes := range byDev {
		d, err := s.c.Devices.Get(r.Context(), dev)
		if err != nil || d.Status != devices.StatusActive {
			return nil, "A selected device is no longer registered."
		}
		out = append(out, clients.Grant{DeviceID: dev, Scopes: scopes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	g, err := clients.ValidateGrants(out)
	if err != nil {
		return nil, "Those permissions are not valid."
	}
	return g, ""
}

// appAndRedirect validates the two values that decide where the browser may be sent. If either is wrong the user is
// shown an error page and is NOT redirected (OAuth 2.1 section 4.1.2.1).
func (s *Server) appAndRedirect(w http.ResponseWriter, r *http.Request, clientID, redirectURI string) (App, string, bool) {
	bad := func(msg string) (App, string, bool) {
		s.page(w, http.StatusBadRequest, errorTmpl, map[string]any{"Message": msg})
		return App{}, "", false
	}
	if clientID == "" || redirectURI == "" {
		return bad("The application did not say who it is or where to return to.")
	}
	app, err := s.c.Store.GetApp(r.Context(), clientID)
	if err != nil {
		return bad("This application is not registered with this relay.")
	}
	for _, u := range app.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(u), []byte(redirectURI)) == 1 { // exact match only
			return app, redirectURI, true
		}
	}
	return bad("The return address does not match what the application registered.")
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	v := url.Values{"error": {code}, "iss": {s.c.Issuer}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	if state != "" {
		v.Set("state", state)
	}
	s.redirect(w, r, redirectURI, v)
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, base string, v url.Values) {
	u, err := url.Parse(base)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	for k, vs := range v {
		for _, x := range vs {
			if x != "" {
				q.Set(k, x)
			}
		}
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) forget(id string) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *Server) sweepLocked() {
	now := s.c.Now()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	for k, c := range s.codes {
		if !now.Before(c.expires) {
			delete(s.codes, k)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// Token endpoint

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.tokenIP.Allow(ip) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil || len(r.PostForm) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "send application/x-www-form-urlencoded parameters in the body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, ip)
	case "refresh_token":
		s.refresh(w, r, ip)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, ip string) {
	f := r.PostForm
	code, verifier := f.Get("code"), f.Get("code_verifier")
	if code == "" || verifier == "" || f.Get("client_id") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code, code_verifier and client_id are required")
		return
	}
	h := sha256.Sum256([]byte(code))
	now := s.c.Now()
	s.mu.Lock()
	ac, ok := s.codes[h]
	delete(s.codes, h) // a code works once, whatever happens next
	s.mu.Unlock()
	if !ok || !now.Before(ac.expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code is invalid, expired or already used")
		return
	}
	if f.Get("client_id") != ac.appID || subtle.ConstantTimeCompare([]byte(f.Get("redirect_uri")), []byte(ac.redirectURI)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code was not issued to this client and redirect_uri")
		return
	}
	if !validVerifier(verifier) || !pkceMatches(verifier, ac.challenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match")
		return
	}
	if res := f.Get("resource"); res != "" && res != ac.resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "the code was issued for a different resource")
		return
	}
	s.issue(w, r, ac.appID, ac.subjectClientID, ac.resource, newFamily(), now.Add(RefreshFamilyTTL), ip, true)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, ip string) {
	f := r.PostForm
	tok := f.Get("refresh_token")
	if tok == "" || f.Get("client_id") == "" || len(tok) > 128 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}
	now := s.c.Now()
	rec, err := s.c.Store.UseRefresh(r.Context(), sha256.Sum256([]byte(tok)), now)
	switch {
	case errors.Is(err, ErrNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is invalid or expired")
		return
	case errors.Is(err, ErrReused):
		// Someone has a copy of an old token. Cut the whole connection off: no refresh, no live access token.
		_ = s.c.Store.RevokeFamily(r.Context(), rec.FamilyID)
		s.c.Auth.RevokeClient(rec.SubjectClientID)
		s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: rec.SubjectClientID, Action: "oauth.refresh_reuse", Outcome: audit.Denied,
			Detail: map[string]string{"oauth_client": rec.AppID, "reason": "refresh_token_reused", "remote": ip}})
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used; the connection was closed")
		return
	case err != nil:
		s.c.Log.Error("oauth: use refresh", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if f.Get("client_id") != rec.AppID {
		_ = s.c.Store.RevokeFamily(r.Context(), rec.FamilyID) // a valid token presented by another client: treat as stolen
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was not issued to this client")
		return
	}
	if res := f.Get("resource"); res != "" && res != rec.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "the refresh token was issued for a different resource")
		return
	}
	s.issue(w, r, rec.AppID, rec.SubjectClientID, rec.Resource, rec.FamilyID, rec.FamilyExpiresAt, ip, false)
}

// issue mints an access token and a fresh refresh token in the family and writes the response.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, appID, subject, resource, family string, familyExpires time.Time, ip string, first bool) {
	access, exp, err := s.c.Auth.IssueForResource(r.Context(), subject, resource)
	if err != nil {
		_ = s.c.Store.RevokeFamily(r.Context(), family)
		if auth.ReasonOf(err) == auth.ReasonClientInactive {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "this connection was revoked")
			return
		}
		s.c.Log.Error("oauth: issue access token", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	refresh, hash, err := newSecret("avr_")
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	now := s.c.Now()
	expires := now.Add(RefreshTTL)
	if familyExpires.Before(expires) {
		expires = familyExpires
	}
	if err := s.c.Store.SaveRefresh(r.Context(), Refresh{Hash: hash, FamilyID: family, AppID: appID, SubjectClientID: subject, Resource: resource,
		CreatedAt: now, ExpiresAt: expires, FamilyExpiresAt: familyExpires}); err != nil {
		s.c.Log.Error("oauth: save refresh", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if first {
		s.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: subject, Action: "oauth.token", Outcome: audit.Allowed,
			Detail: map[string]string{"oauth_client": appID, "remote": ip}})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(exp.Sub(now).Seconds()), "refresh_token": refresh,
	})
}

// ---------------------------------------------------------------------------------------------------------------------
// Consent page

type scopeOption struct{ Scope, Label string }

var offeredScopes = []scopeOption{
	{policy.ScopeDevicesRead, "See this device and whether it is online"},
	{policy.ExecuteScope("device.info"), "Read its make, model and Android version"},
}

func offered(scope string) bool {
	for _, o := range offeredScopes {
		if o.Scope == scope {
			return true
		}
	}
	return false
}

type deviceView struct {
	ID, Label, Short string
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, status int, req string, app App, redirectURI, errMsg string) {
	devs, err := s.c.Devices.List(r.Context())
	if err != nil {
		s.page(w, http.StatusInternalServerError, errorTmpl, map[string]any{"Message": "Could not list devices."})
		return
	}
	var views []deviceView
	for _, d := range devs {
		if d.Status == devices.StatusActive && len(views) < maxDevices {
			views = append(views, deviceView{ID: d.ID, Label: d.Label, Short: d.ID[:8]})
		}
	}
	host := redirectURI
	if u, err := url.Parse(redirectURI); err == nil {
		host = u.Host
	}
	s.page(w, status, consentTmpl, map[string]any{
		"Req": req, "AppName": app.Name, "RedirectHost": host, "RedirectURI": redirectURI, "Devices": views, "Scopes": offeredScopes,
		"Error": errMsg, "Path": AuthorizePath, "Resource": s.c.Resource,
	})
}

func (s *Server) page(w http.ResponseWriter, status int, t *template.Template, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY") // the consent page must not be framed (clickjacking)
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Androvia: connect an application</title><style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--mut:#5a5a5a;--line:#d0d0d0;--acc:#0b57d0;--bad:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ececec;--mut:#a8a8a8;--line:#3a3a3a;--acc:#8ab4f8;--bad:#f2b8b5}}
body{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px}
main{max-width:34rem;margin:0 auto}h1{font-size:1.35rem}fieldset{border:1px solid var(--line);border-radius:8px;margin:0 0 16px;padding:12px 16px}
legend{font-weight:600}label{display:block;margin:6px 0}input[type=password]{width:100%;box-sizing:border-box;padding:10px;font:inherit;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.mut{color:var(--mut);font-size:.9rem}.err{color:var(--bad);font-weight:600}code{word-break:break-all}
button{font:inherit;padding:10px 18px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);cursor:pointer}
button.go{background:var(--acc);border-color:var(--acc);color:#fff}@media(prefers-color-scheme:dark){button.go{color:#000}}
</style></head><body><main>`

var consentTmpl = template.Must(template.New("consent").Parse(pageHead + `
<h1>Connect “{{.AppName}}” to your Androvia relay?</h1>
<p>This application wants to use your phones through <code>{{.Resource}}</code>. After you approve, it returns to
<strong>{{.RedirectHost}}</strong>. Only continue if you started this connection and recognise that address.</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Path}}" autocomplete="off">
<input type="hidden" name="req" value="{{.Req}}">
{{if .Devices}}
<p><strong>Choose exactly what it may do.</strong> Nothing is selected by default.</p>
{{range $d := .Devices}}<fieldset><legend>{{$d.Label}} <span class="mut">({{$d.Short}}…)</span></legend>
{{range $s := $.Scopes}}<label><input type="checkbox" name="grant" value="{{$d.ID}}|{{$s.Scope}}"> {{$s.Label}}</label>
{{end}}</fieldset>
{{end}}
<label for="t"><strong>Relay admin token</strong></label>
<p class="mut" style="margin:0 0 6px">Proves that you own this relay. It is checked here and never stored.</p>
<input id="t" type="password" name="admin_token" required>
<p><button class="go" type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny" formnovalidate>Deny</button></p>
{{else}}
<p class="err">No devices are registered on this relay yet, so there is nothing to grant. Register a phone first, then connect again.</p>
<p><button type="submit" name="action" value="deny" formnovalidate>Cancel</button></p>
{{end}}
</form></main></body></html>`))

var errorTmpl = template.Must(template.New("error").Parse(pageHead + `<h1>Cannot continue</h1><p class="err" role="alert">{{.Message}}</p></main></body></html>`))

// ---------------------------------------------------------------------------------------------------------------------
// helpers

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h // X-Forwarded-For is ignored: it is client-controlled unless a trusted proxy sets it
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newFamily() string { f, _ := randHex(16); return f }

// newSecret returns a random 256-bit secret (with prefix) and its SHA-256 hash.
func newSecret(prefix string) (string, [32]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", [32]byte{}, err
	}
	s := prefix + base64.RawURLEncoding.EncodeToString(b)
	return s, sha256.Sum256([]byte(s)), nil
}

func validChallenge(c string) bool {
	if len(c) != 43 { // base64url of a SHA-256 digest, unpadded
		return false
	}
	return isB64URL(c)
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '~') {
			return false
		}
	}
	return true
}

func isB64URL(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func pkceMatches(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// cleanName makes an application-supplied name safe to store and show: no control characters, at most 64 characters.
func cleanName(n string) string {
	var b strings.Builder
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if rs := []rune(out); len(rs) > 64 {
		out = strings.TrimSpace(string(rs[:64]))
	}
	if out == "" {
		return "MCP application"
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func quote(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return fmt.Sprintf("%q", s)
}
