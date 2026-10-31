// Package mcpgw is the MCP (Model Context Protocol) gateway: AI agents reach a user's devices through it.
//
// It is a thin adapter over the same code REST uses (internal/commands: policy engine, audit, routing), built on the
// official Go SDK so protocol negotiation (2024-11-05 .. 2026-07-28), transport details and JSON-RPC handling follow the
// specification instead of being re-implemented here.
//
// Security properties (each has a test):
//   - Identity comes from the authenticated transport (the bearer token) and never from tool arguments. Tool schemas
//     forbid unknown properties, so "client_id" or "role" arguments are rejected.
//   - An explicit allowlist of tools; nothing is exposed because a device happens to support it.
//   - tools/list shows only tools this client could actually use, and every call is authorised again at call time.
//   - A device or capability the client has no grant on is indistinguishable from one that does not exist.
//   - The Origin header is validated (DNS-rebinding defence), request bodies are size-limited, and failed
//     authentication is rate limited and audited.
//   - Stateless: no session ids, so there is no session to hijack (the 2026-07-28 spec removes sessions altogether).
package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/audit"
	authn "github.com/aman-dhakar-191/androvia/relay/internal/auth"
	"github.com/aman-dhakar-191/androvia/relay/internal/commands"
	"github.com/aman-dhakar-191/androvia/relay/internal/policy"
	"github.com/aman-dhakar-191/androvia/relay/internal/ratelimit"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const (
	maxBodyBytes   = 64 * 1024
	commandTimeout = 15 * time.Second
	instructions   = "These tools inspect the user's Android devices through the Androvia relay. You can only use the devices and capabilities the user granted to this client; anything else answers 'device_not_found' or 'forbidden'. A device must be online, and the capability must also be switched on in the Androvia app on that phone."
	metadataPath   = "/.well-known/oauth-protected-resource/mcp"
	endpointPath   = "/mcp"
	failuresPerMin = 30
)

// Config wires the gateway to the relay.
type Config struct {
	Commands *commands.Service
	Auth     *authn.Authenticator
	Audit    *audit.Recorder
	Log      *slog.Logger
	Now      func() time.Time
	// PublicBase is the relay's public HTTP(S) base URL, e.g. https://relay.example.com (no trailing slash).
	PublicBase string
	// AllowedOrigins are the browser origins that may call /mcp (the Origin header is validated when present).
	// PublicBase is always allowed. Non-browser clients send no Origin and are unaffected.
	AllowedOrigins []string
	Version        string
	// AuthorizationServers are advertised in the protected resource metadata (RFC 9728) so that hosts can discover where
	// to sign in. Empty means no OAuth: only tokens from the signed-challenge login work.
	AuthorizationServers []string
}

type Gateway struct {
	c       Config
	origins map[string]bool
	fail    *ratelimit.Limiter
}

func New(c Config) *Gateway {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Version == "" {
		c.Version = "dev"
	}
	o := map[string]bool{strings.ToLower(c.PublicBase): true}
	for _, x := range c.AllowedOrigins {
		o[strings.ToLower(strings.TrimRight(x, "/"))] = true
	}
	return &Gateway{c: c, origins: o, fail: ratelimit.New(failuresPerMin, time.Minute, 10000, c.Now)}
}

func (g *Gateway) EndpointPath() string { return endpointPath }
func (g *Gateway) MetadataPath() string { return metadataPath }

// MetadataHandler serves RFC 9728 protected resource metadata. authorization_servers is present only when the relay runs
// its OAuth server (Config.AuthorizationServers); otherwise tokens come from the signed-challenge login (docs/relay.md).
func (g *Gateway) MetadataHandler() http.Handler {
	return sdkauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               g.c.PublicBase + endpointPath,
		AuthorizationServers:   g.c.AuthorizationServers,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Androvia relay",
		ResourceDocumentation:  "https://github.com/aman-dhakar-191/Androvia/blob/main/docs/mcp.md",
	})
}

// Handler is the MCP endpoint.
func (g *Gateway) Handler() http.Handler {
	stream := mcp.NewStreamableHTTPHandler(g.serverFor, &mcp.StreamableHTTPOptions{
		Stateless:                    true, // no Mcp-Session-Id: nothing to hijack, nothing to leak between clients
		JSONResponse:                 true,
		MaxRequestBodyBytes:          maxBodyBytes,
		PropagateRequestCancellation: true, // a client that gives up cancels the command on the device
		Logger:                       g.c.Log,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !g.origins[strings.ToLower(strings.TrimRight(o, "/"))] {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		ip := remoteIP(r)
		if g.fail.Blocked(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		reason := "missing_token"
		verify := func(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
			p, err := g.c.Auth.Verify(ctx, token)
			if err != nil {
				if errors.Is(err, authn.ErrUnauthorized) {
					reason = string(authn.ReasonOf(err))
					return nil, sdkauth.ErrInvalidToken
				}
				return nil, err // an internal failure is a 500, never a pass
			}
			// RFC 8707 / MCP: accept only tokens issued for this resource. Key-login tokens carry no audience.
			if p.Audience != "" && p.Audience != g.c.PublicBase+endpointPath {
				reason = "wrong_audience"
				return nil, sdkauth.ErrInvalidToken
			}
			return &sdkauth.TokenInfo{UserID: p.ClientID, Expiration: p.Expires, Extra: map[string]any{"credential_id": p.CredentialID}}, nil
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		sdkauth.RequireBearerToken(verify, &sdkauth.RequireBearerTokenOptions{ResourceMetadataURL: g.c.PublicBase + metadataPath})(stream).ServeHTTP(rec, r)
		if rec.status == http.StatusUnauthorized {
			g.fail.Allow(ip) // count the failure
			g.c.Audit.Note(r.Context(), audit.Event{ActorType: audit.ActorClient, ActorID: audit.ActorAnonymous, Action: "auth.rejected", Outcome: audit.Denied,
				Detail: map[string]string{"reason": reason, "remote": ip, "channel": string(commands.ChannelMCP)}})
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

// Unwrap lets http.ResponseController reach the real writer (flushing).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------------------------------------------------------------
// The tool allowlist. Adding a tool here is an explicit, reviewed act; nothing is derived from what a device reports.

type toolDef struct {
	name, title, description string
	// scope is the scope a client must hold on at least one device for the tool to be listed.
	scope string
	input map[string]any
	// output documents structuredContent. Clients may rely on it; tests check results against it.
	output map[string]any
}

var obj = func(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

var deviceIDProp = map[string]any{
	"type": "string", "pattern": "^[0-9a-f]{64}$",
	"description": "The device id, as returned by list_devices.",
}

var toolDefs = []toolDef{
	{
		name: "get_device_info", title: "Get device info",
		description: "Basic, non-identifying information about one Android device: manufacturer, model, Android version, security patch level. Needs the device online and the device.info capability switched on in the Androvia app.",
		scope:       policy.ExecuteScope("device.info"),
		input:       obj(map[string]any{"device_id": deviceIDProp}, "device_id"),
		output: map[string]any{"type": "object", "properties": map[string]any{
			"manufacturer": map[string]any{"type": "string"}, "model": map[string]any{"type": "string"},
			"android_release": map[string]any{"type": "string"}, "sdk_int": map[string]any{"type": "integer"},
			"security_patch": map[string]any{"type": "string"}, "supported_abis": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}},
	},
	{
		name: "list_devices", title: "List devices",
		description: "The Android devices this client may see, and whether each is online.",
		scope:       policy.ScopeDevicesRead,
		input:       obj(map[string]any{}),
		output: map[string]any{"type": "object", "required": []string{"devices"}, "properties": map[string]any{"devices": map[string]any{"type": "array", "items": map[string]any{
			"type": "object", "required": []string{"device_id", "label", "status", "online"},
			"properties": map[string]any{
				"device_id": map[string]any{"type": "string"}, "label": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"},
				"online": map[string]any{"type": "boolean"}, "last_seen_at": map[string]any{"type": "string"},
			},
		}}}},
	},
}

func init() { sort.Slice(toolDefs, func(i, j int) bool { return toolDefs[i].name < toolDefs[j].name }) } // deterministic order

// ToolNames lists the allowlisted tool names (for documentation and tests).
func ToolNames() []string {
	out := make([]string, 0, len(toolDefs))
	for _, t := range toolDefs {
		out = append(out, t.name)
	}
	return out
}

// serverFor builds the MCP server for one request: only the tools this client could use. In stateless mode that is every
// request, so grants changed by an administrator apply on the very next call.
func (g *Gateway) serverFor(r *http.Request) *mcp.Server {
	info := sdkauth.TokenInfoFromContext(r.Context())
	if info == nil || info.UserID == "" {
		return nil // the bearer middleware guarantees this does not happen; refuse rather than guess
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "androvia-relay", Title: "Androvia relay", Version: g.c.Version}, &mcp.ServerOptions{
		// Say exactly what this server does: tools only. No listChanged (stateless: there is no stream to push notifications
		// on, so claiming it would be a lie) and no logging (deprecated in 2026-07-28, and we emit none).
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		Instructions: instructions, Logger: g.c.Log,
		// The tool list depends on who is asking, so it must never be shared between clients, and is not worth caching:
		// grants can change at any moment.
		SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" },
	})

	grants, f := g.c.Commands.Grants(r.Context(), info.UserID)
	if f != nil {
		g.c.Log.Error("mcp: cannot read grants; offering no tools", "error", f.Message)
		return srv // fail closed: a server with no tools
	}
	held := map[string]bool{}
	for _, gr := range grants {
		for _, sc := range gr.Scopes {
			held[sc] = true
		}
	}
	for _, t := range toolDefs {
		if !held[t.scope] {
			continue
		}
		tool := &mcp.Tool{
			Name: t.name, Title: t.title, Description: t.description, InputSchema: t.input, OutputSchema: t.output,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, Title: t.title},
		}
		switch t.name {
		case "list_devices":
			mcp.AddTool(srv, tool, g.listDevices)
		case "get_device_info":
			mcp.AddTool(srv, tool, g.deviceInfo)
		}
	}
	return srv
}

// clientID is the authenticated client, taken from the transport. Tool arguments are never consulted for identity.
func clientID(req *mcp.CallToolRequest) (string, bool) {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil || req.Extra.TokenInfo.UserID == "" {
		return "", false
	}
	return req.Extra.TokenInfo.UserID, true
}

type noArgs struct{}

type deviceArgs struct {
	DeviceID string `json:"device_id"`
}

func (g *Gateway) listDevices(ctx context.Context, req *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
	cid, ok := clientID(req)
	if !ok {
		return failure(&commands.Failure{Kind: commands.KindForbidden, Message: "not authenticated"}), nil, nil
	}
	views, f := g.c.Commands.ListDevices(ctx, cid)
	if f != nil {
		return failure(f), nil, nil
	}
	devs := make([]map[string]any, 0, len(views))
	for _, v := range views {
		d := map[string]any{"device_id": v.ID, "label": v.Label, "status": v.Status, "online": v.Online}
		if v.LastSeenAt != nil {
			d["last_seen_at"] = v.LastSeenAt.UTC().Format(time.RFC3339)
		}
		devs = append(devs, d)
	}
	return success(map[string]any{"devices": devs}), nil, nil
}

func (g *Gateway) deviceInfo(ctx context.Context, req *mcp.CallToolRequest, in deviceArgs) (*mcp.CallToolResult, any, error) {
	cid, ok := clientID(req)
	if !ok {
		return failure(&commands.Failure{Kind: commands.KindForbidden, Message: "not authenticated"}), nil, nil
	}
	res, f := g.c.Commands.Execute(ctx, commands.Request{
		ClientID: cid, DeviceID: in.DeviceID, Capability: "device.info", Version: 1, Timeout: commandTimeout, Channel: commands.ChannelMCP,
	})
	if f != nil {
		return failure(f), nil, nil
	}
	return success(res.Data()), nil, nil
}

func success(structured any) *mcp.CallToolResult {
	b, _ := json.Marshal(structured)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, StructuredContent: json.RawMessage(b)}
}

// failure turns the shared service's failure into a tool execution error (isError), the way the MCP spec wants
// domain failures reported so the model can read them and react. The same codes the REST API uses.
func failure(f *commands.Failure) *mcp.CallToolResult {
	code, msg, source := "internal", "internal error", ""
	switch f.Kind {
	case commands.KindNotFound:
		code, msg = "device_not_found", "No such device, or this client has no access to it."
	case commands.KindForbidden:
		code, msg = "forbidden", f.Message
	case commands.KindInvalid:
		code, msg = "invalid_request", f.Message
	case commands.KindRevoked:
		code, msg = "device_revoked", f.Message
	case commands.KindOffline:
		code, msg = "device_offline", "The device is not connected right now."
	case commands.KindTimeout:
		code, msg = "timeout", f.Message
	case commands.KindDisconnected:
		code, msg = "device_disconnected", f.Message
	case commands.KindAuditUnavailable:
		code, msg = "audit_unavailable", f.Message
	case commands.KindDevice:
		code, msg, source = f.DeviceCode, f.DeviceMessage, "device"
	}
	e := map[string]any{"code": code, "message": msg}
	if source != "" {
		e["source"] = source
	}
	body := map[string]any{"error": e}
	if f.RequestID != "" {
		body["request_id"] = f.RequestID
	}
	b, _ := json.Marshal(body)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: code + ": " + msg}}, StructuredContent: json.RawMessage(b)}
}
