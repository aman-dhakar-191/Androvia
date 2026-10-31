package mcpgw_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/oauth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------------------------------------------------
// harness: a minimal OAuth client written from the spec, so each rule is exercised explicitly

const (
	cb       = "http://127.0.0.1:9/callback"
	claudeCB = "https://claude.ai/api/mcp/auth_callback"
	mcpRes   = publicBase + "/mcp"
)

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *env) postJSON(path string, body any) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(e.srv.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) registerApp(name string, uris ...string) string {
	e.t.Helper()
	if len(uris) == 0 {
		uris = []string{cb}
	}
	st, out := e.postJSON("/oauth/register", map[string]any{"client_name": name, "redirect_uris": uris})
	if st != http.StatusCreated {
		e.t.Fatalf("register: %d %v", st, out)
	}
	return out["client_id"].(string)
}

func (e *env) authURL(clientID, redirect, challenge, state string, extra map[string]string) string {
	v := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {state}, "resource": {mcpRes}}
	for k, x := range extra {
		if x == "" {
			v.Del(k)
		} else {
			v.Set(k, x)
		}
	}
	return e.srv.URL + "/oauth/authorize?" + v.Encode()
}

func (e *env) get(u string) (*http.Response, string) {
	e.t.Helper()
	resp, err := noRedirect.Get(u)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) postForm(path string, f url.Values) (*http.Response, string) {
	e.t.Helper()
	resp, err := noRedirect.PostForm(e.srv.URL+path, f)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var reqRE = regexp.MustCompile(`name="req" value="([0-9a-f]+)"`)

func pendingReq(t *testing.T, page string) string {
	t.Helper()
	m := reqRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no request id in the consent page:\n%s", page)
	}
	return m[1]
}

func grantValues(gs ...grant) []string {
	var out []string
	for _, g := range gs {
		for _, sc := range g.scopes {
			out = append(out, g.dev.ID+"|"+sc)
		}
	}
	return out
}

func location(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	l, err := resp.Location()
	if err != nil {
		t.Fatalf("no redirect (status %d): %v", resp.StatusCode, err)
	}
	return l
}

// approveFlow runs the browser part: open the consent page, approve with the admin token and the given grants.
func (e *env) approveFlow(appID, redirect, challenge string, gs ...grant) *url.URL {
	e.t.Helper()
	resp, page := e.get(e.authURL(appID, redirect, challenge, "st-1", nil))
	if resp.StatusCode != 200 {
		e.t.Fatalf("consent page: %d %s", resp.StatusCode, page)
	}
	resp, body := e.postForm("/oauth/authorize", url.Values{"req": {pendingReq(e.t, page)}, "action": {"approve"}, "admin_token": {adminToken}, "grant": grantValues(gs...)})
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	return location(e.t, resp)
}

func (e *env) token(f url.Values) (int, map[string]any) {
	e.t.Helper()
	resp, body := e.postForm("/oauth/token", f)
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	return resp.StatusCode, out
}

type connection struct {
	appID, access, refresh, verifier string
}

// connect performs the whole flow and returns the tokens.
func (e *env) connect(name string, gs ...grant) connection {
	e.t.Helper()
	app := e.registerApp(name)
	ver, ch := pkce(e.t)
	loc := e.approveFlow(app, cb, ch, gs...)
	q := loc.Query()
	if q.Get("state") != "st-1" || q.Get("iss") != publicBase || q.Get("code") == "" {
		e.t.Fatalf("redirect: %s", loc)
	}
	st, out := e.token(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {app}, "redirect_uri": {cb}, "code_verifier": {ver}, "resource": {mcpRes}})
	if st != 200 {
		e.t.Fatalf("token: %d %v", st, out)
	}
	return connection{app, out["access_token"].(string), out["refresh_token"].(string), ver}
}

func (e *env) refreshWith(c connection, refresh string) (int, map[string]any) {
	return e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {c.appID}})
}

func (e *env) subjectOf(t *testing.T, name string) string {
	t.Helper()
	cs, _ := e.clients.ListClients(ctx0)
	for _, c := range cs {
		if c.Label == "oauth: "+name {
			return c.ID
		}
	}
	t.Fatalf("no OAuth client for %q", name)
	return ""
}

// ---------------------------------------------------------------------------------------------------------------------
// the whole flow, end to end

func TestOAuthFlowGivesAnMCPSessionWithExactlyTheApprovedGrants(t *testing.T) {
	e := newEnvOAuth(t)
	a, b := e.device(true), e.device(true)
	c := e.connect("Claude", grant{a, readAndInfo}) // b is deliberately not granted

	s, err := e.session(c.access)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(toolNames(t, s), ","); got != "get_device_info,list_devices" {
		t.Fatalf("tools = %s", got)
	}
	r, err := call(t, s, "list_devices", nil)
	if err != nil || r.IsError {
		t.Fatalf("list_devices: %v %v", err, r)
	}
	devs := structured(t, r)["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["device_id"] != a.ID {
		t.Fatalf("saw %v, want only the approved device", devs)
	}
	r, _ = call(t, s, "get_device_info", map[string]any{"device_id": a.ID})
	if r.IsError || structured(t, r)["model"] != "Phone 1" {
		t.Fatalf("device info: %v", r)
	}
	if r, err := call(t, s, "get_device_info", map[string]any{"device_id": b.ID}); err == nil && !r.IsError {
		t.Fatal("an unapproved device answered")
	}
	if b.received.Load() != 0 {
		t.Fatal("the unapproved phone received a command")
	}
}

func TestOAuthApprovalCanBeNarrowerThanTheMenu(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readOnly}) // only "see the device", not "read its info"
	s := mustSession(t, e, c.access)
	if got := strings.Join(toolNames(t, s), ","); got != "list_devices" {
		t.Fatalf("tools = %s", got)
	}
	if r, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID}); err == nil && !r.IsError {
		t.Fatal("a scope that was not ticked was usable")
	}
}

func mustSession(t *testing.T, e *env, tok string) *mcp.ClientSession {
	t.Helper()
	s, err := e.session(tok)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------------------------------------------------
// discovery

func TestOAuthDiscovery(t *testing.T) {
	e := newEnvOAuth(t)
	// 1. an unauthenticated MCP request is a 401 that points at the protected resource metadata
	resp, _ := rawPost(t, e, "", nil, strings.Replace(initBody, "%s", "2025-06-18", 1))
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("401 challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	// 2. which names this relay as the authorization server
	_, prm := e.getJSON("/.well-known/oauth-protected-resource/mcp")
	if as, _ := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != publicBase {
		t.Fatalf("authorization_servers = %v", prm["authorization_servers"])
	}
	// 3. whose metadata advertises PKCE S256, public clients and the iss parameter
	st, m := e.getJSON("/.well-known/oauth-authorization-server")
	if st != 200 || m["issuer"] != publicBase {
		t.Fatalf("%d %v", st, m)
	}
	for k, want := range map[string]string{"authorization_endpoint": "/oauth/authorize", "token_endpoint": "/oauth/token", "registration_endpoint": "/oauth/register"} {
		if m[k] != publicBase+want {
			t.Errorf("%s = %v", k, m[k])
		}
	}
	if cm, _ := m["code_challenge_methods_supported"].([]any); len(cm) != 1 || cm[0] != "S256" {
		t.Errorf("PKCE methods: %v", m["code_challenge_methods_supported"])
	}
	if am, _ := m["token_endpoint_auth_methods_supported"].([]any); len(am) != 1 || am[0] != "none" {
		t.Errorf("client auth methods: %v", m["token_endpoint_auth_methods_supported"])
	}
	if m["authorization_response_iss_parameter_supported"] != true {
		t.Error("iss parameter support not advertised")
	}
}

func TestOAuthIsOffByDefault(t *testing.T) {
	e := newEnv(t) // RELAY_OAUTH_ENABLED not set
	for _, p := range []string{"/oauth/register", "/oauth/authorize", "/oauth/token", "/.well-known/oauth-authorization-server"} {
		resp, err := http.Post(e.srv.URL+p, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("%s answers %d although OAuth is not enabled", p, resp.StatusCode)
		}
	}
}

func (e *env) getJSON(path string) (int, map[string]any) {
	e.t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ---------------------------------------------------------------------------------------------------------------------
// registration

func TestRegistrationAcceptsOnlySafeRedirectURIs(t *testing.T) {
	e := newEnvOAuth(t)
	for _, ok := range []string{claudeCB, "http://localhost:3000/cb", "http://127.0.0.1:1/x", "http://[::1]:8080/cb"} {
		if st, out := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{ok}}); st != 201 {
			t.Errorf("%s refused: %d %v", ok, st, out)
		}
	}
	for name, bad := range map[string]string{
		"plain http to a real host": "http://evil.example.com/cb",
		"custom scheme":             "myapp://callback",
		"javascript":                "javascript:alert(1)",
		"fragment":                  "https://claude.ai/cb#x",
		"credentials":               "https://user:pw@claude.ai/cb",
		"relative":                  "/cb",
		"empty":                     "",
		"file":                      "file:///etc/passwd",
	} {
		st, out := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{bad}})
		if st != 400 || out["error"] != "invalid_redirect_uri" {
			t.Errorf("%s accepted: %d %v", name, st, out)
		}
	}
	if st, _ := e.postJSON("/oauth/register", map[string]any{"client_name": "x"}); st != 400 {
		t.Error("registration without redirect_uris accepted")
	}
	many := []string{}
	for i := 0; i < 6; i++ {
		many = append(many, claudeCB+"?n="+string(rune('a'+i)))
	}
	if st, _ := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": many}); st != 400 {
		t.Error("more than 5 redirect URIs accepted")
	}
}

func TestRegistrationIsAlwaysAPublicClient(t *testing.T) {
	e := newEnvOAuth(t)
	st, out := e.postJSON("/oauth/register", map[string]any{"client_name": "Claude", "redirect_uris": []string{claudeCB},
		"token_endpoint_auth_method": "client_secret_basic", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
	if st != 201 || out["token_endpoint_auth_method"] != "none" || out["client_secret"] != nil {
		t.Fatalf("%d %v", st, out)
	}
	if st, _ := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{cb}, "grant_types": []string{"password"}}); st != 400 {
		t.Error("an unsupported grant type was accepted")
	}
	if st, _ := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{cb}, "response_types": []string{"token"}}); st != 400 {
		t.Error("the implicit response type was accepted")
	}
}

func TestRegistrationNameIsSanitisedAndShownEscaped(t *testing.T) {
	e := newEnvOAuth(t)
	evil := "<script>alert(1)</script>\x00‮Evil" + strings.Repeat("x", 100)
	st, out := e.postJSON("/oauth/register", map[string]any{"client_name": evil, "redirect_uris": []string{cb}})
	if st != 201 {
		t.Fatal(st, out)
	}
	name := out["client_name"].(string)
	if len([]rune(name)) > 64 || strings.ContainsAny(name, "\x00‮") {
		t.Fatalf("name not sanitised: %q", name)
	}
	_, ch := pkce(t)
	_, page := e.get(e.authURL(out["client_id"].(string), cb, ch, "s", nil))
	if strings.Contains(page, "<script>alert(1)") {
		t.Fatal("application name rendered unescaped")
	}
}

func TestRegistrationIsRateLimitedAndCapped(t *testing.T) {
	e := newEnvOAuthLimited(t)
	denied := 0
	for i := 0; i < 15; i++ {
		if st, _ := e.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{cb}}); st == http.StatusTooManyRequests {
			denied++
		}
	}
	if denied == 0 {
		t.Error("no rate limit on open registration")
	}
	e2 := newEnvOAuth(t)
	for i := 0; i < oauth.MaxApps; i++ {
		if err := e2.oauth.CreateApp(ctx0, oauth.App{ID: strings.Repeat("a", 24) + padInt(i), Name: "x", RedirectURIs: []string{cb}, CreatedAt: e2.clk.now()}); err != nil {
			t.Fatal(err)
		}
	}
	if st, out := e2.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{cb}}); st != 503 {
		t.Errorf("registration beyond the cap: %d %v", st, out)
	}
}

func padInt(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(i>>28)&15], digits[(i>>24)&15], digits[(i>>20)&15], digits[(i>>16)&15], digits[(i>>12)&15], digits[(i>>8)&15], digits[(i>>4)&15], digits[i&15]})
}

// ---------------------------------------------------------------------------------------------------------------------
// the authorization request

func TestAuthorizeNeverRedirectsToAnUnverifiedAddress(t *testing.T) {
	e := newEnvOAuth(t)
	app := e.registerApp("Claude", claudeCB)
	_, ch := pkce(t)
	for name, u := range map[string]string{
		"unknown client":         e.authURL("00000000000000000000000000000000", claudeCB, ch, "s", nil),
		"no client":              e.authURL("", claudeCB, ch, "s", nil),
		"other redirect":         e.authURL(app, "https://evil.example.com/cb", ch, "s", nil),
		"prefix of the redirect": e.authURL(app, claudeCB+"/x", ch, "s", nil),
		"redirect with query":    e.authURL(app, claudeCB+"?a=b", ch, "s", nil),
		"different case":         e.authURL(app, strings.ToUpper(claudeCB), ch, "s", nil),
		"no redirect":            e.authURL(app, "", ch, "s", nil),
	} {
		resp, body := e.get(u)
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Errorf("%s: %d location=%q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		if strings.Contains(body, "evil.example.com") && strings.Contains(body, "href") {
			t.Errorf("%s: error page links to the attacker address", name)
		}
	}
}

func TestAuthorizeRequiresPKCEAndTheRightResource(t *testing.T) {
	e := newEnvOAuth(t)
	app := e.registerApp("Claude", claudeCB)
	_, ch := pkce(t)
	for name, c := range map[string]struct {
		extra map[string]string
		want  string
	}{
		"no challenge":           {map[string]string{"code_challenge": ""}, "invalid_request"},
		"plain method":           {map[string]string{"code_challenge_method": "plain"}, "invalid_request"},
		"no method":              {map[string]string{"code_challenge_method": ""}, "invalid_request"},
		"short challenge":        {map[string]string{"code_challenge": "abc"}, "invalid_request"},
		"implicit flow":          {map[string]string{"response_type": "token"}, "unsupported_response_type"},
		"another resource":       {map[string]string{"resource": "https://other.example.com/mcp"}, "invalid_target"},
		"resource with a suffix": {map[string]string{"resource": mcpRes + "/"}, "invalid_target"},
		"oversized state":        {map[string]string{"state": strings.Repeat("s", 600)}, "invalid_request"},
	} {
		resp, _ := e.get(e.authURL(app, claudeCB, ch, "keep-me", c.extra))
		if resp.StatusCode != http.StatusFound {
			t.Errorf("%s: %d, want an error redirect", name, resp.StatusCode)
			continue
		}
		q := location(t, resp).Query()
		if q.Get("error") != c.want || q.Get("code") != "" || q.Get("iss") != publicBase {
			t.Errorf("%s: %v, want error=%s with iss", name, q, c.want)
		}
		if name != "oversized state" && q.Get("state") != "keep-me" {
			t.Errorf("%s: state not echoed", name)
		}
	}
	// without a resource parameter the request is still bound to this server's resource
	resp, _ := e.get(e.authURL(app, claudeCB, ch, "s", map[string]string{"resource": ""}))
	if resp.StatusCode != 200 {
		t.Errorf("default resource: %d", resp.StatusCode)
	}
}

func TestConsentPageIsSafeToShow(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	app := e.registerApp("Claude", claudeCB)
	_, ch := pkce(t)
	resp, page := e.get(e.authURL(app, claudeCB, ch, "s", nil))
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", resp.Header)
	}
	if strings.Contains(page, "<script") || strings.Contains(page, "http://") && !strings.Contains(page, "relay.test") {
		t.Error("the page loads or runs something")
	}
	if !strings.Contains(page, "claude.ai") || !strings.Contains(page, "Claude") {
		t.Error("the page does not show who is asking and where it returns to")
	}
	if regexp.MustCompile(`<input[^>]*\bchecked\b`).MatchString(page) || !strings.Contains(page, `type="checkbox"`) {
		t.Error("a permission is pre-selected: nothing may be granted by default")
	}
	if !strings.Contains(page, d.ID+"|devices:read") {
		t.Error("the device and scope are not offered")
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// the owner's approval

func (e *env) consentPage(app string) (req string) {
	e.t.Helper()
	_, ch := pkce(e.t)
	resp, page := e.get(e.authURL(app, cb, ch, "s", nil))
	if resp.StatusCode != 200 {
		e.t.Fatalf("consent page: %d", resp.StatusCode)
	}
	return pendingReq(e.t, page)
}

func TestApprovalNeedsTheAdminTokenAndFailuresAreAudited(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	app := e.registerApp("Claude")
	req := e.consentPage(app)
	before, _ := e.clients.ListClients(ctx0)
	for _, bad := range []string{"", "wrong-token-wrong-token-wrong-token-0000", "Bearer " + adminToken, adminToken + " "} {
		resp, body := e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"approve"}, "admin_token": {bad}, "grant": grantValues(grant{d, readOnly})})
		if resp.StatusCode != 401 || resp.Header.Get("Location") != "" {
			t.Fatalf("bad token %q: %d", bad, resp.StatusCode)
		}
		if strings.Contains(body, adminToken) {
			t.Fatal("the admin token was echoed back")
		}
	}
	after, _ := e.clients.ListClients(ctx0)
	if len(after) != len(before) {
		t.Fatal("a client was created without a valid admin token")
	}
	denied := false
	for _, ev := range e.audit.All() {
		if ev.Action == "oauth.authorize" && ev.Outcome == "denied" && ev.Detail["reason"] == "bad_admin_token" {
			denied = true
		}
	}
	if !denied {
		t.Error("failed approvals were not audited")
	}
}

func TestApprovalRetriesAreBounded(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	req := e.consentPage(e.registerApp("Claude"))
	form := url.Values{"req": {req}, "action": {"approve"}, "admin_token": {"nope"}, "grant": grantValues(grant{d, readOnly})}
	for i := 0; i < 5; i++ {
		e.postForm("/oauth/authorize", form)
	}
	form.Set("admin_token", adminToken) // even the right token no longer works on a request that was guessed at too often
	var last int
	for i := 0; i < 3; i++ {
		resp, _ := e.postForm("/oauth/authorize", form)
		last = resp.StatusCode
	}
	if last == http.StatusFound {
		t.Fatal("approval succeeded after repeated wrong attempts on the same request")
	}
}

func TestApprovalRejectsEmptyOrUnknownPermissions(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	other := e.device(false)
	if err := e.devices.Revoke(ctx0, other.ID); err != nil {
		t.Fatal(err)
	}
	for name, grants := range map[string][]string{
		"nothing ticked":          nil,
		"unknown scope":           {d.ID + "|admin:everything"},
		"a scope not on the menu": {d.ID + "|capability:sms.read:execute"},
		"wildcard":                {d.ID + "|capability:*:execute"},
		"unknown device":          {strings.Repeat("a", 64) + "|devices:read"},
		"revoked device":          {other.ID + "|devices:read"},
		"malformed":               {"devices:read"},
	} {
		req := e.consentPage(e.registerApp("Claude"))
		before, _ := e.clients.ListClients(ctx0)
		resp, _ := e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"approve"}, "admin_token": {adminToken}, "grant": grants})
		after, _ := e.clients.ListClients(ctx0)
		if resp.StatusCode != 400 || len(after) != len(before) {
			t.Errorf("%s: status %d, clients %d -> %d", name, resp.StatusCode, len(before), len(after))
		}
	}
}

func TestOwnerCanDeny(t *testing.T) {
	e := newEnvOAuth(t)
	req := e.consentPage(e.registerApp("Claude"))
	resp, _ := e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"deny"}})
	q := location(t, resp).Query()
	if q.Get("error") != "access_denied" || q.Get("code") != "" || q.Get("iss") != publicBase {
		t.Fatalf("%v", q)
	}
	// the request is used up
	resp, _ = e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"approve"}, "admin_token": {adminToken}})
	if resp.StatusCode != 400 {
		t.Errorf("a denied request could still be approved: %d", resp.StatusCode)
	}
}

func TestPendingRequestsExpireAndCannotBeInvented(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	req := e.consentPage(e.registerApp("Claude"))
	e.clk.advance(11 * time.Minute)
	resp, _ := e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"approve"}, "admin_token": {adminToken}, "grant": grantValues(grant{d, readOnly})})
	if resp.StatusCode != 400 {
		t.Errorf("expired request: %d", resp.StatusCode)
	}
	resp, _ = e.postForm("/oauth/authorize", url.Values{"req": {"0123456789abcdef0123456789abcdef"}, "action": {"approve"}, "admin_token": {adminToken}, "grant": grantValues(grant{d, readOnly})})
	if resp.StatusCode != 400 {
		t.Errorf("unknown request id: %d", resp.StatusCode)
	}
}

func TestNoAuditNoApproval(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	req := e.consentPage(e.registerApp("Claude"))
	before, _ := e.clients.ListClients(ctx0)
	e.audit.FailAppend = errors.New("disk full")
	resp, _ := e.postForm("/oauth/authorize", url.Values{"req": {req}, "action": {"approve"}, "admin_token": {adminToken}, "grant": grantValues(grant{d, readOnly})})
	e.audit.FailAppend = nil
	after, _ := e.clients.ListClients(ctx0)
	if resp.StatusCode != 503 || len(after) != len(before) || resp.Header.Get("Location") != "" {
		t.Fatalf("approval went ahead without an audit record: %d, clients %d -> %d", resp.StatusCode, len(before), len(after))
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// the token endpoint

func TestAuthorizationCodeIsSingleUseAndBoundToItsRequest(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	newCode := func() (app, code, ver string) {
		app = e.registerApp("Claude")
		v, ch := pkce(t)
		return app, e.approveFlow(app, cb, ch, grant{d, readOnly}).Query().Get("code"), v
	}
	base := func(app, code, ver string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {app}, "redirect_uri": {cb}, "code_verifier": {ver}}
	}
	expectBad := func(name string, f url.Values, wantErr string) {
		t.Helper()
		if st, out := e.token(f); st != 400 || out["error"] != wantErr || out["access_token"] != nil {
			t.Errorf("%s: %d %v, want %s", name, st, out, wantErr)
		}
	}

	app, code, ver := newCode()
	if st, out := e.token(base(app, code, ver)); st != 200 || out["token_type"] != "Bearer" || out["access_token"] == nil || out["refresh_token"] == nil {
		t.Fatalf("first use: %d %v", st, out)
	}
	expectBad("second use", base(app, code, ver), "invalid_grant")

	app, code, ver = newCode()
	f := base(app, code, "wrong"+ver)
	expectBad("wrong verifier", f, "invalid_grant")
	expectBad("the right verifier after a wrong one (code is burned)", base(app, code, ver), "invalid_grant")

	app, code, ver = newCode()
	f = base(app, code, ver)
	f.Set("redirect_uri", "http://127.0.0.1:9/other")
	expectBad("other redirect_uri", f, "invalid_grant")

	app, code, ver = newCode()
	f = base(app, code, ver)
	f.Set("client_id", e.registerApp("Other"))
	expectBad("other client", f, "invalid_grant")

	app, code, ver = newCode()
	f = base(app, code, ver)
	f.Set("resource", "https://other.example.com/mcp")
	expectBad("other resource", f, "invalid_target")

	app, code, ver = newCode()
	e.clk.advance(61 * time.Second)
	expectBad("expired code", base(app, code, ver), "invalid_grant")

	app, code, ver = newCode()
	f = base(app, code, ver)
	f.Del("code_verifier")
	expectBad("no verifier", f, "invalid_request")
	f = base(app, code, ver)
	f.Set("grant_type", "password")
	expectBad("password grant", f, "unsupported_grant_type")
	f.Set("grant_type", "client_credentials")
	expectBad("client credentials", f, "unsupported_grant_type")
}

func TestTokenEndpointOnlyTakesFormPosts(t *testing.T) {
	e := newEnvOAuth(t)
	if resp, err := http.Get(e.srv.URL + "/oauth/token?grant_type=refresh_token&refresh_token=x&client_id=y"); err != nil || resp.StatusCode != 405 {
		t.Errorf("GET /oauth/token: %v %v", resp, err)
	}
	resp, err := http.Post(e.srv.URL+"/oauth/token", "application/json", strings.NewReader(`{"grant_type":"refresh_token"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("JSON body: %d", resp.StatusCode)
	}
	// secrets in the URL are never read
	st, out := e.token(url.Values{})
	if st != 400 {
		t.Errorf("empty form: %d %v", st, out)
	}
}

func TestTokenResponsesAreNotCacheable(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	app := e.registerApp("Claude")
	ver, ch := pkce(t)
	code := e.approveFlow(app, cb, ch, grant{d, readOnly}).Query().Get("code")
	resp, _ := e.postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {app}, "redirect_uri": {cb}, "code_verifier": {ver}})
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
		t.Errorf("headers: %v", resp.Header)
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// audience: an OAuth token is for /mcp only

func TestOAuthTokenWorksOnMCPButNotOnTheRESTAPI(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	for _, path := range []string{"/v1/devices", "/v1/me", "/v1/devices/" + d.ID} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+c.access)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s accepted an OAuth token: %d", path, resp.StatusCode)
		}
	}
	if _, err := e.session(c.access); err != nil {
		t.Fatalf("MCP refused its own OAuth token: %v", err)
	}
	// and the key-login tokens keep working on both
	k := e.client(grant{d, readAndInfo})
	if _, err := e.session(k.token); err != nil {
		t.Fatalf("key-login token on MCP: %v", err)
	}
}

func TestOAuthTokenCannotAdministerTheRelay(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	c := e.connect("Claude", grant{d, readOnly})
	for _, p := range []string{"/v1/admin/clients", "/v1/admin/audit"} {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+c.access)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// refresh tokens

func TestRefreshRotatesAndKeepsTheSameGrants(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	e.clk.advance(11 * time.Minute) // the access token has expired
	if _, err := e.session(c.access); err == nil {
		t.Fatal("an expired access token still worked")
	}
	st, out := e.refreshWith(c, c.refresh)
	if st != 200 || out["refresh_token"] == nil || out["refresh_token"] == c.refresh || out["access_token"] == c.access {
		t.Fatalf("%d %v", st, out)
	}
	s := mustSession(t, e, out["access_token"].(string))
	if r, err := call(t, s, "get_device_info", map[string]any{"device_id": d.ID}); err != nil || r.IsError {
		t.Fatalf("after refresh: %v %v", err, r)
	}
	// it can be refreshed again, each time with the newest token
	if st, out2 := e.refreshWith(c, out["refresh_token"].(string)); st != 200 || out2["refresh_token"] == out["refresh_token"] {
		t.Fatalf("second refresh: %d %v", st, out2)
	}
}

func TestReusedRefreshTokenClosesTheWholeConnection(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	st, fresh := e.refreshWith(c, c.refresh) // legitimate rotation
	if st != 200 {
		t.Fatal(st, fresh)
	}
	liveAccess := fresh["access_token"].(string)
	if _, err := e.session(liveAccess); err != nil {
		t.Fatal(err)
	}
	// someone replays the OLD refresh token
	if st, out := e.refreshWith(c, c.refresh); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", st, out)
	}
	// the newest refresh token and the live access token are dead too
	if st, out := e.refreshWith(c, fresh["refresh_token"].(string)); st != 400 {
		t.Errorf("the family survived the replay: %d %v", st, out)
	}
	if _, err := e.session(liveAccess); err == nil {
		t.Error("an access token survived a refresh-token replay")
	}
	reused := false
	for _, ev := range e.audit.All() {
		if ev.Action == "oauth.refresh_reuse" && ev.Outcome == "denied" {
			reused = true
		}
	}
	if !reused {
		t.Error("the replay was not audited")
	}
}

func TestRefreshTokenIsBoundToItsClientAndResource(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	c := e.connect("Claude", grant{d, readOnly})
	other := e.registerApp("Other")
	if st, out := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c.refresh}, "client_id": {other}}); st != 400 || out["error"] != "invalid_grant" {
		t.Errorf("another client used the token: %d %v", st, out)
	}
	// a token presented by the wrong client is treated as stolen: the real owner's copy is gone too
	if st, _ := e.refreshWith(c, c.refresh); st != 400 {
		t.Error("the stolen token still worked for its owner")
	}
	c2 := e.connect("Claude2", grant{d, readOnly})
	if st, out := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c2.refresh}, "client_id": {c2.appID}, "resource": {"https://other.example.com/mcp"}}); st != 400 || out["error"] != "invalid_target" {
		t.Errorf("resource switch: %d %v", st, out)
	}
	for _, bad := range []string{"", "avr_nonsense", strings.Repeat("a", 500)} {
		if st, _ := e.refreshWith(c2, bad); st != 400 {
			t.Errorf("garbage refresh token %q: %d", bad, st)
		}
	}
}

func TestRefreshTokensExpire(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(false)
	c := e.connect("Claude", grant{d, readOnly})
	e.clk.advance(oauth.RefreshTTL + time.Minute)
	if st, out := e.refreshWith(c, c.refresh); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("expired refresh token: %d %v", st, out)
	}

	// Even a connection that is refreshed on time must be re-approved by the owner after the family lifetime.
	c = e.connect("Claude-long", grant{d, readOnly})
	tok := c.refresh
	var last int
	for i := 0; i < 5; i++ { // 5 x 25 days > 90 days
		e.clk.advance(25 * 24 * time.Hour)
		st, out := e.refreshWith(c, tok)
		last = st
		if st != 200 {
			break
		}
		tok = out["refresh_token"].(string)
	}
	if last == 200 {
		t.Fatal("a connection lived past its absolute lifetime without the owner approving again")
	}
}

func TestRevokingTheClientCutsOffOAuthAccessAtOnce(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	s := mustSession(t, e, c.access)
	if _, err := call(t, s, "list_devices", nil); err != nil {
		t.Fatal(err)
	}
	subject := e.subjectOf(t, "Claude")
	if st, _ := e.adminPost("/v1/admin/clients/"+subject+"/revoke", map[string]any{}); st != 200 {
		t.Fatalf("revoke: %d", st)
	}
	if _, err := e.session(c.access); err == nil {
		t.Error("the access token works after the client was revoked")
	}
	if st, out := e.refreshWith(c, c.refresh); st != 400 || out["error"] != "invalid_grant" {
		t.Errorf("refresh after revoke: %d %v", st, out)
	}
	if d.received.Load() != 0 {
		t.Error("a revoked connection reached the phone")
	}
}

func TestTwoConnectionsAreIsolated(t *testing.T) {
	e := newEnvOAuth(t)
	a, b := e.device(true), e.device(true)
	c1 := e.connect("One", grant{a, readAndInfo})
	c2 := e.connect("Two", grant{b, readAndInfo})
	for _, tc := range []struct {
		tok       string
		own, deny *phone
	}{{c1.access, a, b}, {c2.access, b, a}} {
		s := mustSession(t, e, tc.tok)
		if r, err := call(t, s, "get_device_info", map[string]any{"device_id": tc.own.ID}); err != nil || r.IsError {
			t.Errorf("own device: %v %v", err, r)
		}
		if r, err := call(t, s, "get_device_info", map[string]any{"device_id": tc.deny.ID}); err == nil && !r.IsError {
			t.Error("a connection reached the other connection's device")
		}
	}
	// revoking one leaves the other alone
	e.adminPost("/v1/admin/clients/"+e.subjectOf(t, "One")+"/revoke", map[string]any{})
	if _, err := e.session(c2.access); err != nil {
		t.Errorf("revoking one connection broke another: %v", err)
	}
}

func TestOAuthEventsAreAuditedAndNoSecretIsLogged(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	_, fresh := e.refreshWith(c, c.refresh)
	seen := map[string]bool{}
	for _, ev := range e.audit.All() {
		seen[ev.Action] = true
	}
	for _, a := range []string{"oauth.register", "oauth.authorize", "oauth.connected", "oauth.token"} {
		if !seen[a] {
			t.Errorf("no %s audit event", a)
		}
	}
	logs := e.logs.String()
	for name, secret := range map[string]string{"admin token": adminToken, "access token": c.access, "refresh token": c.refresh, "new refresh token": fresh["refresh_token"].(string), "verifier": c.verifier} {
		if strings.Contains(logs, secret) {
			t.Errorf("%s in the relay log", name)
		}
	}
	for _, ev := range e.audit.All() {
		b, _ := json.Marshal(ev)
		for name, secret := range map[string]string{"admin token": adminToken, "access token": c.access, "refresh token": c.refresh} {
			if strings.Contains(string(b), secret) {
				t.Errorf("%s in an audit event: %s", name, b)
			}
		}
	}
}

func TestMCPRejectsATokenIssuedForAnotherResource(t *testing.T) {
	e := newEnvOAuth(t)
	d := e.device(true)
	c := e.connect("Claude", grant{d, readAndInfo})
	subject := e.subjectOf(t, "Claude")
	// A token for the right client but bound to some other server must not be accepted here (RFC 8707 audience validation).
	foreign, _, err := e.authn.IssueForResource(ctx0, subject, "https://other.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.session(foreign); err == nil {
		t.Fatal("MCP accepted a token whose audience is another resource")
	}
	if resp, _ := rawPost(t, e, foreign, nil, strings.Replace(initBody, "%s", "2025-06-18", 1)); resp.StatusCode != 401 {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	if _, err := e.session(c.access); err != nil {
		t.Errorf("the correctly bound token stopped working: %v", err)
	}
}
