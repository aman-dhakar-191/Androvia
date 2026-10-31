# Connecting an MCP host by URL (OAuth)

With `RELAY_OAUTH_ENABLED=true` the relay is also an OAuth 2.1 authorization server, so a remote MCP host can be pointed at
`https://<your relay>/mcp`, send you to a consent page, and be connected, with nothing installed on your computer.
(The alternative that needs a local program is the stdio bridge, `docs/mcp.md`.)

## Status
| | |
|---|---|
| Implemented | OAuth server in `internal/oauth`: RFC 8414 metadata, RFC 7591 dynamic registration (public clients), authorization code + **PKCE S256**, RFC 8707 resource binding, RFC 9207 `iss`, rotating refresh tokens, owner consent page |
| Tested | Go: 43 new test functions (the whole suite is 293 cases, 0 failed, 0 skipped, with PostgreSQL), covering the flow, every rejection, audience, refresh rotation/replay/expiry, revocation, isolation, audit-first, no secrets in logs, both stores incl. real PostgreSQL; 12 mutation checks (removing PKCE, the redirect match, the admin-token check, replay detection, audience checks, audit-first, … each makes a test fail). **The official Python MCP SDK OAuth client** completes the whole flow against the real relay binary in CI (job `MCP interop`) |
| **Not tested** | **Claude (claude.ai / Desktop / Code) or any other real host.** Whether a given host accepts this server's registration and metadata is unverified. See "Unknowns" |
| Not implemented | Client ID Metadata Documents (the spec's preferred registration; hosts that only use them will fail), phone-side approval, a separate owner password (the admin token is the owner credential), CORS for browser-based clients, OpenID Connect discovery |

## What you need
1. The relay reachable over **HTTPS** at a public address (OAuth requires it). The phone also connects to it. This repository
   does not host anything for you; see "Hosting".
2. `RELAY_OAUTH_ENABLED=true` in the relay's environment. It is off by default.
3. A registered, online phone (`docs/relay.md`).

## Connecting
1. In the MCP host, add a remote/custom MCP server with the URL `https://<your relay>/mcp`. (Where this is in each host's UI
   is the host's business; I have not verified it for any real host.)
2. The host discovers the sign-in server, registers itself and opens your browser on the relay's consent page.
3. The page shows **who is asking** and **which address it will return to**. For each registered device, tick exactly the
   permissions to give it; **nothing is ticked by default**. Type the **relay admin token** (it proves you own the relay; it
   is checked and never stored) and press Approve. Deny, or closing the page, grants nothing.
4. The host is connected. Its access token lasts 10 minutes (`RELAY_TOKEN_TTL_MINUTES`) and is renewed silently with a
   refresh token (30 days; each use issues a new one; after 90 days you must approve again).

## What approving creates
Approving creates one new Androvia client, named `oauth: <application name>`, holding **only** the grants you ticked. From
there everything is the existing machinery: per-call authorization, audit (`channel: mcp`), and revocation. To cut a
connection off: `POST /v1/admin/clients/{id}/revoke` (find it with `GET /v1/admin/clients`); the access token stops working
on its next request and the refresh token can no longer be used.

## Properties
* **Audience-bound.** The access token is for `/mcp` only. The REST API and the admin API reject it; `/mcp` rejects a token
  bound to any other resource.
* **No redirect to an unverified address.** An unknown application or a `redirect_uri` that is not an exact match with what
  was registered gets an error page, never a redirect. Registered redirect URIs must be `https`, or `http` to localhost.
* **Codes** are 256-bit, valid 60 s, single use, and bound to the application, redirect URI, PKCE challenge and resource.
* **Refresh tokens** are stored hashed, rotate on every use, and presenting an already-used one (a sign that a copy exists)
  closes the whole connection: no refresh, and live access tokens are dropped. A valid refresh token presented by a
  different application is treated the same way.
* **Audit-first.** An approval that cannot be recorded in the audit log does not happen. Events: `oauth.register`,
  `oauth.authorize` (allowed/denied, with the reason), `oauth.connected`, `oauth.token`, `oauth.refresh_reuse`. Tokens,
  codes and the admin token are never logged or audited.
* **Abuse limits.** Registration: 10 per minute per address and 200 in total. Wrong admin token: 10 per minute per address,
  and 5 tries per consent request. Open consent requests: 500; unredeemed codes: 2000.

## Configuration
| Variable | |
|---|---|
| `RELAY_OAUTH_ENABLED` | `true` turns the OAuth server on (default off). The public origin must be `wss://…` (HTTPS) |

## Hosting
The relay is a single binary plus PostgreSQL (`relay/Dockerfile`, `deploy/docker-compose.yml`). Anything that gives it a
public HTTPS address works: a small VPS behind a TLS reverse proxy, or a container platform that terminates TLS for you. When
a proxy terminates TLS, set `RELAY_PUBLIC_ORIGIN=wss://your.host` and `RELAY_ALLOW_INSECURE_HTTP=true` (the flag only lets the
relay itself listen on plain HTTP behind the proxy; the public address must still be HTTPS). Run **one** relay instance:
pending approvals and codes are held in memory (`docs/relay.md`).

## Unknowns (read before relying on this)
* **Real hosts.** The server follows the MCP authorization spec and passes the official Python SDK's client, but I have not
  connected Claude or any other product. The risks I can name: a host that only supports Client ID Metadata Documents; a
  host that expects an `openid-configuration` document; a host that wants a `scope`. None of these is known to happen.
* **The admin token is typed into a web page.** A page that looks like this one on another domain could phish it. Check the
  address bar is your relay. A separate, lower-power owner password and phone-side approval are better and not built.
* **Application names are self-asserted** by whoever registers. A malicious application can pick a convincing name; the
  consent page therefore also shows the return address, and you only ever approve connections you started.
