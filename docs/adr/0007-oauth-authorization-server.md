# ADR 0007: OAuth authorization server for remote MCP hosts

* Status: accepted (the owner asked for "connect by URL, no installs"; supersedes the "no OAuth" decision of ADR 0006)
* Date: 2026-10-31

## Context
ADR 0006 deliberately shipped MCP without OAuth: clients logged in with a signed challenge and sent a short-lived bearer
token. That works for software that can hold a key (the stdio bridge, scripts) but not for a typical remote MCP host, which
only knows "paste a URL, sign in in a browser". The owner chose to support that ("approach A").

## Decision
The relay is also an OAuth 2.1 authorization server, **opt-in** (`RELAY_OAUTH_ENABLED`), following the MCP authorization
spec (checked against the 2026-07-28 and 2025-11-25 revisions):
1. **Public clients only**, registered by RFC 7591 dynamic registration. The 2026-07-28 spec marks DCR *deprecated* in favour
   of Client ID Metadata Documents; we implement DCR first because it is simple and widely used, and **not** CIMD, whose
   server-side fetch of an attacker-supplied URL needs SSRF protection we have not built. Revisit if a host needs it.
2. **The owner approves on a consent page** that requires the relay admin token and lets them choose devices and scopes;
   nothing is pre-selected. Approval creates a dedicated Androvia client with exactly those grants, so authorization, audit and
   revocation are unchanged. We did not add a user database: the relay has one owner.
3. **Audience-bound access tokens.** OAuth tokens are the existing `avt_` tokens plus an audience; `/mcp` accepts its own
   audience (and key-login tokens), the REST API accepts only key-login tokens.
4. **Rotating refresh tokens in PostgreSQL** (hashed), with reuse detection closing the connection and an absolute
   90-day lifetime. Authorization codes and pending approvals stay in memory (60 s / 10 min; one relay instance, as before).
5. **Opt-in and fail closed**: off by default; the issuer must be HTTPS unless the development flag is set; an approval that
   cannot be audited does not happen.

## Alternatives considered
* **Long-lived API key pasted as a header**: simpler, but reverses the short-lived-token decision and many hosts cannot send
  custom headers.
* **Delegating sign-in to an external identity provider**: no passwords for us to protect, but adds a third-party dependency
  and setup for a single-owner tool. Possible later behind the same endpoints.
* **A separate owner password instead of the admin token**: lower blast radius if phished. Not done to avoid a second secret
  and a hashing/reset story; recorded as the first improvement.

## Consequences
* The admin token is typed into a browser page (threat model T32). Phone-side approval would remove that and is the natural
  next step.
* Anyone can *register* an application (rate limited, capped); registering grants nothing.
* Real-host compatibility is unverified (`docs/oauth.md`, "Unknowns").
