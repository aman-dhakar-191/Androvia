# ADR 0006 — MCP gateway (Phase 4)

Status: Accepted (implemented; not yet used with a desktop MCP host)
Date: 2026-10-31

## Context
Spec §9 asks for an MCP endpoint over Streamable HTTP that follows the *current* official specification, derives identity
from the transport, exposes an explicit tool allowlist only for capabilities that are enabled and authorised, validates
arguments, returns structured errors, and shares policy, audit and routing with REST.

The specification site was not reachable from the development sandbox. What was verified instead: the spec's source
files on GitHub (the 2026-07-28 changelog, the 2025-11-25 authorization and transport texts) and the official Go SDK
v1.8.0 source, which lists the protocol revisions it supports. **The current revision is `2026-07-28`**, a major change from
what earlier training data describes: no `initialize` handshake, no sessions, `server/discover`, required cache hints on
list results, new request headers.

## Decisions
1. **Use the official Go SDK** instead of hand-rolling JSON-RPC and transport rules for a moving target. It negotiates every
   revision from 2024-11-05 to 2026-07-28, so older and newer clients both work. Cost: the relay now needs **Go 1.25**.
2. **Stateless mode** (`Stateless: true`, JSON responses). It matches the 2026-07-28 direction (no sessions), removes the
   session-hijacking surface, and our tools are plain request/response. Older clients still work: they simply receive no
   session id. Consequence: no server-initiated messages, so `listChanged` is **not** advertised (a test keeps it honest).
3. **One shared command path.** Authorization, auditing and routing moved out of the REST handlers into
   `internal/commands`; REST and MCP are adapters. A policy or audit change cannot apply to one and miss the other, and the
   whole REST test suite doubled as the regression test for the refactor.
4. **A server per request, built from the caller's grants.** `tools/list` offers only tools the client could use; every
   call is checked again, so the list is a convenience and never the control. The list is `cacheScope: private`, `ttlMs: 0`.
5. **Explicit allowlist in code** (`get_device_info`, `list_devices`). Adding a tool is a reviewed change with its schema,
   scope and tests. Nothing is generated from what a device reports.
6. **Non-OAuth bearer authentication, honestly described.** MCP authorization is optional; its OAuth profile targets
   human-operated clients and would require us to run an authorization server with a consent UI. We reuse the
   signed-challenge login (ADR 0005) and publish RFC 9728 metadata without any `authorization_servers`. This limits which MCP
   hosts can connect today (those that can send an `Authorization` header).
7. **Origin validation, body limit, failure rate limit** at the gateway; failed authentication audited.
8. **The authorization header is verified by our authenticator**, and the SDK's bearer middleware only carries the result
   (client id, expiry) to the tool handlers. The client id the tools use is read from the transport, never from arguments.

## Not done, on purpose
* **Device capability advertisement.** Needed to list only tools that are *enabled on the phone* (spec §9). Requires a
  device→relay message and Android UI/state. Until then a listed tool may answer `permission_denied` from the device.
* **OAuth.** If an important MCP host cannot be configured with a custom header, this is the follow-up.

## Consequences
* The 10-minute token is the main usability limit for agents that talk HTTP directly. `cmd/mcpbridge` (stdio⇄HTTP, holds the key,
  logs in and refreshes by itself) removes it for any host that can start a stdio server; it adds no authority of its own.
* Data returned by devices flows into an LLM context: it is untrusted. Every new capability must be reviewed for what it
  returns before it gets a tool.
* The tool allowlist is also a security boundary; the tests that enforce it (unknown tool, extra properties, scope per tool)
  must be extended with every tool.
