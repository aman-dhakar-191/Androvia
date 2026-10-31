#!/usr/bin/env python3
"""Connect to an Androvia relay's MCP endpoint the way a remote MCP host does: OAuth discovery, dynamic client registration,
PKCE, an owner approval in a browser, then tool calls and a refresh-token renewal. Uses the OFFICIAL Python MCP SDK's OAuth
client, which is an implementation independent of the relay's.

    pip install mcp
    python mcp_oauth_client.py https://relay.example.com/mcp "$RELAY_ADMIN_TOKEN" <device_id>

The "browser" is played by this script: it opens the consent page, ticks the two permissions for the device and submits the
admin token, exactly as a person would. Exit status 0 only if every check passes (usable as a smoke test).
Needs the relay to run with RELAY_OAUTH_ENABLED=true.
"""
import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from mcp import ClientSession
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_client import check, fail  # noqa: E402  the same tool checks as the bearer-token example

CALLBACK = "http://127.0.0.1:9/callback"  # never contacted: the script reads the redirect itself


class MemoryStorage:
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.client: OAuthClientInformationFull | None = None
        self.history: list[str] = []

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens
        self.history.append(tokens.refresh_token or "")

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, info: OAuthClientInformationFull) -> None:
        self.client = info


async def main(mcp_url: str, admin_token: str, device_id: str) -> None:
    base = mcp_url.removesuffix("/mcp")
    storage = MemoryStorage()
    result: dict[str, AuthorizationCodeResult] = {}

    async def browser(auth_url: str) -> None:
        async with httpx.AsyncClient(follow_redirects=False, timeout=30) as b:
            page = await b.get(auth_url)
            if page.status_code != 200:
                fail(f"consent page answered {page.status_code}: {page.text[:200]}")
            if re.search(r"<input[^>]*\bchecked\b", page.text):
                fail("a permission is pre-selected on the consent page")
            req = re.search(r'name="req" value="([0-9a-f]+)"', page.text)
            if not req:
                fail("no request id on the consent page")
            grants = [f"{device_id}|devices:read", f"{device_id}|capability:device.info:execute"]
            for g in grants:
                if f'value="{g}"' not in page.text:
                    fail(f"permission {g} is not offered")
            done = await b.post(f"{base}/oauth/authorize", data={"req": req.group(1), "action": "approve", "admin_token": admin_token, "grant": grants})
            if done.status_code != 302:
                fail(f"approval answered {done.status_code}: {done.text[:200]}")
            q = parse_qs(urlsplit(done.headers["location"]).query)
            if "code" not in q or "iss" not in q:
                fail(f"redirect lacks code or iss: {done.headers['location']}")
            result["r"] = AuthorizationCodeResult(code=q["code"][0], state=q.get("state", [None])[0], iss=q["iss"][0])
            print("owner approved; redirect carries code and iss")

    async def callback() -> AuthorizationCodeResult:
        return result["r"]

    provider = OAuthClientProvider(
        server_url=mcp_url,
        client_metadata=OAuthClientMetadata(
            client_name="Interop host", redirect_uris=[CALLBACK], grant_types=["authorization_code", "refresh_token"],
            response_types=["code"], token_endpoint_auth_method="none",
        ),
        storage=storage, redirect_handler=browser, callback_handler=callback,
    )

    async with httpx.AsyncClient(auth=provider, timeout=60) as http:
        async with streamable_http_client(mcp_url, http_client=http) as streams:
            read, write, *_ = streams
            async with ClientSession(read, write) as session:
                await check(session, device_id, discover=False)
        if not storage.tokens or not storage.tokens.refresh_token:
            fail("the relay issued no refresh token")
        first_refresh = storage.tokens.refresh_token

        # The access token is only valid for minutes. Pretend it expired: the SDK must renew it with the refresh token.
        provider.context.token_expiry_time = 1.0
        async with streamable_http_client(mcp_url, http_client=http) as streams:
            read, write, *_ = streams
            async with ClientSession(read, write) as session:
                await session.initialize()
                r = await session.call_tool("list_devices", {})
                if r.is_error or not r.structured_content["devices"]:
                    fail(f"call after refresh failed: {r.content}")
        if storage.tokens.refresh_token == first_refresh:
            fail("the refresh token was not rotated")
        print("access token renewed with the refresh token; refresh token rotated")

        # An OAuth token is for /mcp only.
        rest = await httpx.AsyncClient(timeout=30).get(f"{base}/v1/devices", headers={"Authorization": f"Bearer {storage.tokens.access_token}"})
        if rest.status_code != 401:
            fail(f"the REST API accepted an OAuth token: {rest.status_code}")
        print("the OAuth token is refused by the REST API")

        # Replaying the OLD refresh token must close the whole connection.
        async with httpx.AsyncClient(timeout=30) as raw:
            replay = await raw.post(f"{base}/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first_refresh, "client_id": storage.client.client_id})
            if replay.status_code != 400:
                fail(f"a replayed refresh token was accepted: {replay.status_code}")
            newest = await raw.post(f"{base}/oauth/token", data={"grant_type": "refresh_token", "refresh_token": storage.tokens.refresh_token, "client_id": storage.client.client_id})
            if newest.status_code != 400:
                fail("the newest refresh token survived a replay of an old one")
        print("a replayed refresh token closes the connection")
    print("OK")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    asyncio.run(main(*sys.argv[1:4]))
