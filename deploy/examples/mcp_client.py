#!/usr/bin/env python3
"""Talk to an Androvia relay's MCP endpoint with the OFFICIAL Python MCP SDK (an implementation independent of the relay's).

    pip install mcp
    TOKEN=$(./client-login.sh login https://relay.example.com wss://relay.example.com)
    python mcp_client.py [--discover] https://relay.example.com/mcp "$TOKEN" [device_id]

--discover skips the old initialize handshake and uses server/discover, i.e. the stateless protocol revision 2026-07-28.

Access tokens last 10 minutes by default, so fetch a fresh one for each run. Exit status 0 only if every check passes,
which makes this usable as a smoke test.
"""
import asyncio
import json
import sys

import httpx2 as httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


async def main(url: str, token: str, device_id: str | None, discover: bool) -> None:
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as streams:
            read, write, *_ = streams
            async with ClientSession(read, write) as session:
                if discover:
                    found = await session.discover()
                    print("supported versions:", found.supported_versions)
                    if session.protocol_version != "2026-07-28":
                        fail(f"expected the 2026-07-28 protocol, got {session.protocol_version}")
                else:
                    await session.initialize()
                print("protocol version:", session.protocol_version)

                tools = await session.list_tools()
                names = [t.name for t in tools.tools]
                print("tools:", names)
                if "list_devices" not in names:
                    fail("list_devices is not offered although the client has devices:read")

                listed = await session.call_tool("list_devices", {})
                if listed.is_error:
                    fail(f"list_devices returned an error: {listed.content}")
                devices = listed.structured_content["devices"]
                print("devices:", json.dumps(devices))
                if not devices:
                    fail("no devices visible")
                target = device_id or devices[0]["device_id"]

                if "get_device_info" in names:
                    info = await session.call_tool("get_device_info", {"device_id": target})
                    if info.is_error:
                        fail(f"get_device_info returned an error: {info.structured_content}")
                    print("device info:", json.dumps(info.structured_content))
                    if "model" not in info.structured_content:
                        fail("device info has no model")

                # A tool outside the allowlist and a smuggled identity must both be refused.
                for name, args in (("run_shell", {"command": "id"}), ("get_device_info", {"device_id": target, "client_id": "someone-else"})):
                    try:
                        r = await session.call_tool(name, args)
                        refused = bool(r.is_error)
                    except Exception:  # a protocol-level error is also a refusal
                        refused = True
                    if not refused:
                        fail(f"{name} with {args} was not refused")
                print("refusals ok")
    print("OK")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--discover"]
    if len(args) < 2:
        sys.exit(__doc__)
    asyncio.run(main(args[0], args[1], args[2] if len(args) > 2 else None, "--discover" in sys.argv))
