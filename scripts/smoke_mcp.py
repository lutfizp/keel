from __future__ import annotations

import asyncio
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = {
    "begin_engagement",
    "draft_waves",
    "execute_wave",
    "query_cards",
    "second_look",
    "state_impact",
    "draft_proof",
    "execute_proof",
    "engagement_health",
    "engagement_audit",
}


async def smoke() -> None:
    with tempfile.TemporaryDirectory(prefix="keel-mcp-smoke-") as state_dir:
        env = os.environ.copy()
        env["KEEL_DATA_DIR"] = state_dir
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "keel"],
            env=env,
        )
        async with stdio_client(server) as streams:
            async with ClientSession(*streams) as session:
                initialized = await session.initialize()
                catalog = await session.list_tools()
                health = await session.call_tool("engagement_health", arguments={})

    names = {tool.name for tool in catalog.tools}
    if names != EXPECTED_TOOLS:
        missing = sorted(EXPECTED_TOOLS - names)
        extra = sorted(names - EXPECTED_TOOLS)
        raise RuntimeError(f"unexpected MCP tools: missing={missing}, extra={extra}")

    is_error = getattr(health, "isError", getattr(health, "is_error", False))
    if is_error:
        raise RuntimeError(f"engagement_health tool call failed: {health}")

    server_info = getattr(initialized, "server_info", None)
    if server_info is None:  # MCP Python SDK 1.x field alias
        server_info = initialized.serverInfo
    print(
        f"MCP handshake and tool call ok: "
        f"{server_info.name} {server_info.version}; {len(names)} tools"
    )


if __name__ == "__main__":
    asyncio.run(smoke())
