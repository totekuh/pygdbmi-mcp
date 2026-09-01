"""Black-box MCP stdio handshake and structured-content integration test."""

from __future__ import annotations

import sys

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_protocol_catalog_envelopes_and_lifespan_cleanup() -> None:
    async def exercise() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "pygdbmi_mcp.server"],
        )
        async with stdio_client(parameters, errlog=sys.stderr) as (  # noqa: SIM117
            reader,
            writer,
        ):
            async with ClientSession(reader, writer) as session:
                initialized = await session.initialize()
                assert "gdb_wait_for_stop" in initialized.instructions
                catalog = await session.list_tools()
                assert len(catalog.tools) == 73
                context = next(
                    tool for tool in catalog.tools if tool.name == "gdb_context"
                )
                assert context.annotations.readOnlyHint is True
                assert (
                    context.inputSchema["properties"]["backtrace_depth"]["maximum"]
                    == 64
                )

                started = await session.call_tool("gdb_start", {})
                assert started.isError is False
                assert started.structuredContent["schema"] == "pygdbmi.mcp/1"
                assert started.structuredContent["ok"] is True
                session_id = started.structuredContent["result"]["session_id"]

                capabilities = await session.call_tool(
                    "gdb_capabilities", {"session_id": session_id}
                )
                assert capabilities.isError is False
                assert capabilities.structuredContent["ok"] is True
                assert capabilities.structuredContent["result"]["revision"] == (
                    "pygdbmi.capabilities/1"
                )

                logical_error = await session.call_tool(
                    "gdb_command",
                    {"session_id": "missing", "command": "help"},
                )
                assert logical_error.isError is False
                assert logical_error.structuredContent["ok"] is False
                assert logical_error.structuredContent["error"]["code"] == "no_session"

                stopped = await session.call_tool(
                    "gdb_stop", {"session_id": session_id}
                )
                assert stopped.isError is False
                assert stopped.structuredContent["ok"] is True

    anyio.run(exercise)
