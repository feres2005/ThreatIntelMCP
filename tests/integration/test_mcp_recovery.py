import asyncio
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[2]


async def exercise_mcp_recovery():
    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.server"],
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
    )

    async with stdio_client(
        server_parameters
    ) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
        ) as session:
            await session.initialize()

            first_ping = await session.call_tool(
                "ping",
                {},
            )

            failed_call = await session.call_tool(
                "get_cve_details",
                {"cve_id": "not-a-cve"},
            )

            second_ping = await session.call_tool(
                "ping",
                {},
            )

    return first_ping, failed_call, second_ping


def test_mcp_session_recovers_after_tool_error():
    first_ping, failed_call, second_ping = (
        asyncio.run(exercise_mcp_recovery())
    )

    assert first_ping.isError is False
    assert first_ping.content[0].text == (
        "ThreatIntelMCP is running"
    )

    assert failed_call.isError is True
    assert "CVE ID must follow the format" in (
        failed_call.content[0].text
    )

    assert second_ping.isError is False
    assert second_ping.content[0].text == (
        "ThreatIntelMCP is running"
    )
