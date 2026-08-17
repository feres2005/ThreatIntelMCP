import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
  server_params = StdioServerParameters(
    command=sys.executable,
    args=["-m", "mcp_server.server"]
  )

  async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
      await session.initialize()

      tools = await session.list_tools()

      print("Available tools:")

      for tool in tools.tools:
        print("-", tool.name)

      semantic_result = await session.call_tool(
        "semantic_search_threat_articles",
        {
          "search_query": (
            "security flaws in wireless file sharing "
            "that allow nearby attackers to compromise devices"
          ),
          "limit": 5,
        },
      )

      print("\nSemantic search results:")
      print(semantic_result.content)

      cve_result=await session.call_tool(
        "get_cve_details",
        {
          "cve_id":"CVE-2026-55255",
        },
      )
      print("\nCVE lookup result:")
      print(cve_result.content)


      invalid_cve_result = await session.call_tool(
        "get_cve_details",
        {
          "cve_id": "not-a-cve",
        },
      )

      print("\nInvalid CVE result:")
      print("Is error:", invalid_cve_result.isError)
      print(invalid_cve_result.content)
  await asyncio.sleep(0.2)

if __name__ == "__main__":
  asyncio.run(main())
