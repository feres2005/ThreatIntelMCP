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
      article_result=await session.call_tool(
        "get_threat_article_details",
        {
          "article_id":2562
        }
      )
      result = await session.call_tool(
        "lookup_otx_indicator",
        {
            "indicator": "1.1.1.1",
            "indicator_type": "IPv4",
        },
    )

      print("\nOTX indicator details:")
      print(result.content)
      
      
      
      

if __name__ == "__main__":
  asyncio.run(main())