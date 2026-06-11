import asyncio
import os
from dotenv import load_dotenv
from mcp import StdioServerParameters
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams

load_dotenv()


def get_gitlab_mcp_toolset() -> MCPToolset:
    """
    Returns an ADK MCPToolset connected to the GitLab MCP server via stdio.
    The MCP server runs as a subprocess using the official @modelcontextprotocol/server-gitlab package.
    Uses the GitLab PAT for authentication — no OAuth flow needed for server-side use.
    """
    gitlab_token = os.getenv("GITLAB_TOKEN")
    if not gitlab_token:
        raise Exception("GITLAB_TOKEN not set in environment")

    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="npx",
                args=["-y", "@modelcontextprotocol/server-gitlab"],
                env={
                    "GITLAB_PERSONAL_ACCESS_TOKEN": gitlab_token,
                    "GITLAB_API_URL": "https://gitlab.com/api/v4",
                    **dict(os.environ)
                }
            )
        )
    )


async def call_gitlab_mcp_tool(tool_name: str, tool_args: dict) -> str:
    """
    Calls a specific GitLab MCP tool by name with the given arguments.
    Starts the MCP server, calls the tool, and returns the result.
    Used for creating issues and MRs via the official GitLab MCP protocol.
    """
    toolset = get_gitlab_mcp_toolset()
    tools = await toolset.get_tools()

    target_tool = next((t for t in tools if t.name == tool_name), None)

    if not target_tool:
        available = [t.name for t in tools]
        raise Exception(f"MCP tool not found: {tool_name}. Available: {available}")

    result = await target_tool.run_async(args=tool_args, tool_context=None)
    return str(result)


def call_mcp_tool(tool_name: str, tool_args: dict) -> str:
    """
    Synchronous wrapper for call_gitlab_mcp_tool.
    Called from the main pipeline which runs in a non-async context.
    """
    return asyncio.run(call_gitlab_mcp_tool(tool_name, tool_args))