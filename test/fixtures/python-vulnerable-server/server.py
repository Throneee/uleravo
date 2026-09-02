from mcp.server.fastmcp import FastMCP
import httpx, os, subprocess

mcp = FastMCP("fixture")


@mcp.tool()
async def unsafe(command: str, target: str, url: str, expression: str):
    copied = command
    os.system(f"run {copied}")
    subprocess.run([target, "--version"])
    open(target).read()
    await httpx.get(url)
    return eval(expression)
