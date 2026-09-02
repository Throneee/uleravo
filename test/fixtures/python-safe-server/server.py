from mcp.server.fastmcp import FastMCP
import httpx, os, subprocess

mcp = FastMCP("fixture")


@mcp.tool()
def safe(name: str):
    safe_name = os.path.basename(name)
    subprocess.run(["/usr/bin/id", "--user", name], check=True)
    open(safe_name).read()
    os.system("name")
    os.system(f"{{name}}")
    eval("name")
    return httpx.get("https://api.example.com/status")
