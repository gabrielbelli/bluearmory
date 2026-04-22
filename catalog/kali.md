# Kali MCP

Official Kali Linux MCP server from OffSec — provides access to Kali tools for security testing and analysis.

- **Source:** [offsec/kali-mcp](https://github.com/offsec/kali-mcp)
- **Transport:** stdio (via SSH) or local

## MCP Config (SSH)

```json
{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": ["-T", "-o", "RequestTTY=no", "kali", "mcp-server"]
    }
  }
}
```
