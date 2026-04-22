# graylog-mcp

MCP server for the Graylog REST API — log search, alerts, streams, and system info.

> **Note:** Graylog 6.1+ ships a [built-in MCP server](https://github.com/Graylog2/graylog2-server). This server targets older Graylog versions (4.x / 5.x) that lack native MCP support.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GRAYLOG_URL` | yes | Graylog base URL (e.g. `http://localhost:9000`) |
| `GRAYLOG_API_TOKEN` | yes | API token (create in System → Users → Tokens) |

## Run

```sh
docker pull ghcr.io/gabrielbelli/graylog-mcp
docker run -i --rm --network host \
  -e GRAYLOG_URL=http://localhost:9000 \
  -e GRAYLOG_API_TOKEN=your-token \
  ghcr.io/gabrielbelli/graylog-mcp
```

## MCP Config

```json
{
  "mcpServers": {
    "graylog": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "host", "-e", "GRAYLOG_URL", "-e", "GRAYLOG_API_TOKEN", "ghcr.io/gabrielbelli/graylog-mcp"],
      "env": {
        "GRAYLOG_URL": "http://localhost:9000",
        "GRAYLOG_API_TOKEN": ""
      }
    }
  }
}
```

## Tools

| Tool | Description |
|---|---|
| `search_relative` | Search messages with relative time range |
| `search_absolute` | Search messages with absolute time range |
| `search_keyword` | Search messages with natural language time range |
| `get_message` | Retrieve a specific message by ID |
| `list_streams` | List all streams |
| `get_stream` | Get stream details |
| `search_events` | Search alert events |
| `list_event_definitions` | List alert/event definitions |
| `system_overview` | Graylog system info |
| `list_inputs` | List configured inputs |
