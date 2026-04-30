# graylog-mcp

MCP server for the Graylog REST API — log search, aggregations, alerts, pipelines, dashboards, and system info.

> **Note:** Graylog 6.1+ ships a [built-in MCP server](https://github.com/Graylog2/graylog2-server). This server targets Graylog 4.x / 5.x, but also works with 6.x where the built-in MCP is not available or preferred.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GRAYLOG_URL` | yes | — | Graylog base URL (e.g. `http://localhost:9000`) |
| `GRAYLOG_API_TOKEN` | yes | — | API token (create in System → Users → Tokens) |
| `GRAYLOG_VERIFY_SSL` | no | `true` | Set to `false` only for self-signed certs on trusted internal networks |
| `LOG_LEVEL` | no | `WARNING` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

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
      "args": ["run", "-i", "--rm", "--network", "host",
               "-e", "GRAYLOG_URL", "-e", "GRAYLOG_API_TOKEN",
               "ghcr.io/gabrielbelli/graylog-mcp"],
      "env": {
        "GRAYLOG_URL": "http://localhost:9000",
        "GRAYLOG_API_TOKEN": ""
      }
    }
  }
}
```

## Tools

### Search & Aggregation (Graylog 6.x — `views/search/sync`)

> Use these tools on Graylog 6.x. The legacy tools below return 0 results on 6.x.
> Tool names and parameters match the [native Graylog 6.1+ MCP server](https://github.com/Graylog2/graylog2-server) for skill portability.

| Tool | Description |
|---|---|
| `search_messages` | Search messages — replaces `search_relative`/`search_absolute` for Graylog 6.x |
| `aggregate_messages` | Group-by + metrics (top-N terms, histogram, any aggregation) — replaces `search_terms`/`search_histogram` for Graylog 6.x |

### Search (legacy — Graylog 4.x / 5.x only)

| Tool | Description |
|---|---|
| `search_relative` | Search messages with relative time range (Lucene syntax) |
| `search_absolute` | Search messages with absolute time range (ISO 8601) |
| `search_keyword` | Search messages with natural language time range (e.g. "last 1 hour") |
| `get_message` | Retrieve a specific message by ID and index |

### Aggregations (legacy — Graylog 4.x / 5.x only)

| Tool | Description |
|---|---|
| `search_terms` | Top-N values for a field (e.g. top source IPs, usernames, error codes) |
| `search_stats` | Statistical summary for a numeric field (min, max, mean, sum, stddev) |
| `search_histogram` | Message count bucketed over time — spot volume spikes or drops |
| `search_field_histogram` | Numeric field value distribution over time |

### Streams & Resources

| Tool | Description |
|---|---|
| `list_streams` | List all streams |
| `list_resource` | List streams, dashboards, or event definitions by type — returns GRNs |
| `describe_resource` | Describe a specific resource by GRN (e.g. `grn::::stream:abc123`) |

### Alerts & Events

| Tool | Description |
|---|---|
| `search_events` | Search alert events with pagination |

### Pipelines

> Requires the Graylog Processing Pipelines plugin (built-in since Graylog 4.x).

| Tool | Description |
|---|---|
| `list_pipelines` | List all processing pipelines |
| `get_pipeline` | Get pipeline details (stages, connected streams) |
| `list_pipeline_rules` | List all pipeline rules |
| `get_pipeline_rule` | Get rule source code and metadata |
| `list_pipeline_connections` | Show which streams are connected to which pipelines |

### System

| Tool | Description |
|---|---|
| `get_current_time` | Current UTC time — use to anchor relative time reasoning in skills |
| `get_system_status` | Graylog system info (version, cluster, hostname, timezone, status) |
| `list_fields` | Field names, types, and capabilities — scope to streams to reduce noise |
| `list_inputs` | List configured inputs |
