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

### Search (Graylog 6.x — `views/search/sync`)

> Use these tools on Graylog 6.x. The legacy search tools below return 0 results on 6.x.

| Tool | Description |
|---|---|
| `search_sync` | Search messages — replaces `search_relative`/`search_absolute` for Graylog 6.x |
| `aggregate_terms` | Top-N field value counts via pivot — replaces `search_terms` for Graylog 6.x |
| `aggregate_histogram` | Message count over time via pivot — replaces `search_histogram` for Graylog 6.x |

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

### Streams

| Tool | Description |
|---|---|
| `list_streams` | List all streams |
| `get_stream` | Get stream details |
| `find_stream` | Find streams by name (case-insensitive substring match) |

### Alerts & Events

| Tool | Description |
|---|---|
| `search_events` | Search alert events with pagination |
| `list_event_definitions` | List all alert/event definitions |

### Pipelines

> Requires the Graylog Processing Pipelines plugin (built-in since Graylog 4.x).

| Tool | Description |
|---|---|
| `list_pipelines` | List all processing pipelines |
| `get_pipeline` | Get pipeline details (stages, connected streams) |
| `list_pipeline_rules` | List all pipeline rules |
| `get_pipeline_rule` | Get rule source code and metadata |
| `list_pipeline_connections` | Show which streams are connected to which pipelines |

### Dashboards & Saved Searches

> `list_saved_searches` and `get_saved_search` try the Graylog 5.x/6.x Views API first, and fall back to the 4.x saved search API automatically.

| Tool | Description |
|---|---|
| `list_dashboards` | List all dashboards |
| `get_dashboard` | Get a dashboard and its widget list |
| `list_saved_searches` | List saved searches (version-agnostic) |
| `get_saved_search` | Get a saved search by ID (version-agnostic) |

### System

| Tool | Description |
|---|---|
| `system_overview` | Graylog system info (version, cluster, status) |
| `list_inputs` | List configured inputs |
