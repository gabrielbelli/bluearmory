# iris-mcp

MCP server for [DFIR-IRIS](https://dfir-iris.org/) — incident response case management.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `IRIS_URL` | yes | IRIS base URL (e.g. `https://localhost:8443`) |
| `IRIS_API_KEY` | yes | API key (get from My Settings → API Key) |

## Run

```sh
docker build -t iris-mcp .
docker run -i --rm --network host \
  -e IRIS_URL=https://localhost:8443 \
  -e IRIS_API_KEY=your-key \
  iris-mcp
```

## MCP Config

```json
{
  "mcpServers": {
    "iris": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "host", "-e", "IRIS_URL", "-e", "IRIS_API_KEY", "iris-mcp"],
      "env": {
        "IRIS_URL": "https://localhost:8443",
        "IRIS_API_KEY": ""
      }
    }
  }
}
```

## Tools

| Tool | Description |
|---|---|
| `list_cases` | List all cases |
| `get_case` | Get case details |
| `create_case` | Create a new case |
| `list_iocs` | List IOCs for a case |
| `add_ioc` | Add an IOC to a case |
| `list_assets` | List assets for a case |
| `add_asset` | Add an asset to a case |
| `list_timeline` | Get case timeline |
| `add_timeline_event` | Add a timeline event |
| `list_notes_groups` | List note groups |
| `add_note` | Add a note to a case |
