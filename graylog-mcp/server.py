"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, and alert endpoints
as MCP tools for SOC workflows.
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("graylog")

GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://localhost:9000")
GRAYLOG_API_TOKEN = os.environ.get("GRAYLOG_API_TOKEN", "")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f"{GRAYLOG_URL}/api",
        auth=(GRAYLOG_API_TOKEN, "token"),
        headers={
            "Accept": "application/json",
            "X-Requested-By": "graylog-mcp",
            "User-Agent": "graylog-mcp/1.0",
        },
        verify=False,
        timeout=30,
    )


# ── Search ─────────────────────────────────────────────────────────────────


@mcp.tool()
def search_relative(
    query: str,
    range_seconds: int = 300,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a relative time range.

    Args:
        query: Graylog search query (Lucene syntax)
        range_seconds: How far back to search in seconds (default: 300 = 5 minutes)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params = {"query": query, "range": range_seconds, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    with _client() as c:
        r = c.get("/search/universal/relative", params=params)
        r.raise_for_status()
        return r.json()


@mcp.tool()
def search_absolute(
    query: str,
    from_time: str,
    to_time: str,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with an absolute time range.

    Args:
        query: Graylog search query (Lucene syntax)
        from_time: Start time (ISO 8601, e.g. 2024-01-15T10:00:00.000Z)
        to_time: End time (ISO 8601)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params = {"query": query, "from": from_time, "to": to_time, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    with _client() as c:
        r = c.get("/search/universal/absolute", params=params)
        r.raise_for_status()
        return r.json()


@mcp.tool()
def search_keyword(
    query: str,
    keyword: str = "last 1 hour",
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a keyword time range.

    Args:
        query: Graylog search query (Lucene syntax)
        keyword: Natural language time range (e.g. "last 1 hour", "yesterday")
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params = {"query": query, "keyword": keyword, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    with _client() as c:
        r = c.get("/search/universal/keyword", params=params)
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_message(message_id: str, index: str) -> dict:
    """Retrieve a specific message by ID.

    Args:
        message_id: The message ID
        index: The Elasticsearch index containing the message
    """
    with _client() as c:
        r = c.get(f"/messages/{index}/{message_id}")
        r.raise_for_status()
        return r.json()


# ── Streams ────────────────────────────────────────────────────────────────


@mcp.tool()
def list_streams() -> dict:
    """List all streams configured in Graylog."""
    with _client() as c:
        r = c.get("/streams")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_stream(stream_id: str) -> dict:
    """Get details for a specific stream.

    Args:
        stream_id: The stream ID
    """
    with _client() as c:
        r = c.get(f"/streams/{stream_id}")
        r.raise_for_status()
        return r.json()


# ── Alerts / Events ───────────────────────────────────────────────────────


@mcp.tool()
def search_events(
    query: str = "",
    timerange_from: int = 3600,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search alert events in Graylog.

    Args:
        query: Filter query (optional)
        timerange_from: How far back in seconds (default: 3600 = 1 hour)
        page: Page number (default: 1)
        per_page: Results per page (default: 50)
    """
    with _client() as c:
        r = c.post(
            "/events/search",
            json={
                "query": query,
                "timerange": {"type": "relative", "range": timerange_from},
                "page": page,
                "per_page": per_page,
            },
        )
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_event_definitions() -> dict:
    """List all event/alert definitions configured in Graylog."""
    with _client() as c:
        r = c.get("/events/definitions")
        r.raise_for_status()
        return r.json()


# ── System ─────────────────────────────────────────────────────────────────


@mcp.tool()
def system_overview() -> dict:
    """Get Graylog system overview (version, cluster, status)."""
    with _client() as c:
        r = c.get("/system")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_inputs() -> dict:
    """List all configured inputs in Graylog."""
    with _client() as c:
        r = c.get("/system/inputs")
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    mcp.run(transport="stdio")
