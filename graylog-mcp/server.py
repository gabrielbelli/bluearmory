"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, and alert endpoints
as MCP tools for SOC workflows.
"""

import logging
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

load_dotenv(Path(__file__).parent.parent / ".env")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger("graylog-mcp")

mcp = FastMCP("graylog")

GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://localhost:9000")
GRAYLOG_API_TOKEN = os.environ.get("GRAYLOG_API_TOKEN", "")
GRAYLOG_VERIFY_SSL = os.getenv("GRAYLOG_VERIFY_SSL", "true").lower() != "false"

_http: httpx.Client | None = None


def _client() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(
            base_url=f"{GRAYLOG_URL}/api",
            auth=(GRAYLOG_API_TOKEN, "token"),
            headers={
                "Accept": "application/json",
                "X-Requested-By": "graylog-mcp",
                "User-Agent": "graylog-mcp/1.0",
            },
            verify=GRAYLOG_VERIFY_SSL,
            timeout=30,
        )
    return _http


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
def _get(path: str, params: dict | None = None) -> dict:
    logger.debug("GET %s params=%s", path, params)
    r = _client().get(path, params=params)
    r.raise_for_status()
    return r.json()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
def _post(path: str, body: dict, params: dict | None = None) -> dict:
    logger.debug("POST %s", path)
    r = _client().post(path, json=body, params=params)
    r.raise_for_status()
    return r.json()


def _err(e: Exception) -> dict:
    if isinstance(e, httpx.HTTPStatusError):
        return {
            "error": f"HTTP {e.response.status_code}",
            "url": str(e.request.url),
            "detail": e.response.text[:500],
        }
    return {"error": type(e).__name__, "detail": str(e)}


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
    params: dict = {"query": query, "range": range_seconds, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative", params)
    except Exception as e:
        return _err(e)


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
    params: dict = {"query": query, "from": from_time, "to": to_time, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/absolute", params)
    except Exception as e:
        return _err(e)


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
    params: dict = {"query": query, "keyword": keyword, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/keyword", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_message(message_id: str, index: str) -> dict:
    """Retrieve a specific message by ID.

    Args:
        message_id: The message ID
        index: The Elasticsearch index containing the message
    """
    try:
        return _get(f"/messages/{index}/{message_id}")
    except Exception as e:
        return _err(e)


# ── Streams ────────────────────────────────────────────────────────────────


@mcp.tool()
def list_streams() -> dict:
    """List all streams configured in Graylog."""
    try:
        return _get("/streams")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_stream(stream_id: str) -> dict:
    """Get details for a specific stream.

    Args:
        stream_id: The stream ID
    """
    try:
        return _get(f"/streams/{stream_id}")
    except Exception as e:
        return _err(e)


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
    try:
        return _post(
            "/events/search",
            {
                "query": query,
                "timerange": {"type": "relative", "range": timerange_from},
                "page": page,
                "per_page": per_page,
            },
        )
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_event_definitions() -> dict:
    """List all event/alert definitions configured in Graylog."""
    try:
        return _get("/events/definitions")
    except Exception as e:
        return _err(e)


# ── System ─────────────────────────────────────────────────────────────────


@mcp.tool()
def system_overview() -> dict:
    """Get Graylog system overview (version, cluster, status)."""
    try:
        return _get("/system")
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_inputs() -> dict:
    """List all configured inputs in Graylog."""
    try:
        return _get("/system/inputs")
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run(transport="stdio")
