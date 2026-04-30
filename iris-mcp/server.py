"""DFIR-IRIS MCP Server.

Wraps the DFIR-IRIS REST API and exposes case management, IOC, asset, timeline,
notes, and investigation tools as MCP tools for SOC workflows.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

load_dotenv(Path(__file__).parent.parent / ".env")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger("iris-mcp")

mcp = FastMCP("dfir-iris")

IRIS_URL = os.environ.get("IRIS_URL", "https://localhost:8443")
IRIS_API_KEY = os.environ.get("IRIS_API_KEY", "")
IRIS_VERIFY_SSL = os.getenv("IRIS_VERIFY_SSL", "false").lower() != "false"

if not IRIS_API_KEY:
    logger.warning("IRIS_API_KEY is not set — all API calls will fail with 401")

_http: httpx.Client | None = None


def _client() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(
            base_url=IRIS_URL,
            headers={
                "Authorization": f"Bearer {IRIS_API_KEY}",
                "User-Agent": "iris-mcp/1.0",
                "Content-Type": "application/json",
            },
            verify=IRIS_VERIFY_SSL,
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
def _post(path: str, params: dict | None = None, body: dict | None = None) -> dict:
    logger.debug("POST %s", path)
    r = _client().post(path, params=params, json=body or {})
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


def _parse_since(since: str) -> datetime | None:
    """Parse a human time delta string into a UTC cutoff datetime."""
    if not since:
        return None
    since = since.strip().lower()
    units = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if since[-1] in units and since[:-1].isdigit():
        return datetime.now(timezone.utc) - timedelta(**{units[since[-1]]: int(since[:-1])})
    try:
        return datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── Cases ──────────────────────────────────────────────────────────────────


@mcp.tool()
def list_cases() -> dict:
    """List all cases in DFIR-IRIS."""
    try:
        return _get("/manage/cases/list")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_case(case_id: int) -> dict:
    """Get details for a specific case.

    Args:
        case_id: The numeric case ID
    """
    try:
        return _get(f"/manage/cases/{case_id}")
    except Exception as e:
        return _err(e)


@mcp.tool()
def create_case(
    case_name: str,
    case_description: str,
    case_customer: int = 1,
    case_soc_id: str = "",
) -> dict:
    """Create a new case in DFIR-IRIS.

    Args:
        case_name: Name of the case
        case_description: Description of the incident
        case_customer: Customer ID (default: 1)
        case_soc_id: SOC ticket ID (optional)
    """
    try:
        return _post(
            "/manage/cases/add",
            body={
                "case_name": case_name,
                "case_description": case_description,
                "case_customer": case_customer,
                "case_soc_id": case_soc_id,
            },
        )
    except Exception as e:
        return _err(e)


# ── IOCs ───────────────────────────────────────────────────────────────────


@mcp.tool()
def list_iocs(case_id: int) -> dict:
    """List all IOCs for a case.

    Args:
        case_id: The numeric case ID
    """
    try:
        return _get("/case/ioc/list", {"cid": case_id})
    except Exception as e:
        return _err(e)


@mcp.tool()
def add_ioc(
    case_id: int,
    ioc_value: str,
    ioc_type_id: int,
    ioc_description: str = "",
    ioc_tlp_id: int = 2,
) -> dict:
    """Add an IOC to a case.

    Args:
        case_id: The case ID
        ioc_value: The IOC value (IP, hash, domain, etc.)
        ioc_type_id: IOC type (1=hash, 2=IP, 3=domain, 4=URL, 5=email, 6=filename, 7=hostname)
        ioc_description: Description of the IOC
        ioc_tlp_id: TLP level (1=red, 2=amber, 3=green, 4=white)
    """
    try:
        return _post(
            "/case/ioc/add",
            params={"cid": case_id},
            body={
                "ioc_value": ioc_value,
                "ioc_type_id": ioc_type_id,
                "ioc_description": ioc_description,
                "ioc_tlp_id": ioc_tlp_id,
            },
        )
    except Exception as e:
        return _err(e)


# ── Assets ─────────────────────────────────────────────────────────────────


@mcp.tool()
def list_assets(case_id: int) -> dict:
    """List all assets for a case.

    Args:
        case_id: The numeric case ID
    """
    try:
        return _get("/case/assets/list", {"cid": case_id})
    except Exception as e:
        return _err(e)


@mcp.tool()
def add_asset(
    case_id: int,
    asset_name: str,
    asset_type_id: int,
    asset_description: str = "",
    asset_compromise_status_id: int = 0,
) -> dict:
    """Add an asset to a case.

    Args:
        case_id: The case ID
        asset_name: Name or hostname of the asset
        asset_type_id: Asset type (1=account, 2=firewall, 3=linux-server, 4=linux-workstation, 5=mac, 9=windows-server, 10=windows-workstation)
        asset_description: Description of the asset
        asset_compromise_status_id: Compromise status (0=unknown, 1=compromised, 2=not compromised, 3=remediated)
    """
    try:
        return _post(
            "/case/assets/add",
            params={"cid": case_id},
            body={
                "asset_name": asset_name,
                "asset_type_id": asset_type_id,
                "asset_description": asset_description,
                "asset_compromise_status_id": asset_compromise_status_id,
            },
        )
    except Exception as e:
        return _err(e)


# ── Timeline ───────────────────────────────────────────────────────────────


@mcp.tool()
def list_timeline(case_id: int) -> dict:
    """Get the timeline of events for a case.

    Args:
        case_id: The numeric case ID
    """
    try:
        return _get("/case/timeline/events/list", {"cid": case_id})
    except Exception as e:
        return _err(e)


@mcp.tool()
def add_timeline_event(
    case_id: int,
    event_title: str,
    event_date: str,
    event_content: str = "",
    event_category_id: int = 1,
) -> dict:
    """Add an event to the case timeline.

    Args:
        case_id: The case ID
        event_title: Title of the event
        event_date: Date/time of the event (ISO 8601 format, e.g. 2024-01-15T10:00:00)
        event_content: Detailed description (Markdown supported)
        event_category_id: Category ID for the event
    """
    try:
        return _post(
            "/case/timeline/events/add",
            params={"cid": case_id},
            body={
                "event_title": event_title,
                "event_date": event_date,
                "event_content": event_content,
                "event_category_id": event_category_id,
            },
        )
    except Exception as e:
        return _err(e)


# ── Notes ──────────────────────────────────────────────────────────────────


@mcp.tool()
def list_notes_groups(case_id: int) -> dict:
    """List all note groups for a case.

    Args:
        case_id: The numeric case ID
    """
    try:
        return _get("/case/notes/groups/list", {"cid": case_id})
    except Exception as e:
        return _err(e)


@mcp.tool()
def add_note(
    case_id: int,
    note_title: str,
    note_content: str,
    group_id: int,
) -> dict:
    """Add a note to a case.

    Args:
        case_id: The case ID
        note_title: Title of the note
        note_content: Markdown content of the note
        group_id: Note group ID to add the note to
    """
    try:
        return _post(
            "/case/notes/add",
            params={"cid": case_id},
            body={
                "note_title": note_title,
                "note_content": note_content,
                "group_id": group_id,
            },
        )
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run(transport="stdio")
