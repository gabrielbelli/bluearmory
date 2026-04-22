"""DFIR-IRIS MCP Server.

Wraps the DFIR-IRIS REST API and exposes case management endpoints as MCP tools.
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dfir-iris")

IRIS_URL = os.environ.get("IRIS_URL", "https://localhost:8443")
IRIS_API_KEY = os.environ.get("IRIS_API_KEY", "")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=IRIS_URL,
        headers={"Authorization": f"Bearer {IRIS_API_KEY}"},
        verify=False,
        timeout=30,
    )


# ── Cases ──────────────────────────────────────────────────────────────────


@mcp.tool()
def list_cases() -> dict:
    """List all cases in DFIR-IRIS."""
    with _client() as c:
        r = c.get("/manage/cases/list")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_case(case_id: int) -> dict:
    """Get details for a specific case.

    Args:
        case_id: The numeric case ID
    """
    with _client() as c:
        r = c.get(f"/manage/cases/{case_id}")
        r.raise_for_status()
        return r.json()


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
    with _client() as c:
        r = c.post(
            "/manage/cases/add",
            json={
                "case_name": case_name,
                "case_description": case_description,
                "case_customer": case_customer,
                "case_soc_id": case_soc_id,
            },
        )
        r.raise_for_status()
        return r.json()


# ── IOCs ───────────────────────────────────────────────────────────────────


@mcp.tool()
def list_iocs(case_id: int) -> dict:
    """List all IOCs (Indicators of Compromise) for a case.

    Args:
        case_id: The numeric case ID
    """
    with _client() as c:
        r = c.get("/case/ioc/list", params={"cid": case_id})
        r.raise_for_status()
        return r.json()


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
        case_id: The case ID to add the IOC to
        ioc_value: The IOC value (IP, hash, domain, etc.)
        ioc_type_id: Type of IOC (1=hash, 2=IP, 3=domain, etc.)
        ioc_description: Description of the IOC
        ioc_tlp_id: TLP level (1=red, 2=amber, 3=green, 4=white)
    """
    with _client() as c:
        r = c.post(
            "/case/ioc/add",
            params={"cid": case_id},
            json={
                "ioc_value": ioc_value,
                "ioc_type_id": ioc_type_id,
                "ioc_description": ioc_description,
                "ioc_tlp_id": ioc_tlp_id,
            },
        )
        r.raise_for_status()
        return r.json()


# ── Assets ─────────────────────────────────────────────────────────────────


@mcp.tool()
def list_assets(case_id: int) -> dict:
    """List all assets for a case.

    Args:
        case_id: The numeric case ID
    """
    with _client() as c:
        r = c.get("/case/assets/list", params={"cid": case_id})
        r.raise_for_status()
        return r.json()


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
        asset_type_id: Asset type (1=account, 2=firewall, 3=linux-server, 4=linux-workstation, 5=mac, 9=windows-server, 10=windows-workstation, etc.)
        asset_description: Description of the asset
        asset_compromise_status_id: Compromise status (0=unknown, 1=compromised, 2=not compromised, 3=remediated)
    """
    with _client() as c:
        r = c.post(
            "/case/assets/add",
            params={"cid": case_id},
            json={
                "asset_name": asset_name,
                "asset_type_id": asset_type_id,
                "asset_description": asset_description,
                "asset_compromise_status_id": asset_compromise_status_id,
            },
        )
        r.raise_for_status()
        return r.json()


# ── Timeline ───────────────────────────────────────────────────────────────


@mcp.tool()
def list_timeline(case_id: int) -> dict:
    """Get the timeline of events for a case.

    Args:
        case_id: The numeric case ID
    """
    with _client() as c:
        r = c.get("/case/timeline/events/list", params={"cid": case_id})
        r.raise_for_status()
        return r.json()


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
        event_date: Date/time of the event (ISO format)
        event_content: Detailed description
        event_category_id: Category ID for the event
    """
    with _client() as c:
        r = c.post(
            "/case/timeline/events/add",
            params={"cid": case_id},
            json={
                "event_title": event_title,
                "event_date": event_date,
                "event_content": event_content,
                "event_category_id": event_category_id,
            },
        )
        r.raise_for_status()
        return r.json()


# ── Notes ──────────────────────────────────────────────────────────────────


@mcp.tool()
def list_notes_groups(case_id: int) -> dict:
    """List all note groups for a case.

    Args:
        case_id: The numeric case ID
    """
    with _client() as c:
        r = c.get("/case/notes/groups/list", params={"cid": case_id})
        r.raise_for_status()
        return r.json()


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
    with _client() as c:
        r = c.post(
            "/case/notes/add",
            params={"cid": case_id},
            json={
                "note_title": note_title,
                "note_content": note_content,
                "group_id": group_id,
            },
        )
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    mcp.run(transport="stdio")
