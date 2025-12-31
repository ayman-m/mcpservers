"""System and asset management tools for XSIAM."""

import json
from typing import Annotated, Optional, List, Dict

from pydantic import Field
from fastmcp import Context

from .base_module import BaseModule


async def get_fetcher_from_ctx(ctx: Context):
    """Get Fetcher from MCP context."""
    from main import get_fetcher
    return await get_fetcher(ctx)


def create_response(data: dict, is_error: bool = False) -> str:
    """Create standardized JSON response."""
    if "success" not in data:
        data["success"] = not is_error
    return json.dumps(data, indent=2, ensure_ascii=False)


async def get_assessment_results(
    ctx: Context,
    filters: Annotated[Optional[List[Dict]], Field(
        description="Filter conditions for vulnerability assessments"
    )] = None
) -> str:
    """
    Retrieve vulnerability assessment results from XSIAM.

    Returns vulnerability findings, affected assets, and severity ratings.
    """
    payload = {"request_data": {}}
    if filters:
        payload["request_data"]["filters"] = filters
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("/compliance/get_assessment_results/", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def get_asset_by_id(
    ctx: Context,
    asset_id: Annotated[str, Field(description="Unique asset identifier in XSIAM")]
) -> str:
    """
    Retrieve full details for a specific asset by ID.

    Returns complete asset profile including hardware, software, and network config.
    """
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request(f"/assets/{asset_id}/", method="GET")
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def get_assets(
    ctx: Context,
    filters: Annotated[Optional[Dict], Field(
        description="Filter group for asset search (ip_address, hostname, os_type, etc.)"
    )] = None,
    sort: Annotated[Optional[List[Dict]], Field(
        description="Sort criteria (field and order)"
    )] = None,
    search_from: Annotated[int, Field(description="Pagination offset")] = 0,
    search_to: Annotated[int, Field(description="Pagination limit (max 1000)")] = 100
) -> str:
    """
    Search and retrieve monitored assets from XSIAM.

    Returns list of assets matching criteria with summary information.
    """
    request_data = {"search_from": search_from, "search_to": search_to}
    if filters:
        request_data["filters"] = filters
    if sort:
        request_data["sort"] = sort
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("/assets/", method="POST", data={"request_data": request_data})
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def get_tenant_info(ctx: Context) -> str:
    """
    Retrieve XSIAM tenant license and configuration information.

    Returns tenant details, enabled modules, and configuration settings.
    """
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("/system/get_tenant_info", method="POST", data={"request_data": {}})
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


class SystemModule(BaseModule):
    """System and asset management tools for XSIAM."""

    def register_tools(self):
        """Register system tools."""
        self._add_tool(get_assessment_results)
        self._add_tool(get_asset_by_id)
        self._add_tool(get_assets)
        self._add_tool(get_tenant_info)

    def register_resources(self):
        """No resources for this module."""
        pass
