"""Security issues management tools for XSIAM."""

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


async def get_issues(
    ctx: Context,
    filters: Annotated[Optional[List[Dict]], Field(
        description="Filter conditions (field, operator, value). "
                    "Common fields: severity (LOW/MEDIUM/HIGH/CRITICAL), status (New/Open/Resolved)"
    )] = None,
    search_from: Annotated[int, Field(description="Pagination offset (default: 0)")] = 0
) -> str:
    """
    Search and retrieve security issues from XSIAM.

    Returns issues matching filter criteria with details and pagination.
    """
    payload = {"request_data": {"search_from": search_from}}
    if filters:
        payload["request_data"]["filters"] = filters
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("/issue/search/", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


class IssuesModule(BaseModule):
    """Security issues management tools for XSIAM."""

    def register_tools(self):
        """Register issues tools."""
        self._add_tool(get_issues)

    def register_resources(self):
        """No resources for this module."""
        pass
