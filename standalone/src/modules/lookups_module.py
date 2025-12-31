"""Lookup dataset management tools for XSIAM."""

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


async def add_lookup_data(
    ctx: Context,
    dataset_name: Annotated[str, Field(description="Name of the lookup dataset to add data to")],
    data: Annotated[List[Dict], Field(description="List of records to add (each record is a dict)")],
    key_fields: Annotated[Optional[List[str]], Field(description="Optional unique key fields")] = None
) -> str:
    """
    Add or update data in an XSIAM lookup dataset.

    Use for adding IOCs, asset info, or reference data to lookup tables.
    """
    payload = {"request_data": {"dataset_name": dataset_name, "data": data}}
    if key_fields:
        payload["request_data"]["key_fields"] = key_fields
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("xql/lookups/add_data", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def get_lookup_data(
    ctx: Context,
    dataset_name: Annotated[str, Field(description="Name of the lookup dataset to query")],
    filters: Annotated[Optional[List[Dict]], Field(
        description="Filter conditions (field, operator, value)"
    )] = None,
    limit: Annotated[int, Field(description="Max records (1-1000)", ge=1, le=1000)] = 20
) -> str:
    """
    Retrieve data from an XSIAM lookup dataset.

    Essential for IP-to-location mappings and reference data lookups.
    """
    payload = {"request_data": {"dataset_name": dataset_name, "limit": limit}}
    if filters:
        payload["request_data"]["filters"] = filters
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("xql/lookups/get_data", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def remove_lookup_data(
    ctx: Context,
    dataset_name: Annotated[str, Field(description="Name of the lookup dataset")],
    filters: Annotated[List[Dict], Field(description="Filter conditions to identify records to delete")]
) -> str:
    """
    Remove data from an XSIAM lookup dataset.

    Use carefully - deletion is permanent.
    """
    payload = {"request_data": {"dataset_name": dataset_name, "filters": filters}}
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("xql/lookups/remove_data", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def get_datasets(ctx: Context) -> str:
    """
    List all available datasets in XSIAM.

    Returns lookup tables and log datasets available for querying.
    """
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("xql/get_datasets", data={})
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


async def create_dataset(
    ctx: Context,
    dataset_name: Annotated[str, Field(description="Name for new dataset (lowercase with underscores)")],
    dataset_schema: Annotated[Dict, Field(description="Schema definition with field types")],
    dataset_type: Annotated[str, Field(description="Dataset type (default: lookup)")] = "lookup"
) -> str:
    """
    Create a new lookup dataset in XSIAM.

    For custom enrichment and reference data.
    """
    payload = {
        "request_data": {
            "dataset_name": dataset_name,
            "dataset_schema": dataset_schema,
            "dataset_type": dataset_type
        }
    }
    try:
        fetcher = await get_fetcher_from_ctx(ctx)
        response_data = await fetcher.send_request("xql/add_dataset", data=payload)
        return create_response(response_data)
    except Exception as e:
        return create_response({"error": str(e)}, is_error=True)


class LookupsModule(BaseModule):
    """Lookup dataset management tools for XSIAM."""

    def register_tools(self):
        """Register lookup tools."""
        self._add_tool(add_lookup_data)
        self._add_tool(get_lookup_data)
        self._add_tool(remove_lookup_data)
        self._add_tool(get_datasets)
        self._add_tool(create_dataset)

    def register_resources(self):
        """No resources for this module."""
        pass
