"""Reference documentation module for XQL and dataset fields."""

import os
import logging
from pathlib import Path
from typing import Annotated

from pydantic import Field

from .base_module import BaseModule


class ReferenceModule(BaseModule):
    """
    Reference documentation resources for XSIAM and XQL.

    Provides access to:
    - Dataset field mappings
    - XQL query examples
    - XQL language documentation
    """

    def __init__(self, mcp):
        """Initialize reference module."""
        super().__init__(mcp)

        # Determine resources directory path
        # Try relative to module first, then absolute paths
        module_dir = Path(__file__).parent.parent.parent
        self.resources_dir = module_dir / "resources"

        # Fallback to absolute path if relative doesn't exist
        if not self.resources_dir.exists():
            self.resources_dir = Path("/app/resources")

        self.logger.info(f"Resources directory: {self.resources_dir}")

    def register_tools(self):
        """Register reference tools."""
        self._add_tool(self.get_dataset_fields)
        self._add_tool(self.get_xql_examples)
        self._add_tool(self.get_xql_doc)

    def register_resources(self):
        """Register reference resources - disabled for now."""
        pass

    def _read_file(self, filename: str) -> str:
        """
        Read file from resources directory.

        Args:
            filename: Name of the file to read

        Returns:
            File contents as string
        """
        file_path = self.resources_dir / filename

        try:
            if not file_path.exists():
                self.logger.error(f"File not found: {file_path}")
                return f"Error: File not found: {filename}"

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.logger.debug(f"Read {len(content)} bytes from {filename}")
                return content

        except Exception as e:
            self.logger.error(f"Error reading {filename}: {e}", exc_info=True)
            return f"Error reading {filename}: {str(e)}"

    # Tool functions

    def get_dataset_fields(self) -> str:
        """
        Get reference mapping of XSIAM dataset names to their available XDM fields.

        **When to use this tool:**
        - When constructing XQL queries and need to know which fields are available for a specific dataset
        - When you need to identify valid XDM field names for filtering or selecting data
        - Before writing queries against datasets like panw_ngfw_traffic_raw, corelight_http_raw, xdr_data

        **What this tool returns:**
        A comprehensive reference guide containing:
        - Dataset names (e.g., panw_ngfw_traffic_raw, corelight_http_raw)
        - Available XDM (Cross-Data Model) fields for each dataset
        - Field descriptions and data types
        - Coverage for: Cisco Umbrella, Corelight HTTP/Zeek, JAMF Pro, Palo Alto NGFW (traffic, threat, URL, file, GlobalProtect, HIPmatch), XDR endpoint data

        **Example use case:**
        You want to query firewall traffic but need to know the correct field names:
        1. Call this tool to get dataset_fields
        2. Look for "panw_ngfw_traffic_raw" section
        3. Find available fields like xdm.source.ipv4, xdm.target.ipv4, xdm.network.rule, etc.
        4. Use those fields in your XQL query

        **Returns:**
        Dataset field reference documentation in markdown format
        """
        return self._read_file("dataset_fields.md")

    def get_xql_examples(self) -> str:
        """
        Get collection of real-world XQL query examples from correlation rules and dashboards.

        **When to use this tool:**
        - When you need inspiration or patterns for writing XQL queries
        - When you want to see how to structure queries for specific use cases
        - When looking for examples of threat detection, traffic analysis, or user activity queries
        - Before writing complex queries with aggregations, joins, or filtering

        **What this tool returns:**
        Real-world XQL query examples including:
        - Threat detection patterns (malware, C2 beaconing, suspicious DNS)
        - Traffic analysis queries (connection tracking, bandwidth monitoring)
        - User activity monitoring (authentication, access patterns)
        - Security event correlation (multi-stage attack detection)
        - Dashboard visualization queries
        - Examples show practical patterns with filters, aggregations, field selections, and time-based analysis

        **Example use case:**
        You need to detect beaconing behavior:
        1. Call this tool to get xql_examples
        2. Search for "beacon" or "periodic connection" patterns
        3. Adapt the example query structure to your specific dataset and criteria
        4. Execute the customized query

        **Returns:**
        XQL query examples in markdown format
        """
        return self._read_file("xql_examples.md")

    def get_xql_doc(self) -> str:
        """
        Get comprehensive XQL (eXtended Query Language) reference documentation for Cortex XSIAM.

        **When to use this tool:**
        - When you need to understand XQL syntax, operators, or functions
        - When constructing queries and unsure about proper syntax
        - When you need to use advanced features like joins, sub-queries, or aggregations
        - Before writing any XQL query to ensure syntactic correctness

        **What this tool returns:**
        Complete XQL language reference covering:
        - Query structure and syntax fundamentals
        - Datamodel queries and dataset selection
        - Filtering with pipes (|) and logical operators
        - Aggregation functions (count, sum, avg, min, max)
        - Time-based queries and time range specifications
        - Join operations across datasets
        - Sub-queries and nested query patterns
        - Field transformations with alter statements
        - Sorting, limiting, and result formatting
        - Best practices for query performance
        - Common operators: =, !=, <, >, contains, in, ~=

        **Example use case:**
        You need to write a query with aggregation but unsure of syntax:
        1. Call this tool to get xql_documentation
        2. Search for "aggregation" or "comp count()"
        3. Review syntax examples and operator usage
        4. Construct your query following the documented patterns

        **Returns:**
        XQL language documentation in markdown format
        """
        return self._read_file("xql_doc.md")
