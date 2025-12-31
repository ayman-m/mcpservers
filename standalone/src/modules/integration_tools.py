"""Integration tools for XSIAM security operations."""

import re
import json
import time
import asyncio
from typing import Annotated, Optional

from pydantic import Field
from fastmcp import Context

from .base_module import BaseModule
from config import get_config, get_papi_url, get_papi_auth_headers
from client import PAPIClient, Fetcher, PAPIClientError, PAPIClientRequestError


async def get_fetcher_from_ctx(ctx: Context) -> Fetcher:
    """Get Fetcher from MCP context."""
    from main import get_fetcher
    return await get_fetcher(ctx)


class IntegrationTools(BaseModule):
    """
    Integration tools for XSIAM security operations.

    Provides enrichment, querying, and network lookup capabilities.
    """

    def __init__(self, mcp):
        """Initialize integration tools."""
        super().__init__(mcp)
        config = get_config()
        self.api_url = get_papi_url(config.papi_url_env_key)
        self.headers = get_papi_auth_headers(config.papi_auth_header_key, config.papi_auth_id_key)
        base_root_url = self.api_url.split("/public_api")[0].rstrip("/")
        self.client = PAPIClient(base_root_url, self.headers)
        self.playground_id = config.playground_id

    async def _get_playground_id(self) -> str:
        """Get Playground ID from config."""
        if self.playground_id:
            self.logger.info("Using configured Playground ID: %s", self.playground_id)
            return self.playground_id

        self.logger.error("No Playground ID configured. Set PLAYGROUND_ID environment variable.")
        return None

    async def execute_command(self, command: str, return_context_keys: str = None) -> str:
        """Execute XSOAR/XSIAM command in playground."""
        playground_id = await self._get_playground_id()
        if not playground_id:
            return "Error: No Playground ID configured. Cannot execute command."

        self.logger.info("Executing command '%s' in playground %s", command, playground_id)

        context_keys = [k.strip() for k in return_context_keys.split(",")] if return_context_keys else []

        # Clear context if requested
        if context_keys:
            for key in context_keys:
                try:
                    await self.client.request(
                        "POST",
                        "/xsoar/public/v1/entry",
                        json={"investigationId": playground_id, "data": f"!DeleteContext key={key}"}
                    )
                except (PAPIClientRequestError, Exception) as e:
                    if "Could not find investigation" in str(e) or "noInv" in str(e):
                        return f"Error: Playground '{playground_id}' not found"
                    self.logger.warning("Failed to clear context key %s: %s", key, e)

        # Execute command
        url = "/xsoar/entry/execute/sync"
        payload = {"investigationId": playground_id, "data": command}

        try:
            response = await self.client.request("POST", url, json=payload)

            # Return War Room output if no context keys
            if not context_keys:
                entries = response if isinstance(response, list) else [response]
                output_text = ""
                for entry in entries:
                    if entry.get("type") == 1:
                        continue
                    contents = entry.get("contents", "")
                    if entry.get("type") == 4:  # Error
                        output_text += f"Error: {contents}\n"
                    else:
                        output_text += f"{contents}\n"
                return output_text.strip() if output_text else "Command executed (no output)"

        except (PAPIClientRequestError, Exception) as e:
            if "Could not find investigation" in str(e) or "noInv" in str(e):
                return f"Error: Playground '{playground_id}' not found"
            self.logger.error("Command execution failed: %s", e)
            return f"Error executing command: {str(e)}"

        # Retrieve context
        results = {}
        for key in context_keys:
            context_url = f"/xsoar/public/v1/investigation/{playground_id}/context"
            try:
                ctx_response = await self.client.request(
                    "POST",
                    context_url,
                    json={"query": f"${{{key}}}"}
                )
                results[key] = ctx_response
            except Exception as e:
                self.logger.error("Failed to retrieve context key %s: %s", key, e)
                results[key] = f"Error: {str(e)}"

        return json.dumps(results, indent=2)

    async def enrich_indicator(self, indicator_type: str, value: str) -> str:
        """Enrich indicator using XSOAR command."""
        cmd_map = {
            "ip": ("!ip ip={}", "IP,DBotScore,IPinfo,AutoFocus"),
            "url": ("!url url={}", "URL,DBotScore,AutoFocus"),
            "domain": ("!domain domain={}", "Domain,DBotScore,Whois,AutoFocus"),
            "file": ("!file file={}", "File,DBotScore"),
        }
        normalized_type = indicator_type.lower()
        if normalized_type not in cmd_map:
            return f"Unsupported type: {indicator_type}"
        command_template, context_keys = cmd_map[normalized_type]
        command = command_template.format(f'"{value}"')
        return await self.execute_command(command, return_context_keys=context_keys)

    async def _run_xql(self, query: str, ctx: Context) -> str:
        """Execute XQL query."""
        try:
            fetcher = await get_fetcher_from_ctx(ctx)
            to_ts = int(time.time() * 1000)
            from_ts = to_ts - (30 * 60 * 1000)

            start_payload = {
                "request_data": {
                    "query": query,
                    "timeframe": {"from": from_ts, "to": to_ts}
                }
            }
            start_resp = await fetcher.send_request("xql/start_xql_query", data=start_payload)
            query_id = start_resp.get("reply")
            if not query_id:
                return f"Error starting XQL: {json.dumps(start_resp)}"

            await asyncio.sleep(2)
            results_payload = {
                "request_data": {
                    "query_id": query_id,
                    "pending_flag": False,
                    "limit": 1000,
                    "format": "json"
                }
            }
            results_resp = await fetcher.send_request("xql/get_query_results", data=results_payload)
            return json.dumps(results_resp, indent=2)
        except PAPIClientError as e:
            return f"XQL Query Error: {str(e)}"
        except Exception as e:
            return f"Error running XQL: {str(e)}"

    # Tool methods

    async def enrich_ip(
        self,
        ip: Annotated[str, Field(description="IPv4 or IPv6 address to investigate")]
    ) -> str:
        """
        Enrich IP address with threat intelligence data.

        Returns reputation, geolocation, ISP info, and threat indicators.
        """
        return await self.enrich_indicator("ip", ip)

    async def enrich_file(
        self,
        file_hash: Annotated[str, Field(description="File hash (MD5, SHA1, or SHA256) to investigate")]
    ) -> str:
        """
        Enrich file hash with malware analysis data.

        Returns reputation, malware family, and threat classification.
        """
        return await self.enrich_indicator("file", file_hash)

    async def enrich_domain(
        self,
        domain: Annotated[str, Field(description="Domain name to investigate (no protocol)")]
    ) -> str:
        """
        Enrich domain with threat intelligence and WHOIS data.

        Returns reputation, WHOIS info, and threat indicators.
        """
        return await self.enrich_indicator("domain", domain)

    async def enrich_url(
        self,
        url: Annotated[str, Field(description="Full URL to investigate (with protocol)")]
    ) -> str:
        """
        Enrich URL with threat intelligence data.

        Returns reputation and threat classification.
        """
        return await self.enrich_indicator("url", url)

    async def query_corelight_logs(
        self,
        ip_list: Annotated[str, Field(
            description="IP addresses to search in Corelight logs (comma or space separated)"
        )],
        ctx: Context = None
    ) -> str:
        """
        Query Corelight NDR HTTP logs for network activity.

        Searches last 30 minutes for HTTP activity involving specified IPs.
        """
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = list(set(re.findall(ip_pattern, ip_list)))
        if not ips:
            return f"Error: No valid IP addresses in {ip_list}"

        formatted_ips = ", ".join([f'"{ip}"' for ip in ips])
        query = (
            f"datamodel dataset = corelight_http_raw | "
            f"filter XDM_ALIAS.ip in ({formatted_ips}) | "
            f"fields xdm.source.ipv4, xdm.target.ipv4, xdm.event.outcome, "
            f"xdm.source.user.username, xdm.target.port, xdm.source.port, "
            f"xdm.target.sent_bytes, xdm.observer.product, xdm.event.type"
        )

        return await self._run_xql(query, ctx)

    async def query_paloalto_firewall_logs(
        self,
        ip_list: Annotated[str, Field(
            description="IP addresses to search in NGFW logs (comma or space separated)"
        )],
        ctx: Context = None
    ) -> str:
        """
        Query Palo Alto NGFW threat logs for security events.

        Searches last 30 minutes for threat events involving specified IPs.
        """
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = list(set(re.findall(ip_pattern, ip_list)))
        if not ips:
            return f"Error: No valid IP addresses in {ip_list}"

        formatted_ips = ", ".join([f'"{ip}"' for ip in ips])
        query = (
            f"datamodel dataset = panw_ngfw_threat_raw | "
            f"filter XDM_ALIAS.ip in ({formatted_ips}) | "
            f"fields xdm.source.ipv4, xdm.target.ipv4, xdm.event.outcome, "
            f"xdm.source.user.username, xdm.target.port, xdm.source.port, "
            f"xdm.target.sent_bytes, xdm.observer.product, xdm.event.type"
        )

        return await self._run_xql(query, ctx)

    async def run_xql_query(
        self,
        query: Annotated[str, Field(
            description="XQL query to execute. Use get_xql_doc and get_dataset_fields for syntax help."
        )],
        ctx: Context = None
    ) -> str:
        """
        Execute custom XQL query against XSIAM datasets.

        Queries last 30 minutes by default. Returns JSON results.
        Use get_xql_doc, get_dataset_fields, and get_xql_examples tools for help.
        """
        if not query or not query.strip():
            return "Error: XQL query is required"

        return await self._run_xql(query.strip(), ctx)

    async def get_cases(
        self,
        query: Annotated[str, Field(
            description="Search query for cases (XSIAM syntax, e.g. 'severity:high AND status:new')"
        )]
    ) -> str:
        """
        Search security cases/issues in XSIAM.

        Returns cases matching the query with metadata.
        """
        if not query:
            return "Error: Query required"
        command = f'!getIssues query=`{query}`'
        return await self.execute_command(command, return_context_keys="Case")

    async def ip_lookup_arista(
        self,
        ip: Annotated[str, Field(description="IPv4 address to look up in Arista network")]
    ) -> str:
        """
        Look up IP in Arista network fabric.

        Returns device location, switch port, and network segment info.
        """
        command = f'!ip-lookup ip_address="{ip}" extend-context="AristaIPLookup=."'
        return await self.execute_command(command, return_context_keys="AristaIPLookup")

    async def mac_lookup_arista(
        self,
        mac: Annotated[str, Field(description="MAC address to look up in Arista network")]
    ) -> str:
        """
        Look up MAC address in Arista network fabric.

        Returns device location, switch port, and associated IPs.
        """
        command = f'!mac-lookup mac_address="{mac}" extend-context="AristaMACLookup=."'
        return await self.execute_command(command, return_context_keys="AristaMACLookup")

    async def umbrella_reporting_activity_get(
        self,
        traffic_type: Annotated[str, Field(description="Traffic type: 'dns', 'proxy', or 'firewall'")],
        limit: Annotated[int, Field(description="Max results (1-500)", ge=1, le=500)] = 50,
        time_from: Annotated[str, Field(description="Start time (e.g. '-7days', '-1hour')")] = "-7days",
        time_to: Annotated[str, Field(description="End time (e.g. 'now')")] = "now",
        ip: Annotated[Optional[str], Field(description="Filter by IP address")] = None,
        domains: Annotated[Optional[str], Field(description="Filter by domains (comma-separated)")] = None,
        urls: Annotated[Optional[str], Field(description="Filter by URLs (comma-separated)")] = None
    ) -> str:
        """
        Query Cisco Umbrella for DNS and web activity.

        Returns DNS queries, proxy traffic, or firewall events from Umbrella.
        """
        args = [
            f'traffic_type="{traffic_type}"',
            f'limit="{limit}"',
            f'from="{time_from}"',
            f'to="{time_to}"'
        ]
        if ip:
            args.append(f'ip="{ip}"')
        if domains:
            args.append(f'domains="{domains}"')
        if urls:
            args.append(f'urls="{urls}"')

        command = f'!umbrella-reporting-activity-get {" ".join(args)}'
        return await self.execute_command(command, return_context_keys="UmbrellaReporting")

    def register_tools(self):
        """Register all integration tools."""
        self._add_tool(self.enrich_ip)
        self._add_tool(self.enrich_file)
        self._add_tool(self.enrich_domain)
        self._add_tool(self.enrich_url)
        self._add_tool(self.query_corelight_logs)
        self._add_tool(self.query_paloalto_firewall_logs)
        self._add_tool(self.run_xql_query)
        self._add_tool(self.get_cases)
        self._add_tool(self.ip_lookup_arista)
        self._add_tool(self.mac_lookup_arista)
        self._add_tool(self.umbrella_reporting_activity_get)

    def register_resources(self):
        """Register resources - none for this module."""
        pass
