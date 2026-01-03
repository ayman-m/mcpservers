# Cortex MCP XSIAM Integration

An MCP server that runs as a native Cortex XSIAM integration (inside an XSIAM engine) with the same capabilities as the standalone server.

## Capabilities (MCP Tools)
- Enrichment: `enrich_ip`, `enrich_domain`, `enrich_url`, `enrich_file`
- Queries: `run_xql_query`, `query_corelight_logs`, `query_paloalto_firewall_logs`, `umbrella_reporting_activity_get`
- Lookup datasets: `get_datasets`, `get_lookup_data`, `add_lookup_data`, `remove_lookup_data`, `create_dataset`
- Assets & vulns: `get_assets`, `get_asset_by_id`, `get_assessment_results`, `get_tenant_info`
- Cases/issues: `get_cases`, `get_issues_tool`
- Network: `ip_lookup_arista`, `mac_lookup_arista`
- Reference: `get_xql_doc_tool`, `get_xql_examples_tool`, `get_dataset_fields_tool`
- Utility: `slack_download_file`

## Requirements
- XSIAM tenant and an XSIAM engine to run the integration.
- Standard API key + key ID with appropriate scopes.
- (Optional) Playground/War Room ID for command execution.

## Configuration (XSIAM Integration Parameters)
Map these to the integration form in XSIAM (from `integration.yml`):
- `xsiam_api_url` — Base URL, e.g. `https://api-<tenant>.xdr.<region>.paloaltonetworks.com` (no `/public_api/v1`)
- `xsiam_standard_key` — Standard API key value
- `xsiam_key_id` — Standard API key ID
- `mcp_transport` — `streamable-http` (recommended) or `stdio`
- `mcp_host` / `mcp_port` / `mcp_path` — Defaults: `0.0.0.0` / `9010` / `/api/v1/stream/mcp`
- `playground_id` — Required for War Room command execution
- `mcp_key` — Optional bearer token clients must present
- Optional: `ssl_pem`, `ssl_key` (PEM as one line with `\n`), `slack_bot_token`

## Deployment (inside XSIAM)
1) Upload the integration package (`integration.yml`) to XSIAM.
2) Assign it to an XSIAM engine with network egress to the XSIAM Public API.
3) Fill the parameters above and save. The integration will expose MCP over your chosen transport.
