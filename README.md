[![Python](https://img.shields.io/badge/Python-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/Cortex-FastMCP-0071c5)](https://gofastmcp.com/)
[![Cortex XSOAR/XSIAM](https://img.shields.io/badge/Cortex-XSOAR%20%7C%20XSIAM-0071c5)](https://www.paloaltonetworks.com/cortex)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Snyk Security](https://snyk.io/test/github/ayman-m/mcpservers/badge.svg)](https://snyk.io/test/github/ayman-m/mcpservers)
[![Cortex AppSec](https://img.shields.io/badge/CortexAppSec-monitored-32CD32)](https://www.paloaltonetworks.com/cortex/cloud/application-security)

# Cortex MCP Servers

A collection of Model Context Protocol (MCP) servers for Palo Alto Networks Cortex XSIAM security operations. These servers enable AI agents (like Gemini) to interact with XSIAM through standardized tool interfaces for threat intelligence enrichment, log analysis, asset management, and security operations.

## Overview

This repository contains MCP server implementations that bridge AI agents with Cortex XSIAM capabilities:

- **Standalone Server**: Consolidated MCP server combining all XSIAM tools in one deployable package
- **XSIAM Integration**: MCP server that runs as an XSIAM integration (native deployment inside XSIAM)

## Capabilities (common to both variants)
- Threat intel enrichment: IP, domain, URL, file/hash
- XQL execution and log queries (Corelight NDR, Palo Alto NGFW, Umbrella DNS)
- Lookup datasets: list/create/add/query/remove
- Asset and vulnerability lookups; tenant info
- Security cases/issues search
- Network fabric lookups (Arista IP/MAC)
- Reference docs/resources: XQL language, dataset fields, query examples
- Slack file download utility

## Architecture

```
┌────────────────────────────────────────────────┐
│                AI Agent (Gemini)               │
└───────────────────────┬────────────────────────┘
                        │ MCP Protocol
                        │
        ┌───────────────┴──────────────┐
        │                              │
┌───────▼────────┐            ┌────────▼────────┐
│   Standalone   │            │     XSIAM       │
│   MCP Server   │            │   Integration   │
└───────┬────────┘            └────────┬────────┘
        │                              │
        │       XSIAM Public API       │ 
        │                              │
        └───────────────┬──────────────┘
                        │
              ┌─────────▼──────────┐
              │  Cortex XSIAM/XDR  │
              │   Platform         │
              └────────────────────┘
```

## Available Servers

### 1. Standalone Server (`standalone/`)

**Recommended for most use cases**

A fully-featured, independently deployable MCP server that combines all XSIAM tools in one package.

**Key Features:**
- 25+ tools across 6 modules
- Threat intelligence enrichment (IP, domain, URL, file)
- XQL query execution and log analysis
- Asset inventory and vulnerability management
- Lookup dataset management
- Network fabric lookups (Arista, Cisco Umbrella)
- Slack file download integration
- Docker support with SSL/TLS
- Comprehensive XQL documentation and examples

**Deployment:**
- Docker container
- Local Python environment
- HTTP/HTTPS transport
- STDIO transport for Claude Desktop

[View Standalone Documentation →](standalone/README.md)

### 2. XSIAM Integration (`xsiam/`)

**For native XSIAM deployment**

An MCP server that runs as an XSIAM integration, leveraging XSIAM's API and executing tools directly within the XSIAM platform.

**Key Features:**
- Runs inside XSIAM as a native integration
- War Room/Playground command execution
- Same 25+ tools as standalone version
- Automatic credential management via XSIAM

**Deployment:**
- Upload as XSIAM integration
- Configure in XSIAM integrations panel
- Runs within XSIAM infrastructure

[View XSIAM Integration Documentation →](xsiam/)

## Deployment Options

### XSIAM Integration (`xsiam/`)
Use when you want the MCP to run inside an XSIAM engine.

Parameters to configure in XSIAM (from `integration.yml` / UI):
- `xsiam_api_url` (e.g., `https://api-<tenant>.xdr.<region>.paloaltonetworks.com`)
- `xsiam_standard_key` (Standard API key value)
- `xsiam_key_id` (Standard API key ID)
- `mcp_transport` (`streamable-http` recommended; `stdio` optional)
- `mcp_host` / `mcp_port` / `mcp_path` (default `0.0.0.0` / `9010` / `/api/v1/stream/mcp`)
- `playground_id` (required for tools that use War Room command execution)
- `mcp_key` (optional bearer token for MCP auth)
- `slack_bot_token`, `ssl_pem`, `ssl_key` (optional)

Notes:
- Deploy to an XSIAM engine.
- You do not need Docker/Compose here.
- Make sure your Standard API key has required scopes.

### Standalone Server (`standalone/`)
Use when you want to run outside XSIAM (local, VM, container, or Compose).

Environment setup (applies to Docker and Compose):
```bash
cd standalone
cp .env.example .env
# Fill CORTEX_MCP_PAPI_URL=https://api-<tenant>.xdr.<region>.paloaltonetworks.com
# Fill CORTEX_MCP_PAPI_AUTH_HEADER and CORTEX_MCP_PAPI_AUTH_ID with your Standard API key/value
```

#### Run with Docker (single container)
```bash
docker build -t cortex-mcp-standalone .
docker run --env-file .env -p 9020:9020 -i --rm cortex-mcp-standalone
```
You can also pass env vars inline for quick tests:
```bash
docker run -p 9020:9020 \
  -e CORTEX_MCP_PAPI_URL=... \
  -e CORTEX_MCP_PAPI_AUTH_HEADER=... \
  -e CORTEX_MCP_PAPI_AUTH_ID=... \
  -e MCP_AUTH_TOKEN=... \
  -i --rm cortex-mcp-standalone
```

#### Run with Docker Compose (full stack: MCP + Streamlit agent)
```bash
cd standalone
cp .env.example .env
# Fill MCP_* and CORTEX_* for the server; fill GEMINI/GOOGLE_* and MCP_URL/MCP_TOKEN for the agent.
docker compose up -d
```
Services:
- `mcp-xsiam` on port `9020` (streamable HTTP endpoint)
- `agent-orion` on port `8501` (Streamlit UI consuming the MCP)

#### Local Python (no containers)
```bash
cd standalone
pip install -r requirements.txt
python src/main.py
```


## Available Tools

All servers provide the same comprehensive toolkit:

### Threat Intelligence & Enrichment
- `enrich_ip` - IP threat intelligence and reputation
- `enrich_domain` - Domain reputation and WHOIS
- `enrich_url` - URL-specific threat analysis
- `enrich_file` - File hash reputation and malware family
- `get_cases` - Security case management

### Log Analysis & Queries
- `run_xql_query` - Execute custom XQL queries
- `query_corelight_logs` - NDR HTTP activity (Corelight)
- `query_paloalto_firewall_logs` - Firewall threat events
- `umbrella_reporting_activity_get` - DNS query history

### Network Lookups
- `ip_lookup_arista` - Physical location in network fabric
- `mac_lookup_arista` - Device location by MAC address

### Asset Management
- `get_assets` - Search asset inventory
- `get_asset_by_id` - Detailed asset information
- `get_assessment_results` - Vulnerability assessments
- `get_tenant_info` - XSIAM tenant information

### Lookup Datasets
- `get_datasets` - List available datasets
- `create_dataset` - Create new lookup dataset
- `add_lookup_data` - Add/update lookup data
- `get_lookup_data` - Query lookup dataset
- `remove_lookup_data` - Delete lookup data

### Security Issues
- `get_issues` - Search security issues

### Reference & Documentation
- `get_xql_doc` - XQL language reference
- `get_xql_examples` - Real-world XQL query examples
- `get_dataset_fields` - Dataset schema and field mappings

### Utilities
- `slack_download_file` - Download files from Slack

## Use Cases

### Incident Investigation
```
User: "Investigate IP 192.168.1.100"
Agent uses:
1. enrich_ip - Get threat intelligence
2. ip_lookup_arista - Find physical location
3. query_corelight_logs - Check HTTP activity
4. query_paloalto_firewall_logs - Check for threats
```

### Threat Hunting
```
User: "Hunt for suspicious domain communications"
Agent uses:
1. get_xql_doc - Learn XQL syntax
2. get_dataset_fields - Find relevant fields
3. run_xql_query - Execute custom threat hunting query
4. enrich_domain - Analyze discovered domains
```

### Asset Management
```
User: "Find all Windows servers with critical vulnerabilities"
Agent uses:
1. get_assets - Search for Windows servers
2. get_assessment_results - Get vulnerability data
3. get_asset_by_id - Detailed info on critical systems
```

### Log Analysis
```
User: "Analyze traffic from specific IPs"
Agent uses:
1. get_lookup_data - Get subnet-to-location mapping
2. query_corelight_logs - HTTP activity analysis
3. query_paloalto_firewall_logs - Security events
```

## Environment & Auth

Shared required values (both variants):
- `CORTEX_MCP_PAPI_URL` = `https://api-<tenant>.xdr.<region>.paloaltonetworks.com` (do NOT include `/public_api/v1`; the client appends it)
- `CORTEX_MCP_PAPI_AUTH_HEADER` = Standard API key value
- `CORTEX_MCP_PAPI_AUTH_ID` = Standard API key ID

Optional (commonly used):
- Transport: `MCP_TRANSPORT=streamable-http` or `stdio`; `MCP_HOST`, `MCP_PORT`, `MCP_PATH`
- MCP auth: `MCP_AUTH_TOKEN` (bearer required by clients)
- Playground: `PLAYGROUND_ID` (needed for War Room command execution in the integration)
- TLS: `SSL_CERT_PEM`, `SSL_KEY_PEM` (one-line PEM with `\n`)
- Slack: `SLACK_BOT_TOKEN`
- Agent (Compose): `MCP_URL`, `MCP_TOKEN`, `GEMINI_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_MODEL`, `UI_USER`, `UI_PASSWORD`

.env usage:
- **Standalone**: copy `standalone/.env.example` to `.env` and fill the values. Compose and Docker both read this file.
- **XSIAM integration**: values are entered via the integration parameters in the XSIAM UI (mirrors the variables above).

[See full variable reference →](standalone/ENV_VARIABLES.md)

## Authentication

### XSIAM API Credentials

Obtain Standard API credentials from XSIAM:
1. Navigate to Settings > Configurations > API Keys
2. Create a new Standard API key
3. Save the API Key and API Key ID
4. Configure role-based access as needed

### MCP Client Authentication (Optional)

For secured HTTP transport, set `MCP_AUTH_TOKEN`:
- Clients must send `Authorization: Bearer <token>` header
- Token verified using timing-safe comparison
- 1-hour token expiry with auto-renewal

## Development

### Project Structure

```
mcpservers/
├── standalone/              # Standalone MCP server
│   ├── src/
│   │   ├── main.py         # Server initialization
│   │   ├── config.py       # Configuration management
│   │   ├── client/         # XSIAM API client
│   │   └── modules/        # Tool modules
│   ├── resources/          # XQL docs and examples
│   ├── Dockerfile          # Container build
│   └── README.md           # Standalone docs
│
├── xsiam/                  # XSIAM integration
│   ├── integration.py      # Integration code
│   ├── integration.yml     # XSIAM metadata
│   └── Dockerfile          # Container for XSIAM
│
├── LICENSE                 # MIT License
└── README.md              # This file
```


## Support

- Issues: [GitHub Issues](https://github.com/yourusername/mcpservers/issues)
- Documentation: [Standalone README](standalone/README.md)
- XSIAM Docs: [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
