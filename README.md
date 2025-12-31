[![Python](https://img.shields.io/badge/Python-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/Cortex-FastMCP-0071c5)](https://gofastmcp.com/)
[![Cortex XSOAR/XSIAM](https://img.shields.io/badge/Cortex-XSOAR%20%7C%20XSIAM-0071c5)](https://www.paloaltonetworks.com/cortex)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Snyk Security](https://snyk.io/test/github/ayman-m/mcpservers/badge.svg)](https://snyk.io/test/github/ayman-m/mcpservers)
[![Cortex AppSec](https://img.shields.io/badge/CortexAppSec-monitored-32CD32)](https://www.paloaltonetworks.com/cortex/cloud/application-security)

# Cortex MCP Servers

A collection of Model Context Protocol (MCP) servers for Palo Alto Networks Cortex XSIAM/XDR security operations. These servers enable AI agents (like Claude) to interact with XSIAM through standardized tool interfaces for threat intelligence enrichment, log analysis, asset management, and security operations.

## Overview

This repository contains MCP server implementations that bridge AI agents with Cortex XSIAM capabilities:

- **Standalone Server**: Consolidated MCP server combining all XSIAM tools in one deployable package
- **XSIAM Integration**: MCP server that runs as an XSIAM integration (native deployment inside XSIAM)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent (Claude)                       │
└───────────────────────┬─────────────────────────────────────┘
                        │ MCP Protocol
                        │
        ┌───────────────┴───────────────┐
        │                               │
┌───────▼────────┐            ┌────────▼────────┐
│   Standalone    │            │     XSIAM       │
│   MCP Server    │            │   Integration   │
└───────┬────────┘            └────────┬────────┘
        │                               │
        │ XSIAM Public API             │ XSIAM SDK
        │                               │
        └───────────────┬───────────────┘
                        │
              ┌─────────▼──────────┐
              │  Cortex XSIAM/XDR   │
              │   Platform          │
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

An MCP server that runs as an XSIAM integration (called "Osiris"), leveraging XSIAM's internal SDK and executing tools directly within the XSIAM platform.

**Key Features:**
- Runs inside XSIAM as a native integration
- Direct access to XSIAM SDK and command execution
- War Room/Playground command execution
- Same 25+ tools as standalone version
- Automatic credential management via XSIAM

**Deployment:**
- Upload as XSIAM integration
- Configure in XSIAM integrations panel
- Runs within XSIAM infrastructure

[View XSIAM Integration Documentation →](xsiam/)

## Quick Start

### Standalone Server (Recommended)

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/mcpservers.git
cd mcpservers/standalone
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your XSIAM credentials
```

3. **Run with Docker:**
```bash
docker build -t cortex-mcp-standalone .
docker run --env-file .env -i --rm cortex-mcp-standalone
```

4. **Or run locally with Poetry:**
```bash
poetry install
poetry run python src/main.py
```

### Claude Desktop Integration

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cortex-xsiam": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--env-file",
        "/path/to/.env",
        "cortex-mcp-standalone"
      ]
    }
  }
}
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

## Configuration

### Required Environment Variables

```bash
# XSIAM API Credentials
CORTEX_MCP_PAPI_URL=https://api-<tenant>.xdr.us.paloaltonetworks.com
CORTEX_MCP_PAPI_AUTH_HEADER=<your_standard_api_key>
CORTEX_MCP_PAPI_AUTH_ID=<your_api_key_id>
```

### Optional Configuration

```bash
# MCP Transport (stdio or streamable-http)
MCP_TRANSPORT=stdio
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_PATH=/mcp

# Authentication
MCP_AUTH_TOKEN=<bearer_token_for_clients>

# Playground (for command execution)
PLAYGROUND_ID=<investigation_id>

# Slack Integration
SLACK_BOT_TOKEN=<slack_bot_token>

# Google Gemini (for XQL content design)
GOOGLE_API_KEY=<gemini_api_key>
GEMINI_MODEL=gemini-1.5-pro

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE_PATH=/app/logs/mcp.json
```

[View Complete Configuration Guide →](standalone/ENV_VARIABLES.md)

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

### Adding New Tools

1. Create module in `standalone/src/modules/`
2. Extend `BaseModule` class
3. Implement `register_tools()` and `register_resources()`
4. Register module in `main.py`

Example:
```python
from .base_module import BaseModule
from fastmcp import Context

class MyModule(BaseModule):
    async def my_tool(self, ctx: Context, param: str) -> str:
        """Tool description."""
        # Tool implementation
        return result

    def register_tools(self):
        self._add_tool(self.my_tool)

    def register_resources(self):
        pass
```

### Running Tests

```bash
cd standalone
poetry install
poetry run pytest
```

### Building Docker Image

```bash
cd standalone
docker build -t cortex-mcp-standalone:latest .
```

## Troubleshooting

### Common Issues

**Connection Errors:**
- Verify XSIAM API URL is correct
- Check API credentials are valid
- Ensure network connectivity to XSIAM

**Tool Failures:**
- Check PLAYGROUND_ID is set for command execution tools
- Verify SLACK_BOT_TOKEN for Slack integration
- Review logs at LOG_FILE_PATH

**Authentication Issues:**
- Confirm MCP_AUTH_TOKEN matches client configuration
- Check token hasn't expired
- Verify SSL certificates are valid

### Debug Logging

Enable debug logging:
```bash
LOG_LEVEL=DEBUG
LOG_FORMAT=json
```

View logs:
```bash
tail -f /app/logs/mcp.json | jq
```

## Security

### Best Practices

1. **Credentials Management:**
   - Never commit `.env` files
   - Use environment variables or secrets management
   - Rotate API keys regularly

2. **Network Security:**
   - Enable MCP_AUTH_TOKEN for HTTP transport
   - Use SSL/TLS certificates in production
   - Restrict network access with firewall rules

3. **Access Control:**
   - Use least-privilege XSIAM API keys
   - Review audit logs regularly
   - Monitor tool usage

### Security Audit

Run security scan:
```bash
grep -r "password\|secret\|token" --include="*.py" src/
```

All credentials are managed via environment variables. No secrets are hardcoded.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

Copyright (c) 2025 Ayman Mahmoud

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/mcpservers/issues)
- Documentation: [Standalone README](standalone/README.md)
- XSIAM Docs: [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp)
- Model Context Protocol by [Anthropic](https://www.anthropic.com/news/model-context-protocol)
- Palo Alto Networks [Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam)

## Roadmap

- [ ] Prompts module implementation
- [ ] XQL content design with vector embeddings
- [ ] Additional integrations (ServiceNow, Jira)
- [ ] GraphQL query support
- [ ] Real-time event streaming
- [ ] Web UI for server management

---

**Ready to get started?** Head to the [Standalone Server documentation](standalone/README.md) for detailed setup instructions.
