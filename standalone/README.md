# Cortex MCP Standalone Server

A consolidated Model Context Protocol (MCP) server that bundles the XSIAM integration tools and XQL content design capabilities from the broader project.

## Capabilities (MCP Tools)
- Enrichment: `enrich_ip`, `enrich_domain`, `enrich_url`, `enrich_file`
- Query: `run_xql_query`, `query_corelight_logs`, `query_paloalto_firewall_logs`
- Network: `ip_lookup_arista`, `mac_lookup_arista`, `umbrella_reporting_activity_get`
- Lookup datasets: `get_datasets`, `get_lookup_data`, `add_lookup_data`, `remove_lookup_data`, `create_dataset`
- XQL content: `design_xql_content`, `test_cortex_content`, `curate_cortex_example`, `retrieve_cortex_examples`
- System: `get_cases`, `get_issues_tool`, `get_assets`, `get_asset_by_id`, `get_assessment_results`, `get_tenant_info`
- Reference: `get_xql_doc_tool`, `get_xql_examples_tool`, `get_dataset_fields_tool`

## Run Options

### Local (no Docker)
1) Install Python 3.10+ and dependencies from the project root:
```bash
cd standalone
pip install -r requirements.txt
```
2) Copy the sample env file and fill it in:
```bash
cp .env.example .env
```
3) Run the server (stdio by default; `streamable-http` with host/port/path if set):
```bash
python src/main.py
```

### Docker (prebuilt image)
1) Copy and edit the sample env file:
```bash
cd standalone
cp .env.example .env
```
2) Run the container with the env file:
```bash
docker run -p 9020:9020 --env-file .env -i --rm aymanam/osiris:standalone-latest
```
   Or pass variables inline (useful for quick tests):
```bash
docker run -p 9020:9020 -e CORTEX_MCP_PAPI_URL=... -e CORTEX_MCP_PAPI_AUTH_HEADER=... \
  -e CORTEX_MCP_PAPI_AUTH_ID=... -e MCP_AUTH_TOKEN=... -i --rm aymanam/osiris:standalone-latest
```

### Build your own container
```bash
cd standalone
docker build -t cortex-mcp-standalone .
docker run -p 9020:9020 --env-file .env -i --rm cortex-mcp-standalone
```

## Environment Variables (server + agent)

The `.env.example` file documents all supported values for both the standalone MCP server and the optional Streamlit agent used in the compose stack. Key variables and how to obtain them:

| Variable | Used by | Description / how to get it |
| --- | --- | --- |
| `CORTEX_MCP_PAPI_URL` | MCP | Cortex XSIAM/XDR API base URL, e.g. `https://api-your-tenant.xdr.us.paloaltonetworks.com`. |
| `CORTEX_MCP_PAPI_AUTH_HEADER` | MCP | XSIAM Standard API key (value shown when creating an API key). |
| `CORTEX_MCP_PAPI_AUTH_ID` | MCP | XSIAM Standard API key ID. Create/retrieve from Cortex XDR console: **Settings → Access Management → API Keys**. |
| `MCP_TRANSPORT`/`MCP_HOST`/`MCP_PORT`/`MCP_PATH` | MCP | Transport configuration. Use `streamable-http` with host/port/path set for HTTP; omit for stdio. |
| `MCP_AUTH_TOKEN` | MCP | Bearer token clients must send to the MCP server. Choose your own secret value. |
| `SSL_CERT_PEM` / `SSL_KEY_PEM` | MCP+Agent | One-line PEM content (escape newlines as `\\n`) if you want TLS termination inside the containers. |
| `LOG_FILE_PATH` | MCP | Log path inside the container (default `/app/logs/mcp.json`). |
| `PLAYGROUND_ID` | MCP | Optional investigation/playbook ID for command execution. |
| `SLACK_BOT_TOKEN` | MCP | Optional Slack bot token for file downloads. |
| `MCP_URL` | Agent | Full MCP streamable HTTP endpoint (e.g. `https://<host>:9020/api/v1/stream/mcp`). |
| `MCP_TOKEN` | Agent | Token the agent sends to the MCP server (should match `MCP_AUTH_TOKEN`). |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | Agent | Gemini model credentials (e.g. `gemini-3-pro-preview`). |
| `GOOGLE_APPLICATION_CREDENTIALS` | Agent | Contents of a Google service account JSON that has Vertex AI permissions; paste the JSON as one line or base64-decode into this variable. |
| `UI_USER` / `UI_PASSWORD` | Agent | Optional Streamlit basic auth. |

### Getting cloud credentials
- **Cortex XSIAM**: In the Cortex XDR console, create a Standard API key. Copy the API key ID into `CORTEX_MCP_PAPI_AUTH_ID` and the API key value into `CORTEX_MCP_PAPI_AUTH_HEADER`. Use your tenant’s API base URL for `CORTEX_MCP_PAPI_URL`.
- **Google Vertex AI**: Create a service account with Vertex AI permissions and download its JSON key. Paste the JSON into `GOOGLE_APPLICATION_CREDENTIALS` (single line with escaped newlines) and set `GEMINI_API_KEY`/`GEMINI_MODEL` as provided by Vertex/Gemini.

## Docker Compose: Full Stack (MCP + Streamlit Agent)

The compose file `standalone/docker-compose.yml` boots both services:
- `mcp-xsiam` (`aymanam/osiris:standalone-latest`) on port `9020` with logs in `xsiammcp_logs`.
- `agent-orion` (`aymanam/eset:streamlit-latest`) on port `8501`, pointed at the MCP endpoint.

Steps:
1) From `standalone/`, copy the sample env file:
```bash
cp .env.example .env
```
2) Fill in MCP variables (XSIAM keys, transport, auth) and agent variables (MCP_URL/MCP_TOKEN plus Gemini/Vertex values).
3) Launch the stack:
```bash
docker compose up -d
```
4) Access MCP at `https://localhost:9020/api/v1/stream/mcp` (or http if you omit TLS) and the Streamlit agent UI at `http://localhost:8501`.

## Architecture

```
standalone/
├── src/                      # MCP server code and modules
├── resources/                # XQL docs/examples/dataset schemas
├── tests/                    # Test suite
├── Dockerfile                # MCP container build
├── docker-compose.yml        # MCP + Streamlit agent stack
└── .env.example              # Sample env covering both services
```

## Development
- Install deps: `pip install -r requirements.txt`
- Run tests: `pytest`
- Add tools: create a module in `src/modules/`, extend `BaseModule`, register in `main.py`

## License

See LICENSE file in the parent directory.
