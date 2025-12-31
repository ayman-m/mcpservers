"""Main entry point for Cortex MCP Standalone Server."""

import os
import sys
import asyncio
import logging
import signal
import atexit
import tempfile
import secrets
import time
from typing import Optional, Sequence
from dataclasses import dataclass
from contextlib import asynccontextmanager

import uvicorn
from fastmcp import FastMCP, Context
from pydantic import Field

# Handle Auth Provider Import
try:
    from fastmcp.server.auth import AuthProvider
    from mcp.server.auth.provider import AccessToken
except ImportError:
    # Fallback for environments without full MCP auth support
    class AuthProvider:
        def __init__(self, **kwargs):
            pass

    @dataclass
    class AccessToken:
        token: str
        expires_at: Optional[int] = None
        client_id: str = "system"
        scopes: list[str] = Field(default_factory=list)


from config import get_config, reload_config, get_papi_url, get_papi_auth_headers
from logging_utils import setup_logging
from client import Fetcher

# Import modules
from modules.reference_module import ReferenceModule
from modules.integration_tools import IntegrationTools
from modules.lookups_module import LookupsModule
from modules.issues_module import IssuesModule
from modules.system_module import SystemModule
from modules.slack_tools import SlackTools
# from modules.prompts_module import PromptsModule


# ==========================================
# MCP CONTEXT
# ==========================================

@dataclass
class MCPContext:
    """Context object passed through MCP lifespan."""
    auth_headers: dict[str, str]


async def get_fetcher(ctx: Context) -> Fetcher:
    """
    Get a Fetcher instance from MCP context.

    Args:
        ctx: MCP context containing authentication

    Returns:
        Configured Fetcher instance
    """
    config = get_config()
    url = get_papi_url(config.papi_url_env_key)

    # Try to get credentials from lifespan context first
    lifespan: MCPContext = ctx.request_context.lifespan_context
    api_key = lifespan.auth_headers.get("Authorization")
    xdr_id = lifespan.auth_headers.get("x-xdr-auth-id")

    # Fall back to config if not in context
    if not (api_key and xdr_id):
        api_key = config.papi_auth_header_key
        xdr_id = config.papi_auth_id_key

    return Fetcher(url, api_key, xdr_id)


# ==========================================
# AUTH PROVIDER
# ==========================================

class EnvTokenAuthProvider(AuthProvider):
    """
    Authentication provider using environment variable token.

    Validates bearer tokens against MCP_AUTH_TOKEN environment variable.
    """

    def __init__(self, token: str, base_url: str | None = None, required_scopes: Sequence[str] | None = None):
        """
        Initialize auth provider.

        Args:
            token: Expected bearer token
            base_url: Optional base URL
            required_scopes: Optional list of required scopes
        """
        if not token:
            raise ValueError("Token required for authentication")

        self._token = token
        super().__init__(base_url=base_url, required_scopes=list(required_scopes or []))

    async def verify_token(self, token: str) -> AccessToken | None:
        """
        Verify bearer token.

        Args:
            token: Token to verify

        Returns:
            AccessToken if valid, None otherwise
        """
        if not token or not secrets.compare_digest(token, self._token):
            return None

        # Return valid token with 1 hour expiry
        expiry = int(time.time()) + 3600
        return AccessToken(
            token=token,
            expires_at=expiry,
            client_id="cortex-mcp",
            scopes=[]
        )


def _parse_scopes(raw: str | None) -> list[str]:
    """Parse comma-separated scopes string."""
    if not raw:
        return []
    return [s.strip() for s in raw.split(",") if s.strip()]


def _build_auth_provider() -> AuthProvider | None:
    """Build authentication provider from configuration."""
    config = get_config()

    if not config.mcp_auth_token:
        logging.info("No MCP_AUTH_TOKEN set; authentication disabled")
        return None

    scopes = _parse_scopes(config.mcp_auth_required_scopes)
    logging.info(f"Authentication enabled with {len(scopes)} required scopes")

    return EnvTokenAuthProvider(
        token=config.mcp_auth_token,
        required_scopes=scopes
    )


# ==========================================
# SERVER INITIALIZATION
# ==========================================

def create_mcp_lifespan(api_key: Optional[str] = None, api_key_id: Optional[str] = None):
    """
    Create MCP server lifespan context manager.

    Args:
        api_key: XSIAM API key
        api_key_id: XSIAM API key ID

    Returns:
        Async context manager for MCP lifespan
    """
    @asynccontextmanager
    async def mcp_lifespan(mcp_server: FastMCP):
        """Lifespan context providing auth headers."""
        auth_headers = get_papi_auth_headers(api_key or "", api_key_id or "")
        yield MCPContext(auth_headers=auth_headers)

    return mcp_lifespan


async def initialize_mcp_server(api_key: str, api_key_id: str, papi_url: str) -> FastMCP:
    """
    Initialize and configure the MCP server with all modules.

    Args:
        api_key: XSIAM API key
        api_key_id: XSIAM API key ID
        papi_url: XSIAM API base URL

    Returns:
        Configured FastMCP server instance
    """
    lifespan = create_mcp_lifespan(api_key, api_key_id)
    auth = _build_auth_provider()

    mcp = FastMCP("Cortex MCP Standalone Server", lifespan=lifespan, auth=auth)

    # Register all modules
    modules = [
        ReferenceModule(mcp),
        IntegrationTools(mcp),
        LookupsModule(mcp),
        IssuesModule(mcp),
        SystemModule(mcp),
        SlackTools(mcp),
        # PromptsModule(mcp),
    ]

    # Register tools and resources
    for module in modules:
        try:
            module.register_tools()
            module.register_resources()
            logging.info(f"Registered module: {module.__class__.__name__}")
        except Exception as e:
            logging.error(f"Failed to register module {module.__class__.__name__}: {e}", exc_info=True)

    # Register prompts for modules that support them
    for module in modules:
        if hasattr(module, 'register_prompts'):
            try:
                module.register_prompts()
                logging.info(f"Registered prompts for: {module.__class__.__name__}")
            except Exception as e:
                logging.error(f"Failed to register prompts for {module.__class__.__name__}: {e}", exc_info=True)

    return mcp


# ==========================================
# MAIN EXECUTION
# ==========================================

async def async_main(transport: str):
    """
    Async main function to run the MCP server.

    Args:
        transport: Transport type ('stdio' or 'streamable-http')
    """
    config = get_config()
    setup_logging(config.log_level, config.log_format)

    api_key = config.papi_auth_header_key
    api_key_id = config.papi_auth_id_key
    papi_url = config.papi_url_env_key

    # Validate configuration
    is_valid, missing = config.validate_required_fields()
    if not is_valid:
        logging.error(f"Missing required configuration: {', '.join(missing)}")
        logging.error("Please set the following environment variables:")
        for var in missing:
            logging.error(f"  - {var}")
        return

    logging.info(f"Initializing Cortex MCP Standalone Server (transport={transport})")
    mcp = await initialize_mcp_server(api_key, api_key_id, papi_url)

    if transport == "stdio":
        logging.info("Running MCP server with stdio transport")
        await mcp.run_async(transport=transport)

    else:  # streamable-http
        logging.info(f"Running MCP server with HTTP transport on {config.mcp_host}:{config.mcp_port}")
        app = mcp.http_app(path=config.mcp_path, transport=transport)

        ssl_keyfile = config.ssl_key_file
        ssl_certfile = config.ssl_cert_file

        # Handle SSL via PEM content if files are not provided
        def normalize_pem(pem_str: str) -> str:
            """Normalize PEM string format."""
            content = pem_str.replace("\\n", "\n").replace("\\r", "")

            # Ensure proper separation of headers/footers
            content = content.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
            content = content.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")
            content = content.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n")
            content = content.replace("-----END PRIVATE KEY-----", "\n-----END PRIVATE KEY-----")
            content = content.replace("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n")
            content = content.replace("-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----")

            # Clean up double newlines
            while "\n\n" in content:
                content = content.replace("\n\n", "\n")

            return content.strip() + "\n"

        temp_files = []

        if not ssl_keyfile and config.ssl_key_pem:
            key_temp = tempfile.NamedTemporaryFile(delete=False, mode="w")
            key_temp.write(normalize_pem(config.ssl_key_pem))
            key_temp.close()
            ssl_keyfile = key_temp.name
            temp_files.append(key_temp.name)

        if not ssl_certfile and config.ssl_cert_pem:
            cert_temp = tempfile.NamedTemporaryFile(delete=False, mode="w")
            cert_temp.write(normalize_pem(config.ssl_cert_pem))
            cert_temp.close()
            ssl_certfile = cert_temp.name
            temp_files.append(cert_temp.name)

        # Cleanup temporary files on exit
        def cleanup_temp_files():
            for f in temp_files:
                if os.path.exists(f):
                    try:
                        os.unlink(f)
                    except Exception as e:
                        logging.warning(f"Failed to delete temp file {f}: {e}")

        atexit.register(cleanup_temp_files)

        if ssl_keyfile and ssl_certfile:
            logging.info(f"SSL enabled with cert={ssl_certfile} key={ssl_keyfile}")
        else:
            logging.warning("SSL not configured - running HTTP server without encryption")

        config_uvicorn = uvicorn.Config(
            app,
            host=config.mcp_host,
            port=config.mcp_port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="critical",
            loop="asyncio",
            timeout_keep_alive=300,
            access_log=False,
            log_config=None
        )

        server = uvicorn.Server(config_uvicorn)

        try:
            await server.serve()
        finally:
            cleanup_temp_files()


def main():
    """Main entry point."""
    # Load configuration
    config = get_config()

    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Run async main
    try:
        asyncio.run(async_main(config.mcp_transport))
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
    except Exception as e:
        logging.error(f"Server failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
