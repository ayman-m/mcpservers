"""Configuration management for Cortex MCP Standalone Server."""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # XSIAM API Configuration
    papi_url_env_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_URL")
    papi_auth_header_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_HEADER")
    papi_auth_id_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_ID")

    # MCP Server Configuration
    mcp_transport: str = Field("stdio", validation_alias="MCP_TRANSPORT")
    mcp_host: str = Field("0.0.0.0", validation_alias="MCP_HOST")
    mcp_port: int = Field(8080, validation_alias="MCP_PORT")
    mcp_path: str = Field("/mcp", validation_alias="MCP_PATH")
    mcp_public_url: Optional[str] = Field(None, validation_alias="MCP_PUBLIC_URL")

    # SSL/TLS Configuration
    ssl_cert_file: Optional[str] = Field(None, validation_alias="SSL_CERT_FILE")
    ssl_key_file: Optional[str] = Field(None, validation_alias="SSL_KEY_FILE")
    ssl_cert_pem: Optional[str] = Field(None, validation_alias="SSL_CERT_PEM")
    ssl_key_pem: Optional[str] = Field(None, validation_alias="SSL_KEY_PEM")

    # Optional: Playground ID for XSIAM command execution
    playground_id: str = Field("", validation_alias="PLAYGROUND_ID")

    # Optional: Slack Integration
    slack_bot_token: Optional[str] = Field(None, validation_alias="SLACK_BOT_TOKEN")

    # Optional: MCP Authentication
    mcp_auth_token: Optional[str] = Field(None, validation_alias="MCP_AUTH_TOKEN")
    mcp_auth_required_scopes: str = Field("", validation_alias="MCP_AUTH_REQUIRED_SCOPES")

    # Logging Configuration
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    log_format: str = Field("json", validation_alias="LOG_FORMAT")
    log_file_path: Optional[str] = Field(None, validation_alias="LOG_FILE_PATH")

    # Google Cloud Configuration
    google_api_key: Optional[str] = Field(None, validation_alias="GOOGLE_API_KEY")
    google_application_credentials: Optional[str] = Field(None, validation_alias="GOOGLE_APPLICATION_CREDENTIALS")
    gemini_model: str = Field("gemini-1.5-pro", validation_alias="GEMINI_MODEL")

    # Optional: UI Authentication
    ui_user: Optional[str] = Field(None, validation_alias="UI_USER")
    ui_password: Optional[str] = Field(None, validation_alias="UI_PASSWORD")

    def validate_required_fields(self) -> tuple[bool, list[str]]:
        """Validate that required XSIAM API credentials are present."""
        missing = []

        if not self.papi_url_env_key:
            missing.append("CORTEX_MCP_PAPI_URL")
        if not self.papi_auth_header_key:
            missing.append("CORTEX_MCP_PAPI_AUTH_HEADER")
        if not self.papi_auth_id_key:
            missing.append("CORTEX_MCP_PAPI_AUTH_ID")

        return len(missing) == 0, missing


# Global configuration instance
_config: Optional[Settings] = None


def get_config() -> Settings:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Settings()
    return _config


def reload_config() -> Settings:
    """Reload configuration from environment."""
    global _config
    _config = Settings()
    return _config


def get_papi_url(papi_url_value: str) -> str:
    """
    Build the PAPI base URL (no /public_api/v1 suffix).

    Args:
        papi_url_value: Base URL from configuration

    Returns:
        Base URL without public_api path (Fetcher will append /public_api/v1)
    """
    if not papi_url_value:
        raise ValueError("CORTEX_MCP_PAPI_URL is required")

    base_url = papi_url_value.rstrip("/")
    if "/public_api" in base_url:
        base_url = base_url.split("/public_api")[0].rstrip("/")

    return base_url


def get_papi_auth_headers(api_key: str, api_key_id: str) -> dict[str, str]:
    """
    Build authentication headers for PAPI requests.

    Args:
        api_key: XSIAM API key
        api_key_id: XSIAM API key ID

    Returns:
        Dictionary of authentication headers
    """
    if not api_key or not api_key_id:
        raise ValueError("XSIAM API credentials are required")

    return {
        "x-xdr-auth-id": api_key_id,
        "Authorization": api_key,
        "Content-Type": "application/json"
    }
