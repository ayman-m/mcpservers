"""Slack integration tools."""

import os
from typing import Annotated

from pydantic import Field
import httpx

from .base_module import BaseModule
from config import get_config


class SlackTools(BaseModule):
    """Slack integration tools for file downloads."""

    def __init__(self, mcp):
        """Initialize Slack tools."""
        super().__init__(mcp)
        config = get_config()
        self.bot_token = config.slack_bot_token

    async def slack_download_file(
        self,
        file_url: Annotated[str, Field(
            description="Slack file URL to download (private download URL from Slack)"
        )]
    ) -> str:
        """
        Download a file from Slack using bot authentication.

        Returns file text content or error message.
        Requires SLACK_BOT_TOKEN configuration.
        """
        if not self.bot_token:
            return "Error: SLACK_BOT_TOKEN not configured"

        headers = {"Authorization": f"Bearer {self.bot_token}"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(file_url, headers=headers, timeout=30.0)

                if response.status_code == 200:
                    return response.text
                else:
                    return f"Error: HTTP {response.status_code} - {response.text[:200]}"

        except httpx.TimeoutException:
            return "Error: Request timeout while downloading file"
        except httpx.RequestError as e:
            return f"Error: Request failed - {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"

    def register_tools(self):
        """Register Slack tools."""
        self._add_tool(self.slack_download_file)

    def register_resources(self):
        """No resources for this module."""
        pass
