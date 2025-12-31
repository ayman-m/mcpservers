"""Base module class for MCP tools."""

import logging
from abc import ABC, abstractmethod
from typing import Callable

from fastmcp import FastMCP
from fastmcp.tools import Tool
from fastmcp.resources import Resource
from fastmcp.prompts import Prompt


class BaseModule(ABC):
    """
    Abstract base class for MCP tool modules.

    Each module groups related tools and registers them with the MCP server.
    Subclasses must implement register_tools() and register_resources().
    """

    def __init__(self, mcp: FastMCP):
        """
        Initialize module with MCP server instance.

        Args:
            mcp: FastMCP server instance to register tools/resources with
        """
        self.mcp = mcp
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def register_tools(self) -> None:
        """Register tools with the MCP server. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def register_resources(self) -> None:
        """Register resources with the MCP server. Must be implemented by subclasses."""
        pass

    def register_prompts(self) -> None:
        """
        Register prompts with the MCP server (optional).

        Override this method if your module provides prompts.
        """
        pass

    def _add_tool(self, fn: Callable, description: str = None) -> None:
        """
        Add a tool function to the MCP server.

        Args:
            fn: Tool function (async or sync)
            description: Optional description override
        """
        try:
            tool = Tool.from_function(fn, name=None, description=description)
            self.mcp.add_tool(tool)
            self.logger.debug(f"Registered tool: {fn.__name__}")
        except Exception as e:
            self.logger.error(f"Error adding tool {fn.__name__}: {e}", exc_info=True)

    def _add_resource(
        self,
        fn: Callable,
        uri: str,
        name: str,
        description: str,
        mime_type: str = 'application/json'
    ) -> None:
        """
        Add a resource function to the MCP server.

        Args:
            fn: Resource function that returns resource content
            uri: Resource URI
            name: Resource name
            description: Resource description
            mime_type: MIME type of the resource content
        """
        try:
            resource = Resource.from_function(
                fn,
                uri,
                name=name,
                description=description,
                mime_type=mime_type
            )
            self.mcp.add_resource(resource)
            self.logger.debug(f"Registered resource: {name} ({uri})")
        except Exception as e:
            self.logger.error(f"Error adding resource {name}: {e}", exc_info=True)

    def _add_prompt(self, fn: Callable, name: str, description: str) -> None:
        """
        Add a prompt function to the MCP server.

        Args:
            fn: Prompt function that returns prompt template
            name: Prompt name
            description: Prompt description
        """
        try:
            prompt = Prompt.from_function(fn, name=name, description=description)
            self.mcp.add_prompt(prompt)
            self.logger.debug(f"Registered prompt: {name}")
        except Exception as e:
            self.logger.error(f"Error adding prompt {name}: {e}", exc_info=True)
