"""XSIAM Public API (PAPI) client implementation."""

import os
import json
import logging
from typing import Optional

import httpx

from .exceptions import (
    PAPIConnectionError,
    PAPIResponseError,
    PAPIAuthenticationError,
    PAPIServerError,
    PAPIClientRequestError
)


class PAPIClient(httpx.AsyncClient):
    """
    Async HTTP client for XSIAM Public API.

    This client extends httpx.AsyncClient with:
    - Automatic authentication header injection
    - Response parsing and error handling
    - Credential enforcement across requests
    """

    def __init__(self, base_url: str, headers: dict[str, str], timeout: int = 120, **kwargs):
        """
        Initialize PAPI client.

        Args:
            base_url: Base URL for XSIAM API (e.g., https://api-tenant.xdr.us.paloaltonetworks.com)
            headers: Authentication headers (x-xdr-auth-id, Authorization)
            timeout: Request timeout in seconds
            **kwargs: Additional arguments passed to httpx.AsyncClient
        """
        if 'timeout' not in kwargs:
            kwargs['timeout'] = timeout
        if 'follow_redirects' not in kwargs:
            kwargs['follow_redirects'] = True

        super().__init__(base_url=base_url, headers=headers, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _get_default_headers(self) -> httpx.Headers:
        """Get default headers with Content-Type."""
        headers = self.headers.copy()
        headers.update({'Content-Type': 'application/json'})
        return httpx.Headers(headers)

    async def send(
        self,
        request: httpx.Request,
        *,
        auth=httpx.USE_CLIENT_DEFAULT,
        follow_redirects=httpx.USE_CLIENT_DEFAULT
    ) -> httpx.Response:
        """
        Send request with enforced authentication headers.

        This override ensures authentication headers from the client are always used,
        preventing accidental credential leakage or misuse.
        """
        # Force correct credentials from client initialization
        client_auth = self.headers.get("Authorization")
        client_auth_id = self.headers.get("x-xdr-auth-id") or self.headers.get("X-XDR-AUTH-ID")

        # Enforce Authorization header
        if client_auth:
            if "Authorization" in request.headers and request.headers["Authorization"] != client_auth:
                request.headers["Authorization"] = client_auth
            elif "Authorization" not in request.headers:
                request.headers["Authorization"] = client_auth

        # Enforce x-xdr-auth-id header (case-insensitive)
        if client_auth_id:
            for key in ["x-xdr-auth-id", "X-XDR-AUTH-ID"]:
                if key in request.headers and request.headers[key] != client_auth_id:
                    request.headers[key] = client_auth_id
            # Add if not present
            if "x-xdr-auth-id" not in request.headers and "X-XDR-AUTH-ID" not in request.headers:
                request.headers["x-xdr-auth-id"] = client_auth_id

        return await super().send(request, auth=auth, follow_redirects=follow_redirects)

    async def request(self, method: str, url: str, **kwargs) -> dict:
        """
        Send HTTP request and parse JSON response.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL path (will be appended to base_url)
            **kwargs: Additional arguments for httpx request

        Returns:
            Parsed JSON response as dictionary

        Raises:
            PAPIConnectionError: Connection failed
            PAPIAuthenticationError: Authentication failed (401/403)
            PAPIServerError: Server error (5xx)
            PAPIClientRequestError: Client error (4xx)
            PAPIResponseError: Response parsing failed
        """
        # Merge headers
        if 'headers' not in kwargs:
            kwargs['headers'] = self._get_default_headers()
        else:
            default_headers = dict(self._get_default_headers())
            default_headers.update(kwargs.get('headers', {}))
            kwargs['headers'] = default_headers

        # Log request (mask sensitive data)
        full_url = f'{self.base_url}{url}'
        debug_headers = dict(kwargs['headers'])
        for key in ["Authorization", "authorization", "x-xdr-auth-id", "X-XDR-AUTH-ID"]:
            if key in debug_headers:
                debug_headers[key] = "***REDACTED***"

        self.logger.info(f"Request: {method} {full_url}")
        self.logger.debug(f"Headers: {debug_headers}")

        # Send request
        try:
            response = await super().request(method=method, url=url, **kwargs)
        except httpx.ConnectError as e:
            self.logger.exception(f"Connection failed: {url}")
            raise PAPIConnectionError(f"Failed to connect to {full_url}: {str(e)}")
        except httpx.TimeoutException as e:
            self.logger.exception(f"Request timeout: {url}")
            raise PAPIConnectionError(f"Request timeout: {str(e)}")
        except httpx.RequestError as e:
            self.logger.exception(f"Request failed: {url}")
            raise PAPIConnectionError(f"Request error: {str(e)}")
        except Exception as e:
            self.logger.exception(f"Unexpected error: {url}")
            raise PAPIConnectionError(f"Unexpected error: {str(e)}")

        # Handle null response
        if response is None:
            raise PAPIResponseError("Received None response")

        # Handle HTTP errors
        if response.status_code == 401:
            raise PAPIAuthenticationError(f"Authentication failed: {response.status_code} {response.text}")
        elif response.status_code == 403:
            raise PAPIAuthenticationError(f"Authorization failed (forbidden): {response.status_code} {response.text}")
        elif response.status_code >= 500:
            raise PAPIServerError(f"Server error {response.status_code}: {response.text}")
        elif response.status_code >= 400:
            raise PAPIClientRequestError(f"Client error {response.status_code}: {response.text}")

        # Parse JSON response
        try:
            return response.json()
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {response.text[:500]}")
            raise PAPIResponseError(f"Invalid JSON response: {str(e)}")


class Fetcher:
    """
    High-level XSIAM API request helper.

    Provides a simpler interface for making authenticated requests to XSIAM API.
    """

    def __init__(self, url: str, api_key: str, api_key_id: str):
        """
        Initialize Fetcher.

        Args:
            url: Base XSIAM API URL
            api_key: XSIAM API key
            api_key_id: XSIAM API key ID
        """
        self.url = url
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.logger = logging.getLogger(self.__class__.__name__)

    def _build_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        return {
            "x-xdr-auth-id": self.api_key_id,
            "Authorization": self.api_key,
            "Content-Type": "application/json"
        }

    async def send_request(
        self,
        path: str,
        method: str = "POST",
        data: Optional[dict | str] = None
    ) -> dict:
        """
        Send authenticated request to XSIAM API.

        Args:
            path: API path (e.g., "xql/start_xql_query")
            method: HTTP method (default: POST)
            data: Request body as dict or string

        Returns:
            JSON response as dictionary

        Raises:
            PAPIClientError: Request failed
        """
        # Ensure path includes /public_api/v1
        if "/public_api/v1" not in path:
            path = os.path.join("/public_api/v1", path.lstrip("/"))

        headers = self._build_headers()

        async with PAPIClient(self.url, headers) as client:
            return await client.request(method, path, json=data, headers=headers)
