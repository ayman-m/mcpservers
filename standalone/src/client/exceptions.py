"""Exception classes for PAPI client."""


class PAPIClientError(Exception):
    """Base exception for PAPI client errors."""
    pass


class PAPIConnectionError(PAPIClientError):
    """Raised when connection to PAPI fails."""
    pass


class PAPIResponseError(PAPIClientError):
    """Raised when response parsing fails."""
    pass


class PAPIAuthenticationError(PAPIClientError):
    """Raised when authentication fails (401/403)."""
    pass


class PAPIServerError(PAPIClientError):
    """Raised when server returns 5xx error."""
    pass


class PAPIClientRequestError(PAPIClientError):
    """Raised when client request is invalid (4xx)."""
    pass
