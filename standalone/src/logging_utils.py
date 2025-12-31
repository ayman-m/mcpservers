"""Logging configuration for Cortex MCP Standalone Server."""

import logging
import sys
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter that filters sensitive data."""

    def add_fields(self, log_record: dict, record: logging.LogRecord, message_dict: dict) -> None:
        """Add fields to log record while filtering sensitive data."""
        super().add_fields(log_record, record, message_dict)

        # Add standard fields
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["timestamp"] = self.formatTime(record, self.datefmt)

        # Filter sensitive headers
        if "headers" in log_record:
            headers = log_record["headers"]
            if isinstance(headers, dict):
                # Redact authentication headers
                for key in ["authorization", "x-xdr-auth-id", "Authorization", "x-xdr-auth-id"]:
                    if key in headers:
                        headers[key] = "***REDACTED***"
                log_record["headers"] = headers


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """
    Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Format type ('json' or 'text')
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)

    if log_format.lower() == "json":
        # JSON formatter for structured logging
        formatter = CustomJsonFormatter(
            fmt="%(timestamp)s %(level)s %(name)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        # Standard text formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("chromadb").setLevel(logging.WARNING)

    logging.info(f"Logging configured: level={log_level}, format={log_format}")
