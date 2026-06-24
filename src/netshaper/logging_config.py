"""
NetShaper — Logging configuration.

Centralized logging setup with file and console output,
structured for security auditing and debugging.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path

# Default log level
LOG_LEVEL = os.environ.get("NETSHAPER_LOG_LEVEL", "INFO").upper()
LOG_DIR = Path(os.environ.get("NETSHAPER_LOG_DIR", "/var/log/netshaper"))
LOG_FILE = LOG_DIR / "netshaper.log"


def setup_logging(
    level: str = LOG_LEVEL,
    log_file: Path = LOG_FILE,
    console: bool = True,
) -> None:
    """
    Configure logging with file and optional console output.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (requires writable directory)
        console: Whether to also log to stderr
    """
    # Get root logger
    root_logger = logging.getLogger("netshaper")
    root_logger.setLevel(getattr(logging, level, logging.INFO))
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Format for structured logs
    formatter = logging.Formatter(
        "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Console handler (stderr)
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(getattr(logging, level, logging.INFO))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler (if log directory is writable)
    try:
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                str(log_file),
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,  # Keep 5 rotated files
            )
            file_handler.setLevel(getattr(logging, level, logging.INFO))
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    except (OSError, PermissionError) as e:
        # Silently skip file logging if directory is not writable
        # (common in unprivileged test environments)
        pass


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(f"netshaper.{name}")
