"""Compatibility wrappers for NetShaper logging configuration."""
from __future__ import annotations

import logging
import os

from netshaper import config


def setup_logging(
    level: str | None = None,
    log_file: str | None = None,
    console: bool = True,
) -> None:
    """Configure logging through the hardened central config module."""
    if level is not None:
        os.environ["NETSHAPER_LOG_LEVEL"] = level
    if log_file is not None:
        os.environ["NETSHAPER_LOG_FILE"] = str(log_file)
    config.configure_logging(console_only=not console)


def get_logger(name: str) -> logging.Logger:
    """Get a named NetShaper logger."""
    return logging.getLogger(f"netshaper.{name}")
