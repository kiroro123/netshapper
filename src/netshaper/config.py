"""
NetShaper — global configuration, logging, and constants.

DRY_RUN is mutated by cli.main() after arg parsing; all other
modules read it via  `from netshaper import config; config.DRY_RUN`
so they always see the live value (not an import-time copy).
"""
import logging
import os
from logging.handlers import RotatingFileHandler

from netshaper.version import __version__

# ── Runtime flag (set by --dry-run; never import directly into a local name) ─
DRY_RUN: bool = False

# ── Paths ─────────────────────────────────────────────────────────────────────
# BUG FIX: moved from /tmp (symlink-attack surface) to /run (root-owned dir).
# SystemChecker.check() creates the directory before first write.
STATE_DIR = "/run/netshaper"
LOG_FILE  = "/var/log/netshaper.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# ── Logging ───────────────────────────────────────────────────────────────────

def _secure_log_handler() -> logging.Handler | None:
    """Create a mode-0600 rotating log handler, or return None on failure."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        fd = os.open(LOG_FILE, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        os.chmod(LOG_FILE, 0o600)
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
        )
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
        return handler
    except OSError:
        return None


def configure_logging(console_only: bool = False) -> None:
    """Attach handlers lazily so importing config does not create files."""
    if logging.getLogger().handlers:
        return
    _ch = logging.StreamHandler()
    _ch.setFormatter(logging.Formatter(
        '[NetShaper] %(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
    handlers = [_ch]
    if not console_only:
        _fh = _secure_log_handler()
        if _fh is not None:
            handlers.insert(0, _fh)
    logging.basicConfig(level=logging.INFO, handlers=handlers)
    if not console_only and len(handlers) == 1:
        logging.getLogger("netshaper").warning(
            "Could not open %s; using console logging only", LOG_FILE
        )

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = r"""
  _   _           _   ____  _
 | \ | | ___  ___| |_/ ___|| |__   __ _ _ __   ___ _ __
 |  \| |/ _ \/ __| __\___ \| '_ \ / _` | '_ \ / _ \ '__|
 | |\  |  __/ (__| |_ ___) | | | | (_| | |_) |  __/ |
 |_| \_|\___|\___|\__|____/|_| |_|\__,_| .__/ \___|_|
                                       |_|
                     v{version}
""".format(version=__version__)

VERSION = __version__
