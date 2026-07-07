"""
NetShaper — global configuration, logging, and constants.

DRY_RUN is mutated by cli.main() after arg parsing; all other
modules read it via  `from netshaper import config; config.DRY_RUN`
so they always see the live value (not an import-time copy).
"""
import logging
import os
import stat
from logging.handlers import RotatingFileHandler
from pathlib import Path

from netshaper.version import __version__

# ── Runtime flag (set by --dry-run; never import directly into a local name) ─
DRY_RUN: bool = False

# ── Paths ─────────────────────────────────────────────────────────────────────
# BUG FIX: moved from /tmp (symlink-attack surface) to /run (root-owned dir).
# SystemChecker.check() creates the directory before first write.
STATE_DIR = "/run/netshaper"
LOG_FILE = "/var/log/netshaper.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# ── Logging ───────────────────────────────────────────────────────────────────


def _configured_log_file() -> str:
    """Return the runtime log path, allowing an environment override."""
    return os.environ.get("NETSHAPER_LOG_FILE", LOG_FILE)


def _configured_log_level() -> int:
    """Return a validated logging level from the environment."""
    level_name = os.environ.get("NETSHAPER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    return level if isinstance(level, int) else logging.INFO


def _nofollow_flag() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _cloexec_flag() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _verify_log_parent(metadata: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"log path parent must not be a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"log path parent is not a directory: {path}")
    euid = os.geteuid()
    if euid == 0:
        if metadata.st_uid != 0:
            raise OSError(f"log path parent is not root-owned: {path}")
    if (
        metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and not (euid != 0 and metadata.st_mode & stat.S_ISVTX)
    ):
        raise OSError(f"log path parent is writable by other users: {path}")


def _validate_log_parent_chain(parent: Path) -> None:
    """Require every existing or created log parent to be trusted."""
    existing = parent
    while not existing.exists():
        if existing.parent == existing:
            raise OSError("log path parent does not exist")
        existing = existing.parent
    for component in (existing, *existing.parents):
        _verify_log_parent(os.lstat(component), component)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for component in (parent, *parent.parents):
        _verify_log_parent(os.lstat(component), component)


def _verify_log_file(fd: int, path: Path) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError(f"log path is not a regular file: {path}")
    euid = os.geteuid()
    if metadata.st_uid != euid:
        raise OSError(f"log file is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        os.fchmod(fd, 0o600)
        metadata = os.fstat(fd)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise OSError(f"log file mode is not 0600: {path}")


def _secure_log_handler(log_file: str | None = None) -> logging.Handler | None:
    """Create a mode-0600 rotating log handler, or return None on failure."""
    path = Path(os.path.abspath(os.path.expanduser(
        log_file or _configured_log_file()
    )))
    try:
        _validate_log_parent_chain(path.parent)
        flags = (
            os.O_APPEND
            | os.O_CREAT
            | os.O_WRONLY
            | _nofollow_flag()
            | _cloexec_flag()
        )
        fd = os.open(path, flags, 0o600)
        try:
            _verify_log_file(fd, path)
        finally:
            os.close(fd)
        handler = RotatingFileHandler(
            str(path),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        return handler
    except OSError:
        return None


def configure_logging(console_only: bool = False) -> None:
    """Attach handlers lazily so importing config does not create files."""
    if logging.getLogger().handlers:
        return
    log_file = _configured_log_file()
    _ch = logging.StreamHandler()
    _ch.setFormatter(logging.Formatter(
        "[NetShaper] %(asctime)s - %(levelname)s - "
        "[%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    handlers = [_ch]
    if not console_only:
        _fh = _secure_log_handler(log_file)
        if _fh is not None:
            handlers.insert(0, _fh)
    logging.basicConfig(level=_configured_log_level(), handlers=handlers)
    if not console_only and len(handlers) == 1:
        logging.getLogger("netshaper").warning(
            "Could not open %s; using console logging only", log_file
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
