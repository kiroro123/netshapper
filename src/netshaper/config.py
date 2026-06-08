"""
NetShaper — global configuration, logging, and constants.

DRY_RUN is mutated by cli.main() after arg parsing; all other
modules read it via  `from netshaper import config; config.DRY_RUN`
so they always see the live value (not an import-time copy).
"""
import logging

# ── Runtime flag (set by --dry-run; never import directly into a local name) ─
DRY_RUN: bool = False

# ── Paths ─────────────────────────────────────────────────────────────────────
# BUG FIX: moved from /tmp (symlink-attack surface) to /run (root-owned dir).
# SystemChecker.check() creates the directory before first write.
STATE_DIR = "/run/netshaper"
LOG_FILE  = "netshaper.log"

# ── Logging ───────────────────────────────────────────────────────────────────

def configure_logging() -> None:
    """Attach handlers lazily so importing config does not create files."""
    if logging.getLogger().handlers:
        return
    _fh = logging.FileHandler(LOG_FILE)
    _ch = logging.StreamHandler()
    _fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    _ch.setFormatter(logging.Formatter(
        '[NetShaper] %(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
    logging.basicConfig(level=logging.INFO, handlers=[_fh, _ch])

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = r"""
  _   _           _   ____  _
 | \ | | ___  ___| |_/ ___|| |__   __ _ _ __   ___ _ __
 |  \| |/ _ \/ __| __\___ \| '_ \ / _` | '_ \ / _ \ '__|
 | |\  |  __/ (__| |_ ___) | | | | (_| | |_) |  __/ |
 |_| \_|\___|\___|\__|____/|_| |_|\__,_| .__/ \___|_|
                                       |_|
                     v3.8.0
"""
