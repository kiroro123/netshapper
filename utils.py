"""
NetShaper — terminal I/O helpers.

Kept in a standalone module so that network/discovery.py can call
print_flush() without importing anything from ui/ (which would
create a dependency inversion).
"""
import os
import sys


def print_flush(*args, **kwargs) -> None:
    print(*args, **kwargs)
    sys.stdout.flush()


def safe_input(prompt: str = "") -> str:
    """Read a line from stdin with terminal sanity restored first."""
    os.system("stty sane")
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    try:
        return input().strip()
    except KeyboardInterrupt:
        print("\n  [NetShaper] Interrupted.")
        sys.exit(0)
