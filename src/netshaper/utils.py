"""
NetShaper — terminal I/O helpers and ANSI colour utilities.
"""
import os
import sys

# ANSI colour codes — gracefully disabled on non-TTY outputs
def _tty() -> bool:
    return sys.stdout.isatty() and sys.stderr.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text

def bold(t: str)    -> str: return _c("1", t)
def dim(t: str)     -> str: return _c("2", t)
def green(t: str)   -> str: return _c("32", t)
def yellow(t: str)  -> str: return _c("33", t)
def red(t: str)     -> str: return _c("31", t)
def cyan(t: str)    -> str: return _c("36", t)
def magenta(t: str) -> str: return _c("35", t)


def print_flush(*args, **kwargs) -> None:
    print(*args, **kwargs)
    sys.stdout.flush()


def safe_input(prompt: str = "") -> str:
    """Read a line from stdin with terminal sanity restored first."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        os.system("stty sane")
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    try:
        return input().strip()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
