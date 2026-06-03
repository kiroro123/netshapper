"""
netshaper.system
────────────────
System-level utilities: privilege checks, subprocess wrapper, port probing,
and terminal I/O helpers.

No netshaper-internal imports — sits at the bottom of the dependency tree
so every other module can import freely from here.
"""

import os
import sys
import socket
import subprocess
import logging

log = logging.getLogger("netshaper")

# ── Global dry-run flag (set by run.py before any module uses it) ─────────────
DRY_RUN: bool = False


# ── Terminal helpers ──────────────────────────────────────────────────────────
def safe_input(prompt: str = "") -> str:
    """Read a line from stdin; reset terminal state first to avoid TTY weirdness."""
    os.system("stty sane")
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    try:
        return input().strip()
    except KeyboardInterrupt:
        print("\n  [NetShaper] Interrupted.")
        sys.exit(0)


def print_flush(*args, **kwargs):
    """print() that flushes immediately — needed for live status lines."""
    print(*args, **kwargs)
    sys.stdout.flush()


# ── Privilege / platform checks ───────────────────────────────────────────────
class SystemChecker:
    @staticmethod
    def check():
        if not sys.platform.startswith("linux"):
            sys.exit("[NetShaper] Linux only.")
        if os.geteuid() != 0:
            sys.exit("[NetShaper] Root required.")


# ── Subprocess wrapper ────────────────────────────────────────────────────────
class SubprocessRunner:
    @staticmethod
    def run(args, description: str = "", check: bool = True,
            silent: bool = False) -> bool:
        """
        Run a system command.
        Returns True on success, False on any failure.
        Respects the global DRY_RUN flag — prints the command instead of running it.
        """
        if DRY_RUN:
            print_flush(f"[DRY-RUN] {' '.join(str(a) for a in args)}")
            return True
        try:
            res = subprocess.run(args, capture_output=True, text=True, check=check)
            if res.returncode != 0 and check and not silent:
                log.error(
                    f"Command failed ({description}): {' '.join(str(a) for a in args)}"
                )
                if res.stderr and not silent:
                    log.debug(f"stderr: {res.stderr.strip()}")
            return res.returncode == 0
        except subprocess.CalledProcessError as e:
            if not silent:
                log.error(f"CalledProcessError ({description}): {e}")
        except FileNotFoundError:
            if not silent:
                log.error(f"Binary not found ({description}): {args[0]}")
        except Exception as e:
            if not silent:
                log.error(f"Unexpected error ({description}): {e}")
        return False


# ── Port probe ────────────────────────────────────────────────────────────────
def check_local_port(host: str, port: int,
                     socket_type=socket.SOCK_STREAM) -> bool:
    """
    Check whether a local port is actively listening.
    For UDP, sends a minimal DNS probe and waits for any response.
    """
    try:
        s = socket.socket(socket.AF_INET, socket_type)
        s.settimeout(1.0)
        if socket_type == socket.SOCK_DGRAM:
            probe = (
                b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                b'\x04test\x00\x00\x01\x00\x01'
            )
            s.sendto(probe, (host, port))
            try:
                s.recvfrom(512)
                return True
            except socket.timeout:
                return False
        else:
            s.connect((host, port))
            return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass
