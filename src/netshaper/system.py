"""
NetShaper — OS / system utilities.

  SystemChecker  — pre-flight root + platform checks
  SubprocessRunner — DRY_RUN-aware subprocess wrapper (reads config.DRY_RUN
                     at call time, so --dry-run works even when set after import)
  check_local_port — TCP/UDP liveness probe
"""
import logging
import os
import socket
import subprocess
import sys

from netshaper import config

log = logging.getLogger("netshaper")


class SystemChecker:
    @staticmethod
    def check() -> None:
        if not sys.platform.startswith("linux"):
            sys.exit("[NetShaper] Linux only.")
        if os.geteuid() != 0:
            sys.exit("[NetShaper] Root required.")
        # BUG FIX: ensure state directory exists under /run (root-only mode 700)
        # so no unprivileged user can create a symlink there before us.
        os.makedirs(config.STATE_DIR, mode=0o700, exist_ok=True)


class SubprocessRunner:
    @staticmethod
    def run(args, description: str = "", check: bool = True,
            silent: bool = False) -> bool:
        # Always read config.DRY_RUN at call time (not import time)
        if config.DRY_RUN:
            print(f"[DRY-RUN] {' '.join(str(a) for a in args)}", flush=True)
            return True
        try:
            res = subprocess.run(
                args, capture_output=True, text=True, check=check)
            if res.returncode != 0 and check and not silent:
                log.error(
                    f"Command failed ({description}): "
                    f"{' '.join(str(a) for a in args)}")
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


def check_local_port(host: str, port: int,
                     socket_type: int = socket.SOCK_STREAM) -> bool:
    """
    Check whether a local port is listening.

    For UDP: sends a minimal DNS probe and waits up to 1 s for any reply.
    Limitation: a firewalled-but-listening UDP port is indistinguishable
    from not listening — callers should document this in pre-flight warnings.
    """
    try:
        s = socket.socket(socket.AF_INET, socket_type)
        s.settimeout(1.0)
        try:
            if socket_type == socket.SOCK_DGRAM:
                probe = (b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         b'\x04test\x00\x00\x01\x00\x01')
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
    except Exception:
        return False
