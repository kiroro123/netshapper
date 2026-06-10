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
from dataclasses import dataclass
from enum import Enum

from netshaper import config

log = logging.getLogger("netshaper")


class InspectionStatus(Enum):
    PRESENT = "present"
    ABSENT = "absent"
    ERROR = "error"


@dataclass(frozen=True)
class InspectionResult:
    status: InspectionStatus
    stdout: str = ""
    stderr: str = ""


_ABSENT_MARKERS = (
    "does a matching rule exist",
    "no chain/target/match by that name",
    "no such file or directory",
    "cannot find device",
    "no such qdisc",
    "no such file",
    "not found",
)

_ERROR_MARKERS = (
    "permission denied",
    "operation not permitted",
    "you must be root",
    "can't initialize",
    "cannot initialize",
    "invalid option",
    "unknown option",
    "bad argument",
    "syntax error",
)


def _stable_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "LANG": "C",
        "LC_ALL": "C",
        "LANGUAGE": "C",
    })
    return env


def inspect_resource(args) -> InspectionResult:
    if config.DRY_RUN:
        return InspectionResult(InspectionStatus.ABSENT)
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=_stable_subprocess_env(),
        )
    except FileNotFoundError as exc:
        return InspectionResult(InspectionStatus.ERROR, stderr=str(exc))
    except Exception as exc:
        return InspectionResult(InspectionStatus.ERROR, stderr=str(exc))
    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    if not isinstance(stdout, str):
        stdout = ""
    if not isinstance(stderr, str):
        stderr = ""
    if result.returncode == 0:
        return InspectionResult(InspectionStatus.PRESENT, stdout, stderr)
    output = f"{stdout}\n{stderr}".lower()
    if any(marker in output for marker in _ERROR_MARKERS):
        return InspectionResult(InspectionStatus.ERROR, stdout, stderr)
    if not output.strip() or any(marker in output for marker in _ABSENT_MARKERS):
        return InspectionResult(InspectionStatus.ABSENT, stdout, stderr)
    return InspectionResult(InspectionStatus.ERROR, stdout, stderr)


class SystemChecker:
    @staticmethod
    def check() -> None:
        if config.DRY_RUN:
            return
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
                args,
                capture_output=True,
                text=True,
                check=check,
                env=_stable_subprocess_env(),
            )
            if res.returncode != 0:
                if not silent:
                    # Always log on failure when silent=False.
                    # Tests expect logger.error() to be called even when
                    # stderr is empty or mocked without real attributes.
                    cmd = " ".join(str(a) for a in args)
                    log.error(f"Command failed ({description}): {cmd}")
                    stderr_val = getattr(res, "stderr", "")
                    if stderr_val and not silent:
                        err = str(stderr_val).strip()
                        if err:
                            log.debug(f"stderr: {err}")
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
            except Exception as exc:
                log.debug("Socket close failed during port check: %s", exc)
    except Exception:
        return False
