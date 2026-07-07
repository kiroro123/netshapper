"""
NetShaper — mitmproxy lifecycle management.

Handles mitmproxy startup, shutdown, log management, and readiness checks.
"""
from __future__ import annotations

import logging
import os
import subprocess  # nosec B404
import time
from typing import Optional

from netshaper import config
from netshaper.exceptions import NetShaperError
from netshaper.system import check_local_port

log = logging.getLogger("netshaper")


class MitmProxyError(NetShaperError):
    """Raised when mitmproxy operations fail."""
    pass


class MitmProxyManager:
    """
    Manages mitmproxy (mitmweb) lifecycle for HTTPS inspection.
    Tracks process, logs, and readiness state.
    """

    def __init__(self, own_ip: str):
        """
        Initialize mitmproxy manager.

        Args:
            own_ip: Local IP address where mitmproxy binds
        """
        self.own_ip = own_ip
        self._mitm_proc: Optional[subprocess.Popen] = None
        self._mitm_log_path: Optional[str] = None
        self._mitm_log_handle: Optional[object] = None

    def _open_log(self, session_dir: str) -> Optional[object]:
        """Open mitmproxy log file."""
        if config.DRY_RUN:
            return None

        os.makedirs(session_dir, mode=0o700, exist_ok=True)
        self._mitm_log_path = os.path.join(session_dir, "mitmproxy.log")
        self._mitm_log_handle = open(
            self._mitm_log_path, "a", encoding="utf-8", buffering=1
        )
        self._mitm_log_handle.write(f"{self._timestamp()} starting mitmproxy\n")
        return self._mitm_log_handle

    def _close_log(self) -> None:
        """Close mitmproxy log file."""
        handle = getattr(self, "_mitm_log_handle", None)
        if not handle:
            return
        try:
            handle.write(f"{self._timestamp()} mitmproxy stopped\n")
            handle.close()
        finally:
            self._mitm_log_handle = None

    def _clear_completed_process(self) -> None:
        self._mitm_proc = None
        self._close_log()

    @staticmethod
    def _timestamp() -> str:
        """Get ISO-formatted timestamp."""
        return time.strftime("%Y-%m-%d %H:%M:%S %z")

    def launch(self, port: int = 8088, web_port: int = 8083) -> bool:
        """
        Launch mitmweb in transparent mode.
        Poll for readiness without hard-coded sleep.

        Args:
            port: Port for transparent proxy
            web_port: Port for web dashboard

        Returns:
            True if mitmproxy became ready, False otherwise

        Raises:
            MitmProxyError: If mitmproxy binary not found
        """
        if config.DRY_RUN:
            log.info(
                f"[DRY-RUN] mitmweb --mode transparent "
                f"--listen-port {port} --set web_port={web_port}"
            )
            return True

        if check_local_port(self.own_ip, port):
            log.error(
                "Refusing to adopt existing listener on mitmproxy port :%s",
                port,
            )
            return False

        log_handle = None
        try:
            log_handle = self._open_log(config.STATE_DIR)
            # mitmweb is the intentional child process for transparent proxying.
            self._mitm_proc = subprocess.Popen(  # nosec B603 B607
                [
                    "mitmweb",
                    "--mode",
                    "transparent",
                    "--listen-port",
                    str(port),
                    "--set",
                    f"web_port={web_port}",
                ],
                stdout=log_handle or subprocess.DEVNULL,
                stderr=subprocess.STDOUT if log_handle else subprocess.DEVNULL,
            )

            # Poll for readiness
            for attempt in range(10):
                return_code = self._mitm_proc.poll()
                if return_code is not None:
                    log.error(
                        f"mitmproxy exited during startup with code {return_code}; "
                        f"see {self._mitm_log_path or 'logs'}"
                    )
                    self._clear_completed_process()
                    return False
                if check_local_port(self.own_ip, port):
                    log.info(
                        f"  [+] mitmproxy ready → http://127.0.0.1:{web_port}"
                    )
                    return True
                log.debug(
                    f"Waiting for mitmproxy… (attempt {attempt + 1}/10)"
                )
                time.sleep(0.5)

            # Readiness timeout
            return_code = self._mitm_proc.poll()
            if return_code is None:
                log.error(f"mitmproxy did not bind to :{port} within 5s")
                self.terminate()
            else:
                log.error(
                    f"mitmproxy exited during startup with code {return_code}; "
                    f"see {self._mitm_log_path or 'logs'}"
                )
                self._clear_completed_process()
            return False

        except FileNotFoundError as exc:
            raise MitmProxyError("mitmweb not found. Install with: pip install mitmproxy") from exc
        except Exception:
            if log_handle:
                self._close_log()
            raise

    def terminate(self) -> bool:
        """
        Terminate mitmproxy process gracefully or forcefully.

        Returns:
            True if process terminated cleanly, False otherwise
        """
        proc = getattr(self, "_mitm_proc", None)
        if not proc:
            return True

        ok = True
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

            if proc.poll() is None:
                ok = False
            else:
                log.info("mitmproxy terminated")

        except Exception as exc:
            ok = False
            log.error(f"mitmproxy cleanup failed: {exc}")

        if ok:
            self._mitm_proc = None
            self._close_log()

        return ok

    def get_state_for_persistence(self) -> dict:
        """Get mitmproxy state for persistence."""
        return {
            "mitm_log_path": self._mitm_log_path,
        }
