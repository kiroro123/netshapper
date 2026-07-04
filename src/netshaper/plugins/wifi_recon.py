"""Authorized 802.11 discovery and bounded radio-test plugin.

The plugin captures only frames that match its explicit BSSID/ESSID scope.
Any transmission additionally requires an opt-in scope flag and shares a
small, process-local frame budget.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess  # nosec B404
import threading
from typing import Any, ClassVar

from netshaper import config
from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.plugin import PluginError, PluginInterface
from netshaper.exceptions import NetShaperError

log = logging.getLogger("netshaper.wifi")

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_LAB_ESSID_PREFIX = "NETSHAPER-LAB-"


class WifiError(NetShaperError):
    """Raised when a Wi-Fi operation cannot be performed safely."""


@dataclass
class DiscoveredNetwork:
    """An authorized 802.11 network observed during this session."""

    bssid: str
    essid: str
    band: str
    channel: int
    signal_dbm: int
    seen_count: int = 0
    handshake_status: str = "none"
    wpa_version: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TransmissionBudget:
    """Thread-safe, attempt-based cap shared by all active Wi-Fi actions."""

    def __init__(self, maximum: int) -> None:
        if not 1 <= maximum <= 100:
            raise WifiError("max_tx_frames must be between 1 and 100")
        self.maximum = maximum
        self.attempted = 0
        self._lock = threading.Lock()

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.maximum - self.attempted

    def reserve(self, requested: int) -> int:
        if requested < 1:
            return 0
        with self._lock:
            allowed = min(requested, self.maximum - self.attempted)
            self.attempted += allowed
            return allowed


class WifiReconPlugin(PluginInterface):
    """Passive Wi-Fi recon with explicitly authorized, bounded test traffic."""

    PLUGIN_ID = "wifi-recon"
    PLUGIN_NAME = "Wi-Fi Reconnaissance"
    SUPPORTED_SCOPE_TYPES = ("bssid", "essid", "mixed")

    MAX_BURST: ClassVar[int] = 5
    MIN_TX_INTERVAL: ClassVar[float] = 0.25
    MAX_CONFIGURED_ACTIONS: ClassVar[int] = 8

    def __init__(
        self,
        instance_id: str,
        scope: dict[str, Any],
        plugin_config: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        self.validate_scope(scope, auth_policy)
        if not _INSTANCE_RE.fullmatch(instance_id):
            raise WifiError("invalid plugin instance id")
        super().__init__(instance_id, scope, plugin_config, auth_policy)

        interface = plugin_config.get("interface", "wlan0")
        if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
            raise WifiError("interface must be a valid Linux interface name")
        self.interface = interface
        self.monitor_iface: str | None = None

        capture_dir = plugin_config.get(
            "capture_dir", os.path.join(config.STATE_DIR, "captures")
        )
        if not isinstance(capture_dir, str) or not capture_dir:
            raise WifiError("capture_dir must be a non-empty path")
        self.capture_dir = capture_dir

        self.authorized_bssids = tuple(
            item.lower() for item in self._scope_values(scope, "bssids")
        )
        self.authorized_essids = tuple(self._scope_values(scope, "essids"))
        self.authorized_clients = tuple(
            item.lower() for item in self._scope_values(scope, "client_macs")
        )
        self.test_essids = tuple(self._scope_values(scope, "test_essids"))
        self.allow_hidden = bool(scope.get("allow_hidden", False))
        self.allow_active_scan = bool(scope.get("allow_active_scan", False))
        self.allow_deauth_test = bool(scope.get("allow_deauth_test", False))
        self.allow_beacon_test = bool(scope.get("allow_beacon_test", False))
        self.channels: list[int] = list(scope.get("channels") or [1, 6, 11])

        self.probe_burst = self._bounded_int(
            plugin_config.get("probe_burst", 1), "probe_burst", 1, self.MAX_BURST
        )
        self.probe_interval = self._bounded_float(
            plugin_config.get("probe_interval", 2.0),
            "probe_interval",
            self.MIN_TX_INTERVAL,
            60.0,
        )
        self.channel_interval = self._bounded_float(
            plugin_config.get("channel_interval", 1.0),
            "channel_interval",
            0.25,
            60.0,
        )
        self.max_tx_frames = self._bounded_int(
            plugin_config.get("max_tx_frames", 50),
            "max_tx_frames",
            1,
            100,
        )
        self._budget = TransmissionBudget(self.max_tx_frames)
        self._deauth_tests = self._validate_deauth_tests(
            plugin_config.get("deauth_tests", [])
        )
        self._beacon_test_frames = self._bounded_int(
            plugin_config.get("beacon_test_frames", 0),
            "beacon_test_frames",
            0,
            self.MAX_BURST,
        )
        if self._deauth_tests and not self.allow_deauth_test:
            raise WifiError("deauth_tests require scope.allow_deauth_test=true")
        if self._beacon_test_frames and not self.allow_beacon_test:
            raise WifiError("beacon_test_frames require scope.allow_beacon_test=true")

        self.pcap_file: str | None = None
        self.pcap_handshake_files: dict[str, str] = {}
        self.scan_start: str | None = None
        self.scan_end: str | None = None

        self._scapy: dict[str, Any] = {}
        self._main_writer: Any = None
        self._handshake_writers: dict[str, Any] = {}
        self._writer_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._channel_thread: threading.Thread | None = None
        self._active_thread: threading.Thread | None = None
        self._monitor_enabled = False
        self._discovered_networks: dict[str, DiscoveredNetwork] = {}
        self._bssid_essids: dict[str, str] = {}
        self._eapol_fingerprints: dict[str, set[bytes]] = {}
        self._tx_audit: list[dict[str, Any]] = []

    @staticmethod
    def _scope_values(scope: dict[str, Any], key: str) -> list[str]:
        raw = scope.get(key) or []
        if isinstance(raw, str):
            return [raw]
        return list(raw)

    @classmethod
    def validate_scope(
        cls,
        scope: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        if not isinstance(scope, dict):
            raise PluginError("Wi-Fi scope must be a dictionary")
        scope_type = scope.get("type")
        if scope_type not in cls.SUPPORTED_SCOPE_TYPES:
            raise PluginError(
                "wifi-recon scope type must be 'bssid', 'essid', or 'mixed'"
            )

        bssids = cls._validated_string_list(scope, "bssids")
        essids = cls._validated_string_list(scope, "essids")
        clients = cls._validated_string_list(scope, "client_macs")
        test_essids = cls._validated_string_list(scope, "test_essids")

        for bssid in (*bssids, *clients):
            auth_policy._validate_bssid_format(bssid)
            if cls._is_group_mac(bssid):
                raise PluginError(f"group/broadcast MAC is not allowed: {bssid}")
        for essid in (*essids, *test_essids):
            auth_policy._validate_essid_format(essid)

        if scope_type == "bssid" and not bssids:
            raise PluginError("BSSID scope requires at least one BSSID")
        if scope_type == "essid" and not essids:
            raise PluginError("ESSID scope requires at least one ESSID")
        if scope_type == "mixed" and not (bssids or essids):
            raise PluginError("mixed scope requires BSSIDs or ESSIDs")

        for flag in (
            "allow_hidden",
            "allow_active_scan",
            "allow_deauth_test",
            "allow_beacon_test",
        ):
            if flag in scope and not isinstance(scope[flag], bool):
                raise PluginError(f"{flag} must be true or false")

        if scope.get("allow_active_scan") and not essids:
            raise PluginError("active probe scanning requires an ESSID allowlist")
        if scope.get("allow_deauth_test") and not (bssids and clients):
            raise PluginError("deauth testing requires BSSID and client MAC allowlists")
        if scope.get("allow_beacon_test"):
            if not test_essids:
                raise PluginError("beacon testing requires test_essids")
            if any(not value.startswith(_LAB_ESSID_PREFIX) for value in test_essids):
                raise PluginError(f"test ESSIDs must start with {_LAB_ESSID_PREFIX!r}")

        channels = scope.get("channels", [1, 6, 11])
        if (
            not isinstance(channels, list)
            or not channels
            or len(channels) > 64
            or any(
                isinstance(channel, bool)
                or not isinstance(channel, int)
                or not 1 <= channel <= 233
                for channel in channels
            )
        ):
            raise PluginError("channels must contain 1-64 channel numbers (1-233)")

    @staticmethod
    def _validated_string_list(scope: dict[str, Any], key: str) -> list[str]:
        raw = scope.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, (list, tuple)) or any(
            not isinstance(item, str) or not item for item in raw
        ):
            raise PluginError(f"{key} must be a string or list of strings")
        return list(raw)

    @staticmethod
    def _is_group_mac(raw_mac: str) -> bool:
        return bool(int(raw_mac.split(":", 1)[0], 16) & 1)

    @staticmethod
    def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise WifiError(f"{name} must be an integer")
        if not minimum <= value <= maximum:
            raise WifiError(f"{name} must be between {minimum} and {maximum}")
        return value

    @staticmethod
    def _bounded_float(value: Any, name: str, minimum: float, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise WifiError(f"{name} must be numeric")
        result = float(value)
        if not minimum <= result <= maximum:
            raise WifiError(f"{name} must be between {minimum} and {maximum}")
        return result

    def _validate_deauth_tests(self, raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list) or len(raw) > self.MAX_CONFIGURED_ACTIONS:
            raise WifiError(
                f"deauth_tests must be a list of at most "
                f"{self.MAX_CONFIGURED_ACTIONS} actions"
            )
        result: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                raise WifiError("each deauth test must be an object")
            bssid = item.get("bssid")
            client = item.get("client")
            frames = item.get("frames", 1)
            if not isinstance(bssid, str) or not isinstance(client, str):
                raise WifiError("deauth tests require bssid and client strings")
            self.auth_policy.assert_bssid_authorized(bssid, self.authorized_bssids)
            self.auth_policy.assert_bssid_authorized(client, self.authorized_clients)
            result.append(
                {
                    "bssid": bssid.lower(),
                    "client": client.lower(),
                    "frames": self._bounded_int(
                        frames, "deauth frames", 1, self.MAX_BURST
                    ),
                }
            )
        return result

    @staticmethod
    def _load_scapy() -> dict[str, Any]:
        try:
            from scapy.all import (  # type: ignore[attr-defined]
                Dot11,
                Dot11Auth,
                Dot11Beacon,
                Dot11Deauth,
                Dot11Elt,
                Dot11ProbeReq,
                Dot11ProbeResp,
                EAPOL,
                PcapWriter,
                RadioTap,
                sendp,
                sniff,
            )
        except (ImportError, OSError) as exc:
            raise WifiError("scapy with 802.11 support is required") from exc
        return {
            "Dot11": Dot11,
            "Dot11Auth": Dot11Auth,
            "Dot11Beacon": Dot11Beacon,
            "Dot11Deauth": Dot11Deauth,
            "Dot11Elt": Dot11Elt,
            "Dot11ProbeReq": Dot11ProbeReq,
            "Dot11ProbeResp": Dot11ProbeResp,
            "EAPOL": EAPOL,
            "PcapWriter": PcapWriter,
            "RadioTap": RadioTap,
            "sendp": sendp,
            "sniff": sniff,
        }

    def start(self) -> bool:
        if self.active:
            return True
        if config.DRY_RUN:
            self.monitor_iface = self.interface
            self.active = True
            self.scan_start = datetime.now(timezone.utc).isoformat()
            log.info("[DRY-RUN] Would set %s to monitor mode", self.interface)
            log.info(
                "[DRY-RUN] Would capture authorized frames on channels %s",
                self.channels,
            )
            self._log_dry_run_actions()
            return True

        try:
            self._scapy = self._load_scapy()
            self._open_capture()
            self._activate_monitor_mode()
            self.scan_start = datetime.now(timezone.utc).isoformat()
            self._stop_event.clear()
            self._capture_thread = self._start_thread(
                "wifi-capture", self._capture_loop
            )
            if len(self.channels) > 1:
                self._channel_thread = self._start_thread(
                    "wifi-channel-hop", self._channel_loop
                )
            if self.allow_active_scan or self._deauth_tests or self._beacon_test_frames:
                self._active_thread = self._start_thread(
                    "wifi-bounded-active", self._active_loop
                )
            self.active = True
            log.info(
                "Wi-Fi recon started on %s; capture=%s",
                self.monitor_iface,
                self.pcap_file,
            )
            return True
        except Exception as exc:
            log.error("Wi-Fi recon start failed: %s", exc)
            self._stop_event.set()
            self._close_writers()
            self._restore_managed_mode()
            self.active = False
            return False

    def stop(self) -> bool:
        if config.DRY_RUN:
            self.active = False
            self.scan_end = datetime.now(timezone.utc).isoformat()
            log.info("[DRY-RUN] Would stop Wi-Fi capture and restore managed mode")
            return True

        ok = True
        self._stop_event.set()
        for thread in (
            self._active_thread,
            self._channel_thread,
            self._capture_thread,
        ):
            if thread is not None:
                thread.join(timeout=3)
                if thread.is_alive():
                    ok = False
                    log.error("Wi-Fi worker %s did not stop", thread.name)
        self._close_writers()
        if not self._restore_managed_mode():
            ok = False
        self.scan_end = datetime.now(timezone.utc).isoformat()
        if ok:
            self.active = False
        return ok

    @staticmethod
    def _start_thread(name: str, target: Any) -> threading.Thread:
        thread = threading.Thread(name=name, target=target, daemon=True)
        thread.start()
        return thread

    def _open_capture(self) -> None:
        capture_path = Path(
            os.path.abspath(os.path.expanduser(self.capture_dir))
        )
        parent = capture_path.parent
        if not parent.exists():
            raise WifiError(
                "capture_dir parent must already exist and be trusted"
            )

        # Reject symlink traversal and writable non-sticky parents. This keeps
        # the subsequent writer open inside an operator-owned directory.
        for component in (capture_path, *capture_path.parents):
            if not component.exists() and component == capture_path:
                continue
            try:
                metadata = os.lstat(component)
            except OSError as exc:
                raise WifiError(f"cannot inspect capture path {component}: {exc}") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise WifiError("capture_dir and its parents must not be symlinks")
            if (
                component != capture_path
                and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                and not metadata.st_mode & stat.S_ISVTX
            ):
                raise WifiError(
                    f"capture_dir parent is writable by other users: {component}"
                )

        if capture_path.exists():
            metadata = os.stat(capture_path, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise WifiError("capture_dir must be a real directory")
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise WifiError(
                    "existing capture_dir must be owned by the current user "
                    "and have mode 0700"
                )
        else:
            capture_path.mkdir(mode=0o700)

        self.pcap_file = str(capture_path / f"{self.instance_id}.pcap")
        self._main_writer = self._scapy["PcapWriter"](
            self.pcap_file, append=False, sync=True
        )
        os.chmod(self.pcap_file, 0o600)

    @staticmethod
    def _binary(name: str) -> str:
        binary = shutil.which(name)
        if not binary:
            raise WifiError(f"required binary not found: {name}")
        return binary

    def _run(self, command: Sequence[str], *, check: bool = True) -> bool:
        result = subprocess.run(  # nosec B603
            list(command),
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode and check:
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise WifiError(detail)
        return result.returncode == 0

    def _activate_monitor_mode(self) -> None:
        ip = self._binary("ip")
        iw = self._binary("iw")
        self.monitor_iface = self.interface
        self._run([ip, "link", "set", self.interface, "down"])
        try:
            self._run([iw, "dev", self.interface, "set", "type", "monitor"])
            self._monitor_enabled = True
            self._run([ip, "link", "set", self.interface, "up"])
            self._set_channel(self.channels[0], check=True)
        except Exception:
            self._run([ip, "link", "set", self.interface, "up"], check=False)
            raise

    def _restore_managed_mode(self) -> bool:
        if not self._monitor_enabled:
            return True
        ok = True
        try:
            ip = self._binary("ip")
            iw = self._binary("iw")
            ok &= self._run([ip, "link", "set", self.interface, "down"], check=False)
            ok &= self._run(
                [iw, "dev", self.interface, "set", "type", "managed"],
                check=False,
            )
            ok &= self._run([ip, "link", "set", self.interface, "up"], check=False)
        except Exception as exc:
            log.error("Could not restore managed mode on %s: %s", self.interface, exc)
            ok = False
        if ok:
            self._monitor_enabled = False
        return bool(ok)

    def _set_channel(self, channel: int, *, check: bool = False) -> bool:
        try:
            return self._run(
                [
                    self._binary("iw"),
                    "dev",
                    self.interface,
                    "set",
                    "channel",
                    str(channel),
                ],
                check=check,
            )
        except WifiError:
            if check:
                raise
            return False

    def _capture_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scapy["sniff"](
                    iface=self.monitor_iface,
                    prn=self._frame_callback,
                    store=False,
                    timeout=1.0,
                )
            except Exception as exc:
                log.error("Wi-Fi capture failed: %s", exc)
                self._stop_event.set()

    def _channel_loop(self) -> None:
        while not self._stop_event.is_set():
            for channel in self.channels:
                if self._stop_event.is_set():
                    return
                if not self._set_channel(channel):
                    log.debug(
                        "Channel %s is unavailable on %s", channel, self.interface
                    )
                if self._stop_event.wait(self.channel_interval):
                    return

    def _active_loop(self) -> None:
        try:
            for test in self._deauth_tests:
                if self._stop_event.is_set():
                    return
                self.send_deauth_test(**test)
            if self._beacon_test_frames:
                self.send_beacon_test(self._beacon_test_frames)

            while (
                self.allow_active_scan
                and not self._stop_event.is_set()
                and self._budget.remaining
            ):
                for essid in self.authorized_essids:
                    if self._stop_event.is_set() or not self._budget.remaining:
                        return
                    self.send_probe_request(essid, self.probe_burst)
                    if self._stop_event.wait(self.probe_interval):
                        return
        except Exception as exc:
            log.error("Bounded Wi-Fi action failed: %s", exc)

    def _source_mac(self) -> str:
        raw = Path(f"/sys/class/net/{self.interface}/address").read_text(
            encoding="ascii"
        )
        source = raw.strip().lower()
        self.auth_policy._validate_bssid_format(source)
        return source

    def send_probe_request(self, essid: str, frames: int = 1) -> int:
        if not self.allow_active_scan:
            raise WifiError("active probe scanning is not authorized")
        self.auth_policy.assert_essid_authorized(essid, self.authorized_essids)
        count = self._budget.reserve(min(frames, self.MAX_BURST))
        if not count:
            return 0
        packet = (
            self._scapy["RadioTap"]()
            / self._scapy["Dot11"](
                type=0,
                subtype=4,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self._source_mac(),
                addr3="ff:ff:ff:ff:ff:ff",
            )
            / self._scapy["Dot11ProbeReq"]()
            / self._scapy["Dot11Elt"](ID="SSID", info=essid.encode())
        )
        self._send_packets(packet, count, "probe", {"essid": essid})
        return count

    def send_deauth_test(self, bssid: str, client: str, frames: int = 1) -> int:
        """Send a small, unicast-only disconnect test to an authorized client."""
        if not self.allow_deauth_test:
            raise WifiError("deauthentication testing is not authorized")
        self.auth_policy.assert_bssid_authorized(bssid, self.authorized_bssids)
        self.auth_policy.assert_bssid_authorized(client, self.authorized_clients)
        count = self._budget.reserve(min(frames, self.MAX_BURST))
        if not count:
            return 0
        packet = (
            self._scapy["RadioTap"]()
            / self._scapy["Dot11"](
                type=0,
                subtype=12,
                addr1=client,
                addr2=bssid,
                addr3=bssid,
            )
            / self._scapy["Dot11Deauth"](reason=3)
        )
        self._send_packets(
            packet,
            count,
            "deauth-test",
            {"bssid": bssid.lower(), "client": client.lower()},
        )
        return count

    def send_beacon_test(self, frames_per_essid: int = 1) -> int:
        """Advertise clearly marked lab ESSIDs under the shared frame cap."""
        if not self.allow_beacon_test:
            raise WifiError("beacon testing is not authorized")
        total = 0
        for essid in self.test_essids:
            count = self._budget.reserve(min(frames_per_essid, self.MAX_BURST))
            if not count:
                break
            bssid = self._test_bssid(essid)
            packet = (
                self._scapy["RadioTap"]()
                / self._scapy["Dot11"](
                    type=0,
                    subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=bssid,
                    addr3=bssid,
                )
                / self._scapy["Dot11Beacon"](cap="ESS")
                / self._scapy["Dot11Elt"](ID="SSID", info=essid.encode())
                / self._scapy["Dot11Elt"](ID="Rates", info=b"\x82\x84\x8b\x96")
            )
            self._send_packets(
                packet, count, "beacon-test", {"essid": essid, "bssid": bssid}
            )
            total += count
        return total

    def _test_bssid(self, essid: str) -> str:
        digest = bytearray(
            hashlib.sha256(f"{self.instance_id}:{essid}".encode()).digest()[:6]
        )
        digest[0] = (digest[0] | 0x02) & 0xFE
        return ":".join(f"{value:02x}" for value in digest)

    def _send_packets(
        self,
        packet: Any,
        count: int,
        action: str,
        detail: dict[str, Any],
    ) -> None:
        self._scapy["sendp"](
            packet,
            iface=self.monitor_iface,
            count=count,
            inter=0.02,
            verbose=False,
        )
        audit = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "frames": count,
            **detail,
        }
        self._tx_audit.append(audit)
        log.warning("Authorized bounded Wi-Fi action: %s", audit)

    def _log_dry_run_actions(self) -> None:
        if self.allow_active_scan:
            log.info(
                "[DRY-RUN] Would send directed probe requests for %s "
                "(burst=%d, budget=%d)",
                self.authorized_essids,
                self.probe_burst,
                self.max_tx_frames,
            )
        for test in self._deauth_tests:
            log.info("[DRY-RUN] Would run bounded unicast deauth test: %s", test)
        if self._beacon_test_frames:
            log.info(
                "[DRY-RUN] Would advertise lab ESSIDs %s (%d frames each)",
                self.test_essids,
                self._beacon_test_frames,
            )

    def _frame_callback(self, packet: Any) -> None:
        dot11_type = self._scapy["Dot11"]
        if not packet.haslayer(dot11_type):
            return
        bssid = self._packet_bssid(packet)
        if not bssid:
            return
        essid = self._extract_essid(packet)
        if not self._packet_is_authorized(bssid, essid):
            return

        with self._writer_lock:
            if self._main_writer is not None:
                self._main_writer.write(packet)

        if packet.haslayer(self._scapy["Dot11Beacon"]):
            self._process_network(packet, bssid, essid, "beacon")
        elif packet.haslayer(self._scapy["Dot11ProbeResp"]):
            self._process_network(packet, bssid, essid, "probe")
        elif packet.haslayer(self._scapy["Dot11Auth"]):
            self._update_handshake_status(bssid, "auth")
        if packet.haslayer(self._scapy["EAPOL"]):
            self._capture_eapol(packet, bssid)

    def _packet_bssid(self, packet: Any) -> str | None:
        dot11 = packet[self._scapy["Dot11"]]
        frame_control = int(getattr(dot11, "FCfield", 0))
        to_ds = bool(frame_control & 0x1)
        from_ds = bool(frame_control & 0x2)
        if to_ds and not from_ds:
            candidate = dot11.addr1
        elif from_ds and not to_ds:
            candidate = dot11.addr2
        else:
            candidate = dot11.addr3 or dot11.addr2
        if not candidate or candidate.lower() == "ff:ff:ff:ff:ff:ff":
            return None
        try:
            self.auth_policy._validate_bssid_format(candidate)
        except AuthorizationError:
            return None
        return str(candidate).lower()

    def _packet_is_authorized(self, bssid: str, essid: str | None) -> bool:
        bssid_allowed = False
        if self.authorized_bssids:
            try:
                self.auth_policy.assert_bssid_authorized(bssid, self.authorized_bssids)
                bssid_allowed = True
            except AuthorizationError:
                pass

        essid_allowed = False
        if essid is not None:
            if essid == "":
                essid_allowed = self.allow_hidden
            elif self.authorized_essids:
                try:
                    self.auth_policy.assert_essid_authorized(
                        essid, self.authorized_essids
                    )
                    essid_allowed = True
                except AuthorizationError:
                    pass
            if essid_allowed:
                self._bssid_essids[bssid] = essid
        elif self._bssid_essids.get(bssid) in self.authorized_essids:
            essid_allowed = True

        scope_type = self.scope["type"]
        if scope_type == "bssid":
            return bssid_allowed
        if scope_type == "essid":
            return essid_allowed
        return bssid_allowed or essid_allowed

    def _extract_essid(self, packet: Any) -> str | None:
        elt_type = self._scapy["Dot11Elt"]
        if not packet.haslayer(elt_type):
            return None
        element = packet.getlayer(elt_type)
        visited = 0
        while element is not None and visited < 64:
            if getattr(element, "ID", None) in (0, "SSID"):
                raw = bytes(getattr(element, "info", b""))
                return raw.decode("utf-8", errors="replace")
            payload = getattr(element, "payload", None)
            element = payload if isinstance(payload, elt_type) else None
            visited += 1
        return None

    def _process_network(
        self, packet: Any, bssid: str, essid: str | None, status: str
    ) -> None:
        display_essid = "(hidden)" if essid == "" else (essid or "(unknown)")
        channel = self._packet_channel(packet)
        signal = int(getattr(packet, "dBm_AntSignal", 0) or 0)
        network = self._discovered_networks.get(bssid)
        if network is None:
            network = DiscoveredNetwork(
                bssid=bssid,
                essid=display_essid,
                band="2.4GHz" if channel <= 14 else "5/6GHz",
                channel=channel,
                signal_dbm=signal,
                wpa_version=self._security_label(packet),
            )
            self._discovered_networks[bssid] = network
        network.seen_count += 1
        network.signal_dbm = signal
        network.channel = channel
        if network.handshake_status == "none":
            network.handshake_status = status

    def _packet_channel(self, packet: Any) -> int:
        elt_type = self._scapy["Dot11Elt"]
        element = packet.getlayer(elt_type)
        visited = 0
        while element is not None and visited < 64:
            if getattr(element, "ID", None) in (3, "DSset"):
                raw = bytes(getattr(element, "info", b""))
                if raw:
                    return int(raw[0])
            payload = getattr(element, "payload", None)
            element = payload if isinstance(payload, elt_type) else None
            visited += 1
        return int(self.channels[0])

    def _security_label(self, packet: Any) -> str:
        raw = bytes(packet)
        if b"\x00\x0f\xac\x08" in raw:
            return "WPA3"
        if b"\x00\x0f\xac" in raw:
            return "WPA2"
        if b"\x00\x50\xf2\x01" in raw:
            return "WPA"
        return "Open/Unknown"

    def _update_handshake_status(self, bssid: str, status: str) -> None:
        network = self._discovered_networks.get(bssid)
        if network is not None:
            network.handshake_status = status

    def _capture_eapol(self, packet: Any, bssid: str) -> None:
        capture_path = Path(self.capture_dir) / (
            f"{self.instance_id}-handshake-{bssid.replace(':', '')}.pcap"
        )
        fingerprint = bytes(packet[self._scapy["EAPOL"]])
        fingerprints = self._eapol_fingerprints.setdefault(bssid, set())
        fingerprints.add(fingerprint)

        with self._writer_lock:
            writer = self._handshake_writers.get(bssid)
            if writer is None:
                writer = self._scapy["PcapWriter"](
                    str(capture_path), append=False, sync=True
                )
                os.chmod(capture_path, 0o600)
                self._handshake_writers[bssid] = writer
                self.pcap_handshake_files[bssid] = str(capture_path)
            writer.write(packet)

        self._update_handshake_status(
            bssid, "complete" if len(fingerprints) >= 4 else "partial"
        )

    def _close_writers(self) -> None:
        with self._writer_lock:
            writers: Iterable[Any] = [
                self._main_writer,
                *self._handshake_writers.values(),
            ]
            for writer in writers:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception as exc:
                        log.warning("Could not close capture writer: %s", exc)
            self._main_writer = None
            self._handshake_writers.clear()

    def get_state_for_persistence(self) -> dict[str, Any]:
        return {
            "monitor_iface": self.monitor_iface,
            "pcap_file": self.pcap_file,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "channels": list(self.channels),
            "transmission_budget": {
                "maximum": self._budget.maximum,
                "attempted": self._budget.attempted,
                "remaining": self._budget.remaining,
            },
            "transmission_audit": list(self._tx_audit),
            "discovered_networks": [
                network.to_dict() for network in self._discovered_networks.values()
            ],
            "handshake_pcaps": dict(self.pcap_handshake_files),
        }
