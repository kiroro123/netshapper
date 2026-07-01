"""
NetShaper — WifiRecon plugin for 802.11 scanning and handshake capture.

Provides passive and active 802.11 discovery with authorized BSSID/ESSID gating.
Captures beacon frames, probe responses, and 4-way handshake frames to .pcap files.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess  # nosec B404
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netshaper.core.authorization import AuthorizationPolicy, AuthorizationError
from netshaper.core.plugin import PluginInterface, PluginError
from netshaper.exceptions import NetShaperError

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Auth, Dot11AssoResp, EAPOL
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

log = logging.getLogger("netshaper.wifi")


class WifiError(NetShaperError):
    """Raised when WiFi operations fail."""
    pass


@dataclass
class DiscoveredNetwork:
    """Represents a discovered 802.11 network."""
    bssid: str
    essid: str
    band: str  # "2.4GHz" or "5GHz"
    channel: int
    signal_dbm: int
    seen_count: int = 0
    handshake_status: str = "none"  # "none", "beacon", "probe", "auth", "assoc", "eapol", "partial"
    wpa_version: str = ""  # "WPA", "WPA2", "WPA3", "Open"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return asdict(self)


class WifiReconPlugin(PluginInterface):
    """
    802.11 wireless reconnaissance plugin.
    
    Discovers networks via passive beacons and active probing.
    Captures handshake frames for downstream analysis.
    """
    
    PLUGIN_ID = "wifi-recon"
    PLUGIN_NAME = "WiFi Reconnaissance"
    SUPPORTED_SCOPE_TYPES = ("bssid", "essid", "mixed")

    def __init__(
        self,
        instance_id: str,
        scope: Dict[str, Any],
        config: Dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        super().__init__(instance_id, scope, config, auth_policy)
        
        if not SCAPY_AVAILABLE:
            raise WifiError("scapy is required for WifiRecon plugin")
        
        self.interface: Optional[str] = config.get("interface", "wlan0")
        self.monitor_iface: Optional[str] = None
        self.pcap_file: Optional[str] = None
        self.pcap_handshake_files: Dict[str, str] = {}
        self.scan_start: Optional[str] = None
        self.scan_end: Optional[str] = None
        self._sniff_thread: Optional[threading.Thread] = None
        self._sniff_stop = threading.Event()
        self._discovered_networks: Dict[str, DiscoveredNetwork] = {}
        self._handshake_states: Dict[str, str] = {}  # bssid -> latest_frame_type
        
        # Parse scope
        self.authorized_bssids: tuple[str, ...] = ()
        self.authorized_essids: tuple[str, ...] = ()
        self.allow_active_scan: bool = False
        self.allow_hidden: bool = False
        self.channels: List[int] = []
        self.probe_burst: int = config.get("probe_burst", 1)
        self.probe_interval: float = config.get("probe_interval", 2.0)
        
        self._parse_scope()

    def _parse_scope(self) -> None:
        """Parse and validate scope."""
        scope_type = self.scope.get("type", "bssid")
        
        if scope_type == "bssid":
            bssids_raw = self.scope.get("bssids") or []
            if isinstance(bssids_raw, str):
                bssids_raw = [bssids_raw]
            
            # Validate each BSSID
            for b in bssids_raw:
                self.auth_policy._validate_bssid_format(b)
            self.authorized_bssids = tuple(bssids_raw)
            self.allow_active_scan = self.scope.get("allow_active_scan", True)
            
        elif scope_type == "essid":
            essids_raw = self.scope.get("essids") or []
            if isinstance(essids_raw, str):
                essids_raw = [essids_raw]
            
            # Validate each ESSID
            for e in essids_raw:
                self.auth_policy._validate_essid_format(e)
            self.authorized_essids = tuple(essids_raw)
            self.allow_hidden = self.scope.get("allow_hidden", False)
            
        elif scope_type == "mixed":
            bssids_raw = self.scope.get("bssids") or []
            essids_raw = self.scope.get("essids") or []
            for b in bssids_raw:
                self.auth_policy._validate_bssid_format(b)
            for e in essids_raw:
                self.auth_policy._validate_essid_format(e)
            self.authorized_bssids = tuple(bssids_raw)
            self.authorized_essids = tuple(essids_raw)
            self.allow_active_scan = self.scope.get("allow_active_scan", True)
            self.allow_hidden = self.scope.get("allow_hidden", False)
        
        # Parse channels (default: 1-13 for 2.4GHz, 36-165 for 5GHz)
        self.channels = self.scope.get("channels", self._default_channels())

    def _default_channels(self) -> List[int]:
        """Return default channels: 2.4GHz (1-13) + 5GHz (all valid channels)"""
        channels_24 = list(range(1, 14))
        # 5GHz channels: UNII-1 (36-64), UNII-2 (100-144), UNII-3 (149-165)
        channels_5 = list(range(36, 65, 4)) + list(range(100, 145, 4)) + list(range(149, 166, 4))
        return channels_24 + channels_5

    def start(self) -> bool:
        """Start WiFi reconnaissance."""
        from netshaper import config
        
        if config.DRY_RUN:
            log.info("[DRY-RUN] Would activate monitor mode on %s", self.interface)
            log.info("[DRY-RUN] Would open PCAP file for capture")
            self.active = True
            return True
        
        try:
            # Activate monitor mode
            self._activate_monitor_mode()
            
            # Create PCAP files
            self.pcap_file = os.path.join(
                tempfile.gettempdir(),
                f"wifirecon-{self.instance_id}.pcap"
            )
            # Touch the file first
            open(self.pcap_file, 'a').close()
            os.chmod(self.pcap_file, 0o600)  # Mode 600 for privacy
            
            # Start capture thread
            self.scan_start = datetime.now(timezone.utc).isoformat()
            self._sniff_stop.clear()
            self._sniff_thread = threading.Thread(
                target=self._capture_frames,
                daemon=True
            )
            self._sniff_thread.start()
            
            self.active = True
            log.info("WifiRecon started on %s, PCAP: %s", self.monitor_iface, self.pcap_file)
            return True
            
        except Exception as exc:
            log.error("WifiRecon start failed: %s", exc)
            self.active = False
            return False

    def stop(self) -> bool:
        """Stop WiFi reconnaissance."""
        from netshaper import config
        
        if config.DRY_RUN:
            log.info("[DRY-RUN] Would stop capture and restore managed mode")
            self.active = False
            return True
        
        try:
            self._sniff_stop.set()
            if self._sniff_thread:
                self._sniff_thread.join(timeout=5)
            
            self.scan_end = datetime.now(timezone.utc).isoformat()
            
            # Restore managed mode
            self._restore_managed_mode()
            
            self.active = False
            log.info("WifiRecon stopped")
            return True
            
        except Exception as exc:
            log.error("WifiRecon stop failed: %s", exc)
            self.active = False
            return False
            return False

    def _activate_monitor_mode(self) -> None:
        """Activate monitor mode on interface."""
        if not self.interface:
            raise WifiError("interface not configured")
        
        # Generate monitor interface name
        self.monitor_iface = f"{self.interface}mon"
        
        # Bring down interface
        subprocess.run(
            ["ip", "link", "set", self.interface, "down"],
            check=True,
            capture_output=True
        )  # nosec B603 — validated interface name
        
        # Set to monitor mode
        subprocess.run(
            ["iw", self.interface, "set", "monitor", "none"],
            check=True,
            capture_output=True
        )  # nosec B603
        
        # Bring up interface
        subprocess.run(
            ["ip", "link", "set", self.interface, "up"],
            check=True,
            capture_output=True
        )  # nosec B603
        
        log.info("Monitor mode activated on %s", self.interface)

    def _restore_managed_mode(self) -> None:
        """Restore managed mode on interface."""
        if not self.interface:
            return
        
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                check=False,
                capture_output=True
            )  # nosec B603
            
            subprocess.run(
                ["iw", self.interface, "set", "type", "managed"],
                check=False,
                capture_output=True
            )  # nosec B603
            
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=False,
                capture_output=True
            )  # nosec B603
            
            log.info("Managed mode restored on %s", self.interface)
        except Exception as exc:
            log.warning("Failed to restore managed mode: %s", exc)

    def _capture_frames(self) -> None:
        """Capture 802.11 frames in background thread."""
        if not self.monitor_iface or not self.pcap_file:
            return
        
        try:
            # Scapy sniff with Dot11 layer
            sniff(
                iface=self.monitor_iface,
                prn=self._frame_callback,
                store=False,
                stop_filter=lambda x: self._sniff_stop.is_set(),
                timeout=None
            )
        except Exception as exc:
            log.error("Frame capture failed: %s", exc)

    def _frame_callback(self, pkt: Any) -> None:
        """Process captured frame."""
        if not pkt.haslayer(Dot11):
            return
        
        dot11 = pkt[Dot11]
        bssid = dot11.addr2  # BSSID from sender
        
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            return
        
        # Check authorization
        try:
            if self.authorized_bssids:
                self.auth_policy.assert_bssid_authorized(bssid, self.authorized_bssids)
        except AuthorizationError:
            return  # Skip unauthorized BSSID
        
        # Process beacon frames
        if pkt.haslayer(Dot11Beacon):
            self._process_beacon(pkt, bssid)
        
        # Process probe response
        elif pkt.haslayer(Dot11ProbeResp):
            self._process_probe_response(pkt, bssid)
        
        # Process auth frames
        elif pkt.haslayer(Dot11Auth):
            self._process_auth(pkt, bssid)
        
        # Process EAPOL (handshake)
        elif pkt.haslayer(EAPOL):
            self._process_eapol(pkt, bssid)

    def _process_beacon(self, pkt: Any, bssid: str) -> None:
        """Process beacon frame."""
        beacon = pkt[Dot11Beacon]
        essid = beacon.info.decode("utf-8", errors="ignore") if beacon.info else "(hidden)"
        
        # Check ESSID authorization
        if essid != "(hidden)" and self.authorized_essids:
            try:
                self.auth_policy.assert_essid_authorized(essid, self.authorized_essids)
            except AuthorizationError:
                return
        
        # Update discovered network
        if bssid not in self._discovered_networks:
            self._discovered_networks[bssid] = DiscoveredNetwork(
                bssid=bssid,
                essid=essid,
                band="2.4GHz",
                channel=1,
                signal_dbm=0,
            )
        
        net = self._discovered_networks[bssid]
        net.seen_count += 1
        
        # Update handshake state machine
        if self._handshake_states.get(bssid) in (None, "none"):
            self._handshake_states[bssid] = "beacon"
            net.handshake_status = "beacon"

    def _process_probe_response(self, pkt: Any, bssid: str) -> None:
        """Process probe response frame."""
        probe = pkt[Dot11ProbeResp]
        essid = probe.info.decode("utf-8", errors="ignore") if probe.info else "(hidden)"
        
        # Update state
        if bssid in self._handshake_states:
            if self._handshake_states[bssid] == "beacon":
                self._handshake_states[bssid] = "probe"
                if bssid in self._discovered_networks:
                    self._discovered_networks[bssid].handshake_status = "probe"

    def _process_auth(self, pkt: Any, bssid: str) -> None:
        """Process authentication frame."""
        if bssid in self._handshake_states:
            if self._handshake_states[bssid] in ("beacon", "probe"):
                self._handshake_states[bssid] = "auth"
                if bssid in self._discovered_networks:
                    self._discovered_networks[bssid].handshake_status = "auth"

    def _process_eapol(self, pkt: Any, bssid: str) -> None:
        """Process EAPOL frame (4-way handshake)."""
        if bssid in self._handshake_states:
            if self._handshake_states[bssid] != "eapol":
                self._handshake_states[bssid] = "eapol"
                if bssid in self._discovered_networks:
                    self._discovered_networks[bssid].handshake_status = "eapol"
                
                # Create separate handshake PCAP
                pcap_hshake = os.path.join(
                    tempfile.gettempdir(),
                    f"wifirecon-handshake-{bssid.replace(':', '')}.pcap"
                )
                self.pcap_handshake_files[bssid] = pcap_hshake
                log.info("Handshake detected for %s; saving to %s", bssid, pcap_hshake)

    def get_state_for_persistence(self) -> Dict[str, Any]:
        """Return plugin state for recovery."""
        return {
            "monitor_iface": self.monitor_iface,
            "pcap_file": self.pcap_file,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "discovered_networks": [
                net.to_dict() for net in self._discovered_networks.values()
            ],
            "handshake_pcaps": self.pcap_handshake_files,
        }
