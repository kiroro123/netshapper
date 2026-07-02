"""Authorized passive BLE discovery and read-only GATT security auditing."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import re
import threading
from typing import Any
from uuid import UUID

from netshaper import config
from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.plugin import PluginError, PluginInterface
from netshaper.exceptions import NetShaperError

log = logging.getLogger("netshaper.ble")

_BLE_ADDRESS_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_BLUETOOTH_BASE_UUID = "0000{short}-0000-1000-8000-00805f9b34fb"


class BleError(NetShaperError):
    """Raised when a BLE operation cannot be performed safely."""


@dataclass
class DiscoveredBleDevice:
    address: str
    name: str = ""
    rssi: int | None = None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_ids: list[int] = field(default_factory=list)
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    seen_count: int = 1
    services: list[dict[str, Any]] = field(default_factory=list)
    unpaired_access: str = "not-tested"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BleReconPlugin(PluginInterface):
    """Passive discovery plus explicitly scoped, read-only GATT enumeration."""

    PLUGIN_ID = "ble-recon"
    PLUGIN_NAME = "BLE Reconnaissance"
    SUPPORTED_SCOPE_TYPES = ("ble-address", "ble-service", "mixed")

    def __init__(
        self,
        instance_id: str,
        scope: dict[str, Any],
        plugin_config: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        self.validate_scope(scope, auth_policy)
        if not _INSTANCE_RE.fullmatch(instance_id):
            raise BleError("invalid plugin instance id")
        super().__init__(instance_id, scope, plugin_config, auth_policy)

        self.authorized_addresses = tuple(
            value.lower() for value in self._scope_values(scope, "addresses")
        )
        self.authorized_service_uuids = tuple(
            self._normalize_uuid(value)
            for value in self._scope_values(scope, "service_uuids")
        )
        self.allow_service_enumeration = bool(
            scope.get("allow_service_enumeration", False)
        )
        self.audit_unpaired_access = bool(scope.get("audit_unpaired_access", False))
        self.scan_timeout = self._bounded_number(
            plugin_config.get("scan_timeout", 15.0),
            "scan_timeout",
            1.0,
            300.0,
        )
        self.connection_timeout = self._bounded_number(
            plugin_config.get("connection_timeout", 10.0),
            "connection_timeout",
            1.0,
            60.0,
        )
        self.passive_patterns = self._passive_service_patterns()
        self.passive_patterns.extend(
            self._validate_passive_patterns(plugin_config.get("passive_patterns", []))
        )
        if not self.passive_patterns:
            raise BleError(
                "passive BLE scanning requires authorized service UUIDs or "
                "config.passive_patterns"
            )

        self.scan_start: str | None = None
        self.scan_end: str | None = None
        self._bleak: dict[str, Any] = {}
        self._devices: dict[str, DiscoveredBleDevice] = {}
        self._devices_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._startup_event = threading.Event()
        self._worker_error = ""
        self._worker: threading.Thread | None = None

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
        del auth_policy  # BLE authorization is independent of IP CIDR scope.
        if not isinstance(scope, dict):
            raise PluginError("BLE scope must be a dictionary")
        scope_type = scope.get("type")
        if scope_type not in cls.SUPPORTED_SCOPE_TYPES:
            raise PluginError(
                "ble-recon scope type must be 'ble-address', 'ble-service', or 'mixed'"
            )
        addresses = cls._validated_string_list(scope, "addresses")
        service_uuids = cls._validated_string_list(scope, "service_uuids")
        for address in addresses:
            if not _BLE_ADDRESS_RE.fullmatch(address):
                raise PluginError(f"invalid BLE address: {address!r}")
        for service_uuid in service_uuids:
            try:
                cls._normalize_uuid(service_uuid)
            except ValueError as exc:
                raise PluginError(
                    f"invalid BLE service UUID: {service_uuid!r}"
                ) from exc

        if scope_type == "ble-address" and not addresses:
            raise PluginError("BLE address scope requires at least one address")
        if scope_type == "ble-service" and not service_uuids:
            raise PluginError("BLE service scope requires at least one UUID")
        if scope_type == "mixed" and not (addresses or service_uuids):
            raise PluginError("mixed BLE scope requires addresses or service UUIDs")

        for flag in ("allow_service_enumeration", "audit_unpaired_access"):
            if flag in scope and not isinstance(scope[flag], bool):
                raise PluginError(f"{flag} must be true or false")
        if scope.get("audit_unpaired_access") and not scope.get(
            "allow_service_enumeration"
        ):
            raise PluginError(
                "audit_unpaired_access requires allow_service_enumeration=true"
            )

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
    def _normalize_uuid(raw_uuid: str) -> str:
        value = raw_uuid.strip().lower()
        if re.fullmatch(r"[0-9a-f]{4}", value):
            value = _BLUETOOTH_BASE_UUID.format(short=value)
        elif re.fullmatch(r"[0-9a-f]{8}", value):
            value = f"{value}-0000-1000-8000-00805f9b34fb"
        return str(UUID(value))

    @staticmethod
    def _bounded_number(value: Any, name: str, minimum: float, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BleError(f"{name} must be numeric")
        result = float(value)
        if not minimum <= result <= maximum:
            raise BleError(f"{name} must be between {minimum} and {maximum}")
        return result

    def _passive_service_patterns(self) -> list[tuple[int, int, bytes]]:
        patterns: list[tuple[int, int, bytes]] = []
        base_suffix = "-0000-1000-8000-00805f9b34fb"
        for normalized in self.authorized_service_uuids:
            uuid_value = UUID(normalized)
            if normalized.endswith(base_suffix):
                assigned = int(normalized[:8], 16)
                if assigned <= 0xFFFF:
                    content = assigned.to_bytes(2, "little")
                    data_types = (0x02, 0x03, 0x16)
                else:
                    content = assigned.to_bytes(4, "little")
                    data_types = (0x04, 0x05, 0x20)
            else:
                content = uuid_value.bytes_le
                data_types = (0x06, 0x07, 0x21)
            patterns.extend((0, data_type, content) for data_type in data_types)
        return patterns

    @staticmethod
    def _validate_passive_patterns(raw: Any) -> list[tuple[int, int, bytes]]:
        if not isinstance(raw, list) or len(raw) > 32:
            raise BleError("passive_patterns must be a list of at most 32 patterns")
        result: list[tuple[int, int, bytes]] = []
        for item in raw:
            if not isinstance(item, dict):
                raise BleError("each passive pattern must be an object")
            start = item.get("start_position", 0)
            data_type = item.get("ad_data_type")
            content_hex = item.get("content_hex")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or not 0 <= start <= 31
            ):
                raise BleError("passive pattern start_position must be 0-31")
            if (
                isinstance(data_type, bool)
                or not isinstance(data_type, int)
                or not 1 <= data_type <= 255
            ):
                raise BleError("passive pattern ad_data_type must be 1-255")
            if not isinstance(content_hex, str):
                raise BleError("passive pattern content_hex must be a hex string")
            try:
                content = bytes.fromhex(content_hex)
            except ValueError as exc:
                raise BleError("passive pattern content_hex is invalid") from exc
            if not content or len(content) > 31:
                raise BleError("passive pattern content must contain 1-31 bytes")
            result.append((start, data_type, content))
        return result

    @staticmethod
    def _load_bleak() -> dict[str, Any]:
        try:
            from bleak import BleakClient, BleakScanner
        except ImportError as exc:
            raise BleError(
                "BLE support requires the optional dependency: "
                "pip install 'netshaper[ble]'"
            ) from exc
        return {"BleakClient": BleakClient, "BleakScanner": BleakScanner}

    def start(self) -> bool:
        if self.active:
            return True
        self.scan_start = datetime.now(timezone.utc).isoformat()
        if config.DRY_RUN:
            self.active = True
            log.info(
                "[DRY-RUN] Would passively scan BLE scope for %.1f seconds",
                self.scan_timeout,
            )
            if self.allow_service_enumeration:
                log.info(
                    "[DRY-RUN] Would enumerate authorized GATT services "
                    "without pairing requests"
                )
            return True
        try:
            self._bleak = self._load_bleak()
            self._stop_event.clear()
            self._startup_event.clear()
            self._worker_error = ""
            self._worker = threading.Thread(
                name="ble-recon",
                target=self._worker_main,
                daemon=True,
            )
            self._worker.start()
            if not self._startup_event.wait(timeout=5):
                raise BleError("BLE scanner did not start within 5 seconds")
            if self._worker_error:
                raise BleError(self._worker_error)
            self.active = True
            return True
        except Exception as exc:
            log.error("BLE recon start failed: %s", exc)
            self._stop_event.set()
            if self._worker is not None:
                self._worker.join(timeout=2)
            self.active = False
            return False

    def stop(self) -> bool:
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=5)
            if self._worker.is_alive():
                log.error("BLE worker did not stop")
                return False
        self.scan_end = datetime.now(timezone.utc).isoformat()
        self.active = False
        return True

    def _worker_main(self) -> None:
        try:
            asyncio.run(self._scan_and_enumerate())
        except Exception as exc:
            self._worker_error = f"{type(exc).__name__}: {exc}"
            log.error("BLE worker failed: %s", exc)
        finally:
            self._startup_event.set()
            self.scan_end = datetime.now(timezone.utc).isoformat()

    async def _scan_and_enumerate(self) -> None:
        scanner_cls = self._bleak["BleakScanner"]
        try:
            scanner = scanner_cls(
                detection_callback=self._detection_callback,
                scanning_mode="passive",
                bluez={"or_patterns": self.passive_patterns},
            )
        except TypeError as exc:
            raise BleError(
                "BLE backend does not expose an explicit passive scan mode"
            ) from exc

        await scanner.start()
        self._startup_event.set()
        deadline = asyncio.get_running_loop().time() + self.scan_timeout
        try:
            while (
                not self._stop_event.is_set()
                and asyncio.get_running_loop().time() < deadline
            ):
                await asyncio.sleep(0.2)
        finally:
            await scanner.stop()

        if not self.allow_service_enumeration or self._stop_event.is_set():
            return
        with self._devices_lock:
            addresses = list(self._devices)
        for address in addresses:
            if self._stop_event.is_set():
                return
            await self._enumerate_services(address)

    def _detection_callback(self, device: Any, advertisement: Any) -> None:
        address = str(getattr(device, "address", "")).lower()
        if not _BLE_ADDRESS_RE.fullmatch(address):
            return
        advertised_uuids = {
            self._normalize_uuid(value)
            for value in (getattr(advertisement, "service_uuids", None) or [])
            if value
        }
        if not self._is_authorized(address, advertised_uuids):
            return

        now = datetime.now(timezone.utc).isoformat()
        name = str(
            getattr(advertisement, "local_name", None)
            or getattr(device, "name", None)
            or ""
        )
        rssi = getattr(advertisement, "rssi", None)
        manufacturer_data = getattr(advertisement, "manufacturer_data", None) or {}
        with self._devices_lock:
            existing = self._devices.get(address)
            if existing is None:
                self._devices[address] = DiscoveredBleDevice(
                    address=address,
                    name=name,
                    rssi=int(rssi) if isinstance(rssi, (int, float)) else None,
                    service_uuids=sorted(advertised_uuids),
                    manufacturer_ids=sorted(int(key) for key in manufacturer_data),
                )
            else:
                existing.last_seen = now
                existing.seen_count += 1
                existing.name = name or existing.name
                if isinstance(rssi, (int, float)):
                    existing.rssi = int(rssi)
                existing.service_uuids = sorted(
                    set(existing.service_uuids) | advertised_uuids
                )

    def _is_authorized(self, address: str, advertised_uuids: set[str]) -> bool:
        address_allowed = address in self.authorized_addresses
        service_allowed = bool(
            advertised_uuids.intersection(self.authorized_service_uuids)
        )
        scope_type = self.scope["type"]
        if scope_type == "ble-address":
            return address_allowed
        if scope_type == "ble-service":
            return service_allowed
        return address_allowed or service_allowed

    async def _enumerate_services(self, address: str) -> None:
        with self._devices_lock:
            device = self._devices.get(address)
        if device is None:
            return
        if not self._is_authorized(address, set(device.service_uuids)):
            return

        client_cls = self._bleak["BleakClient"]
        try:
            client = client_cls(
                address,
                timeout=self.connection_timeout,
                pair=False,
            )
            async with client:
                services = getattr(client, "services", None)
                if services is None and hasattr(client, "get_services"):
                    services = await client.get_services()
                device.services = self._serialize_services(services or [])
                if self.audit_unpaired_access:
                    device.unpaired_access = (
                        "services-readable" if device.services else "connected"
                    )
        except Exception as exc:
            device.error = f"{type(exc).__name__}: {exc}"
            if self.audit_unpaired_access:
                device.unpaired_access = "blocked-or-unavailable"

    def _serialize_services(self, services: Any) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for service in services:
            service_uuid = self._normalize_uuid(str(service.uuid))
            if (
                self.authorized_service_uuids
                and service_uuid not in self.authorized_service_uuids
            ):
                continue
            characteristics = []
            for characteristic in getattr(service, "characteristics", []):
                characteristics.append(
                    {
                        "uuid": self._normalize_uuid(str(characteristic.uuid)),
                        "properties": sorted(
                            str(value)
                            for value in getattr(characteristic, "properties", [])
                        ),
                    }
                )
            result.append(
                {
                    "uuid": service_uuid,
                    "description": str(getattr(service, "description", "") or ""),
                    "characteristics": characteristics,
                }
            )
        return result

    def get_state_for_persistence(self) -> dict[str, Any]:
        with self._devices_lock:
            devices = [device.to_dict() for device in self._devices.values()]
        return {
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "passive": True,
            "service_enumeration": self.allow_service_enumeration,
            "unpaired_access_audit": self.audit_unpaired_access,
            "devices": devices,
        }
