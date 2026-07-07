"""Process ownership helpers for session locks and stale-state recovery."""

from __future__ import annotations

import os
import time
from enum import Enum
from typing import Mapping, Optional

import psutil


class OwnerStatus(Enum):
    """Tri-state process ownership result."""

    LIVE = "live"
    STALE = "stale"
    UNKNOWN = "unknown"


def current_owner_metadata() -> dict[str, object]:
    """Return metadata that can later identify this exact process instance."""
    pid = os.getpid()
    try:
        process_create_time: Optional[float] = psutil.Process(pid).create_time()
    except Exception:
        process_create_time = None
    return {
        "pid": pid,
        "process_create_time": process_create_time,
        "created_at": time.time(),
    }


def _expected_create_time(owner: Mapping[str, object]) -> Optional[float]:
    raw_value = owner.get("process_create_time")
    if raw_value is None:
        return None
    if not isinstance(raw_value, (int, float, str)):
        return None
    try:
        return float(raw_value)
    except (TypeError, ValueError):
        return None


def owner_status(owner: Mapping[str, object] | None) -> OwnerStatus:
    """
    Determine whether persisted ownership belongs to a live process.

    Missing PID means there is no owner to protect. Missing or malformed
    create-time metadata for an existing process is ambiguous and fails closed.
    """
    owner = owner or {}
    raw_pid = owner.get("pid", 0)
    if raw_pid is None:
        raw_pid = 0
    if not isinstance(raw_pid, (int, str)):
        return OwnerStatus.UNKNOWN
    try:
        pid = int(raw_pid)
    except (TypeError, ValueError):
        return OwnerStatus.UNKNOWN
    if pid <= 0:
        return OwnerStatus.STALE

    expected_create_time = _expected_create_time(owner)
    try:
        process = psutil.Process(pid)
        actual_create_time = process.create_time()
    except psutil.NoSuchProcess:
        return OwnerStatus.STALE
    except Exception:
        return OwnerStatus.UNKNOWN

    if expected_create_time is None:
        return OwnerStatus.UNKNOWN
    if actual_create_time == expected_create_time:
        return OwnerStatus.LIVE
    return OwnerStatus.STALE
