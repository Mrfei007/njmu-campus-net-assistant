"""Read-only, redacted health of this app's constrained keepalive bridge."""
from __future__ import annotations

import ctypes
import json
import math
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from .config import APP_DIR

STATUS_PATH = APP_DIR / "native-keepalive-state.json"


def _session_is_running() -> bool | None:
    """Observe the bridge's existing mutex; never signal its stop event."""
    try:
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        api.OpenMutexW.restype = wintypes.HANDLE
        api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        api.ReleaseMutex.argtypes = [wintypes.HANDLE]
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = api.OpenMutexW(0x100001, False, r"Local\NJMUCampusNetAssistant-RuijieSession")
        if not handle:
            return False if ctypes.get_last_error() == 2 else None
        try:
            status = api.WaitForSingleObject(handle, 0)
            if status == 258:
                return True
            if status in {0, 128}:
                api.ReleaseMutex(handle)
                return False
            return None
        finally:
            api.CloseHandle(handle)
    except (OSError, AttributeError):
        return None


def _process_state(pid: int, started_at: datetime) -> str:
    """Check image and creation time to reject stale state and reused PIDs."""
    try:
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        api.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        handle = api.OpenProcess(0x1000, False, pid)
        if not handle:
            return "exited" if ctypes.get_last_error() == 87 else "unknown"
        try:
            code = wintypes.DWORD()
            if not api.GetExitCodeProcess(handle, ctypes.byref(code)):
                return "unknown"
            if code.value != 259:
                return "exited"
            values = [wintypes.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
                return "unknown"
            creation = ((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime) / 10_000_000 - 11644473600
            size = wintypes.DWORD(32768)
            image = ctypes.create_unicode_buffer(size.value)
            if not api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                return "unknown"
            if abs(creation - started_at.timestamp()) > 1 or Path(image.value).name.casefold() != "rawetherbridge.exe":
                return "exited"
            return "running"
        finally:
            api.CloseHandle(handle)
    except (OSError, AttributeError):
        return "unknown"


def read_health(path: Path | None = None, now: datetime | None = None) -> dict[str, object]:
    result: dict[str, object] = {"state": "unknown", "reason": "no-send-record", "server_receipt": "unverified"}
    try:
        raw = json.loads((path or STATUS_PATH).read_text(encoding="utf-8-sig"))
        UUID(str(raw["session_id"]))
        pid = int(raw["process_id"])
        started = datetime.fromisoformat(raw["process_started_at"])
        updated = datetime.fromisoformat(raw["updated_at"])
        current = now or datetime.now(timezone.utc)
        if pid <= 0 or started.tzinfo is None or updated.tzinfo is None:
            raise ValueError("invalid session")
        count = int(raw["successful_sends"])
        if count < 0 or raw["schema_version"] != 1:
            raise ValueError("invalid counters")
        # Copy only the documented allowlist; never copy arbitrary bridge data.
        result.update({key: raw[key] for key in ("session_id", "process_id", "adapter_description", "successful_sends", "last_send_status", "last_success_at")})
        for key in ("last_failure_at", "last_failure_status", "send_duration_ms", "send_attempt",
                    "retry_recoveries", "failure_driver_state", "failure_service_state", "failure_link_state"):
            if key in raw and isinstance(raw[key], (str, int)):
                result[key] = raw[key]
        process = _process_state(pid, started)
        state = raw["state"]
        age = (current - updated).total_seconds()
        if not math.isfinite(age) or age < -5:
            result.update(state="unknown", reason="invalid-clock")
        elif process == "exited" and _session_is_running() is not False:
            # A newer bridge may be alive even if its file writer failed. An
            # old stopped/exited record must not authorize resetting it.
            result.update(state="unknown", reason="session-record-mismatch")
        elif state == "send-failed" and count > 0:
            result.update(state="send-failed", reason="driver-send-failed")
        elif state == "stopped" and count > 0:
            result.update(state="stopped", reason="session-stopped")
        elif process == "exited" and count > 0:
            result.update(state="exited", reason="bridge-exited")
        elif process == "exited" and count == 0 and state in {"authenticating", "authentication-failed"}:
            result.update(state="inactive", reason="no-native-session")
        elif process != "running":
            result.update(state="unknown", reason="process-unverified")
        elif state == "retrying" and count > 0:
            result.update(state="retrying" if age <= 30 else "stale", reason="bounded-send-retry" if age <= 30 else "send-record-stale")
        elif state == "running" and count > 0 and int(raw["last_send_status"]) == 0:
            success = datetime.fromisoformat(raw["last_success_at"])
            send_age = (current - success).total_seconds()
            if success.tzinfo is None or send_age < -5:
                raise ValueError("invalid send timestamp")
            result.update(state="running" if age <= 90 and send_age <= 90 else "stale", reason="recent-send-success" if age <= 90 and send_age <= 90 else "send-record-stale", last_success_age_seconds=max(0, round(send_age, 1)))
        else:
            result.update(state="unknown", reason="authentication-in-progress" if state == "authenticating" else "no-successful-send")
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return {"state": "unknown", "reason": "no-valid-send-record", "server_receipt": "unverified"}
    return result
