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
            image_name = Path(image.value).name.casefold()
            if image_name not in ("rawetherbridge.exe", "npcapbridge.exe"):
                return "exited"
            # process_started_at 是桥接自己写入的"开始保活"时刻，不是进程创建时间：
            # 它取在网卡打开完成之后（PyInstaller onefile 自解包 + Python 初始化 +
            # wpcap 加载 + 网卡枚举），实测比真实创建时间晚 1~3 秒。此处的时间比对
            # 只用于排除 PID 复用，容差取 300 秒；沿用 1 秒会把仍在正常发送心跳的
            # 桥接进程误判成 exited，进而触发看门狗误杀重建。
            if abs(creation - started_at.timestamp()) > 300:
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
        result.update({key: raw[key] for key in (
            "session_id", "process_id", "adapter_description", "successful_sends",
            "last_send_status", "last_success_at", "updated_at",
        ) if key in raw})
        for key in ("last_failure_at", "last_failure_status", "send_duration_ms", "send_attempt",
                    "retry_recoveries", "failure_driver_state", "failure_service_state", "failure_link_state",
                    "exit_reason", "exit_code", "exited_at", "native_backend"):
            if key in raw and isinstance(raw[key], (str, int)):
                result[key] = raw[key]
        if result.get("native_backend") not in {"npcap", "rawether"}:
            # Records written by 1.5.x before the backend field existed were all
            # produced by NpcapBridge.exe.
            result["native_backend"] = "npcap"
        process = _process_state(pid, started)
        state = raw["state"]
        age = (current - updated).total_seconds()
        send_age: float | None = None
        try:
            success_at = datetime.fromisoformat(str(raw["last_success_at"]))
            if success_at.tzinfo is not None:
                send_age = (current - success_at).total_seconds()
        except (KeyError, TypeError, ValueError):
            send_age = None
        if math.isfinite(age) and age >= -5:
            result["record_age_seconds"] = max(0, round(age, 1))
        if not math.isfinite(age) or age < -5:
            result.update(state="unknown", reason="invalid-clock")
        elif process == "exited" and _session_is_running() is not False:
            # A newer bridge may be alive even if its file writer failed. An
            # old stopped/exited record must not authorize resetting it.
            result.update(state="unknown", reason="session-record-mismatch")
        elif state == "send-failed" and count > 0:
            result.update(state="send-failed", reason="driver-send-failed")
        elif state == "stopped":
            result.update(state="stopped", reason="session-stopped")
        elif (count > 0 and state in {"running", "retrying"}
              and raw.get("last_send_status", 0) == 0
              and send_age is not None and -5 <= send_age <= 90
              and age <= 90):
            # 心跳新鲜优先于进程句柄判定：桥每 30 秒成功发送一次，90 秒内仍有
            # 成功发送即证明保活会话活着。进程句柄、进程创建时间等次要判据的
            # 误判不得把健康会话判死，否则看门狗会反复误杀重建（历史故障）。
            result.update(
                state="running" if state == "running" else "retrying",
                reason="recent-send-success" if state == "running" else "bounded-send-retry",
                last_success_age_seconds=max(0, round(send_age, 1)),
            )
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
