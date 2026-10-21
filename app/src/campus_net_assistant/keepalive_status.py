"""Read-only, redacted health of this app's constrained keepalive bridge.

判定模型（1.6 起）：
  * 桥接写 schema v2：带真实进程创建时间、保活开始时刻、单调心跳序号。
  * 读取端输出三态语义，用 verdict_basis 说明结论来自哪条判据：
      - "heartbeat"       最近一次发送成功且记录新鲜（最可信）
      - "process-mutex"   进程存在且持有会话互斥体
      - "process-without-owner" / "pid-mismatch" / "mutex-held-elsewhere"  存疑，判 unknown
      - "absent"          进程不存在、互斥体无人持有、记录已过期（唯一允许看门狗重建的依据）
      - "legacy-v1"       旧桥（schema v1）记录，沿用 1.5.9.2 的判定
  * unknown 永不升级为 exited：宁可不动，也不误杀健康会话。
"""
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
SESSION_MUTEX_NAME = r"Local\NJMUCampusNetAssistant-RuijieSession"

EXPECTED_BRIDGE_SCHEMA = 2
FRESH_SECONDS = 90          # 心跳/记录新鲜窗口
CLOCK_TOLERANCE = 5         # 允许的时钟回拨
CREATION_TOLERANCE = 2      # v2：进程创建时间比对容差（秒）
LEGACY_CREATION_TOLERANCE = 300  # v1：process_started_at 是"开始保活"时刻，比真实创建晚 1~3 秒
BRIDGE_IMAGES = ("rawetherbridge.exe", "npcapbridge.exe")

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
ERROR_FILE_NOT_FOUND = 2


def session_mutex_held() -> bool | None:
    """Observe the session mutex; True=有会话持有, False=无人持有, None=无法判定."""
    try:
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        api.OpenMutexW.restype = wintypes.HANDLE
        api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        api.ReleaseMutex.argtypes = [wintypes.HANDLE]
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = api.OpenMutexW(0x100001, False, SESSION_MUTEX_NAME)
        if not handle:
            error = ctypes.get_last_error()
            return False if error == ERROR_FILE_NOT_FOUND else None
        try:
            status = api.WaitForSingleObject(handle, 0)
            if status == WAIT_TIMEOUT:
                return True
            if status in {WAIT_OBJECT_0, WAIT_ABANDONED}:
                api.ReleaseMutex(handle)
                return False
            return None
        finally:
            api.CloseHandle(handle)
    except (OSError, AttributeError):
        return None


# 1.5.x 的内部名字，保留以便旧调用点继续可用。
def _session_is_running() -> bool | None:
    return session_mutex_held()


def _process_info(pid: int) -> dict[str, object] | None:
    """Return process facts, or None when the process cannot be inspected."""
    try:
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        api.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        api.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        handle = api.OpenProcess(0x1000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:
                return {"exists": False, "creation": None, "image": None}
            return None
        try:
            code = wintypes.DWORD()
            if not api.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            if code.value != 259:
                return {"exists": False, "creation": None, "image": None}
            values = [wintypes.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
                return None
            creation = ((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime) / 10_000_000 - 11644473600
            size = wintypes.DWORD(32768)
            image = ctypes.create_unicode_buffer(size.value)
            if not api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                return {"exists": True, "creation": creation, "image": None}
            return {"exists": True, "creation": creation, "image": image.value}
        finally:
            api.CloseHandle(handle)
    except (OSError, AttributeError):
        return None


def _process_state(pid: int, started_at: datetime, tolerance: float = CREATION_TOLERANCE) -> str:
    """Backwards-compatible helper: running / exited / unknown."""
    info = _process_info(pid)
    if info is None:
        return "unknown"
    if not info["exists"]:
        return "exited"
    image = info["image"]
    if image and Path(str(image)).name.casefold() not in BRIDGE_IMAGES:
        return "exited"
    creation = info["creation"]
    if creation is not None and abs(float(creation) - started_at.timestamp()) > tolerance:
        return "exited"
    return "running"


def _parse_moment(raw: dict, key: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(raw[key]))
    except (KeyError, TypeError, ValueError):
        return None
    return moment if moment.tzinfo is not None else None


def read_health(path: Path | None = None, now: datetime | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "state": "unknown",
        "reason": "no-send-record",
        "verdict_basis": "no-record",
        "bridge_schema": 0,
    }
    try:
        raw = json.loads((path or STATUS_PATH).read_text(encoding="utf-8-sig"))
        UUID(str(raw["session_id"]))
        pid = int(raw["process_id"])
        if pid <= 0:
            raise ValueError("invalid pid")
        schema = int(raw.get("schema_version", 0))
        if schema not in (1, EXPECTED_BRIDGE_SCHEMA):
            return {"state": "unknown", "reason": "unsupported-bridge-schema",
                    "verdict_basis": "schema-mismatch", "bridge_schema": schema}
        updated = _parse_moment(raw, "updated_at")
        if updated is None:
            raise ValueError("invalid updated_at")
        current = now or datetime.now(timezone.utc)
        count = int(raw["successful_sends"])
        if count < 0:
            raise ValueError("invalid counters")

        # Copy only the documented allowlist; never copy arbitrary bridge data.
        result.update({key: raw[key] for key in (
            "session_id", "process_id", "adapter_description", "successful_sends",
            "last_send_status", "last_success_at", "updated_at",
        ) if key in raw})
        for key in ("last_failure_at", "last_failure_status", "send_duration_ms", "send_attempt",
                    "retry_recoveries", "failure_driver_state", "failure_service_state", "failure_link_state",
                    "exit_reason", "exit_code", "exited_at", "native_backend", "heartbeat_seq"):
            if key in raw and isinstance(raw[key], (str, int)):
                result[key] = raw[key]
        result["bridge_schema"] = schema
        if result.get("native_backend") not in {"npcap", "rawether"}:
            # Records written before the backend field existed were all produced by NpcapBridge.exe.
            result["native_backend"] = "npcap"

        state = str(raw.get("state") or "")
        age = (current - updated).total_seconds()
        if not math.isfinite(age) or age < -CLOCK_TOLERANCE:
            result.update(state="unknown", reason="invalid-clock", verdict_basis="invalid-clock")
            return result
        result["record_age_seconds"] = max(0, round(age, 1))

        send_age: float | None = None
        success_at = _parse_moment(raw, "last_success_at")
        if success_at is not None:
            send_age = (current - success_at).total_seconds()
            if -CLOCK_TOLERANCE <= send_age <= FRESH_SECONDS * 4:
                result["last_success_age_seconds"] = max(0, round(send_age, 1))
        fresh = age <= FRESH_SECONDS
        sending = (count > 0 and state in {"running", "retrying"}
                   and raw.get("last_send_status", 0) == 0
                   and send_age is not None and -CLOCK_TOLERANCE <= send_age <= FRESH_SECONDS)

        if schema == 1:
            return _evaluate_legacy(raw, result, pid, state, count, age, send_age, fresh, sending)

        started = _parse_moment(raw, "keepalive_started_at") or _parse_moment(raw, "process_started_at")
        created_raw = _parse_moment(raw, "process_created_at")
        if created_raw is None:
            # v2 桥必写 process_created_at；缺了说明记录不完整，按"无法判定"处理。
            result.update(state="unknown", reason="missing-created-at", verdict_basis="schema-incomplete")
            return result
        result["process_created_at"] = created_raw.isoformat()

        info = _process_info(pid)
        held = session_mutex_held()
        alive = False
        creation_skew: float | None = None
        if info is not None and info["exists"]:
            image = info["image"]
            if image:
                result["image_path"] = image
                if Path(str(image)).name.casefold() not in BRIDGE_IMAGES:
                    result.update(state="unknown", reason="unexpected-image", verdict_basis="image-mismatch")
                    return result
            creation = info["creation"]
            if creation is not None:
                creation_skew = abs(float(creation) - created_raw.timestamp())
                result["creation_skew_seconds"] = round(creation_skew, 2)
                alive = creation_skew <= CREATION_TOLERANCE

        if state == "stopped":
            result.update(state="stopped", reason="session-stopped", verdict_basis="graceful-stop")
        elif state == "send-failed":
            result.update(state="send-failed", reason="driver-send-failed", verdict_basis="record")
        elif sending and fresh:
            # 心跳新鲜是最高优先判据：每 30 秒成功发送一次就证明会话活着。
            result.update(state="running" if state in {"", "running"} else "retrying",
                          verdict_basis="heartbeat",
                          reason="recent-send-success" if state in {"", "running"} else "bounded-send-retry")
        elif alive and held:
            result.update(state="running", reason="process-mutex-ok", verdict_basis="process-mutex")
        elif info is not None and info["exists"] and creation_skew is not None and creation_skew > CREATION_TOLERANCE:
            result.update(state="unknown", reason="pid-mismatch", verdict_basis="pid-mismatch")
        elif info is not None and info["exists"]:
            # 进程活着却不持有互斥体：异常态，不重建（避免出现双会话）。
            result.update(state="unknown", reason="session-owner-missing", verdict_basis="process-without-owner")
        elif info is None:
            # 进程打不开（权限/系统繁忙）：无法判定，绝不因此判 absent。
            result.update(state="unknown", reason="process-unverified", verdict_basis="process-unverified")
        elif held is True:
            # 有别人的会话持有互斥体：这份记录属于已退出的进程，不能据此重建。
            result.update(state="unknown", reason="session-owned-by-other", verdict_basis="mutex-held-elsewhere")
        elif held is None:
            # 互斥体状态未知（对象打不开又非"不存在"）：同样不许判 absent。
            result.update(state="unknown", reason="mutex-unverified", verdict_basis="mutex-unverified")
        elif not fresh and age > FRESH_SECONDS:
            # 唯一允许看门狗重建的结论：进程不存在 + 互斥体可获取 + 记录过期。
            result.update(state="exited", reason="bridge-gone", verdict_basis="absent")
        elif state == "retrying" and count > 0:
            result.update(state="retrying" if age <= 30 else "stale",
                          reason="bounded-send-retry" if age <= 30 else "send-record-stale",
                          verdict_basis="record")
        elif state in {"authenticating", "authentication-failed"}:
            result.update(state="inactive", reason="no-native-session", verdict_basis="record")
        else:
            result.update(state="unknown", reason="no-successful-send", verdict_basis="record")
        return result
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return {"state": "unknown", "reason": "no-valid-send-record",
                "verdict_basis": "no-record", "bridge_schema": 0}
    except Exception:
        return {"state": "unknown", "reason": "no-valid-send-record",
                "verdict_basis": "no-record", "bridge_schema": 0}


def _evaluate_legacy(raw: dict, result: dict, pid: int, state: str, count: int,
                     age: float, send_age: float | None, fresh: bool, sending: bool) -> dict:
    """1.5.x 桥（schema v1）：逐条沿用 1.5.9.2 的判定，只把结论来源标成 legacy-v1。

    顺序与 1.5.9.2 完全一致（含"心跳新鲜优先""会话被占则不判死"），
    这样还没升级桥的老机器行为不变，不会因为读取端换版本而误杀会话。
    """
    started = _parse_moment(raw, "process_started_at")
    if started is None:
        raise ValueError("invalid process_started_at")
    process = _process_state(pid, started, tolerance=LEGACY_CREATION_TOLERANCE)
    result["verdict_basis"] = "legacy-v1"
    if process == "exited" and _session_is_running() is not False:
        result.update(state="unknown", reason="session-record-mismatch")
    elif state == "send-failed" and count > 0:
        result.update(state="send-failed", reason="driver-send-failed")
    elif state == "stopped":
        result.update(state="stopped", reason="session-stopped")
    elif sending and fresh:
        result.update(state="running" if state == "running" else "retrying",
                      reason="recent-send-success" if state == "running" else "bounded-send-retry")
    elif process == "exited" and count > 0:
        result.update(state="exited", reason="bridge-exited")
    elif process == "exited" and count == 0 and state in {"authenticating", "authentication-failed"}:
        result.update(state="inactive", reason="no-native-session")
    elif process != "running":
        result.update(state="unknown", reason="process-unverified")
    elif state == "retrying" and count > 0:
        result.update(state="retrying" if age <= 30 else "stale",
                      reason="bounded-send-retry" if age <= 30 else "send-record-stale")
    elif state == "running" and count > 0 and int(raw.get("last_send_status", 0)) == 0:
        if send_age is None or send_age < -CLOCK_TOLERANCE:
            raise ValueError("invalid send timestamp")
        healthy = age <= FRESH_SECONDS and send_age <= FRESH_SECONDS
        result.update(state="running" if healthy else "stale",
                      reason="recent-send-success" if healthy else "send-record-stale")
    else:
        result.update(state="unknown",
                      reason="authentication-in-progress" if state == "authenticating" else "no-successful-send")
    return result