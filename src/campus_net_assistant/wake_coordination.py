from __future__ import annotations

import contextlib
import ctypes
import json
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Iterator

from .config import APP_DIR
from .logging_redacted import event


STATE_PATH = APP_DIR / "wake-coordination.json"
EVENT_NAME = r"Local\NJMUCampusNetAssistant-WakeRequest"
PRIORITY_LEAD_MINUTES = 15
PRIORITY_GRACE_MINUTES = 5
FALLBACK_WINDOW_MINUTES = 30


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now().astimezone()
    return current.astimezone() if current.tzinfo is None else current


def _read() -> dict:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, TypeError, ValueError):
        return {}


def _write(state: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(STATE_PATH)


def create_request(source: str, now: datetime | None = None) -> dict:
    current = _now(now)
    state = _read()
    request = state.get("request")
    if (
        isinstance(request, dict)
        and request.get("date") == current.date().isoformat()
        and request.get("status") in {"pending", "running"}
    ):
        return request
    request = {
        "id": uuid.uuid4().hex,
        "date": current.date().isoformat(),
        "requested_at": current.isoformat(timespec="milliseconds"),
        "source": source,
        "status": "pending",
    }
    _write({"request": request})
    return request


def open_request(now: datetime | None = None) -> dict | None:
    current = _now(now)
    request = _read().get("request")
    if not isinstance(request, dict):
        return None
    if request.get("date") != current.date().isoformat():
        return None
    if request.get("status") not in {"pending", "running"}:
        return None
    return request


def mark_running(request_id: str, now: datetime | None = None) -> bool:
    state = _read()
    request = state.get("request")
    if not isinstance(request, dict) or request.get("id") != request_id:
        return False
    request["status"] = "running"
    request["started_at"] = _now(now).isoformat(timespec="milliseconds")
    _write(state)
    return True


def complete_request(
    request_id: str,
    success: bool,
    message: str,
    now: datetime | None = None,
) -> bool:
    state = _read()
    request = state.get("request")
    if not isinstance(request, dict) or request.get("id") != request_id:
        return False
    request.update(
        {
            "status": "succeeded" if success else "failed",
            "success": bool(success),
            "message": message,
            "completed_at": _now(now).isoformat(timespec="milliseconds"),
        }
    )
    _write(state)
    return True


def result(request_id: str) -> dict | None:
    request = _read().get("request")
    if not isinstance(request, dict) or request.get("id") != request_id:
        return None
    if request.get("status") not in {"succeeded", "failed"}:
        return None
    return request


def wait_for_result(request_id: str, timeout_seconds: int) -> dict | None:
    deadline = time.monotonic() + max(0, timeout_seconds)
    while True:
        completed = result(request_id)
        if completed is not None:
            return completed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.5, remaining))


def _wake_datetime(wake_time: str, now: datetime) -> datetime:
    hour, minute = (int(part) for part in wake_time.split(":"))
    return now.replace(hour=hour, minute=minute, second=0, microsecond=0)


def priority_delay_seconds(wake_time: str, now: datetime | None = None) -> int:
    """Delay ordinary recovery while today's wake request has priority."""
    current = _now(now)
    wake_at = _wake_datetime(wake_time, current)
    window_start = wake_at - timedelta(minutes=PRIORITY_LEAD_MINUTES)
    grace_end = wake_at + timedelta(minutes=PRIORITY_GRACE_MINUTES)
    if not window_start <= current < grace_end:
        return 0
    request = _read().get("request")
    if isinstance(request, dict) and request.get("date") == current.date().isoformat():
        return 0
    return max(1, int((grace_end - current).total_seconds() + 0.999))


def create_fallback_request_if_due(
    wake_time: str,
    now: datetime | None = None,
) -> dict | None:
    current = _now(now)
    wake_at = _wake_datetime(wake_time, current)
    fallback_start = wake_at + timedelta(minutes=PRIORITY_GRACE_MINUTES)
    fallback_end = wake_at + timedelta(minutes=FALLBACK_WINDOW_MINUTES)
    if not fallback_start <= current <= fallback_end:
        return None
    state_request = _read().get("request")
    if (
        isinstance(state_request, dict)
        and state_request.get("date") == current.date().isoformat()
    ):
        return None
    return create_request("monitor-fallback", current)


def signal_monitor() -> bool:
    if os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    kernel32.SetEvent.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateEventW(None, False, False, EVENT_NAME)
    if not handle:
        return False
    try:
        return bool(kernel32.SetEvent(handle))
    finally:
        kernel32.CloseHandle(handle)


def wait_for_monitor_signal(seconds: float) -> bool:
    if seconds <= 0:
        return False
    if os.name != "nt":
        time.sleep(seconds)
        return False
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateEventW(None, False, False, EVENT_NAME)
    if not handle:
        time.sleep(seconds)
        return False
    try:
        timeout_ms = min(0xFFFFFFFE, max(1, int(seconds * 1000)))
        return kernel32.WaitForSingleObject(handle, timeout_ms) == 0
    finally:
        kernel32.CloseHandle(handle)


class SystemAwakeLease:
    """Own a system-only power request on the calling monitor thread.

    ES_CONTINUOUS keeps the request alive across probes and waits. Deliberately
    omit DISPLAY_REQUIRED and AWAYMODE: display-off and explicit sleep remain
    under the user's control. The same thread must update and release it.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self.active = False

    def __enter__(self) -> SystemAwakeLease:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.set_required(False)

    def set_required(self, required: bool) -> bool:
        required = bool(required)
        if required == self.active:
            return True
        if os.name != "nt":
            return False
        kernel32 = ctypes.windll.kernel32
        set_state = kernel32.SetThreadExecutionState
        set_state.argtypes = [ctypes.c_uint32]
        set_state.restype = ctypes.c_uint32
        flags = 0x80000000 | (0x00000001 if required else 0)
        if not set_state(flags):
            event(
                "system-awake-request-failed", False,
                "系统保持唤醒请求申请失败" if required else "系统保持唤醒请求释放失败",
                power_request_source=self.source, power_request_required=required,
                power_request_process_id=os.getpid(),
            )
            return False
        self.active = required
        event(
            "system-awake-acquired" if required else "system-awake-released", True,
            "已保持系统唤醒；屏幕仍可关闭，手动休眠不受影响" if required else "已释放系统保持唤醒请求",
            power_request_source=self.source, power_request_process_id=os.getpid(),
        )
        return True


@contextlib.contextmanager
def keep_system_awake() -> Iterator[None]:
    with SystemAwakeLease("wake-coordinator") as lease:
        lease.set_required(True)
        yield
