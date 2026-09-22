from __future__ import annotations

import ctypes
import json
import os
import time
from datetime import datetime, timedelta

from .config import APP_DIR, AppConfig


STATE_PATH = APP_DIR / "monitor-state.json"


def _boot_epoch() -> float:
    """Return a stable approximation of the current Windows boot epoch."""
    if os.name == "nt":
        try:
            uptime_seconds = ctypes.windll.kernel32.GetTickCount64() / 1000
            return time.time() - uptime_seconds
        except (AttributeError, OSError):
            pass
    return time.time() - time.monotonic()


def _new_state(config: AppConfig, source: str) -> dict:
    current = datetime.now().astimezone().isoformat(timespec="milliseconds")
    armed = bool(config.auto_connect_on_startup)
    return {
        "boot_epoch": _boot_epoch(),
        "armed": armed,
        "policy": "active" if armed else "passive",
        "armed_at": current if armed else None,
        "wake_keep_awake": False,
        "source": source,
        "updated_at": current,
    }


def load(config: AppConfig) -> dict:
    previous_state: dict = {}
    try:
        previous_state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if abs(float(previous_state["boot_epoch"]) - _boot_epoch()) <= 60:
            return previous_state
    except (KeyError, OSError, TypeError, ValueError):
        pass
    state = _new_state(config, "new-boot")
    if suppression_remaining_seconds(previous_state) > 0:
        state["monitor_suppressed_until"] = previous_state.get(
            "monitor_suppressed_until"
        )
        state["monitor_suppression_source"] = previous_state.get(
            "monitor_suppression_source"
        )
    save(state)
    return state


def save(state: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = datetime.now().astimezone().isoformat(timespec="milliseconds")
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def arm(config: AppConfig, source: str) -> dict:
    state = load(config)
    if source in {"wake-coordinator", "wake-request"}:
        state["wake_keep_awake"] = True
    elif "wake_keep_awake" not in state:
        # Preserve a same-boot wake session when upgrading from 1.24.15.
        state["wake_keep_awake"] = state.get("source") in {
            "wake-coordinator", "wake-request"
        }
    current = datetime.now().astimezone().isoformat(timespec="milliseconds")
    state.update(
        {
            "armed": True,
            "policy": "active",
            "armed_at": current,
            "source": source,
        }
    )
    save(state)
    return state


def disarm(config: AppConfig, source: str) -> dict:
    state = load(config)
    state.update(
        {
            "armed": False,
            "policy": "passive",
            "armed_at": None,
            "wake_keep_awake": False,
            "source": source,
        }
    )
    save(state)
    return state


def suppress(config: AppConfig, source: str, seconds: int) -> dict:
    """Persist a same-boot pause so every monitor process honors manual logout."""
    state = load(config)
    current = datetime.now().astimezone()
    state.update(
        {
            "monitor_suppressed_until": (
                current + timedelta(seconds=max(0, seconds))
            ).isoformat(timespec="milliseconds"),
            "monitor_suppression_source": source,
        }
    )
    save(state)
    return state


def clear_suppression(config: AppConfig, source: str) -> dict:
    state = load(config)
    state.update(
        {
            "monitor_suppressed_until": None,
            "monitor_suppression_source": None,
            "monitor_suppression_cleared_by": source,
        }
    )
    save(state)
    return state


def suppression_remaining_seconds(
    state: dict,
    now: datetime | None = None,
) -> int:
    value = str(state.get("monitor_suppressed_until") or "").strip()
    if not value:
        return 0
    try:
        until = datetime.fromisoformat(value)
        current = now or datetime.now().astimezone()
        if until.tzinfo is None:
            until = until.astimezone()
        return max(0, int((until - current).total_seconds() + 0.999))
    except (TypeError, ValueError):
        return 0
