from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .config import APP_DIR
from .product import EVENT_SOURCE


LOG_DIR = APP_DIR / "logs"
DIAGNOSTICS_DIR = APP_DIR / "diagnostics"
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|token|credential)[=:][^\s,;]+"),
    re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    re.compile(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}"),
]


def redact(value: str) -> str:
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def _safe(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(key): _safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    return value


def prune() -> None:
    for folder in (LOG_DIR, DIAGNOSTICS_DIR):
        if not folder.exists():
            continue
        cutoff = datetime.now().timestamp() - 7 * 24 * 60 * 60
        for path in folder.iterdir():
            try:
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                pass


def event(stage: str, success: bool | None, message: str = "", **fields: object) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "stage": stage,
        "success": success,
        "message": redact(message),
        **_safe(fields),
    }
    path = LOG_DIR / f"run-{datetime.now().date().isoformat()}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_connectivity_event(event_name: str, **fields: object) -> None:
    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    current = datetime.now().astimezone()
    path = DIAGNOSTICS_DIR / f"wifi-connectivity-events-{current.date().isoformat()}.jsonl"
    record = {"event": event_name, "time": current.isoformat(timespec="milliseconds"), **_safe(fields)}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def keepalive_stop_requested(success: bool, reason: str, backend: str) -> None:
    """Leave an audit trail for every request that stops our native keepalive."""
    event(
        "keepalive-stop-requested",
        success,
        "已请求停止后台原生保活" if success else "停止后台原生保活的请求未确认",
        reason=reason or "unspecified",
        backend=backend,
    )



def save_morning_online_baseline(record: dict) -> None:
    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    path = DIAGNOSTICS_DIR / f"daily-wifi-morning-online-{datetime.now().date().isoformat()}.json"
    if path.exists():
        return
    safe = {"record_type": "morning-online-baseline", "source": EVENT_SOURCE, **record}
    path.write_text(json.dumps(safe, ensure_ascii=False, indent=2), encoding="utf-8")
