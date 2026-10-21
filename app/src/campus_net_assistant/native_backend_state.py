"""Persisted verification state for the native (Npcap/Rawether) auth path.

The bridge processes are only allowed to authenticate automatically after the
user has completed a real field verification of the primary Npcap path.  The
Rawether fallback only needs a read-only component check.  This module owns both
records and validates them against the current program/bridge files.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .config import APP_DIR
from .version import VERSION

SCHEMA_VERSION = 1
STATE_PATH = APP_DIR / "native-backend-state.json"
NPCAP_BRIDGE_PATH = Path(__file__).resolve().parent / "native" / "bin" / "NpcapBridge.exe"
RAWETHER_BRIDGE_PATH = Path(__file__).resolve().parent / "native" / "bin" / "RawetherBridge.exe"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: Path) -> str:
    try:
        stat = path.stat()
        key = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return ""
    cached = _HASH_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        value = digest.hexdigest()
    except OSError:
        return ""
    _HASH_CACHE[key] = value
    return value


_HASH_CACHE: dict[tuple[str, int, int], str] = {}


def bridge_sha256(backend: str) -> str:
    path = NPCAP_BRIDGE_PATH if backend == "npcap" else RAWETHER_BRIDGE_PATH
    return file_sha256(path)


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "primary": {},
        "fallback": {},
        "last_attempt_backend": "",
        "last_success_backend": "",
    }


def _coerce_state(raw: object) -> dict:
    state = _default_state()
    if not isinstance(raw, dict):
        return state
    if raw.get("schema_version") != SCHEMA_VERSION:
        return state
    for key in ("primary", "fallback"):
        value = raw.get(key)
        if isinstance(value, dict):
            state[key] = value
    for key in ("last_attempt_backend", "last_success_backend"):
        value = raw.get(key)
        if isinstance(value, str) and value in {"", "npcap", "rawether"}:
            state[key] = value
    return state


def load_state() -> dict:
    try:
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _default_state()
    return _coerce_state(raw)


def save_state(state: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    try:
        temporary.write_text(
            json.dumps(_coerce_state(state), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(temporary, STATE_PATH)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def primary_status() -> dict:
    """Return whether the currently installed Npcap path is field-verified."""
    state = load_state()
    record = state.get("primary") or {}
    result = {"valid": False, "reason": "never-verified", "record": record}
    if not record:
        return result
    if record.get("backend") != "npcap":
        result["reason"] = "backend-mismatch"
        return result
    if record.get("app_version") != VERSION:
        result["reason"] = "app-version-changed"
        return result
    current_bridge = bridge_sha256("npcap")
    if not current_bridge:
        result["reason"] = "bridge-missing"
        return result
    if str(record.get("npcap_bridge_sha256") or "") != current_bridge:
        result["reason"] = "bridge-changed"
        return result
    result["valid"] = True
    result["reason"] = "verified"
    return result


def mark_primary_verified(adapter: str, session_id: str = "") -> dict:
    state = load_state()
    record = {
        "backend": "npcap",
        "verified_at": _now(),
        "app_version": VERSION,
        "npcap_bridge_sha256": bridge_sha256("npcap"),
        "adapter": str(adapter),
        "session_id": str(session_id),
        "last_result": "success",
    }
    state["primary"] = record
    state["last_success_backend"] = "npcap"
    save_state(state)
    return record


def _normalized_path(value: str | Path) -> str:
    try:
        return os.path.normcase(os.path.abspath(str(value))).casefold()
    except (OSError, ValueError):
        return str(value).casefold()


def fallback_status(configured_path: str | Path = "") -> dict:
    """Fast validity check for the Rawether fallback check record."""
    state = load_state()
    record = state.get("fallback") or {}
    result = {"valid": False, "reason": "never-checked", "record": record}
    if not record:
        return result
    if record.get("restore_pending") is True:
        result["reason"] = "restore-pending"
        return result
    current_bridge = bridge_sha256("rawether")
    if not current_bridge:
        result["reason"] = "bridge-missing"
        return result
    if str(record.get("rawether_bridge_sha256") or "") != current_bridge:
        result["reason"] = "bridge-changed"
        return result
    if configured_path:
        if _normalized_path(configured_path) != _normalized_path(
                str(record.get("client_path") or "")):
            result["reason"] = "client-path-changed"
            return result
    result["valid"] = True
    result["reason"] = "checked"
    return result


def mark_fallback_checked(record: dict) -> dict:
    state = load_state()
    cleaned = {
        key: value for key, value in record.items()
        if key in {
            "client_path", "worker_sha256", "w64n55_sha256", "pcasp50_sha256",
            "rawether_bridge_sha256", "restore_pending", "link_ok", "client_running",
        }
    }
    cleaned["checked_at"] = _now()
    cleaned["rawether_bridge_sha256"] = bridge_sha256("rawether")
    state["fallback"] = cleaned
    save_state(state)
    return cleaned


def record_attempt(backend: str, success: bool) -> None:
    state = load_state()
    if backend in {"npcap", "rawether"}:
        state["last_attempt_backend"] = backend
        if success:
            state["last_success_backend"] = backend
        save_state(state)


def describe_primary() -> str:
    status = primary_status()
    if status["valid"]:
        return "成功"
    if status["reason"] == "never-verified":
        return "未验证"
    return "需重新验证"


def describe_fallback() -> str:
    status = fallback_status()
    return "已通过" if status["valid"] else "未检查"
