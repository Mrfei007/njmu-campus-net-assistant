"""1.6 保活状态契约：三态判定矩阵与版本衔接检查。

只mock两个不确定输入（进程是否存在、互斥体是否被持有），其余走真实 read_health。
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from campus_net_assistant import component_compat, keepalive_status as ks  # noqa: E402

NOW = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
SESSION = "11111111-2222-3333-4444-555555555555"
BRIDGE_IMAGE = r"C:\App\_internal\campus_net_assistant\native\bin\NpcapBridge.exe"
ALIVE = {"exists": True, "creation": (NOW - timedelta(hours=1)).timestamp(), "image": BRIDGE_IMAGE}
DEAD = {"exists": False, "creation": None, "image": None}


def record(**overrides) -> dict:
    payload = {
        "schema_version": 2,
        "session_id": SESSION,
        "process_id": 4242,
        "process_created_at": (NOW - timedelta(hours=1)).isoformat(),
        "keepalive_started_at": (NOW - timedelta(hours=1) + timedelta(seconds=2)).isoformat(),
        "process_started_at": (NOW - timedelta(hours=1) + timedelta(seconds=2)).isoformat(),
        "heartbeat_seq": 120,
        "bridge_sha256": "a" * 64,
        "image_path": BRIDGE_IMAGE,
        "adapter_description": "Realtek Gaming 2.5GbE Family Controller #3",
        "updated_at": (NOW - timedelta(seconds=5)).isoformat(),
        "state": "running",
        "successful_sends": 120,
        "last_send_status": 0,
        "last_success_at": (NOW - timedelta(seconds=5)).isoformat(),
        "last_failure_at": "",
        "last_failure_status": 0,
        "send_duration_ms": 5,
        "send_attempt": 1,
        "retry_recoveries": 0,
        "failure_driver_state": "npcap",
        "failure_service_state": "not-applicable",
        "failure_link_state": "unknown",
        "native_backend": "npcap",
        "exit_reason": "",
        "exit_code": -1,
        "exited_at": "",
    }
    payload.update(overrides)
    return payload


def stale(**overrides) -> dict:
    """记录与心跳都停在 5 分钟前：进程/互斥体成为唯一判据。"""
    merged = {
        "updated_at": (NOW - timedelta(minutes=5)).isoformat(),
        "last_success_at": (NOW - timedelta(minutes=5)).isoformat(),
    }
    merged.update(overrides)
    return record(**merged)


class ReadHealthMatrixTests(unittest.TestCase):
    def read(self, payload: dict, *, info=DEAD, held: bool | None = False) -> dict:
        directory = ROOT / ".test-temp"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"kv2-{time.time_ns()}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        with (
            patch.object(ks, "_process_info", return_value=info),
            patch.object(ks, "session_mutex_held", return_value=held),
        ):
            return ks.read_health(path, now=NOW)

    def assertVerdict(self, result: dict, state: str, basis: str) -> None:
        self.assertEqual((result.get("state"), result.get("verdict_basis")), (state, basis), result)

    # ---- 心跳优先 -------------------------------------------------------
    def test_fresh_heartbeat_wins_over_missing_process(self):
        self.assertVerdict(self.read(record(), info=DEAD), "running", "heartbeat")

    def test_fresh_heartbeat_with_unknown_clock_is_not_trusted(self):
        payload = record(updated_at=(NOW + timedelta(minutes=10)).isoformat())
        self.assertVerdict(self.read(payload, info=ALIVE, held=True), "unknown", "invalid-clock")

    # ---- 进程 + 互斥体 -------------------------------------------------
    def test_alive_process_holding_mutex_is_running(self):
        self.assertVerdict(self.read(stale(), info=ALIVE, held=True), "running", "process-mutex")

    def test_alive_process_without_mutex_is_unknown(self):
        self.assertVerdict(self.read(stale(), info=ALIVE, held=False), "unknown", "process-without-owner")

    def test_alive_process_with_other_creation_time_is_pid_mismatch(self):
        other = {"exists": True, "creation": (NOW - timedelta(minutes=3)).timestamp(), "image": BRIDGE_IMAGE}
        self.assertVerdict(self.read(stale(), info=other, held=False), "unknown", "pid-mismatch")

    def test_unexpected_image_is_rejected(self):
        other = {"exists": True, "creation": (NOW - timedelta(hours=1)).timestamp(),
                 "image": r"C:\Windows\explorer.exe"}
        self.assertVerdict(self.read(stale(), info=other, held=False), "unknown", "image-mismatch")

    # ---- 只有 absent 允许重建 ------------------------------------------
    def test_dead_process_but_mutex_held_by_other_session(self):
        self.assertVerdict(self.read(stale(), info=DEAD, held=True), "unknown", "mutex-held-elsewhere")

    def test_dead_process_and_free_mutex_is_absent(self):
        self.assertVerdict(self.read(stale(), info=DEAD, held=False), "exited", "absent")

    def test_mutex_state_unavailable_is_not_absent(self):
        self.assertVerdict(self.read(stale(), info=DEAD, held=None), "unknown", "mutex-unverified")

    def test_unreadable_process_is_not_absent(self):
        self.assertVerdict(self.read(stale(), info=None, held=False), "unknown", "process-unverified")

    # ---- 记录自身状态 ---------------------------------------------------
    def test_graceful_stop(self):
        payload = record(state="stopped", exit_reason="stop-requested", exited_at=NOW.isoformat())
        self.assertVerdict(self.read(payload, info=DEAD), "stopped", "graceful-stop")

    def test_send_failed(self):
        self.assertVerdict(self.read(record(state="send-failed", last_send_status=31)), "send-failed", "record")

    def test_retrying_is_not_absent(self):
        self.assertVerdict(self.read(record(state="retrying")), "retrying", "heartbeat")

    # ---- schema 兼容 ----------------------------------------------------
    def test_legacy_v1_fresh_heartbeat(self):
        payload = record(schema_version=1)
        payload.pop("process_created_at")
        self.assertVerdict(self.read(payload, info=ALIVE, held=True), "running", "legacy-v1")

    def test_legacy_v1_dead_process_is_still_absent(self):
        payload = stale(schema_version=1)
        payload.pop("process_created_at")
        self.assertVerdict(self.read(payload, info=DEAD, held=False), "exited", "legacy-v1")

    def test_unsupported_schema_is_reported(self):
        payload = record(schema_version=3)
        self.assertVerdict(self.read(payload), "unknown", "schema-mismatch")

    def test_v2_without_created_at_is_incomplete(self):
        payload = record()
        payload.pop("process_created_at")
        self.assertVerdict(self.read(payload), "unknown", "schema-incomplete")

    # ---- 方案 A：移除 server_receipt ------------------------------------
    def test_server_receipt_is_gone(self):
        self.assertNotIn("server_receipt", self.read(record()))
        self.assertNotIn("server_receipt", self.read({"schema_version": 2}))


class ComponentCompatTests(unittest.TestCase):
    def test_legacy_schema_is_flagged_as_outdated_bridge(self):
        codes = [item["code"] for item in component_compat.issues({"bridge_schema": 1})]
        self.assertIn("bridge-outdated", codes)

    def test_newer_schema_is_flagged_as_outdated_app(self):
        codes = [item["code"] for item in component_compat.issues({"bridge_schema": 99})]
        self.assertIn("app-outdated", codes)

    def test_bridge_from_other_install_is_flagged(self):
        health = {"bridge_schema": 2, "image_path": r"D:\OldInstall\_internal\campus_net_assistant\native\bin\NpcapBridge.exe"}
        codes = [item["code"] for item in component_compat.issues(health)]
        self.assertIn("bridge-from-other-install", codes)

    def test_current_install_is_clean(self):
        try:
            from campus_net_assistant.native_backend_state import NPCAP_BRIDGE_PATH
        except Exception:  # pragma: no cover
            self.skipTest("bridge path unavailable")
        health = {"bridge_schema": 2, "image_path": str(NPCAP_BRIDGE_PATH)}
        self.assertEqual(component_compat.issues(health), [])

    def test_hint_prefers_version_mismatch(self):
        self.assertIn("schema v1", component_compat.first_hint({"bridge_schema": 1}))


if __name__ == "__main__":
    unittest.main()