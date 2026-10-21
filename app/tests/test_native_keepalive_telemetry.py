from __future__ import annotations

import base64
import json
import shutil
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import npcap_backend, npcap_bridge


class TelemetryExitTests(unittest.TestCase):
    def setUp(self):
        # Workspace-local temp dir: the DSH sandbox rejects the 0o700 ACL used
        # by Windows tempfile.TemporaryDirectory.
        base = Path(__file__).resolve().parents[1] / ".test-temp"
        root = base / f"bridge-{time.time_ns()}"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        self.state = root / "native-keepalive-state.json"
        self.diagnostics = root / "diagnostics"
        patches = [
            patch.object(npcap_bridge, "TELEMETRY_DIR", root),
            patch.object(npcap_bridge, "STATE_PATH", self.state),
            patch.object(npcap_bridge, "DIAG_DIR", self.diagnostics),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def diagnostic_lines(self) -> list[dict]:
        path = self.diagnostics / (
            "native-keepalive-"
            + datetime.now(timezone.utc).strftime("%Y-%m-%d")
            + ".jsonl"
        )
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def test_stop_request_is_written_with_reason_and_exit_code(self):
        telemetry = npcap_bridge.Telemetry("Intel Ethernet")
        telemetry.enable()
        telemetry.record("running", 0, 1)
        telemetry.finalize("stop-requested", 0)

        payload = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(payload["state"], "stopped")
        self.assertEqual(payload["exit_reason"], "stop-requested")
        self.assertEqual(payload["exit_code"], 0)
        self.assertTrue(payload["exited_at"])
        lines = self.diagnostic_lines()
        self.assertTrue(any(line.get("record_type") == "bridge-exit" for line in lines))
        self.assertEqual(lines[-1]["exit_reason"], "stop-requested")

    def test_link_down_is_written_as_abnormal_exit(self):
        telemetry = npcap_bridge.Telemetry("Intel Ethernet")
        telemetry.enable()
        telemetry.record("running", 0, 1)
        telemetry.finalize("link-down", 76)

        payload = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(payload["state"], "exited")
        self.assertEqual(payload["exit_reason"], "link-down")
        self.assertEqual(payload["exit_code"], 76)
        self.assertTrue(payload["exited_at"])

    def test_exception_is_recorded_before_the_exit_record(self):
        telemetry = npcap_bridge.Telemetry("Intel Ethernet")
        telemetry.enable()
        telemetry.record("running", 0, 1)
        telemetry.record_exception("Traceback (most recent call last): ...")
        telemetry.finalize("exception", 1)

        payload = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(payload["state"], "exited")
        self.assertEqual(payload["exit_reason"], "exception")
        self.assertEqual(payload["exit_code"], 1)
        kinds = [line.get("record_type") for line in self.diagnostic_lines()]
        self.assertIn("bridge-exception", kinds)
        self.assertIn("bridge-exit", kinds)

    def test_auth_failure_without_telemetry_still_leaves_diagnostic_trail(self):
        telemetry = npcap_bridge.Telemetry("Intel Ethernet")
        telemetry.finalize("authentication-failed", 76)

        self.assertFalse(self.state.exists())
        lines = self.diagnostic_lines()
        self.assertTrue(lines)
        self.assertEqual(lines[-1]["record_type"], "bridge-exit")
        self.assertEqual(lines[-1]["exit_reason"], "authentication-failed")
        self.assertEqual(lines[-1]["exit_code"], 76)

    def test_main_marks_unhandled_exception_and_finalizes_with_it(self):
        adapter = base64.b64encode(b"Intel Ethernet").decode("ascii")
        session = Mock()
        session.persistent = False
        session.create_stop_event.return_value = True
        session.exit_reason = ""
        session.telemetry = Mock()
        session.run.side_effect = RuntimeError("boom")

        def fake_set_exit(reason, code=None):
            session.exit_reason = reason

        session.set_exit.side_effect = fake_set_exit
        with (
            patch.object(npcap_bridge, "Session", return_value=session),
            patch.object(sys, "argv", ["NpcapBridge.exe", "send-private-md5", "path", adapter, "15000"]),
        ):
            with self.assertRaises(RuntimeError):
                npcap_bridge.main()
        session.set_exit.assert_called_with("exception", 1)
        session.telemetry.record_exception.assert_called_once()
        self.assertIn("Traceback", session.telemetry.record_exception.call_args.args[0])
        self.assertEqual(session.telemetry.finalize.call_args.args[0], "exception")
        self.assertEqual(session.telemetry.finalize.call_args.args[1], 1)


class StopRequestLoggingTests(unittest.TestCase):
    def test_npcap_stop_session_logs_the_reason(self):
        completed = Mock(returncode=0)
        with (
            patch.object(npcap_backend, "bridge_command", return_value=["NpcapBridge.exe"]),
            patch.object(npcap_backend.subprocess, "run", return_value=completed),
            patch("campus_net_assistant.logging_redacted.keepalive_stop_requested") as logged,
        ):
            self.assertTrue(npcap_backend.stop_session("settings-change"))
        logged.assert_called_once_with(True, "settings-change", "npcap")

    def test_failed_stop_request_is_logged_too(self):
        with (
            patch.object(npcap_backend, "bridge_command", return_value=["NpcapBridge.exe"]),
            patch.object(npcap_backend.subprocess, "run", side_effect=OSError("boom")),
            patch("campus_net_assistant.logging_redacted.keepalive_stop_requested") as logged,
        ):
            self.assertFalse(npcap_backend.stop_session("stop-automation"))
        logged.assert_called_once_with(False, "stop-automation", "npcap")


if __name__ == "__main__":
    unittest.main()
