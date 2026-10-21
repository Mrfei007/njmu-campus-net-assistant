from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import config, controller, native_backend_state
from campus_net_assistant.config import AppConfig


def workspace_temp(test: unittest.TestCase) -> Path:
    folder = ROOT / ".test-temp"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"backend-{time.time_ns()}"
    path.mkdir(parents=True, exist_ok=True)
    test.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
    return path


class NativeAttemptSelectionTests(unittest.TestCase):
    def test_rawether_fallback_requires_primary_verification(self):
        config = AppConfig(
            connection_mode="workstation_ruijie",
            ruijie_native_auto_enabled=True,
            rawether_fallback_enabled=True,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        with (
            patch.object(controller, "_native_verified", return_value=False),
            patch("campus_net_assistant.native_backend_state.fallback_status",
                  return_value={"valid": True}),
        ):
            self.assertEqual(controller._native_auth_attempts(config), ["npcap"])
        with (
            patch.object(controller, "_native_verified", return_value=True),
            patch("campus_net_assistant.native_backend_state.fallback_status",
                  return_value={"valid": True}),
        ):
            self.assertEqual(controller._native_auth_attempts(config), ["npcap", "rawether"])


class NativeBackendStateTests(unittest.TestCase):
    def setUp(self):
        self.folder = workspace_temp(self)
        self.state = self.folder / "native-backend-state.json"
        self.npcap_bridge = self.folder / "NpcapBridge.exe"
        self.rawether_bridge = self.folder / "RawetherBridge.exe"
        self.npcap_bridge.write_bytes(b"npcap-bridge")
        self.rawether_bridge.write_bytes(b"rawether-bridge")
        self.stack = [
            patch.object(native_backend_state, "STATE_PATH", self.state),
            patch.object(native_backend_state, "NPCAP_BRIDGE_PATH", self.npcap_bridge),
            patch.object(native_backend_state, "RAWETHER_BRIDGE_PATH", self.rawether_bridge),
            patch.object(native_backend_state, "VERSION", "1.5.9.1"),
        ]
        for item in self.stack:
            item.start()
            self.addCleanup(item.stop)

    def test_primary_requires_a_matching_bridge_and_app_version(self):
        self.assertFalse(native_backend_state.primary_status()["valid"])
        native_backend_state.mark_primary_verified("Intel Ethernet", "session-1")
        self.assertTrue(native_backend_state.primary_status()["valid"])
        native_backend_state.VERSION = "1.5.9.2"
        self.assertEqual(native_backend_state.primary_status()["reason"], "app-version-changed")
        native_backend_state.VERSION = "1.5.9.1"
        self.npcap_bridge.write_bytes(b"changed")
        self.assertEqual(native_backend_state.primary_status()["reason"], "bridge-changed")

    def test_fallback_check_tracks_path_and_bridge_changes(self):
        native_backend_state.mark_fallback_checked({
            "client_path": r"D:\Ruijie\RuijieSupplicant.exe",
            "worker_sha256": "a" * 64,
            "w64n55_sha256": "b" * 64,
            "pcasp50_sha256": "c" * 64,
            "restore_pending": False,
            "link_ok": True,
        })
        self.assertTrue(native_backend_state.fallback_status(
            r"D:\Ruijie\RuijieSupplicant.exe")["valid"])
        self.assertEqual(
            native_backend_state.fallback_status(r"D:\Other\RuijieSupplicant.exe")["reason"],
            "client-path-changed",
        )
        self.rawether_bridge.write_bytes(b"changed")
        self.assertEqual(native_backend_state.fallback_status()["reason"], "bridge-changed")

    def test_record_attempt_keeps_last_backend(self):
        native_backend_state.record_attempt("rawether", True)
        state = native_backend_state.load_state()
        self.assertEqual(state["last_attempt_backend"], "rawether")
        self.assertEqual(state["last_success_backend"], "rawether")


class NativeVerificationTests(unittest.TestCase):
    def config(self):
        return AppConfig(connection_mode="workstation_ruijie")

    def test_verify_refuses_while_online(self):
        with (
            patch.object(controller, "acquire_recovery_lock", return_value=nullcontext(True)),
            patch.object(controller, "get_ethernet", return_value=Mock(ip="10.0.0.2")),
            patch.object(controller, "_connectivity_online", return_value=True),
        ):
            result = controller.verify_native_primary(self.config())
        self.assertFalse(result["success"])
        self.assertIn("断开校园网认证", result["message"])

    def test_verify_check_failure_stops_before_auth(self):
        with (
            patch.object(controller, "acquire_recovery_lock", return_value=nullcontext(True)),
            patch.object(controller, "get_ethernet", return_value=None),
            patch.object(controller, "get_linked_physical_ethernet", return_value=Mock(
                description="Intel", interface="Ethernet")),
            patch("campus_net_assistant.native_backend_check.npcap_environment",
                  return_value={"success": False, "message": "Npcap 未安装", "rows": []}),
            patch.object(controller, "event"),
            patch.object(controller, "_attempt_native_auth") as attempt,
        ):
            result = controller.verify_native_primary(self.config())
        self.assertFalse(result["success"])
        attempt.assert_not_called()

    def test_verify_success_writes_primary_state_and_enables_gate(self):
        config = self.config()
        with (
            patch.object(controller, "acquire_recovery_lock", return_value=nullcontext(True)),
            patch.object(controller, "get_ethernet", return_value=None),
            patch.object(controller, "get_linked_physical_ethernet", return_value=Mock(
                description="Intel", interface="Ethernet")),
            patch("campus_net_assistant.native_backend_check.npcap_environment",
                  return_value={"success": True, "message": "ok", "rows": []}),
            patch.object(controller, "load", return_value=("user", "pass")),
            patch.object(controller, "stop_private_session"),
            patch.object(controller, "_attempt_native_auth",
                         return_value={"success": True, "session_started": True,
                                       "native_backend": "npcap", "session_process_id": "123"}),
            patch.object(controller, "_record_ruijie_submission"),
            patch.object(controller, "save_config") as save,
            patch.object(controller, "event"),
            patch.object(controller, "write_status"),
            patch("campus_net_assistant.native_backend_state.mark_primary_verified") as mark,
        ):
            result = controller.verify_native_primary(config)
        self.assertTrue(result["success"])
        self.assertTrue(config.ruijie_native_auto_enabled)
        save.assert_called_once()
        mark.assert_called_once()


class WorkstationNativeFlowTests(unittest.TestCase):
    def config(self, **kwargs):
        values = {"connection_mode": "workstation_ruijie", "ruijie_native_auto_enabled": True}
        values.update(kwargs)
        return AppConfig(**values)

    def test_unverified_native_is_blocked_before_credentials(self):
        config = self.config()
        with (
            patch.object(controller, "get_ethernet", return_value=None),
            patch.object(controller, "_native_verified", return_value=False),
            patch.object(controller, "write_status") as status,
            patch.object(controller, "get_linked_physical_ethernet") as link,
        ):
            self.assertFalse(controller.do_login(config, wait_seconds=0))
        self.assertEqual(status.call_args.args[0], "native-verification-required")
        link.assert_not_called()

    def test_verified_flow_tries_npcap_then_rawether_fallback(self):
        config = self.config(rawether_fallback_enabled=True)
        attempts = [{"success": False, "session_started": False, "native_backend": "npcap",
                     "message": "npcap failed"},
                    {"success": True, "session_started": True, "native_backend": "rawether",
                     "message": "rawether ok"}]
        with (
            patch.object(controller, "get_ethernet", return_value=None),
            patch.object(controller, "_native_verified", return_value=True),
            patch.object(controller, "_native_auth_attempts", return_value=["npcap", "rawether"]),
            patch.object(controller, "_attempt_native_auth", side_effect=attempts) as attempt,
            patch.object(controller, "get_linked_physical_ethernet",
                         return_value=Mock(description="Intel", interface="Ethernet")),
            patch.object(controller, "load", return_value=("user", "pass")),
            patch.object(controller, "_ruijie_submission_rate_limited", return_value=False),
            patch.object(controller, "_record_ruijie_submission"),
            patch.object(controller, "append_connectivity_event"),
            patch.object(controller, "event"),
            patch.object(controller, "write_status") as status,
        ):
            self.assertTrue(controller.do_login(config, wait_seconds=0))
        self.assertEqual(attempt.call_count, 2)
        self.assertEqual(attempt.call_args.args[-1], "rawether")
        self.assertEqual(status.call_args.kwargs.get("native_backend"), "rawether")


class ConfigMigrationTests(unittest.TestCase):
    def test_old_fallback_key_and_removed_fields_are_tolerated(self):
        folder = workspace_temp(self)
        path = folder / "config.json"
        path.write_text(json.dumps({
            "connection_mode": "workstation_ruijie",
            "ruijie_background_client_fallback": True,
            "ruijie_auto_enabled": True,
            "ruijie_safety_blocked": True,
            "ruijie_layout_profile_revision": 1,
        }), encoding="utf-8")
        with patch.object(config, "CONFIG_PATH", path):
            loaded = config.load_config(read_only=True)
        self.assertTrue(loaded.rawether_fallback_enabled)
        self.assertTrue(loaded.ruijie_native_auto_enabled is False)


if __name__ == "__main__":
    unittest.main()
