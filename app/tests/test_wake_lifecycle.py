from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import controller, monitor_state, wake_coordination
from campus_net_assistant.config import AppConfig


class StopMonitor(Exception):
    pass


class WakeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.api = Mock(return_value=0x80000000)
        self.stack.enter_context(patch.object(
            wake_coordination.ctypes, "windll",
            Mock(kernel32=Mock(SetThreadExecutionState=self.api)),
        ))
        self.stack.enter_context(patch.object(wake_coordination, "event"))

    def test_power_lease_is_continuous_system_only_and_idempotent(self):
        with wake_coordination.SystemAwakeLease("test") as lease:
            self.assertTrue(lease.set_required(True))
            self.assertTrue(lease.set_required(True))
            self.assertTrue(lease.active)
            self.api.assert_called_once_with(0x80000001)
        self.assertFalse(lease.active)
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_failed_acquisition_is_not_claimed_and_is_retried(self):
        self.api.side_effect = [0, 0x80000000, 0x80000001]
        with wake_coordination.SystemAwakeLease("test") as lease:
            self.assertFalse(lease.set_required(True))
            self.assertFalse(lease.active)
            self.assertTrue(lease.set_required(True))
        self.assertEqual(self.api.call_count, 3)

    def test_exception_releases_temporary_coordinator_request(self):
        with self.assertRaises(StopMonitor):
            with wake_coordination.keep_system_awake():
                raise StopMonitor()
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def _prepare_monitor(self, config=None, state=None):
        self.config = config or AppConfig(wake_enabled=True)
        self.state = state or {
            "armed": True, "source": "wake-request", "wake_keep_awake": True,
        }
        patches = {
            "acquire_monitor_lock": {"return_value": nullcontext(True)},
            "prune": {}, "event": {}, "write_status": {},
            "append_connectivity_event": {},
            "load_config": {"return_value": self.config},
            "load_monitor_state": {"return_value": self.state},
            "_in_monitor_window": {"return_value": True},
            "open_wake_request": {"return_value": None},
            "create_fallback_request_if_due": {"return_value": None},
            "_monitor_probe": {"return_value": (True, "microsoft-connect-test", 1)},
            "wait_for_monitor_signal": {"side_effect": StopMonitor},
            # 1.6.2 的等待包装器会按 5 秒切片轮询；这些用例只关心"等待发生过"和
            # 睡前的唤醒租约状态，因此把它直接映射回同一个 wait 模拟对象。
            "_wait_for_next_probe": {
                "side_effect": lambda seconds: self.mocks["wait_for_monitor_signal"](seconds),
            },
        }
        self.mocks = {
            name: self.stack.enter_context(patch.object(controller, name, **kwargs))
            for name, kwargs in patches.items()
        }

    def test_monitor_holds_after_success_and_through_online_wait_all_modes(self):
        for mode in ("wireless", "dorm_ethernet", "workstation_ruijie"):
            with self.subTest(mode=mode):
                self.api.reset_mock()
                self._prepare_monitor(AppConfig(wake_enabled=True, connection_mode=mode))
                self.mocks["open_wake_request"].return_value = {"id": "wake-1"}

                def recover(*_args):
                    self.api.assert_called_once_with(0x80000001)
                    return True

                def online_wait(*_args):
                    self.api.assert_called_once_with(0x80000001)
                    raise StopMonitor()

                self.mocks["wait_for_monitor_signal"].side_effect = online_wait
                with patch.object(controller, "_process_wake_request", side_effect=recover):
                    with self.assertRaises(StopMonitor):
                        controller.monitor(self.config)
                self.assertEqual([c.args[0] for c in self.api.call_args_list],
                                 [0x80000001, 0x80000000])

    def test_pending_wake_acquires_before_auth_and_holds_failed_retry(self):
        self._prepare_monitor(state={"armed": True, "source": "configuration"})
        self.mocks["open_wake_request"].return_value = {"id": "wake-2"}

        def failed_recovery(*_args):
            self.api.assert_called_once_with(0x80000001)
            return False

        def retry_wait(*_args):
            self.api.assert_called_once_with(0x80000001)
            raise StopMonitor()

        self.mocks["wait_for_monitor_signal"].side_effect = retry_wait
        with (
            patch.object(controller, "arm_monitor", return_value={
                "armed": True, "wake_keep_awake": True,
            }) as arm,
            patch.object(controller, "_process_wake_request", side_effect=failed_recovery),
        ):
            with self.assertRaises(StopMonitor):
                controller.monitor(self.config)
        arm.assert_called_once_with(self.config, "wake-request")
        self.mocks["wait_for_monitor_signal"].assert_called_once_with(
            self.config.recovery_retry_seconds)
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_disabled_wake_releases_on_next_iteration(self):
        self._prepare_monitor()
        self.mocks["load_config"].side_effect = [
            self.config, AppConfig(wake_enabled=False),
        ]

        def probe(config, **_kwargs):
            self.assertEqual(self.api.call_args.args[0],
                             0x80000001 if config.wake_enabled else 0x80000000)
            return True, "microsoft-connect-test", 1

        self.mocks["_monitor_probe"].side_effect = probe
        self.mocks["wait_for_monitor_signal"].side_effect = [False, StopMonitor()]
        with self.assertRaises(StopMonitor):
            controller.monitor(self.config)
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_window_end_releases_and_exits(self):
        self._prepare_monitor()
        self.mocks["_in_monitor_window"].side_effect = [True, False]
        self.mocks["wait_for_monitor_signal"].side_effect = None
        controller.monitor(self.config)
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_manual_logout_pause_releases_before_wait(self):
        self._prepare_monitor()
        paused = dict(self.state, monitor_suppressed_until=(
            datetime.now().astimezone() + timedelta(minutes=5)
        ).isoformat())
        self.mocks["load_monitor_state"].side_effect = [self.state, self.state, paused]

        def wait(_seconds):
            if self.mocks["wait_for_monitor_signal"].call_count == 1:
                self.api.assert_called_once_with(0x80000001)
                return False
            self.assertEqual(self.api.call_args.args[0], 0x80000000)
            raise StopMonitor()

        self.mocks["wait_for_monitor_signal"].side_effect = wait
        with self.assertRaises(StopMonitor):
            controller.monitor(self.config)
        self.mocks["_monitor_probe"].assert_called_once()
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_startup_monitor_without_wake_session_does_not_hold(self):
        self._prepare_monitor(state={"armed": True, "source": "configuration"})
        with self.assertRaises(StopMonitor):
            controller.monitor(self.config)
        self.api.assert_not_called()

    def test_once_probe_does_not_hold(self):
        self._prepare_monitor()
        controller.monitor(self.config, once=True)
        self.api.assert_not_called()

    def test_legacy_same_boot_wake_state_restores_request(self):
        self._prepare_monitor(state={"armed": True, "source": "wake-coordinator"})
        with self.assertRaises(StopMonitor):
            controller.monitor(self.config)
        self.assertEqual([c.args[0] for c in self.api.call_args_list],
                         [0x80000001, 0x80000000])

    def test_request_reuses_only_pending_or_running_not_completed_results(self):
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(wake_coordination, "APP_DIR", Path(folder)),
                patch.object(wake_coordination, "STATE_PATH", Path(folder) / "wake.json"),
            ):
                now = datetime.now().astimezone()
                request = wake_coordination.create_request("wake-task", now)
                self.assertEqual(wake_coordination.create_request("wake-task", now)["id"], request["id"])
                wake_coordination.mark_running(request["id"], now)
                self.assertEqual(wake_coordination.create_request("wake-task", now)["id"], request["id"])
                for success in (True, False):
                    wake_coordination.complete_request(request["id"], success, "test", now)
                    new_request = wake_coordination.create_request("wake-task", now)
                    self.assertNotEqual(new_request["id"], request["id"])
                    self.assertIsNone(wake_coordination.result(new_request["id"]))
                    self.assertEqual(new_request["status"], "pending")
                    request = new_request

    def test_wake_state_survives_monitor_restart_config_save_but_not_reboot(self):
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(monitor_state, "APP_DIR", Path(folder)),
                patch.object(monitor_state, "STATE_PATH", Path(folder) / "monitor.json"),
                patch.object(monitor_state, "_boot_epoch", return_value=1000.0) as boot,
            ):
                config = AppConfig(wake_enabled=True)
                self.assertFalse(monitor_state.load(config)["wake_keep_awake"])
                self.assertTrue(monitor_state.arm(config, "wake-coordinator")["wake_keep_awake"])
                self.assertTrue(monitor_state.arm(config, "configuration-wake-enabled")["wake_keep_awake"])
                self.assertTrue(monitor_state.load(config)["wake_keep_awake"])
                boot.return_value = 2000.0
                self.assertFalse(monitor_state.load(config)["wake_keep_awake"])
                monitor_state.arm(config, "wake-request")
                self.assertFalse(monitor_state.disarm(config, "automation-stopped")["wake_keep_awake"])


if __name__ == "__main__":
    unittest.main()
