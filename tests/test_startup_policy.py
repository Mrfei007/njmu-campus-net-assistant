import json
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from campus_net_assistant import config, controller, monitor_state, scheduler


class IndependentStartupTests(unittest.TestCase):
    def test_old_configuration_migration_preserves_preference_once(self):
        for wake in (False, True):
            with self.subTest(wake=wake), tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / "config.json"
                target.write_text(json.dumps({"wake_enabled": wake}), encoding="utf-8")
                with patch.object(config, "CONFIG_PATH", target), patch.object(config, "APP_DIR", Path(folder)):
                    loaded = config.load_config()
                    self.assertEqual(loaded.auto_connect_on_startup, wake)
                    self.assertEqual(json.loads(target.read_text())["auto_connect_on_startup"], wake)
                    loaded.wake_enabled = not wake
                    config.save_config(loaded)
                    self.assertEqual(config.load_config().auto_connect_on_startup, wake)

    def test_new_boot_uses_only_startup_switch_in_all_modes(self):
        for mode in config.CONNECTION_MODES:
            for startup in (False, True):
                for wake in (False, True):
                    current = config.AppConfig(connection_mode=mode, auto_connect_on_startup=startup, wake_enabled=wake)
                    state = monitor_state._new_state(current, "new-boot")
                    self.assertEqual(state["armed"], startup)
                    self.assertFalse(state["wake_keep_awake"])

    def test_startup_enabled_is_not_restricted_by_wake_sleep_window(self):
        current = config.apply_schedule(config.AppConfig(auto_connect_on_startup=True, wake_enabled=True, hibernate_enabled=True))
        self.assertTrue(controller._in_monitor_window(current, datetime(2026, 9, 20, 3, 0)))
        current.auto_connect_on_startup = False
        self.assertFalse(controller._in_monitor_window(current, datetime(2026, 9, 20, 3, 0)))

    def test_scheduler_switch_combinations_are_independent(self):
        for startup in (False, True):
            for wake in (False, True):
                with self.subTest(startup=startup, wake=wake), ExitStack() as stack:
                    current = config.AppConfig(auto_connect_on_startup=startup, wake_enabled=wake)
                    stack.enter_context(patch.object(scheduler, "is_admin", return_value=True))
                    stack.enter_context(patch.object(scheduler, "_sid", return_value="S-1-5-21-test"))
                    stack.enter_context(patch.object(scheduler, "_stop_orphaned_monitor_processes", return_value=[]))
                    register = stack.enter_context(patch.object(scheduler, "_register"))
                    stack.enter_context(patch.object(scheduler, "_delete_task", return_value=True))
                    stack.enter_context(patch.object(scheduler.subprocess, "run", return_value=Mock(returncode=0)))
                    stack.enter_context(patch.object(scheduler, "event"))
                    arm = stack.enter_context(patch.object(scheduler, "arm_monitor"))
                    disarm = stack.enter_context(patch.object(scheduler, "disarm_monitor"))
                    result = scheduler.install(current)
                    self.assertEqual(arm.call_count, int(startup))
                    self.assertEqual(disarm.call_count, int(not startup))
                    self.assertEqual("NJMUCampusNetAssistant-Wake" in result["installed"], wake)
                    monitor_xml = next(c.args[1] for c in register.call_args_list if c.args[0].endswith("-Monitor"))
                    self.assertIn("LogonTrigger", monitor_xml)

    def test_auto_connect_drives_recovery_in_each_mode_without_wake(self):
        for mode in config.CONNECTION_MODES:
            with self.subTest(mode=mode), ExitStack() as stack:
                current = config.AppConfig(connection_mode=mode, auto_connect_on_startup=True,
                                           ruijie_auto_enabled=True, ruijie_native_auto_enabled=True)
                stack.enter_context(patch.object(controller, "acquire_monitor_lock", return_value=nullcontext(True)))
                stack.enter_context(patch.object(controller, "_monitor_probe", return_value=(False, "all-connectivity-probes-failed", 2)))
                stack.enter_context(patch.object(controller, "_online_detail", side_effect=AssertionError("must not enter passive path")))
                for name in ("prune", "event", "write_status", "append_connectivity_event", "_ensure_uu"):
                    stack.enter_context(patch.object(controller, name))
                stack.enter_context(patch.object(controller, "read_status", return_value={}))
                recover = stack.enter_context(patch.object(controller, "_recover", return_value=True))
                controller.monitor(current, once=True)
                recover.assert_called_once()

    def test_wake_only_boot_remains_passive(self):
        current = config.AppConfig(wake_enabled=True, auto_connect_on_startup=False)
        with (patch.object(controller, "_online_detail", return_value=(False, "all-connectivity-probes-failed")),
              patch.object(controller, "prune"), patch.object(controller, "event"),
              patch.object(controller, "write_status"), patch.object(controller, "_recover") as recover):
            controller.monitor(current, once=True)
        recover.assert_not_called()

    def test_startup_checkbox_does_not_toggle_wake(self):
        from PySide6.QtWidgets import QApplication
        from campus_net_assistant import gui
        app = QApplication.instance() or QApplication([])
        with (patch.object(gui, "load_config", return_value=config.AppConfig()),
              patch.object(gui.MainWindow, "refresh"),
              patch.object(gui.MainWindow, "update_credentials_hint")):
            window = gui.MainWindow()
            try:
                window.auto_connect_on_startup.setChecked(True)
                self.assertFalse(window.wake_enabled.isChecked())
                self.assertIn("开机后自动联网", window.schedule_hint.text())
                window.wake_enabled.setChecked(True)
                window.auto_connect_on_startup.setChecked(False)
                self.assertTrue(window.wake_enabled.isChecked())
            finally:
                window.timer.stop()
                window.tray.hide()
                window._allow_close = True
                window.close()
                window.deleteLater()
                app.processEvents()
