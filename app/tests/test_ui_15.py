"""Behavioral regression for the tab migration and explicitly approved wireless policy."""
from contextlib import ExitStack
from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch

from PySide6.QtCore import QTime
from PySide6.QtWidgets import QApplication, QMessageBox
from campus_net_assistant.config import AppConfig, apply_schedule
from campus_net_assistant.gui import MainWindow


class TabMigrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.config = AppConfig(wake_enabled=True, wake_time="08:30")
        self.status = dict(stage="online", success=True, current_online=True,
                           connection_mode="wireless", monitor_policy="active")
        for target, value in (
            ("load_config", self.config), ("read_status", self.status),
            ("installed_task_names", ["NJMUCampusNetAssistant-Monitor"]),
            ("is_admin", False), ("load_credentials", ("demo", "fake-password")),
            ("npcap_detected", True),
            ("load_monitor_state", {"monitor_suppression_source": "",
                                    "monitor_suppressed_until": None}),
            ("suppression_remaining_seconds", 0),
        ):
            self.stack.enter_context(patch("campus_net_assistant.gui." + target, return_value=value))
        self.w = MainWindow()
        self.w.timer.stop()
        self.w.show()
        self.app.processEvents()
        self.addCleanup(self.dispose)

    def dispose(self):
        self.w.tray.hide()
        self.w._allow_close = True
        self.w.close()
        self.app.processEvents()

    def test_tab_navigation_keeps_drafts_and_applied_status(self):
        title = self.w.status_title.text()
        next_action = self.w.next_action_label.text()
        self.w.connection_mode.setCurrentIndex(self.w.connection_mode.findData("dorm_ethernet"))
        self.w.username.setText("new-account")
        self.w.password.setText("fake-new-password")
        self.w.tabs.setCurrentIndex(1)
        self.w.wake_time.setTime(QTime(9, 45))
        self.w.tabs.setCurrentIndex(2)
        self.w.refresh()
        self.w.tabs.setCurrentIndex(0)
        self.assertEqual(self.w.username.text(), "new-account")
        self.assertEqual(self.w.password.text(), "fake-new-password")
        self.assertEqual(self.w.wake_time.time(), QTime(9, 45))
        self.assertEqual(self.w.status_title.text(), title)
        self.assertEqual(self.w.next_action_label.text(), next_action)
        self.assertIn("09:45", self.w.schedule_hint.text())
        self.assertIn("·", self.w.tabs.tabText(0))
        self.assertIn("·", self.w.tabs.tabText(1))

    def test_network_details_entry_point_is_removed(self):
        self.assertFalse(hasattr(self.w, "network_details_button"))
        self.assertFalse(hasattr(self.w, "show_network_details"))

    def test_save_applies_all_tabs_without_rewriting_existing_credentials(self):
        self.w.connection_mode.setCurrentIndex(self.w.connection_mode.findData("dorm_ethernet"))
        self.w.operator.setCurrentText("移动")
        self.w.tabs.setCurrentIndex(1)
        self.w.start_uu.setChecked(True)
        self.w.uu_path.setText(r"D:\UU\GameViewer.exe")
        self.w.wake_time.setTime(QTime(9, 15))
        self.w.hibernate_enabled.setChecked(True)
        self.w.sleep_time.setTime(QTime(23, 10))
        self.w.tabs.setCurrentIndex(2)
        saved = []
        with patch("campus_net_assistant.gui.save_config", side_effect=lambda cfg: saved.append(deepcopy(cfg))), patch("campus_net_assistant.gui.save_credentials") as credentials, patch("campus_net_assistant.gui.install_with_elevation") as tasks, patch.object(QMessageBox, "information"), patch("campus_net_assistant.gui.event"):
            self.w.configure_button.click()
        tasks.assert_called_once()
        credentials.assert_not_called()
        self.assertTrue(saved)
        result = saved[-1]
        self.assertEqual(result.connection_mode, "dorm_ethernet")
        self.assertEqual(result.portal.operator, "移动")
        self.assertEqual(result.wake_time, "09:15")
        self.assertEqual(result.sleep_time, "23:10")
        self.assertTrue(result.start_uu)
        self.assertTrue(result.hibernate_enabled)
        self.assertEqual(result.uu_path, r"D:\UU\GameViewer.exe")
        self.assertTrue(result.wireless_http_experimental)
        self.assertFalse(result.dorm_protocol_observer_enabled)
        self.assertFalse(self.w._settings_dirty)

    def test_native_verification_is_a_network_action_only_when_required(self):
        self.assertFalse(self.w.native_verify_button.isVisible())
        self.assertEqual(self.w.native_verify_button.text(), "原生认证检查并验证")
        self.status.update(stage="offline", success=False, current_online=False)
        self.w.connection_mode.setCurrentIndex(
            self.w.connection_mode.findData("workstation_ruijie"))
        self.w.refresh()
        self.assertTrue(self.w.native_verify_button.isVisible())
        self.assertFalse(self.w.login_validate_button.isVisible())
        self.assertTrue(self.w.native_verify_hint.isVisible())
        self.assertIn("首次使用工位有线网", self.w.native_verify_hint.text())
        self.assertFalse(self.w.rawether_check_button.isVisible())
        self.assertEqual(self.w.rawether_check_status.text(), "未启用")

        self.status.update(stage="online", success=True, current_online=True)
        self.w.refresh()
        self.assertTrue(self.w.native_verify_button.isVisible())
        self.assertTrue(self.w.reauthenticate_button.isVisible())
        self.assertFalse(self.w.login_validate_button.isVisible())
        self.assertIn("当前已联网", self.w.native_verify_hint.text())

    def test_invalidated_verification_reappears_with_update_reason(self):
        self.w.connection_mode.setCurrentIndex(
            self.w.connection_mode.findData("workstation_ruijie"))
        self.w.config.ruijie_native_auto_enabled = True
        self.status.update(stage="offline", success=False, current_online=False)
        with patch("campus_net_assistant.gui.primary_status",
                   return_value={"valid": False, "reason": "app-version-changed"}):
            self.w.refresh()
        self.assertTrue(self.w.native_verify_button.isVisible())
        self.assertIn("程序已更新", self.w.native_verify_hint.text())

    def test_verified_workstation_restores_the_normal_online_actions(self):
        self.w.connection_mode.setCurrentIndex(
            self.w.connection_mode.findData("workstation_ruijie"))
        self.w.config.ruijie_native_auto_enabled = True
        self.status.update(stage="online", success=True, current_online=True)
        with patch("campus_net_assistant.gui.primary_status",
                   return_value={"valid": True, "reason": "verified"}):
            self.w.refresh()
        self.assertFalse(self.w.native_verify_button.isVisible())
        self.assertFalse(self.w.native_verify_hint.isVisible())
        self.assertFalse(self.w.login_validate_button.isVisible())
        self.assertTrue(self.w.reauthenticate_button.isVisible())

        self.status.update(stage="offline", success=False, current_online=False)
        with patch("campus_net_assistant.gui.primary_status",
                   return_value={"valid": True, "reason": "verified"}):
            self.w.refresh()
        self.assertFalse(self.w.native_verify_button.isVisible())
        self.assertTrue(self.w.login_validate_button.isVisible())
        self.assertFalse(self.w.reauthenticate_button.isVisible())

    def test_first_verification_popup_success_and_failure(self):
        self.w.connection_mode.setCurrentIndex(
            self.w.connection_mode.findData("workstation_ruijie"))
        with (
            patch("campus_net_assistant.gui.primary_status",
                  return_value={"valid": False, "reason": "never-verified"}),
            patch("campus_net_assistant.gui.event"),
            patch.object(QMessageBox, "warning") as warning,
        ):
            self.w._native_verify_finished({"success": False, "message": "未检测到 Npcap"})
        warning.assert_called_once()
        self.assertIn("未检测到 Npcap", warning.call_args.args[2])
        self.w.verify_thread = None
        self.w._native_verify_thread_finished()
        self.assertTrue(self.w.native_verify_button.isVisible())

        self.w.config.ruijie_native_auto_enabled = True
        with (
            patch("campus_net_assistant.gui.primary_status",
                  return_value={"valid": True, "reason": "verified"}),
            patch("campus_net_assistant.gui.event"),
            patch.object(QMessageBox, "information") as information,
        ):
            self.w._native_verify_finished({"success": True})
        information.assert_called_once()
        with patch("campus_net_assistant.gui.primary_status",
                   return_value={"valid": True, "reason": "verified"}):
            self.w.verify_thread = None
            self.w._native_verify_thread_finished()
        self.assertFalse(self.w.native_verify_button.isVisible())
        self.assertFalse(self.w.native_verify_hint.isVisible())

    def test_save_confirms_then_clears_manual_logout_pause(self):
        with (
            patch("campus_net_assistant.gui.load_monitor_state",
                  return_value={"monitor_suppression_source": "manual-network-logout"}),
            patch("campus_net_assistant.gui.suppression_remaining_seconds",
                  return_value=300),
            patch("campus_net_assistant.gui.clear_monitor_suppression") as clear,
            patch("campus_net_assistant.gui.save_config") as save,
            patch("campus_net_assistant.gui.install_with_elevation", return_value={}) as install,
            patch("campus_net_assistant.gui.event"),
            patch.object(QMessageBox, "question", return_value=QMessageBox.Yes) as question,
            patch.object(QMessageBox, "information") as information,
        ):
            self.w.configure_button.click()
        question.assert_called_once()
        install.assert_called_once()
        save.assert_called_once()
        clear.assert_called_once_with(self.w.config, "settings-saved")
        self.assertIn("已取消手动注销后的暂停", information.call_args.args[2])

    def test_save_cancel_keeps_manual_logout_pause_and_skips_save(self):
        with (
            patch("campus_net_assistant.gui.load_monitor_state",
                  return_value={"monitor_suppression_source": "manual-network-logout"}),
            patch("campus_net_assistant.gui.suppression_remaining_seconds",
                  return_value=300),
            patch("campus_net_assistant.gui.clear_monitor_suppression") as clear,
            patch("campus_net_assistant.gui.save_config") as save,
            patch("campus_net_assistant.gui.install_with_elevation") as install,
            patch.object(QMessageBox, "question", return_value=QMessageBox.No),
        ):
            self.w.configure_button.click()
        save.assert_not_called()
        install.assert_not_called()
        clear.assert_not_called()

    def test_failed_task_install_does_not_clear_manual_logout_pause(self):
        with (
            patch("campus_net_assistant.gui.load_monitor_state",
                  return_value={"monitor_suppression_source": "manual-network-logout"}),
            patch("campus_net_assistant.gui.suppression_remaining_seconds",
                  return_value=300),
            patch("campus_net_assistant.gui.clear_monitor_suppression") as clear,
            patch("campus_net_assistant.gui.save_config"),
            patch("campus_net_assistant.gui.install_with_elevation",
                  side_effect=RuntimeError("install failed")),
            patch("campus_net_assistant.gui.event"),
            patch.object(QMessageBox, "question", return_value=QMessageBox.Yes),
            patch.object(QMessageBox, "critical"),
        ):
            self.w.configure_button.click()
        clear.assert_not_called()


class WirelessPriorityTests(TestCase):
    def test_old_disabled_experiment_migrates_without_changing_other_preferences(self):
        cfg = AppConfig(wireless_http_experimental=False, wake_time="09:20", start_uu=True, ruijie_native_auto_enabled=True)
        cfg.dorm_protocol_observer_enabled = True
        apply_schedule(cfg)
        self.assertTrue(cfg.wireless_http_experimental)
        self.assertFalse(cfg.dorm_protocol_observer_enabled)
        self.assertEqual(cfg.wake_time, "09:20")
        self.assertTrue(cfg.start_uu)
        self.assertTrue(cfg.ruijie_native_auto_enabled)

    def test_wireless_http_success_never_opens_browser_even_with_legacy_false(self):
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wlan import WlanInfo
        cfg = AppConfig(wireless_http_experimental=False)
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        result = dict(login_submitted_at="2026-10-17T08:30:00+08:00", probe_succeeded_at="2026-10-17T08:30:01+08:00",provider="wireless-http")
        with patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(wlan,False,"connected")), patch("campus_net_assistant.controller._connectivity_online", return_value=False), patch("campus_net_assistant.controller.load", return_value=("demo","fake")), patch("campus_net_assistant.controller.login_wireless_http", return_value=result) as http, patch("campus_net_assistant.controller.login") as browser, patch("campus_net_assistant.controller.event"), patch("campus_net_assistant.controller.append_connectivity_event"), patch("campus_net_assistant.controller.write_status"):
            self.assertTrue(do_login(cfg))
        http.assert_called_once()
        browser.assert_not_called()
