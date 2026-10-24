from __future__ import annotations

import sys
import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import nullcontext
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import ANY, Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))


class SmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Business-loop tests must not depend on whether this development PC is
        # currently running a packaged monitor.  The dedicated duplicate test
        # overrides this patch with ``False``.
        monitor_lock = patch(
            "campus_net_assistant.controller.acquire_monitor_lock",
            return_value=nullcontext(True),
        )
        monitor_lock.start()
        self.addCleanup(monitor_lock.stop)

    def test_default_schedule_and_redaction(self):
        from campus_net_assistant.config import AppConfig, apply_schedule, minutes_between
        from campus_net_assistant.logging_redacted import redact

        config = AppConfig()
        self.assertEqual(config.wake_time, "08:55")
        self.assertEqual(config.sleep_time, "00:30")
        self.assertEqual(config.monitor_start_time, "09:10")
        self.assertEqual(config.recovery_attempts_before_wifi_restart, 2)
        self.assertEqual(config.connection_mode, "wireless")
        self.assertEqual(config.wlan_interface, "auto")
        self.assertFalse(config.wake_enabled)
        self.assertFalse(config.hibernate_enabled)
        self.assertEqual(config.monitor_interval_seconds, 120)
        self.assertEqual(config.passive_probe_interval_seconds, 30)
        self.assertEqual(config.recovery_retry_seconds, 60)
        self.assertEqual(config.ssid_not_visible_retry_seconds, 300)
        self.assertEqual(
            config.portal.secondary_check_url,
            "http://connectivitycheck.gstatic.cn/generate_204",
        )
        self.assertFalse(config.start_uu)
        self.assertEqual(config.uu_path, "")
        self.assertTrue(config.wireless_http_experimental)
        self.assertFalse(config.dorm_protocol_observer_enabled)
        config.wake_time = "07:30"
        config.sleep_time = "23:40"
        apply_schedule(config)
        self.assertEqual(config.monitor_start_time, "07:45")
        self.assertEqual(config.monitor_window_start, "07:30")
        self.assertEqual(config.monitor_window_end, "23:40")
        self.assertEqual(minutes_between(config.monitor_start_time, config.sleep_time), 955)
        self.assertNotIn("214652", redact("password=214652"))
        self.assertNotIn("192.0.2.1", redact("192.0.2.1"))

    def test_browser_discovery_prefers_chrome_then_falls_back_to_edge(self):
        from campus_net_assistant.edge import _browser_display_name, _edge_path

        edge = Path(r"C:\Browsers\Edge\msedge.exe")
        chrome = Path(r"C:\Browsers\Chrome\chrome.exe")
        candidates = (("Google Chrome", chrome), ("Microsoft Edge", edge))
        with (
            patch(
                "campus_net_assistant.edge._browser_candidates",
                return_value=candidates,
            ),
            patch.object(Path, "exists", autospec=True, return_value=True),
        ):
            selected = _edge_path()
        self.assertEqual(selected, str(chrome))
        self.assertEqual(_browser_display_name(selected), "Google Chrome")

        with (
            patch(
                "campus_net_assistant.edge._browser_candidates",
                return_value=candidates,
            ),
            patch.object(
                Path,
                "exists",
                autospec=True,
                side_effect=lambda candidate: candidate.name == "msedge.exe",
            ),
        ):
            selected = _edge_path()
        self.assertEqual(selected, str(edge))
        self.assertEqual(_browser_display_name(selected), "Microsoft Edge")

    def test_browser_discovery_reports_both_supported_browsers_when_missing(self):
        from campus_net_assistant.edge import EdgeLoginError, _edge_path

        with patch("campus_net_assistant.edge._browser_candidates", return_value=()):
            with self.assertRaisesRegex(EdgeLoginError, "Microsoft Edge 或 Google Chrome"):
                _edge_path()

    def test_chrome_launch_flags_do_not_include_edge_only_features(self):
        from campus_net_assistant.edge import _browser_feature_arguments

        edge_flags = _browser_feature_arguments("msedge.exe")
        chrome_flags = _browser_feature_arguments("chrome.exe")
        self.assertTrue(any("EdgeFirstRunExperience" in value for value in edge_flags))
        self.assertFalse(any("EdgeFirstRunExperience" in value for value in chrome_flags))
        self.assertTrue(any("HttpsUpgrades" in value for value in chrome_flags))

    def test_displayed_product_version_matches_package_version(self):
        from campus_net_assistant import __version__
        from campus_net_assistant.product import PRODUCT_VERSION
        from campus_net_assistant.version import VERSION

        self.assertEqual(PRODUCT_VERSION, VERSION)
        self.assertEqual(__version__, VERSION)

    def test_version_literal_has_one_authoritative_source(self):
        from campus_net_assistant.version import VERSION

        duplicate_candidates = (
            "build_local.py",
            "pyproject.toml",
            "version_info.txt",
            "src/campus_net_assistant/__init__.py",
            "src/campus_net_assistant/product.py",
        )
        for relative in duplicate_candidates:
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn(VERSION, text)
        self.assertIn(VERSION, (ROOT / "README.md").read_text(encoding="utf-8"))
        usage_template = (ROOT / "使用说明.txt").read_text(encoding="utf-8")
        self.assertIn("{{VERSION}}", usage_template)
        self.assertIn(VERSION, usage_template.replace("{{VERSION}}", VERSION))

    def test_load_config_migrates_monitor_interval_to_two_minutes(self):
        from campus_net_assistant import config as config_module

        old_app_dir = config_module.APP_DIR
        old_config_path = config_module.CONFIG_PATH
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                config_module.APP_DIR = Path(temp_dir)
                config_module.CONFIG_PATH = config_module.APP_DIR / "config.json"
                legacy = config_module.AppConfig().public_dict()
                legacy.pop("connection_mode")
                legacy["monitor_interval_seconds"] = 300
                legacy["portal"].pop("secondary_check_url")
                config_module.CONFIG_PATH.write_text(
                    json.dumps(legacy, ensure_ascii=False),
                    encoding="utf-8",
                )

                loaded = config_module.load_config()

                self.assertEqual(loaded.monitor_interval_seconds, 120)
                self.assertEqual(loaded.connection_mode, "wireless")
                saved = json.loads(config_module.CONFIG_PATH.read_text(encoding="utf-8"))
                self.assertEqual(saved["monitor_interval_seconds"], 120)
                self.assertEqual(saved["connection_mode"], "wireless")
                self.assertEqual(
                    saved["portal"]["secondary_check_url"],
                    "http://connectivitycheck.gstatic.cn/generate_204",
                )
        finally:
            config_module.APP_DIR = old_app_dir
            config_module.CONFIG_PATH = old_config_path

    def test_formal_source_has_no_external_fallback(self):
        package = ROOT / "src" / "campus_net_assistant"
        self.assertFalse((package / "fallback.py").exists())
        controller = (package / "controller.py").read_text(encoding="utf-8")
        self.assertNotIn("run_fallback", controller)
        self.assertNotIn("ensure-wifi-online.ps1", controller)
        self.assertNotIn("daily-tasks", controller)

    def test_portable_source_has_no_self_install_or_self_delete(self):
        package = ROOT / "src" / "campus_net_assistant"
        self.assertFalse((package / "deployment.py").exists())
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in package.glob("*.py")
        )
        for forbidden in (
            "UninstallString",
            "QuietUninstallString",
            "install_to(",
            "--uninstall",
            "Remove-Item -LiteralPath",
            ".njmu-campus-net-assistant-install.json",
        ):
            self.assertNotIn(forbidden, source)

    def test_dual_connectivity_probe_uses_android_when_microsoft_fails(self):
        from campus_net_assistant import probe

        with (
            patch.object(probe, "internet_probe", return_value=False) as microsoft,
            patch.object(probe, "http_status_probe", return_value=True) as android,
        ):
            result = probe.connectivity_probe(
                "192.0.2.10",
                "http://www.msftconnecttest.com/connecttest.txt",
                "Microsoft Connect Test",
                "http://connectivitycheck.gstatic.cn/generate_204",
            )

        self.assertEqual(result, (True, "android-generate-204"))
        microsoft.assert_called_once()
        android.assert_called_once_with(
            "192.0.2.10",
            "http://connectivitycheck.gstatic.cn/generate_204",
            204,
        )

    def test_dual_connectivity_probe_requires_both_targets_to_fail(self):
        from campus_net_assistant import probe

        with (
            patch.object(probe, "internet_probe", return_value=False),
            patch.object(probe, "http_status_probe", return_value=False),
        ):
            result = probe.connectivity_probe(
                "192.0.2.10",
                "http://www.msftconnecttest.com/connecttest.txt",
                "Microsoft Connect Test",
                "http://connectivitycheck.gstatic.cn/generate_204",
            )

        self.assertEqual(result, (False, "all-connectivity-probes-failed"))

    def test_android_status_probe_bypasses_proxy_and_does_not_follow_redirects(self):
        from campus_net_assistant import probe

        with patch.object(probe.subprocess, "check_output", return_value="204") as curl:
            self.assertTrue(
                probe.http_status_probe(
                    "192.0.2.10",
                    "http://connectivitycheck.gstatic.cn/generate_204",
                )
            )

        command = curl.call_args.args[0]
        self.assertEqual(command[command.index("--noproxy") + 1], "*")
        self.assertEqual(command[command.index("--interface") + 1], "192.0.2.10")
        self.assertEqual(command[command.index("-w") + 1], "%{http_code}")
        self.assertNotIn("-L", command)

    def test_status_round_trip_does_not_require_network(self):
        from campus_net_assistant import status

        old_app_dir = status.APP_DIR
        old = status.STATUS_PATH
        try:
            status.APP_DIR = ROOT / "test-app"
            status.STATUS_PATH = status.APP_DIR / "test-status.json"
            status.write("test", True, "脱敏测试")
            self.assertEqual(status.read()["stage"], "test")
        finally:
            status.APP_DIR = old_app_dir
            status.STATUS_PATH = old
            (ROOT / "test-app" / "test-status.json").unlink(missing_ok=True)
            (ROOT / "test-app").rmdir()

    def test_scheduler_xml_has_background_action_and_wake_flag(self):
        from campus_net_assistant.scheduler import _xml

        with patch("campus_net_assistant.scheduler._sid", return_value="S-1-5-21-test"):
            xml = _xml("NJMUCampusNetAssistant-Wake", "wake", "08:55", "PT25M", True)
        self.assertIn("WakeToRun", xml)
        self.assertIn("--background wake", xml)
        self.assertIn("InteractiveToken", xml)
        self.assertIn("PT25M", xml)
        self.assertNotIn("RestartOnFailure", xml)
        self.assertIn("encoding='utf-16'", xml)
        ET.fromstring(xml)
        with patch("campus_net_assistant.scheduler._sid", return_value="S-1-5-21-test"):
            monitor_xml = _xml(
                "NJMUCampusNetAssistant-Monitor",
                "monitor",
                "09:10",
                "PT15H20M",
                restart_on_failure=True,
            )
        self.assertIn("RestartOnFailure", monitor_xml)
        self.assertIn("PT1M", monitor_xml)
        self.assertIn("<Count>3</Count>", monitor_xml)

    def test_scheduler_install_adds_logon_resume_and_unlimited_monitor(self):
        import subprocess

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import install

        config = AppConfig(
            wake_enabled=True,
            hibernate_enabled=True,
            wake_time="07:30",
            sleep_time="23:40",
        )
        captured = {}

        def remember(name, xml):
            captured[name] = xml

        with (
            patch("campus_net_assistant.scheduler.is_admin", return_value=True),
            patch("campus_net_assistant.scheduler._sid", return_value="S-1-5-21-test"),
            patch("campus_net_assistant.scheduler._register", side_effect=remember),
            patch("campus_net_assistant.scheduler._delete_task", return_value=False),
            patch("campus_net_assistant.scheduler.arm_monitor"),
            patch("campus_net_assistant.scheduler.disarm_monitor"),
            patch(
                "campus_net_assistant.scheduler.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            patch("campus_net_assistant.scheduler.event"),
        ):
            install(config)
        monitor_xml = captured["NJMUCampusNetAssistant-Monitor"]
        self.assertIn("T07:45:00", monitor_xml)
        self.assertIn("PT0S", monitor_xml)
        self.assertIn("LogonTrigger", monitor_xml)
        self.assertNotIn("Power-Troubleshooter", monitor_xml)
        self.assertIn("RestartOnFailure", monitor_xml)

    def test_scheduler_installs_only_enabled_optional_tasks(self):
        import subprocess

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import install

        cases = (
            (True, True, {"NJMUCampusNetAssistant-Wake", "NJMUCampusNetAssistant-Hibernate", "NJMUCampusNetAssistant-Monitor"}),
            (True, False, {"NJMUCampusNetAssistant-Wake", "NJMUCampusNetAssistant-Monitor"}),
            (False, True, {"NJMUCampusNetAssistant-Hibernate", "NJMUCampusNetAssistant-Monitor"}),
            (False, False, {"NJMUCampusNetAssistant-Monitor"}),
        )
        for wake_enabled, hibernate_enabled, expected in cases:
            with self.subTest(wake_enabled=wake_enabled, hibernate_enabled=hibernate_enabled):
                captured = {}

                def remember(name, xml):
                    captured[name] = xml

                config = AppConfig(
                    wake_enabled=wake_enabled,
                    auto_connect_on_startup=wake_enabled,
                    hibernate_enabled=hibernate_enabled,
                )
                with (
                    patch("campus_net_assistant.scheduler.is_admin", return_value=True),
                    patch("campus_net_assistant.scheduler._sid", return_value="S-1-5-21-test"),
                    patch("campus_net_assistant.scheduler._register", side_effect=remember),
                    patch("campus_net_assistant.scheduler._delete_task", return_value=True),
                    patch("campus_net_assistant.scheduler.arm_monitor") as arm,
                    patch("campus_net_assistant.scheduler.disarm_monitor") as disarm,
                    patch(
                        "campus_net_assistant.scheduler.subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, "", ""),
                    ),
                    patch("campus_net_assistant.scheduler.event"),
                ):
                    result = install(config)
                self.assertEqual(set(captured), expected)
                self.assertEqual(set(result["installed"]), expected)
                monitor_xml = captured["NJMUCampusNetAssistant-Monitor"]
                self.assertIn("LogonTrigger", monitor_xml)
                if wake_enabled:
                    self.assertIn("CalendarTrigger", monitor_xml)
                    self.assertNotIn("Power-Troubleshooter", monitor_xml)
                    arm.assert_called_once()
                    disarm.assert_not_called()
                else:
                    self.assertNotIn("CalendarTrigger", monitor_xml)
                    self.assertIn("Power-Troubleshooter", monitor_xml)
                    disarm.assert_called_once()
                    arm.assert_not_called()

    def test_scheduler_stops_orphaned_product_monitor_processes(self):
        import subprocess

        from campus_net_assistant.scheduler import _stop_orphaned_monitor_processes

        completed = subprocess.CompletedProcess([], 0, "2\n", "")
        with patch("campus_net_assistant.scheduler.subprocess.run", return_value=completed) as run:
            self.assertEqual(_stop_orphaned_monitor_processes(), 2)

        command = run.call_args.args[0][-1]
        self.assertIn("--background", command)
        self.assertIn("monitor", command)
        self.assertIn("NJMU校园网自动化连接程序.exe", command)
        self.assertIn("南医校园网自动登录辅助程序.exe", command)

    def test_scheduler_one_click_remove_cleans_all_formal_tasks(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import remove_all_tasks

        with (
            patch("campus_net_assistant.scheduler.is_admin", return_value=True),
            patch("campus_net_assistant.scheduler._delete_task", return_value=True) as delete_task,
            patch("campus_net_assistant.scheduler._stop_orphaned_monitor_processes", return_value=2),
            patch("campus_net_assistant.scheduler.load_config", return_value=AppConfig()),
            patch("campus_net_assistant.scheduler.disarm_monitor") as disarm,
            patch("campus_net_assistant.scheduler.event"),
        ):
            result = remove_all_tasks()

        self.assertEqual(delete_task.call_count, 4)
        self.assertEqual(
            set(result["removed"]),
            {
                "NJMUCampusNetAssistant-Wake",
                "NJMUCampusNetAssistant-MorningLogin",
                "NJMUCampusNetAssistant-Hibernate",
                "NJMUCampusNetAssistant-Monitor",
            },
        )
        self.assertEqual(result["stopped_orphan_monitors"], 2)
        disarm.assert_called_once()

    def test_wlan_uses_flattened_powershell_fields(self):
        from campus_net_assistant.wlan import get_wlan

        powershell_json = json.dumps({
            "InterfaceIndex": 15,
            "IPAddress": "192.0.2.10",
            "Gateway": "192.0.2.1",
            "DNSServers": ["192.0.2.53"],
        })
        netsh_output = "\r\n    Name                   : WLAN\r\n    SSID                   : NJMU_WLAN\r\n"
        with patch(
            "campus_net_assistant.wlan.subprocess.check_output",
            side_effect=[powershell_json, netsh_output],
        ) as check_output:
            wlan = get_wlan("WLAN")
        self.assertIsNotNone(wlan)
        self.assertEqual(wlan.ssid, "NJMU_WLAN")
        self.assertEqual(wlan.ip, "192.0.2.10")
        self.assertEqual(wlan.gateway, "192.0.2.1")
        self.assertEqual(wlan.ifindex, 15)
        powershell_command = check_output.call_args_list[0].args[0][-1]
        self.assertIn("[pscustomobject]", powershell_command)
        self.assertIn("ConvertTo-Json -Depth 3", powershell_command)

    def test_wlan_decodes_gb18030_chinese_interface_output(self):
        from campus_net_assistant.wlan import get_wlan

        powershell_json = json.dumps({
            "InterfaceIndex": 4,
            "IPAddress": "192.0.2.10",
            "Gateway": "192.0.2.1",
            "DNSServers": ["192.0.2.53"],
        })
        netsh_output = """
            名称 : WLAN
            状态 : 已连接
            SSID : NJMU_WLAN
        """.encode("gb18030")
        with patch(
            "campus_net_assistant.wlan.subprocess.check_output",
            side_effect=[powershell_json, netsh_output],
        ):
            wlan = get_wlan("WLAN")
        self.assertIsNotNone(wlan)
        self.assertEqual(wlan.interface, "WLAN")
        self.assertEqual(wlan.ssid, "NJMU_WLAN")

    def test_wireless_interface_discovery_excludes_not_present_ghosts(self):
        from campus_net_assistant.wlan import _powershell_wireless_interfaces

        with patch(
            "campus_net_assistant.wlan.subprocess.check_output",
            return_value=json.dumps("WLAN"),
        ) as check_output:
            self.assertEqual(_powershell_wireless_interfaces(), ["WLAN"])
        powershell_command = check_output.call_args.args[0][-1]
        self.assertIn("$_.Status -ne 'Not Present'", powershell_command)

    def test_wlan_connect_uses_saved_target_profile(self):
        from campus_net_assistant.wlan import connect_wlan

        completed = __import__("subprocess").CompletedProcess([], 0, "", "")
        with patch("campus_net_assistant.wlan.subprocess.run", return_value=completed) as run:
            requested, reason = connect_wlan("WLAN", "NJMU_WLAN")
        self.assertTrue(requested)
        self.assertEqual(reason, "connection-requested")
        command = run.call_args.args[0]
        self.assertIn("name=NJMU_WLAN", command)
        self.assertIn("ssid=NJMU_WLAN", command)
        self.assertIn("interface=WLAN", command)

    def test_wlan_visibility_parses_target_ssid(self):
        from campus_net_assistant.wlan import ssid_visible

        completed = __import__("subprocess").CompletedProcess(
            [],
            0,
            "\r\nSSID 1 : Other\r\nSSID 2 : NJMU_WLAN\r\n",
            "",
        )
        with patch("campus_net_assistant.wlan.subprocess.run", return_value=completed):
            visible, reason = ssid_visible("WLAN", "NJMU_WLAN")
        self.assertTrue(visible)
        self.assertEqual(reason, "visible")

    def test_auto_wlan_prefers_adapter_with_visible_saved_target_profile(self):
        from campus_net_assistant import wlan as wlan_module

        wlan_module._AUTO_INTERFACE_CACHE.clear()
        blocks = [("Wi-Fi", "Other"), ("Wi-Fi 2", "")]
        with (
            patch("campus_net_assistant.wlan._netsh_interfaces", return_value=blocks),
            patch(
                "campus_net_assistant.wlan._powershell_wireless_interfaces",
                return_value=["Wi-Fi", "Wi-Fi 2"],
            ),
            patch(
                "campus_net_assistant.wlan._profile_exists_on_interface",
                side_effect=lambda name, _ssid: name == "Wi-Fi 2",
            ),
            patch(
                "campus_net_assistant.wlan._ssid_visible_on_interface",
                side_effect=lambda name, _ssid: (name == "Wi-Fi 2", "visible"),
            ),
        ):
            selected = wlan_module.resolve_wlan_interface("auto", "NJMU_WLAN")
        self.assertEqual(selected, "Wi-Fi 2")
        wlan_module._AUTO_INTERFACE_CACHE.clear()

    def test_wait_for_target_wlan_requests_connection(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _wait_for_target_wlan
        from campus_net_assistant.wlan import WlanEnableResult, WlanInfo

        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch(
                "campus_net_assistant.controller.ensure_wlan_enabled",
                return_value=WlanEnableResult(
                    True,
                    True,
                    "software-radio-enabled",
                    "WLAN",
                    software_radio_enabled=True,
                ),
            ) as enable,
            patch("campus_net_assistant.controller.get_wlan", side_effect=[None, target]),
            patch("campus_net_assistant.controller.ssid_visible", return_value=(True, "visible")),
            patch("campus_net_assistant.controller.connect_wlan", return_value=(True, "connection-requested")) as connect,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
            patch("campus_net_assistant.controller.time.sleep"),
        ):
            result, requested, reason = _wait_for_target_wlan(AppConfig(), 30)
        self.assertEqual(result, target)
        self.assertTrue(requested)
        self.assertEqual(reason, "connected")
        enable.assert_called_once_with("auto", "NJMU_WLAN")
        connect.assert_called_once_with("auto", "NJMU_WLAN")

    def test_wlan_enable_path_never_disables_an_enabled_adapter(self):
        from campus_net_assistant import wlan as wlan_module

        response = json.dumps(
            {
                "Interface": "Wi-Fi",
                "InterfaceGuid": "0d18b483-e88e-45d2-99a1-28f3e79b187e",
                "Status": "Disconnected",
                "Changed": False,
            }
        )
        with (
            patch(
                "campus_net_assistant.wlan.resolve_wlan_interface",
                return_value="Wi-Fi",
            ),
            patch(
                "campus_net_assistant.wlan.subprocess.check_output",
                return_value=response,
            ) as check_output,
        ):
            result = wlan_module._enable_wlan_adapter("auto", "NJMU_WLAN")

        self.assertTrue(result.success)
        self.assertFalse(result.changed)
        command = check_output.call_args.args[0][-1]
        self.assertIn("Enable-NetAdapter", command)
        self.assertNotIn("Disable-NetAdapter", command)

    def test_ensure_wlan_enabled_turns_on_adapter_then_software_radio(self):
        from campus_net_assistant import wlan as wlan_module

        adapter = wlan_module._AdapterEnableResult(
            True,
            True,
            "adapter-enabled",
            "Wi-Fi",
            "0d18b483-e88e-45d2-99a1-28f3e79b187e",
        )
        radio = wlan_module._RadioEnableResult(
            True,
            True,
            "software-radio-enabled",
        )
        with (
            patch(
                "campus_net_assistant.wlan._enable_wlan_adapter",
                return_value=adapter,
            ) as enable_adapter,
            patch(
                "campus_net_assistant.wlan._set_wlan_software_radio",
                return_value=radio,
            ) as enable_radio,
            patch("campus_net_assistant.wlan.time.sleep") as sleep,
        ):
            result = wlan_module.ensure_wlan_enabled("auto", "NJMU_WLAN")

        self.assertTrue(result.success)
        self.assertTrue(result.changed)
        self.assertTrue(result.adapter_enabled)
        self.assertTrue(result.software_radio_enabled)
        enable_adapter.assert_called_once_with("auto", "NJMU_WLAN")
        enable_radio.assert_called_once_with(adapter.interface_guid)
        sleep.assert_called_once_with(2)

    def test_software_radio_enable_reports_hardware_radio_block(self):
        from campus_net_assistant import wlan as wlan_module

        wlan_api = Mock()
        wlan_api.WlanOpenHandle.return_value = 0
        wlan_api.WlanCloseHandle.return_value = 0
        with (
            patch("campus_net_assistant.wlan._load_wlan_api", return_value=wlan_api),
            patch(
                "campus_net_assistant.wlan._query_radio_states",
                return_value=(0, [(0, 1, 2)]),
            ),
        ):
            result = wlan_module._set_wlan_software_radio(
                "0d18b483-e88e-45d2-99a1-28f3e79b187e"
            )

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "hardware-radio-off")
        self.assertTrue(result.hardware_radio_blocked)
        wlan_api.WlanSetInterface.assert_not_called()
        wlan_api.WlanCloseHandle.assert_called_once()

    def test_software_radio_enable_sets_off_phy_and_verifies_it(self):
        from campus_net_assistant import wlan as wlan_module

        wlan_api = Mock()
        wlan_api.WlanOpenHandle.return_value = 0
        wlan_api.WlanSetInterface.return_value = 0
        wlan_api.WlanCloseHandle.return_value = 0
        with (
            patch("campus_net_assistant.wlan._load_wlan_api", return_value=wlan_api),
            patch(
                "campus_net_assistant.wlan._query_radio_states",
                side_effect=[(0, [(0, 2, 1)]), (0, [(0, 1, 1)])],
            ) as query,
            patch("campus_net_assistant.wlan.time.sleep") as sleep,
        ):
            result = wlan_module._set_wlan_software_radio(
                "0d18b483-e88e-45d2-99a1-28f3e79b187e"
            )

        self.assertTrue(result.success)
        self.assertTrue(result.changed)
        self.assertEqual(result.reason, "software-radio-enabled")
        self.assertEqual(query.call_count, 2)
        wlan_api.WlanSetInterface.assert_called_once()
        sleep.assert_called_once_with(2)
        wlan_api.WlanCloseHandle.assert_called_once()

    def test_ethernet_detection_selects_unique_physical_default_route(self):
        from campus_net_assistant.ethernet import detect_ethernet_interface

        route_output = """
Interface List
  5...02 00 00 00 00 05 ......Realtek PCIe GbE Family Controller
 17...02 00 00 00 00 11 ......VMware Virtual Ethernet Adapter for VMnet1
IPv4 Route Table
          0.0.0.0          0.0.0.0        192.0.2.1       192.0.2.62     25
"""
        interface_output = """
Idx     Met         MTU          State                Name
  5          25        1500  connected     以太网
 17          35        1500  connected     VMware Network Adapter VMnet1
"""
        address_output = """
Configuration for interface "以太网"
    IP Address:                           192.0.2.62
    Default Gateway:                      192.0.2.1
Configuration for interface "VMware Network Adapter VMnet1"
    IP Address:                           203.0.113.1
"""
        dns_output = """
Configuration for interface "以太网"
    DNS servers configured through DHCP:  192.0.2.53
                                          198.51.100.53
Configuration for interface "VMware Network Adapter VMnet1"
    DNS servers configured through DHCP:  None
"""
        with patch(
            "campus_net_assistant.ethernet._run_text",
            side_effect=[route_output, interface_output, address_output, dns_output],
        ):
            result = detect_ethernet_interface()

        self.assertEqual(result.interface, "以太网")
        self.assertEqual(result.description, "Realtek PCIe GbE Family Controller")
        self.assertEqual(result.ip, "192.0.2.62")
        self.assertEqual(result.gateway, "192.0.2.1")
        self.assertEqual(result.ifindex, 5)
        self.assertEqual(result.dns_servers, ("192.0.2.53", "198.51.100.53"))
        self.assertEqual(result.route_metric, 25)

    def test_ethernet_detection_refuses_ambiguous_preferred_routes(self):
        from campus_net_assistant.ethernet import detect_ethernet_interface

        route_output = """
Interface List
  5...02 00 00 00 00 05 ......Realtek PCIe GbE Family Controller
 11...02 00 00 00 00 0b ......Sangfor SSL VPN CS Support System VNIC
IPv4 Route Table
          0.0.0.0          0.0.0.0        192.0.2.1       192.0.2.62     25
          0.0.0.0          0.0.0.0       172.16.0.1       172.16.0.2     25
"""
        interface_output = """
  5          25        1500  connected     以太网
 11          25        1400  connected     以太网 2
"""
        address_output = """
Configuration for interface "以太网"
    IP Address:                           192.0.2.62
Configuration for interface "以太网 2"
    IP Address:                           172.16.0.2
"""
        dns_output = """
Configuration for interface "以太网"
    DNS servers configured through DHCP:  192.0.2.53
Configuration for interface "以太网 2"
    DNS servers configured through DHCP:  172.16.0.1
"""
        with patch(
            "campus_net_assistant.ethernet._run_text",
            side_effect=[route_output, interface_output, address_output, dns_output],
        ):
            with self.assertRaisesRegex(RuntimeError, "unique-preferred"):
                detect_ethernet_interface()

    def test_wait_for_target_wlan_does_not_connect_when_ssid_invisible(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _wait_for_target_wlan
        from campus_net_assistant.wlan import WlanEnableResult

        with (
            patch(
                "campus_net_assistant.controller.ensure_wlan_enabled",
                return_value=WlanEnableResult(
                    True,
                    False,
                    "software-radio-already-enabled",
                    "WLAN",
                ),
            ),
            patch("campus_net_assistant.controller.get_wlan", return_value=None),
            patch("campus_net_assistant.controller.ssid_visible", return_value=(False, "not-visible")),
            patch("campus_net_assistant.controller.connect_wlan") as connect,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            result, requested, reason = _wait_for_target_wlan(AppConfig(), 0)
        self.assertIsNone(result)
        self.assertFalse(requested)
        self.assertEqual(reason, "ssid-not-visible")
        connect.assert_not_called()

    def test_do_login_probes_after_wifi_connect_before_opening_portal(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wlan import WlanInfo

        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, True, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch("campus_net_assistant.controller.load") as load,
            patch("campus_net_assistant.controller.login") as login,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertTrue(do_login(AppConfig()))
        load.assert_not_called()
        login.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "wifi-reconnected-online")

    def test_dorm_ethernet_login_reuses_primary_portal_with_bound_interface(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import EthernetInfo

        config = AppConfig(
            connection_mode="dorm_ethernet",
            dorm_protocol_observer_enabled=True,
        )
        ethernet = EthernetInfo(
            "以太网",
            "Realtek PCIe GbE Family Controller",
            "192.0.2.62",
            "192.0.2.1",
            5,
            ("192.0.2.53", "198.51.100.53"),
            25,
        )
        result = {
            "success": True,
            "login_submitted_at": "2026-08-18T01:30:28.755+08:00",
            "probe_succeeded_at": "2026-08-18T01:30:29.375+08:00",
            "edge_launch_attempt": 1,
            "dorm_inline_survey_file": "inline-wrapper-test.zip",
        }
        with (
            patch(
                "campus_net_assistant.controller._wait_for_dorm_ethernet",
                return_value=(ethernet, False, "connected"),
            ),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch("campus_net_assistant.controller.login", return_value=result) as login,
            patch("campus_net_assistant.controller.get_wlan") as get_wlan,
            patch("campus_net_assistant.controller.connect_wlan") as connect_wlan,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertTrue(do_login(config))

        get_wlan.assert_not_called()
        connect_wlan.assert_not_called()
        self.assertEqual(login.call_args.kwargs["interface_ip"], ethernet.ip)
        self.assertEqual(login.call_args.kwargs["route_gateway"], ethernet.gateway)
        self.assertEqual(login.call_args.kwargs["route_ifindex"], ethernet.ifindex)
        self.assertEqual(login.call_args.kwargs["dns_servers"], ethernet.dns_servers)
        self.assertFalse(login.call_args.kwargs["include_wireless_portal_host"])
        self.assertTrue(login.call_args.kwargs["dorm_ethernet_flow"])
        self.assertNotIn("dorm_protocol_observer_enabled", login.call_args.kwargs)
        self.assertEqual(write_status.call_args.args[0], "primary-login-succeeded")
        self.assertEqual(
            write_status.call_args.kwargs["dorm_inline_survey_file"],
            "inline-wrapper-test.zip",
        )

    def test_wireless_login_keeps_wireless_portal_host_routing(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wlan import WlanInfo

        wlan = WlanInfo(
            "WLAN",
            "NJMU_WLAN",
            "192.0.2.100",
            "192.0.2.1",
            15,
            ("192.0.2.53",),
        )
        result = {
            "success": True,
            "login_submitted_at": "2026-08-18T01:30:28.755+08:00",
            "probe_succeeded_at": "2026-08-18T01:30:29.375+08:00",
            "edge_launch_attempt": 1,
        }
        with (
            patch(
                "campus_net_assistant.controller._wait_for_target_wlan",
                return_value=(wlan, False, "connected"),
            ),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch("campus_net_assistant.controller.login", return_value=result) as login,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(do_login(AppConfig()))

        self.assertTrue(login.call_args.kwargs["include_wireless_portal_host"])
        self.assertFalse(login.call_args.kwargs["dorm_ethernet_flow"])

    def test_authentication_rejection_pauses_future_submissions(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.edge import AuthenticationRejectedError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.login",
                side_effect=AuthenticationRejectedError("credentials-invalid"),
            ) as login,
            patch("campus_net_assistant.controller.save_config") as save_config,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(do_login(config))
        self.assertTrue(config.auth_paused)
        self.assertEqual(config.auth_pause_reason, "credentials-invalid")
        self.assertEqual(login.call_args.kwargs["dns_servers"], ())
        save_config.assert_called_once_with(config)
        self.assertEqual(write_status.call_args.args[0], "authentication-paused")

    def test_authentication_rejection_distinguishes_account_and_password(self):
        from campus_net_assistant.edge import _authentication_rejection

        self.assertEqual(_authentication_rejection("用户不存在"), "account-invalid")
        self.assertEqual(_authentication_rejection("密码错误"), "password-invalid")
        self.assertEqual(_authentication_rejection("账号或密码错误"), "credentials-invalid")
        self.assertIsNone(_authentication_rejection("欢迎使用校园网"))

    def test_portal_allowlist_rejection_pauses_future_submissions(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.edge import PortalAllowlistError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.login",
                side_effect=PortalAllowlistError("blocked"),
            ) as login,
            patch("campus_net_assistant.controller.save_config") as save_config,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(do_login(config))
            self.assertFalse(do_login(config))

        self.assertTrue(config.auth_paused)
        self.assertEqual(config.auth_pause_reason, "portal-allowlist-blocked")
        self.assertEqual(login.call_count, 1)
        save_config.assert_called_once_with(config)
        self.assertEqual(write_status.call_args.args[0], "portal-allowlist-blocked")
        self.assertTrue(write_status.call_args.kwargs["automatic_submission_paused"])

    def test_portal_allowlist_allows_one_manual_full_recheck_only(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _manual_validation_preflight, do_login
        from campus_net_assistant.edge import PortalAllowlistError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig(
            auth_paused=True,
            auth_pause_reason="portal-allowlist-blocked",
        )
        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.login",
                side_effect=PortalAllowlistError("blocked again"),
            ) as login,
            patch("campus_net_assistant.controller.save_config"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as status,
        ):
            self.assertTrue(_manual_validation_preflight(config))
            self.assertFalse(
                do_login(config, require_submission=True, manual_validation=True)
            )
            self.assertFalse(_manual_validation_preflight(config))

        login.assert_called_once()
        self.assertTrue(config.auth_paused)
        self.assertFalse(config.portal_allowlist_manual_retry_available)
        self.assertEqual(status.call_args.kwargs["manual_retry_available"], False)

    def test_submission_rate_limit_pauses_before_opening_portal(self):
        from datetime import datetime

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wlan import WlanInfo

        now = datetime.now().astimezone().isoformat(timespec="milliseconds")
        config = AppConfig(login_submission_timestamps=[now, now])
        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.login") as login,
            patch("campus_net_assistant.controller.save_config") as save_config,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(do_login(config))

        login.assert_not_called()
        self.assertTrue(config.auth_paused)
        self.assertEqual(config.auth_pause_reason, "submission-rate-limit")
        save_config.assert_called_once_with(config)
        self.assertEqual(write_status.call_args.args[0], "authentication-paused")

    def test_manual_unknown_result_pauses_automatic_resubmission(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.edge import LoginOutcomeUnknownError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.login",
                side_effect=LoginOutcomeUnknownError("result unknown"),
            ),
            patch("campus_net_assistant.controller.save_config") as save_config,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(do_login(config, require_submission=True, manual_validation=True))

        self.assertTrue(config.auth_paused)
        self.assertEqual(config.auth_pause_reason, "result-unknown")
        save_config.assert_called_once_with(config)
        self.assertEqual(write_status.call_args.args[0], "authentication-paused")

    def test_online_before_main_submit_is_only_external_confirmation(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wlan import WlanInfo

        target = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        result = {
            "success": True,
            "login_submitted_at": None,
            "probe_succeeded_at": "2026-07-30T09:03:46.000+08:00",
            "edge_launch_attempt": 1,
        }
        with (
            patch("campus_net_assistant.controller._wait_for_target_wlan", return_value=(target, False, "connected")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch("campus_net_assistant.controller.login", return_value=result),
            patch("campus_net_assistant.controller.append_connectivity_event") as append_event,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertTrue(do_login(AppConfig()))
        self.assertEqual(write_status.call_args.args[0], "online-confirmed-before-submit")
        self.assertEqual(append_event.call_args.kwargs["source"], "external-or-concurrent-flow")

    def test_logout_current_session_uses_wlan_dns_and_confirms_offline_twice(self):
        from campus_net_assistant.edge import logout_current_session

        class FakeSocket:
            def __init__(self) -> None:
                self.bound = None
                self.connected = None
                self.request = b""
                self.responses = [
                    b"HTTP/1.1 200 OK\r\n\r\nLogout Successful",
                    b"",
                ]

            def settimeout(self, _seconds) -> None:
                pass

            def bind(self, address) -> None:
                self.bound = address

            def connect(self, address) -> None:
                self.connected = address

            def sendall(self, payload) -> None:
                self.request = payload

            def recv(self, _size):
                return self.responses.pop(0)

            def close(self) -> None:
                pass

        fake_socket = FakeSocket()
        probe_results = iter([True, False, False])
        with (
            patch(
                "campus_net_assistant.edge._resolve_from_wlan",
                return_value=["198.51.100.14"],
            ) as resolve,
            patch("campus_net_assistant.edge.socket.socket", return_value=fake_socket),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = logout_current_session(
                "192.0.2.10",
                ("192.0.2.53",),
                lambda: next(probe_results),
            )

        resolve.assert_called_once_with(
            "captiveportal-login.njmu.edu.cn",
            "192.0.2.10",
            ("192.0.2.53",),
        )
        self.assertEqual(fake_socket.bound, ("192.0.2.10", 0))
        self.assertEqual(fake_socket.connected, ("198.51.100.14", 80))
        self.assertIn(b"GET /auth/logout.html HTTP/1.1", fake_socket.request)
        self.assertIn(b"Host: captiveportal-login.njmu.edu.cn", fake_socket.request)
        self.assertEqual(result["probe_attempts"], 3)

    def test_dorm_logout_refreshes_official_portal_and_confirms_offline_twice(self):
        from campus_net_assistant.edge import logout_dorm_ethernet_session

        class FakeClient:
            def call(self, _method, _params=None):
                return None

            def close(self):
                pass

        page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/entry/pc/finish",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1",
        }
        cdp_status = {
            "cdp_reachable": True,
            "page_count": 1,
            "cdp_reason": "reachable",
        }
        states = iter(
            [
                {"online": True, "hasLogoutAction": True},
                {"confirmVisible": True},
                {"offlineSuccess": True},
                {"offlineSuccess": True},
            ]
        )
        probe_results = iter([False, False])
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
                patch(
                    "campus_net_assistant.edge._select_edge_attempt_ports",
                    return_value=((9222, 9223), "saved"),
                ),
                patch(
                    "campus_net_assistant.edge._portal_page_status",
                    return_value=(page, cdp_status),
                ),
                patch("campus_net_assistant.edge._navigate_first_page", return_value=True) as navigate,
                patch("campus_net_assistant.edge.Cdp", return_value=FakeClient()),
                patch("campus_net_assistant.edge._dorm_logout_page_state", side_effect=lambda _client: next(states)),
                patch("campus_net_assistant.edge._click_dorm_logout", return_value=True) as click_logout,
                patch("campus_net_assistant.edge._confirm_dorm_logout", return_value=True) as confirm_logout,
                patch("campus_net_assistant.edge.subprocess.Popen") as popen,
                patch("campus_net_assistant.edge.time.sleep"),
                patch("campus_net_assistant.edge.event"),
            ):
                result = logout_dorm_ethernet_session(
                    "192.0.2.62",
                    lambda: next(probe_results),
                    edge_profile_root=Path(temp_dir) / "logout-profile",
                )

        navigate.assert_called_once_with(9222, "http://202.195.176.60")
        popen.assert_not_called()
        click_logout.assert_called_once()
        confirm_logout.assert_called_once()
        self.assertTrue(result["success"])
        self.assertEqual(result["probe_attempts"], 2)
        self.assertEqual(result["method"], "dorm-official-portal-ui")

    def test_dorm_logout_confirmation_uses_cdp_mouse_input(self):
        from campus_net_assistant.edge import _confirm_dorm_logout

        class FakeClient:
            def __init__(self):
                self.calls = []

            def evaluate(self, _expression):
                return '{"x":321.5,"y":123.25}'

            def call(self, method, params=None):
                self.calls.append((method, params))

        client = FakeClient()
        self.assertTrue(_confirm_dorm_logout(client))
        self.assertEqual(
            [params["type"] for method, params in client.calls if method == "Input.dispatchMouseEvent"],
            ["mouseMoved", "mousePressed", "mouseReleased"],
        )
        self.assertEqual(client.calls[-1][1]["button"], "left")

    def test_dorm_logout_action_uses_cdp_mouse_input(self):
        from campus_net_assistant.edge import _click_dorm_logout

        class FakeClient:
            def __init__(self):
                self.calls = []

            def evaluate(self, _expression):
                return '{"x":111.5,"y":222.25}'

            def call(self, method, params=None):
                self.calls.append((method, params))

        client = FakeClient()
        self.assertTrue(_click_dorm_logout(client))
        self.assertEqual(
            [params["type"] for method, params in client.calls if method == "Input.dispatchMouseEvent"],
            ["mouseMoved", "mousePressed", "mouseReleased"],
        )
        self.assertEqual(client.calls[-1][1]["clickCount"], 1)

    def test_dorm_login_actions_use_verified_two_stage_flow(self):
        from campus_net_assistant.edge import (
            _click_dorm_confirmation,
            _fill_dorm_credentials,
            _select_dorm_operator,
            _submit_dorm_credentials,
        )

        class FillClient:
            def evaluate(self, expression):
                self.expression = expression
                return json.dumps({"allowed": True, "value": True})

        fill_client = FillClient()
        self.assertTrue(_fill_dorm_credentials(fill_client, "user", "secret"))
        self.assertIn("input", fill_client.expression)

        class ClickClient:
            def __init__(self):
                self.calls = []
                self.expressions = []

            def evaluate(self, expression):
                self.expressions.append(expression)
                if "const rules=" in expression:
                    return json.dumps(
                        {
                            "allowed": True,
                            "value": json.dumps(
                                {
                                    "x": 210.5,
                                    "y": 310.25,
                                    "domClicked": True,
                                    "recognizedLabel": "点击登录",
                                    "matchStrategy": "exact-login-label",
                                    "controlTag": "button",
                                    "controlType": "button",
                                }
                            ),
                        }
                    )
                return '{"x":210.5,"y":310.25,"domClicked":true}'

            def call(self, method, params=None):
                self.calls.append((method, params))

        click_client = ClickClient()
        login_action = _submit_dorm_credentials(click_client)
        self.assertTrue(login_action)
        self.assertEqual(login_action["recognized_label"], "点击登录")
        self.assertEqual(login_action["match_strategy"], "exact-login-label")
        self.assertEqual(login_action["click_method"], "dom")
        self.assertTrue(any("点击登录" in expression for expression in click_client.expressions))
        self.assertEqual(_select_dorm_operator(click_client, "电信")["click_method"], "dom")
        self.assertEqual(_click_dorm_confirmation(click_client)["click_method"], "dom")
        self.assertFalse(click_client.calls)
        self.assertEqual(
            sum("target.click()" in expression for expression in click_client.expressions),
            3,
        )

    def test_dorm_login_actions_fall_back_to_cdp_mouse_input(self):
        from campus_net_assistant.edge import (
            _click_dorm_confirmation,
            _select_dorm_operator,
            _submit_dorm_credentials,
        )

        class ClickClient:
            def __init__(self):
                self.calls = []

            def evaluate(self, expression):
                result = {
                    "x": 210.5,
                    "y": 310.25,
                    "domClicked": False,
                }
                if "const rules=" in expression:
                    result.update(
                        {
                            "recognizedLabel": "立即登录",
                            "matchStrategy": "exact-login-label",
                            "controlTag": "button",
                            "controlType": "button",
                        }
                    )
                    return json.dumps(
                        {
                            "allowed": True,
                            "value": json.dumps(result, ensure_ascii=False),
                        },
                        ensure_ascii=False,
                    )
                return json.dumps(result)

            def call(self, method, params=None):
                self.calls.append((method, params))

        client = ClickClient()
        self.assertEqual(
            _submit_dorm_credentials(client)["click_method"],
            "coordinate-fallback",
        )
        self.assertEqual(
            _select_dorm_operator(client, "电信")["click_method"],
            "coordinate-fallback",
        )
        self.assertEqual(
            _click_dorm_confirmation(client)["click_method"],
            "coordinate-fallback",
        )
        self.assertEqual(
            [params["type"] for method, params in client.calls if method == "Input.dispatchMouseEvent"],
            ["mouseMoved", "mousePressed", "mouseReleased"] * 3,
        )

    def test_dorm_service_diagnostic_records_structure_without_urls_or_text(self):
        from campus_net_assistant.edge import _dorm_service_page_diagnostic

        class DiagnosticClient:
            def evaluate(self, expression, *, context_id=None):
                self.expression = expression
                return json.dumps(
                    {
                        "url": (
                            "http://202.195.176.60/portal/entry/pc/"
                            "serviceSelection?token=private-session&username=private-user"
                        ),
                        "readyState": "complete",
                        "bodyPresent": True,
                        "bodyTextCharacters": 321,
                        "iframeElements": 1,
                        "passwordFields": 0,
                        "visiblePasswordFields": 0,
                        "operatorExactCandidates": 2,
                        "operatorVisibleCandidates": 1,
                        "operatorClickableCandidates": 1,
                        "operatorBoxCandidates": 0,
                        "confirmationCandidates": 1,
                        "visibleConfirmationCandidates": 0,
                        "visibleLoadingIndicators": 1,
                        "visibleDialogs": 1,
                    }
                )

        diagnostic = _dorm_service_page_diagnostic(DiagnosticClient(), "电信")

        self.assertEqual(diagnostic["page_roles"], {"official-service-selection": 1})
        self.assertEqual(diagnostic["document_ready_states"], {"complete": 1})
        self.assertEqual(diagnostic["operatorExactCandidates"], 2)
        self.assertEqual(diagnostic["operatorBoxCandidates"], 0)
        self.assertEqual(diagnostic["visibleLoadingIndicators"], 1)
        serialized = json.dumps(diagnostic, ensure_ascii=False)
        self.assertNotIn("202.195.176.60", serialized)
        self.assertNotIn("private-session", serialized)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("token", serialized.lower())

    def test_dorm_service_diagnostic_logs_only_error_type_when_read_fails(self):
        from campus_net_assistant.edge import _dorm_service_page_diagnostic

        class FailingDiagnosticClient:
            def evaluate(self, _expression, *, context_id=None):
                raise RuntimeError("password=private-secret token=private-token")

        diagnostic = _dorm_service_page_diagnostic(FailingDiagnosticClient(), "电信")

        self.assertEqual(diagnostic["frame_reads_ok"], 0)
        self.assertEqual(diagnostic["frame_read_errors"], 1)
        self.assertEqual(diagnostic["frame_error_types"], ["RuntimeError"])
        serialized = json.dumps(diagnostic, ensure_ascii=False)
        self.assertNotIn("private-secret", serialized)
        self.assertNotIn("private-token", serialized)

    def test_dorm_stage_diagnostic_event_contains_safe_structured_context(self):
        from campus_net_assistant.edge import _emit_dorm_stage_diagnostic

        safe_diagnostic = {
            "frame_contexts": 2,
            "frame_reads_ok": 2,
            "page_roles": {"official-transition": 1, "official-service-selection": 1},
        }
        with (
            patch(
                "campus_net_assistant.edge._dorm_service_page_diagnostic",
                return_value=safe_diagnostic,
            ),
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            result = _emit_dorm_stage_diagnostic(
                "dorm-service-page-waiting",
                "仍在等待运营商控件",
                object(),
                "电信",
                launch_attempt=1,
                elapsed_seconds=12.3456,
                action_attempts=4,
            )

        self.assertEqual(result, safe_diagnostic)
        log_event.assert_called_once_with(
            "dorm-service-page-waiting",
            False,
            "仍在等待运营商控件",
            launch_attempt=1,
            elapsed_seconds=12.346,
            action_attempts=4,
            diagnostic=safe_diagnostic,
        )

    def test_dorm_stage_diagnostic_collection_failure_does_not_break_login(self):
        from campus_net_assistant.edge import _emit_dorm_stage_diagnostic

        with (
            patch(
                "campus_net_assistant.edge._dorm_service_page_diagnostic",
                side_effect=RuntimeError("token=private-token"),
            ),
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            result = _emit_dorm_stage_diagnostic(
                "dorm-service-page-waiting",
                "仍在等待运营商控件",
                object(),
                "电信",
                launch_attempt=1,
                elapsed_seconds=1,
                action_attempts=1,
            )

        self.assertEqual(
            result,
            {
                "diagnostic_collection_failed": True,
                "diagnostic_error_type": "RuntimeError",
            },
        )
        serialized = json.dumps(log_event.call_args.kwargs, ensure_ascii=False)
        self.assertNotIn("private-token", serialized)

    def test_dorm_login_finds_form_inside_child_frame_and_translates_click(self):
        from campus_net_assistant.edge import (
            _fill_dorm_credentials,
            _page_state,
            _submit_dorm_credentials,
        )

        class FrameClient:
            def __init__(self):
                self.mouse_calls = []
                self.evaluated_contexts = []

            def call_result(self, method, params=None):
                params = params or {}
                if method == "Page.getFrameTree":
                    return {
                        "frameTree": {
                            "frame": {
                                "id": "main",
                                "url": "http://202.195.176.60/portal/entry/pc/authenticate",
                            },
                            "childFrames": [
                                {
                                    "frame": {
                                        "id": "login-frame",
                                        "url": "http://202.195.176.60/portal/portal-main",
                                    }
                                }
                            ],
                        }
                    }
                if method == "Page.createIsolatedWorld":
                    return {
                        "executionContextId": 101
                        if params["frameId"] == "main"
                        else 202
                    }
                if method == "DOM.getFrameOwner":
                    self.assert_equal(params["frameId"], "login-frame")
                    return {"backendNodeId": 77}
                if method == "DOM.getBoxModel":
                    return {
                        "model": {
                            "content": [100, 200, 500, 200, 500, 500, 100, 500]
                        }
                    }
                raise AssertionError(method)

            def assert_equal(self, left, right):
                if left != right:
                    raise AssertionError(f"{left!r} != {right!r}")

            def evaluate(self, expression, *, context_id=None):
                self.evaluated_contexts.append(context_id)
                if "hasPassword" in expression:
                    return json.dumps(
                        {
                            "url": (
                                "http://202.195.176.60/portal/portal-main"
                                if context_id == 202
                                else "http://202.195.176.60/portal/entry/pc/authenticate"
                            ),
                            "hasPassword": context_id == 202,
                            "pageText": "账号登录" if context_id == 202 else "",
                        }
                    )
                if "const user=" in expression:
                    return json.dumps(
                        {"allowed": True, "value": context_id == 202}
                    )
                if "立即登录" in expression:
                    return json.dumps(
                        {
                            "allowed": True,
                            "value": (
                                json.dumps({"x": 12.5, "y": 23.25})
                                if context_id == 202
                                else "null"
                            ),
                        }
                    )
                raise AssertionError("unexpected expression")

            def call(self, method, params=None):
                if method != "Input.dispatchMouseEvent":
                    raise AssertionError(method)
                self.mouse_calls.append(params)

        client = FrameClient()
        state = _page_state(client)
        self.assertTrue(state["hasPassword"])
        self.assertEqual(state["frameCount"], 2)
        self.assertIn("账号登录", state["pageText"])
        self.assertTrue(_fill_dorm_credentials(client, "user", "secret"))
        self.assertTrue(_submit_dorm_credentials(client))
        self.assertIn(202, client.evaluated_contexts)
        self.assertEqual(
            [item["type"] for item in client.mouse_calls],
            ["mouseMoved", "mousePressed", "mouseReleased"],
        )
        self.assertEqual(client.mouse_calls[0]["x"], 112.5)
        self.assertEqual(client.mouse_calls[0]["y"], 223.25)

    def test_dorm_credentials_never_touch_an_unallowlisted_frame(self):
        from campus_net_assistant.edge import _fill_dorm_credentials, _submit_dorm_credentials

        class RejectedFrameClient:
            def __init__(self):
                self.mouse_calls = []
                self.expressions = []

            def evaluate(self, expression):
                self.expressions.append(expression)
                return json.dumps({"allowed": False, "value": None})

            def call(self, method, params=None):
                self.mouse_calls.append((method, params))

        client = RejectedFrameClient()
        self.assertFalse(_fill_dorm_credentials(client, "user", "secret"))
        self.assertFalse(_submit_dorm_credentials(client))
        self.assertFalse(client.mouse_calls)
        self.assertTrue(all("202.195.176.60" in expression for expression in client.expressions))
        self.assertTrue(all("hostOnly=true" in expression for expression in client.expressions))

    def test_manual_network_logout_pauses_monitor_without_logging_back_in(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        wlan = WlanInfo(
            "WLAN",
            "NJMU_WLAN",
            "192.0.2.10",
            "192.0.2.1",
            15,
            ("192.0.2.53",),
        )
        logout_result = {
            "success": True,
            "logout_confirmed_at": "2026-07-30T18:00:00.000+08:00",
            "probe_attempts": 2,
        }
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=True),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch(
                "campus_net_assistant.controller.logout_current_session",
                return_value=logout_result,
            ) as logout,
            patch(
                "campus_net_assistant.controller.suppress_monitor",
                return_value={"monitor_suppressed_until": "2026-07-30T18:05:00.000+08:00"},
            ) as suppress,
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(logout_network(config))

        self.assertEqual(logout.call_args.args[:2], (wlan.ip, wlan.dns_servers))
        self.assertTrue(callable(logout.call_args.args[2]))
        login.assert_not_called()
        suppress.assert_called_once_with(
            config,
            "manual-network-logout",
            300,
        )
        restart.assert_called_once_with()

    def test_manual_network_logout_supports_dorm_ethernet_without_login(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.ethernet import EthernetInfo

        config = AppConfig(connection_mode="dorm_ethernet")
        ethernet = EthernetInfo(
            "以太网",
            "Realtek PCIe GbE Family Controller",
            "192.0.2.62",
            "192.0.2.1",
            5,
            ("192.0.2.53",),
            25,
        )
        logout_result = {
            "success": True,
            "logout_confirmed_at": "2026-08-18T01:30:00.000+08:00",
            "probe_attempts": 2,
        }
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=True),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication"),
            patch("campus_net_assistant.controller.get_ethernet", return_value=ethernet),
            patch("campus_net_assistant.controller.get_wlan") as get_wlan,
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch(
                "campus_net_assistant.controller.logout_dorm_ethernet_session",
                return_value=logout_result,
            ) as logout,
            patch("campus_net_assistant.controller.logout_current_session") as wireless_logout,
            patch(
                "campus_net_assistant.controller.suppress_monitor",
                return_value={"monitor_suppressed_until": "2026-08-18T01:35:00.000+08:00"},
            ) as suppress,
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(logout_network(config))

        get_wlan.assert_not_called()
        self.assertEqual(logout.call_args.args[0], ethernet.ip)
        self.assertTrue(callable(logout.call_args.args[1]))
        wireless_logout.assert_not_called()
        login.assert_not_called()
        suppress.assert_called_once_with(
            config,
            "manual-network-logout",
            300,
        )

    def test_manual_network_logout_requires_an_online_session(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=False),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.arm_monitor"),
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.logout_current_session") as logout,
            patch("campus_net_assistant.controller.do_login", return_value=True) as login,
            patch("campus_net_assistant.controller._ensure_uu"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(logout_network(config))

        logout.assert_not_called()
        login.assert_not_called()
        restart.assert_not_called()

    def test_manual_network_logout_does_not_pause_when_logout_is_unconfirmed(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.edge import EdgeLoginError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=True),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch(
                "campus_net_assistant.controller.logout_current_session",
                side_effect=EdgeLoginError("logout-unconfirmed"),
            ),
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.suppress_monitor") as suppress,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(logout_network(config))

        login.assert_not_called()
        suppress.assert_not_called()
        restart.assert_called_once_with()

    def test_manual_login_validation_uses_primary_once_while_offline(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import validate_login
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=False),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller._manual_validation_preflight", return_value=True),
            patch("campus_net_assistant.controller.arm_monitor") as arm,
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.do_login", return_value=False) as login,
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(validate_login(config))
        arm.assert_not_called()
        login.assert_called_once_with(
            config,
            wait_seconds=60,
            require_submission=True,
            manual_validation=True,
        )
        restart.assert_not_called()

    def test_manual_login_validation_refuses_to_claim_success_when_already_online(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import validate_login
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig()
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=False),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.acquire_recovery_lock", return_value=nullcontext(True)),
            patch("campus_net_assistant.controller._selected_network", return_value=(wlan, "wireless")),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch("campus_net_assistant.controller._manual_validation_preflight") as preflight,
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(validate_login(config))

        preflight.assert_not_called()
        login.assert_not_called()
        restart.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "manual-login-validation-requires-offline")

    def test_successful_manual_login_clears_logout_pause_and_arms_monitor(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import validate_login

        config = AppConfig()
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=False),
            patch("campus_net_assistant.controller.acquire_recovery_lock", return_value=nullcontext(True)),
            patch("campus_net_assistant.controller._selected_network", return_value=(None, "wlan-unavailable")),
            patch("campus_net_assistant.controller._manual_validation_preflight", return_value=True),
            patch("campus_net_assistant.controller.do_login", return_value=True),
            patch("campus_net_assistant.controller.clear_monitor_suppression") as clear,
            patch("campus_net_assistant.controller.arm_monitor") as arm,
            patch("campus_net_assistant.controller._ensure_uu"),
            patch(
                "campus_net_assistant.controller.read_status",
                return_value={
                    "login_submitted_at": "2026-09-03T12:00:00+08:00",
                    "probe_succeeded_at": "2026-09-03T12:00:03+08:00",
                },
            ),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(validate_login(config))

        clear.assert_called_once_with(config, "manual-login-succeeded")
        arm.assert_called_once_with(config, "manual-login-validation")

    def test_workstation_login_authentication_keeps_existing_validation_flow(self):
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import validate_login

        config = AppConfig(connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=False),
            patch("campus_net_assistant.controller.acquire_recovery_lock", return_value=nullcontext(True)),
            patch("campus_net_assistant.controller.do_login", return_value=True) as login,
            patch("campus_net_assistant.controller.clear_monitor_suppression") as clear,
            patch("campus_net_assistant.controller.arm_monitor") as arm,
            patch("campus_net_assistant.controller._ensure_uu"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(validate_login(config))

        login.assert_called_once_with(
            config,
            wait_seconds=60,
            require_submission=True,
            manual_validation=True,
        )
        clear.assert_called_once_with(config, "manual-workstation-login-succeeded")
        arm.assert_called_once_with(config, "manual-workstation-native-login")

    def test_manual_reauthentication_ssid_mismatch_failure_keeps_passive_policy(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import reauthenticate
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig(wake_enabled=False, hibernate_enabled=False)
        wlan = WlanInfo("WLAN", "Other", "192.0.2.10", "192.0.2.1", 4)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication"),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication"),
            patch("campus_net_assistant.controller.arm_monitor") as arm,
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller.do_login", return_value=False),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(reauthenticate(config))
        arm.assert_not_called()

    def test_manual_reauthentication_refuses_other_ssid(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import reauthenticate
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig(wake_enabled=False, hibernate_enabled=False)
        wlan = WlanInfo("WLAN", "Other", "192.0.2.10", "192.0.2.1", 4)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication"),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication"),
            patch("campus_net_assistant.controller.arm_monitor") as arm,
            patch("campus_net_assistant.controller.get_wlan", return_value=wlan),
            patch("campus_net_assistant.controller.do_login", return_value=True),
            patch("campus_net_assistant.controller._ensure_uu"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(reauthenticate(config))
        arm.assert_not_called()

    def test_manual_reauthentication_does_not_logout_without_recovery_lock(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import reauthenticate

        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication"),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.arm_monitor"),
            patch(
                "campus_net_assistant.controller.acquire_recovery_lock",
                return_value=nullcontext(False),
            ),
            patch("campus_net_assistant.controller.get_wlan") as get_wlan,
            patch("campus_net_assistant.controller.logout_current_session") as logout,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(reauthenticate(AppConfig()))

        get_wlan.assert_not_called()
        logout.assert_not_called()
        restart.assert_called_once_with()

    def test_duplicate_monitor_process_exits_before_monitoring(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        with (
            patch(
                "campus_net_assistant.controller.acquire_monitor_lock",
                return_value=nullcontext(False),
            ),
            patch("campus_net_assistant.controller._monitor_locked") as monitor_locked,
            patch("campus_net_assistant.controller.event") as event,
        ):
            monitor(AppConfig(), once=True)

        monitor_locked.assert_not_called()
        self.assertEqual(event.call_args.args[0], "monitor-already-running")

    def test_edge_pages_treats_startup_connection_refusal_as_not_ready(self):
        import urllib.error

        from campus_net_assistant.edge import _pages, _pages_status

        with patch(
            "campus_net_assistant.edge.NO_PROXY_OPENER.open",
            side_effect=urllib.error.URLError(ConnectionRefusedError(10061, "refused")),
        ):
            self.assertEqual(_pages(9236), [])
            self.assertEqual(_pages_status(9236), (False, [], "connection-refused"))

    def test_edge_cdp_ports_are_auto_selected_distinct_and_released(self):
        import socket

        from campus_net_assistant.edge import _find_available_loopback_ports

        ports = _find_available_loopback_ports(2)
        self.assertEqual(len(ports), 2)
        self.assertEqual(len(set(ports)), 2)
        rebound = []
        try:
            for port in ports:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", port))
                listener.listen(1)
                rebound.append(listener)
        finally:
            for listener in rebound:
                listener.close()

    def test_explicit_edge_port_keeps_consecutive_retry_for_tests(self):
        from campus_net_assistant.edge import _select_edge_attempt_ports

        self.assertEqual(
            _select_edge_attempt_ports(49236),
            ((49236, 49237), "explicit"),
        )

    def test_saved_edge_ports_are_reused_when_still_usable(self):
        from campus_net_assistant.edge import _select_edge_attempt_ports

        with (
            patch("campus_net_assistant.edge._load_saved_edge_ports", return_value=(49236, 49317)),
            patch("campus_net_assistant.edge._saved_edge_ports_usable", return_value=True),
            patch("campus_net_assistant.edge._find_available_loopback_ports") as find_ports,
        ):
            self.assertEqual(
                _select_edge_attempt_ports(None),
                ((49236, 49317), "saved"),
            )
        find_ports.assert_not_called()

    def test_occupied_saved_edge_ports_are_reselected(self):
        from campus_net_assistant.edge import _select_edge_attempt_ports

        with (
            patch("campus_net_assistant.edge._load_saved_edge_ports", return_value=(49236, 49317)),
            patch("campus_net_assistant.edge._saved_edge_ports_usable", return_value=False),
            patch(
                "campus_net_assistant.edge._find_available_loopback_ports",
                return_value=(50123, 50456),
            ),
        ):
            self.assertEqual(
                _select_edge_attempt_ports(None),
                ((50123, 50456), "automatic-reselected"),
            )

    def test_edge_internal_page_is_navigated_to_current_portal(self):
        from campus_net_assistant.edge import _navigate_first_page

        calls = []

        class FakeCdp:
            def __init__(self, url):
                self.url = url

            def call(self, method, params=None):
                calls.append((method, params))

            def close(self):
                calls.append(("close", None))

        pages = [{
            "type": "page",
            "url": "edge://newtab/",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/internal",
        }]
        with (
            patch("campus_net_assistant.edge._pages", return_value=pages),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
        ):
            self.assertTrue(_navigate_first_page(9237, "https://portal.invalid/login"))
        self.assertIn(("Page.navigate", {"url": "https://portal.invalid/login"}), calls)
        self.assertIn(("close", None), calls)

    def test_cdp_websocket_explicitly_bypasses_proxy(self):
        from campus_net_assistant.edge import Cdp

        class FakeSocket:
            def close(self):
                pass

        with patch(
            "campus_net_assistant.edge.websocket.create_connection",
            return_value=FakeSocket(),
        ) as create_connection:
            client = Cdp("ws://127.0.0.1/devtools/page/1")
        create_connection.assert_called_once_with(
            "ws://127.0.0.1/devtools/page/1",
            timeout=8,
            http_no_proxy=["*"],
            suppress_origin=True,
        )
        client.close()

    def test_cdp_origin_rejection_is_explicit_and_not_transient(self):
        from campus_net_assistant import edge
        from campus_net_assistant.edge import Cdp, CdpHandshakeRejectedError, _transient_cdp_error

        rejected = edge.websocket.WebSocketBadStatusException(
            "Forbidden",
            status_code=403,
            status_message="Forbidden",
        )
        with patch(
            "campus_net_assistant.edge.websocket.create_connection",
            side_effect=rejected,
        ):
            with self.assertRaises(CdpHandshakeRejectedError) as raised:
                Cdp("ws://127.0.0.1/devtools/page/1")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertFalse(_transient_cdp_error(raised.exception))

    def test_portal_routes_use_wlan_dns_and_return_edge_host_mapping(self):
        from campus_net_assistant.edge import _add_routes

        completed = __import__("subprocess").CompletedProcess([], 0, "", "")
        with (
            patch(
                "campus_net_assistant.edge._resolve_from_wlan",
                side_effect=[["192.0.2.10"], ["192.0.2.11"]],
            ) as resolve,
            patch("campus_net_assistant.edge.subprocess.run", return_value=completed) as run,
        ):
            routes, mappings = _add_routes(
                ["portal.example", "complete.example"],
                "192.0.2.1",
                15,
                interface_ip="192.0.2.100",
                dns_servers=("192.0.2.53",),
            )
        self.assertEqual(routes, ["192.0.2.10", "192.0.2.11"])
        self.assertEqual(
            mappings,
            {"portal.example": "192.0.2.10", "complete.example": "192.0.2.11"},
        )
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(run.call_count, 2)

    def test_dorm_login_route_hosts_exclude_wireless_portal(self):
        from campus_net_assistant.edge import WIRELESS_PORTAL_HOST, _login_route_hosts

        hosts = _login_route_hosts("http://202.195.176.60/portal/entry/pc", False)

        self.assertEqual(hosts, ["202.195.176.60"])
        self.assertNotIn(WIRELESS_PORTAL_HOST, hosts)

    def test_wireless_login_route_hosts_keep_completion_portal(self):
        from campus_net_assistant.edge import WIRELESS_PORTAL_HOST, _login_route_hosts

        hosts = _login_route_hosts("http://portal.example/login", True)

        self.assertEqual(hosts, ["portal.example", WIRELESS_PORTAL_HOST])

    def test_portal_routes_accept_ipv4_literal_without_dns(self):
        from campus_net_assistant.edge import _add_routes

        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            patch("campus_net_assistant.edge._resolve_from_wlan") as resolve,
            patch("campus_net_assistant.edge.subprocess.run", return_value=completed) as run,
        ):
            routes, mappings = _add_routes(
                ["202.195.176.60"],
                "192.0.2.1",
                5,
                interface_ip="192.0.2.62",
                dns_servers=("198.51.100.53",),
            )

        self.assertEqual(routes, ["202.195.176.60"])
        self.assertEqual(mappings, {"202.195.176.60": "202.195.176.60"})
        resolve.assert_not_called()
        self.assertEqual(run.call_count, 1)

    def test_portal_route_failure_rolls_back_only_added_routes(self):
        from campus_net_assistant.edge import EdgeLoginError, _add_routes

        added = subprocess.CompletedProcess([], 0, "", "")
        failed = subprocess.CompletedProcess([], 1, "", "route failed")
        with (
            patch(
                "campus_net_assistant.edge._resolve_from_wlan",
                side_effect=[["192.0.2.10"], ["192.0.2.11"]],
            ),
            patch("campus_net_assistant.edge.subprocess.run", side_effect=[added, failed]),
            patch("campus_net_assistant.edge._delete_routes") as delete_routes,
        ):
            with self.assertRaises(EdgeLoginError):
                _add_routes(
                    ["portal.example", "complete.example"],
                    "192.0.2.1",
                    15,
                    interface_ip="192.0.2.100",
                    dns_servers=("192.0.2.53",),
                )

        delete_routes.assert_called_once_with(["192.0.2.10"], "192.0.2.1", 15)

    def test_portal_route_cleanup_is_scoped_to_gateway_and_interface(self):
        from campus_net_assistant.edge import _delete_routes

        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("campus_net_assistant.edge.subprocess.run", return_value=completed) as run:
            _delete_routes(["192.0.2.10"], "192.0.2.1", 15)

        self.assertEqual(
            run.call_args.args[0],
            [
                "route.exe",
                "delete",
                "192.0.2.10",
                "mask",
                "255.255.255.255",
                "192.0.2.1",
                "if",
                "15",
            ],
        )

    def test_login_url_discovery_follows_portal_location_like_fallback(self):
        from campus_net_assistant.edge import _discover_login_url

        with patch(
            "campus_net_assistant.edge._curl",
            side_effect=[
                "<meta http-equiv='refresh' content='0;url=http://portal.example/intermediate'>",
                "HTTP/1.1 302 Found\r\nLocation: https://login.example/form\r\n",
            ],
        ) as curl:
            result = _discover_login_url(
                "192.0.2.100",
                "http://www.msftconnecttest.com/connecttest.txt",
            )
        self.assertEqual(result, "https://login.example/form")
        self.assertEqual(curl.call_count, 2)
        self.assertTrue(curl.call_args_list[1].kwargs["headers"])

    def test_official_portal_allowlist_keeps_wireless_paths_and_dorm_origin(self):
        from campus_net_assistant.edge import (
            _credential_targets_allowed,
            _portal_navigation_path_observed,
            _portal_url_allowed,
        )

        self.assertTrue(
            _portal_url_allowed(
                "https://wlan.njmu.edu.cn/guest/wifi_login.php?session=redacted",
                False,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "https://wlan.njmu.edu.cn/new/official/transition?session=redacted",
                False,
            )
        )
        self.assertFalse(
            _portal_navigation_path_observed(
                "https://wlan.njmu.edu.cn/new/official/transition?session=redacted",
                False,
            )
        )
        self.assertFalse(
            _portal_url_allowed(
                "https://wlan.njmu.edu.cn/new/official/transition?session=redacted",
                False,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/cas-sso/login?service=redacted",
                True,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/portal/portal-main?sessionId=redacted",
                True,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/portal/entry/pc/authenticate;flowParams=undefined;from=",
                True,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/portal/entry/pc/terminalLoad",
                True,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/a/new/internal/login/route",
                True,
                credentials=True,
            )
        )
        self.assertTrue(
            _portal_url_allowed(
                "http://202.195.176.60/portal/entry/pc/serviceSelection",
                True,
            )
        )
        self.assertFalse(
            _portal_url_allowed("https://ruijie.njmu.edu.cn/login", False, credentials=True)
        )
        self.assertFalse(
            _portal_url_allowed("https://wlan.njmu.edu.cn/admin/login", False, credentials=True)
        )
        self.assertFalse(
            _portal_url_allowed("http://202.195.176.61/cas-sso/login", True, credentials=True)
        )
        self.assertTrue(
            _credential_targets_allowed(
                {
                    "url": "http://202.195.176.60/unobserved/transition",
                    "hasPassword": False,
                    "passwordUrls": [],
                },
                True,
            )
        )
        self.assertTrue(
            _credential_targets_allowed(
                {
                    "url": "https://transition.example/session",
                    "hasPassword": True,
                    "passwordUrls": ["http://202.195.176.60/a/new/internal/login/route"],
                },
                True,
            )
        )
        self.assertFalse(
            _credential_targets_allowed(
                {
                    "url": "https://transition.example/session",
                    "hasPassword": True,
                    "passwordUrls": ["https://evil.example/login"],
                },
                True,
            )
        )
        self.assertTrue(
            _credential_targets_allowed(
                {
                    "url": "https://transition.example/session",
                    "hasPassword": True,
                    "passwordUrls": ["https://wlan.njmu.edu.cn/guest/wifi_login.php"],
                },
                False,
            )
        )
        self.assertFalse(
            _credential_targets_allowed(
                {
                    "url": "https://transition.example/session",
                    "hasPassword": True,
                    "passwordUrls": ["https://evil.example/login"],
                },
                False,
            )
        )

    def test_login_url_discovery_follows_unlisted_intermediate_without_credentials(self):
        from campus_net_assistant.edge import _discover_login_url

        body = (
            "<meta http-equiv='refresh' "
            "content='0;url=https://transition.example/new/path?session=private'>"
        )
        headers = (
            "HTTP/1.1 302 Found\r\n"
            "Location: https://wlan.njmu.edu.cn/guest/wifi_login.php?session=private\r\n"
        )
        with (
            patch("campus_net_assistant.edge._curl", side_effect=[body, headers]) as curl,
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            result = _discover_login_url(
                "192.0.2.100",
                "http://www.msftconnecttest.com/connecttest.txt",
                dorm_ethernet_flow=False,
            )

        self.assertEqual(
            result,
            "https://wlan.njmu.edu.cn/guest/wifi_login.php?session=private",
        )
        self.assertEqual(curl.call_count, 2)
        self.assertEqual(log_event.call_args.args[0], "portal-navigation-allowlist-bypassed")
        self.assertEqual(log_event.call_args.kwargs["navigation_host"], "transition.example")
        self.assertEqual(log_event.call_args.kwargs["navigation_path"], "/new/path")
        self.assertNotIn("private", repr(log_event.call_args))

    def test_login_url_discovery_rejects_nonofficial_final_target(self):
        from campus_net_assistant.edge import PortalAllowlistError, _discover_login_url

        body = "<meta http-equiv='refresh' content='0;url=https://transition.example/start'>"
        headers = "HTTP/1.1 302 Found\r\nLocation: https://evil.example/login?session=private\r\n"
        with (
            patch("campus_net_assistant.edge._curl", side_effect=[body, headers]) as curl,
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            with self.assertRaisesRegex(PortalAllowlistError, "最终登录地址"):
                _discover_login_url(
                    "192.0.2.100",
                    "http://www.msftconnecttest.com/connecttest.txt",
                    dorm_ethernet_flow=False,
                )
        self.assertEqual(curl.call_count, 2)
        self.assertEqual(
            [call.args[0] for call in log_event.call_args_list],
            [
                "portal-navigation-allowlist-bypassed",
                "portal-navigation-allowlist-rejected",
            ],
        )
        self.assertNotIn("private", repr(log_event.call_args_list))

    def test_login_url_discovery_ignores_opaque_userurl_before_meta_refresh(self):
        from campus_net_assistant.edge import _discover_login_url

        body = (
            "<script>const query='userurl=354a4879&apmac=&nasid=abc';</script>"
            "<meta http-equiv='refresh' "
            "content='0; url=http%3A%2F%2Fportal.example%2Fintermediate%3Fa%3D1'>"
        )
        with patch(
            "campus_net_assistant.edge._curl",
            side_effect=[body, "HTTP/1.1 302 Found\r\nLocation: /login/form\r\n"],
        ) as curl:
            result = _discover_login_url("192.0.2.100", "http://check.example/connecttest.txt")

        self.assertEqual(result, "http://portal.example/login/form")
        self.assertEqual(curl.call_args_list[1].args[1], "http://portal.example/intermediate?a=1")

    def test_login_redirect_rejects_opaque_userurl_without_real_redirect(self):
        from campus_net_assistant.edge import EdgeLoginError, _extract_login_redirect

        with self.assertRaisesRegex(EdgeLoginError, "有效的登录跳转地址"):
            _extract_login_redirect(
                "<script>const query='userurl=354a4879&apmac=&nasid=abc';</script>",
                "http://check.example/connecttest.txt",
            )

    def test_portal_curl_error_does_not_expose_session_url(self):
        from campus_net_assistant.edge import EdgeLoginError, _curl

        secret_url = "http://portal.example/login?session=do-not-log-this"
        failure = subprocess.CalledProcessError(3, ["curl.exe", secret_url])
        with patch("campus_net_assistant.edge.subprocess.check_output", side_effect=failure):
            with self.assertRaises(EdgeLoginError) as raised:
                _curl("192.0.2.100", secret_url)

        self.assertIn("curl 退出码 3", str(raised.exception))
        self.assertNotIn("do-not-log-this", str(raised.exception))

    def test_edge_login_tolerates_launcher_exit_and_uses_fallback_form_rhythm(self):
        from campus_net_assistant.edge import login

        class FakeProcess:
            def __init__(self):
                self.waited = False

            def poll(self):
                # Chromium may hand work to another process and let the launcher
                # exit before the CDP page becomes visible.
                return 0

            def terminate(self):
                raise AssertionError("an exited launcher must not be terminated")

            def wait(self, timeout=None):
                self.waited = True
                return 0

            def kill(self):
                raise AssertionError("an exited launcher must not be killed")

        class FakeCdp:
            def __init__(self, _url):
                self.closed = False
                self.browser_closed = False

            def call(self, method, _params=None):
                if method == "Browser.close":
                    self.browser_closed = True

            def close(self):
                self.closed = True

        fake_process = FakeProcess()
        page = {
            "type": "page",
            "url": "https://wlan.njmu.edu.cn/guest/wifi_login.php",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
        }
        not_ready = (None, {"cdp_reachable": False, "page_count": 0, "cdp_reason": "connection-refused"})
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        probe_results = iter([False, False, False, False, True])
        submissions = []
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=fake_process) as popen,
            patch("campus_net_assistant.edge._load_saved_edge_ports", return_value=None),
            patch(
                "campus_net_assistant.edge._find_available_loopback_ports",
                return_value=(49236, 49317),
            ) as select_ports,
            patch("campus_net_assistant.edge._save_edge_ports", return_value=True) as save_ports,
            patch(
                "campus_net_assistant.edge._portal_page_status",
                side_effect=[not_ready, ready, ready, ready],
            ) as page_query,
            patch("campus_net_assistant.edge._portal_page", return_value=page),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
            patch(
                "campus_net_assistant.edge._page_state",
                return_value={
                    "url": "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                    "hasPassword": True,
                    "pageText": "",
                },
            ),
            patch(
                "campus_net_assistant.edge._fill_form",
                return_value={"filled": True, "operatorMatched": True},
            ) as fill,
            patch("campus_net_assistant.edge._submit_form", return_value=True) as submit,
            patch("campus_net_assistant.edge.append_connectivity_event"),
            patch("campus_net_assistant.edge.event"),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = login(
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "user@ctcc",
                "secret",
                "电信",
                probe=lambda: next(probe_results),
                wait_seconds=5,
                edge_profile_root=Path(temp_profile) / "profile",
                submission_callback=submissions.append,
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["edge_launch_attempt"], 1)
        select_ports.assert_called_once_with(2)
        save_ports.assert_called_once_with((49236, 49317))
        self.assertEqual(page_query.call_count, 4)
        fill.assert_called_once()
        self.assertEqual(fill.call_args.args[1:], ("user", "secret", "电信"))
        submit.assert_called_once()
        self.assertEqual(len(submissions), 1)
        self.assertFalse(fake_process.waited)
        self.assertIsNotNone(result["edge_ready_seconds"])
        self.assertTrue(result["login_page_retained"])
        self.assertIn("--no-proxy-server", popen.call_args.args[0])
        self.assertIn("--window-size=900,700", popen.call_args.args[0])
        self.assertIn("--new-window", popen.call_args.args[0])
        self.assertIn("--remote-debugging-port=49236", popen.call_args.args[0])
        self.assertNotIn("--disable-gpu", popen.call_args.args[0])
        self.assertNotIn("--headless=new", popen.call_args.args[0])

    def test_dorm_edge_login_submits_credentials_then_service_confirmation(self):
        from campus_net_assistant.edge import login

        class FakeProcess:
            def __init__(self):
                self.running = True

            def poll(self):
                return None if self.running else 0

            def terminate(self):
                self.running = False

            def wait(self, timeout=None):
                self.running = False
                return 0

            def kill(self):
                self.running = False

        class FakeCdp:
            def __init__(self, _url):
                self.closed = False

            def call(self, _method, _params=None):
                return None

            def close(self):
                self.closed = True

        fake_process = FakeProcess()
        page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/entry/pc/authenticate",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
        }
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        confirmation_clicked = False

        def click_confirmation(_client):
            nonlocal confirmation_clicked
            confirmation_clicked = True
            return True

        def probe():
            return confirmation_clicked

        submissions = []
        page_states = [
            {
                "url": page["url"],
                "hasPassword": True,
                "passwordUrls": [
                    "http://202.195.176.60/portal/portal-main?sessionId=redacted",
                    "http://202.195.176.60/portal/entry/pc/terminalLoad",
                ],
                "pageText": "",
            },
            {
                "url": page["url"],
                "hasPassword": True,
                "passwordUrls": [
                    "http://202.195.176.60/portal/portal-main?sessionId=redacted",
                    "http://202.195.176.60/portal/entry/pc/terminalLoad",
                ],
                "pageText": "",
            },
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
        ]
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=fake_process),
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
            patch("campus_net_assistant.edge._page_state", side_effect=page_states),
            patch("campus_net_assistant.edge._fill_dorm_credentials", return_value=True) as fill,
            patch("campus_net_assistant.edge._submit_dorm_credentials", return_value=True) as credentials,
            patch("campus_net_assistant.edge._select_dorm_operator", return_value=True) as service,
            patch("campus_net_assistant.edge._click_dorm_confirmation", side_effect=click_confirmation) as confirm,
            patch("campus_net_assistant.edge._fill_form") as wireless_fill,
            patch("campus_net_assistant.edge._submit_form") as wireless_submit,
            patch("campus_net_assistant.edge.append_connectivity_event"),
            patch("campus_net_assistant.edge.event") as log_event,
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = login(
                "http://202.195.176.60/portal/entry/pc/authenticate",
                "user",
                "secret",
                "电信",
                probe=probe,
                wait_seconds=5,
                dorm_ethernet_flow=True,
                include_wireless_portal_host=False,
                keep_page_open=False,
                edge_profile_root=Path(temp_profile) / "profile",
                edge_port=49236,
                submission_callback=submissions.append,
            )

        self.assertTrue(result["success"])
        self.assertIsNotNone(result["login_submitted_at"])
        fill.assert_called_once_with(ANY, "user", "secret")
        credentials.assert_called_once()
        service.assert_called_once_with(ANY, "电信")
        confirm.assert_called_once()
        self.assertEqual(len(submissions), 1)
        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertLess(stages.index("dorm-login-click-dispatched"), stages.index("dorm-credentials-submitted"))
        self.assertLess(stages.index("dorm-credentials-submitted"), stages.index("dorm-service-selected"))
        submitted_call = next(call for call in log_event.call_args_list if call.args[0] == "dorm-credentials-submitted")
        self.assertTrue(submitted_call.kwargs["transition_verified"])
        wireless_fill.assert_not_called()
        wireless_submit.assert_not_called()

    def test_dorm_edge_login_logs_waiting_and_timeout_when_service_never_appears(self):
        from campus_net_assistant.edge import LoginOutcomeUnknownError, login

        class FakeProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        class FakeCdp:
            def __init__(self, _url):
                return None

            def call(self, _method, _params=None):
                return None

            def close(self):
                return None

        class Clock:
            def __init__(self, step):
                self.value = 0.0
                self.step = step

            def tick(self):
                self.value += self.step
                return self.value

        page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/entry/pc/authenticate",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
        }
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        credential_state = {
            "url": page["url"],
            "hasPassword": True,
            "passwordUrls": ["http://202.195.176.60/portal/portal-main"],
            "pageText": "",
        }
        service_state = {
            "url": "http://202.195.176.60/portal/entry/pc/serviceSelection",
            "hasPassword": False,
            "passwordUrls": [],
            "pageText": "",
        }
        state_reads = 0

        def page_state(_client):
            nonlocal state_reads
            state_reads += 1
            return credential_state if state_reads <= 2 else service_state

        wall_clock = Clock(0.25)
        monotonic_clock = Clock(0.25)
        safe_diagnostic = {
            "frame_contexts": 1,
            "frame_reads_ok": 1,
            "page_roles": {"official-service-selection": 1},
            "operatorVisibleCandidates": 0,
        }
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=FakeProcess()),
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
            patch("campus_net_assistant.edge._page_state", side_effect=page_state),
            patch("campus_net_assistant.edge._fill_dorm_credentials", return_value=True),
            patch("campus_net_assistant.edge._submit_dorm_credentials", return_value=True),
            patch("campus_net_assistant.edge._select_dorm_operator", return_value=False),
            patch(
                "campus_net_assistant.edge._dorm_service_page_diagnostic",
                return_value=safe_diagnostic,
            ),
            patch("campus_net_assistant.edge.event") as log_event,
            patch("campus_net_assistant.edge.time.time", side_effect=wall_clock.tick),
            patch("campus_net_assistant.edge.time.monotonic", side_effect=monotonic_clock.tick),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            with self.assertRaises(LoginOutcomeUnknownError):
                login(
                    "http://202.195.176.60/portal/entry/pc/authenticate",
                    "user",
                    "secret",
                    "电信",
                    probe=lambda: False,
                    wait_seconds=5,
                    dorm_ethernet_flow=True,
                    include_wireless_portal_host=False,
                    keep_page_open=False,
                    edge_profile_root=Path(temp_profile) / "profile",
                    edge_port=49236,
                )

        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertIn("dorm-service-page-waiting", stages)
        self.assertIn("dorm-service-selection-timeout", stages)
        self.assertNotIn("dorm-confirmation-timeout", stages)
        timeout_call = next(
            call for call in log_event.call_args_list
            if call.args[0] == "dorm-service-selection-timeout"
        )
        self.assertEqual(timeout_call.kwargs["diagnostic"], safe_diagnostic)

    def test_dorm_login_click_is_not_submission_until_password_page_disappears(self):
        from campus_net_assistant.edge import LoginOutcomeUnknownError, login

        class FakeProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        class FakeCdp:
            def __init__(self, _url):
                return None

            def call(self, _method, _params=None):
                return None

            def close(self):
                return None

        class Clock:
            def __init__(self, step):
                self.value = 0.0
                self.step = step

            def tick(self):
                self.value += self.step
                return self.value

        page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/entry/pc/authenticate",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
        }
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        credential_state = {
            "url": page["url"],
            "hasPassword": True,
            "passwordUrls": ["http://202.195.176.60/portal/portal-main"],
            "pageText": "",
        }
        wall_clock = Clock(0.25)
        monotonic_clock = Clock(0.25)
        submissions = []
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=FakeProcess()),
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
            patch("campus_net_assistant.edge._page_state", return_value=credential_state),
            patch("campus_net_assistant.edge._fill_dorm_credentials", return_value=True),
            patch(
                "campus_net_assistant.edge._submit_dorm_credentials",
                return_value={
                    "recognized_label": "点击登录",
                    "match_strategy": "exact-login-label",
                    "control_tag": "button",
                    "control_type": "button",
                },
            ),
            patch("campus_net_assistant.edge._dorm_service_page_diagnostic", return_value={"visiblePasswordFields": 1}),
            patch("campus_net_assistant.edge._select_dorm_operator") as select_operator,
            patch("campus_net_assistant.edge.event") as log_event,
            patch("campus_net_assistant.edge.time.time", side_effect=wall_clock.tick),
            patch("campus_net_assistant.edge.time.monotonic", side_effect=monotonic_clock.tick),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            with self.assertRaises(LoginOutcomeUnknownError):
                login(
                    page["url"],
                    "user",
                    "secret",
                    "电信",
                    probe=lambda: False,
                    wait_seconds=5,
                    dorm_ethernet_flow=True,
                    include_wireless_portal_host=False,
                    keep_page_open=False,
                    edge_profile_root=Path(temp_profile) / "profile",
                    edge_port=49236,
                    submission_callback=submissions.append,
                )

        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertIn("dorm-login-click-dispatched", stages)
        self.assertIn("dorm-login-transition-waiting", stages)
        self.assertIn("dorm-login-transition-timeout", stages)
        self.assertNotIn("dorm-credentials-submitted", stages)
        self.assertNotIn("dorm-service-page-waiting", stages)
        self.assertNotIn("dorm-service-selection-timeout", stages)
        select_operator.assert_not_called()
        self.assertEqual(len(submissions), 1)

    def test_portal_form_fill_supports_select_radio_and_clickable_operator_controls(self):
        from campus_net_assistant.edge import _fill_form

        class FakeCdp:
            expression = ""

            def evaluate(self, expression):
                self.expression = expression
                return json.dumps(
                    {
                        "filled": True,
                        "operatorMatched": True,
                        "operatorStrategy": "select",
                    }
                )

        client = FakeCdp()
        result = _fill_form(client, "user", "secret", "电信")
        self.assertTrue(result["filled"])
        self.assertTrue(result["operatorMatched"])
        self.assertIn("ctcc", client.expression)
        self.assertIn("HTMLSelectElement", client.expression)
        self.assertIn("radio", client.expression)
        self.assertIn("clickable-label", client.expression)

    def test_edge_login_closes_automation_browser_when_page_retention_is_disabled(self):
        from campus_net_assistant.edge import login

        class FakeProcess:
            def __init__(self):
                self.waited = False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                self.waited = True
                return 0

        class FakeCdp:
            instances = []

            def __init__(self, _url):
                self.closed = False
                self.browser_closed = False
                self.__class__.instances.append(self)

            def call(self, method, _params=None):
                if method == "Browser.close":
                    self.browser_closed = True

            def close(self):
                self.closed = True

        fake_process = FakeProcess()
        page = {
            "type": "page",
            "url": "https://wlan.njmu.edu.cn/guest/wifi_login.php",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
        }
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        probe_results = iter([False, False, False, False, True])
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=fake_process) as popen,
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeCdp),
            patch(
                "campus_net_assistant.edge._page_state",
                return_value={"url": page["url"], "hasPassword": True, "pageText": ""},
            ),
            patch(
                "campus_net_assistant.edge._fill_form",
                return_value={"filled": True, "operatorMatched": True},
            ),
            patch("campus_net_assistant.edge._submit_form", return_value=True),
            patch("campus_net_assistant.edge.append_connectivity_event"),
            patch("campus_net_assistant.edge.event"),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = login(
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "user",
                "secret",
                "电信",
                probe=lambda: next(probe_results),
                wait_seconds=5,
                keep_page_open=False,
                edge_profile_root=Path(temp_profile) / "profile",
                edge_port=49236,
            )
        self.assertTrue(result["success"])
        self.assertFalse(result["login_page_retained"])
        self.assertTrue(fake_process.waited)
        self.assertTrue(FakeCdp.instances[-1].browser_closed)
        self.assertTrue(FakeCdp.instances[-1].closed)
        self.assertIn("--headless=new", popen.call_args.args[0])

    def test_background_monitor_honors_once_flag(self):
        from campus_net_assistant.cli import _background
        from campus_net_assistant.config import AppConfig

        config = AppConfig()
        with (
            patch("campus_net_assistant.cli.load_config", return_value=config),
            patch("campus_net_assistant.cli.monitor") as monitor,
        ):
            self.assertEqual(_background("monitor", once=True), 0)
        monitor.assert_called_once_with(config, once=True)

    def test_edge_login_relaunches_when_first_attempt_never_exposes_cdp(self):
        from campus_net_assistant.edge import login

        class ExitedProcess:
            def __init__(self):
                self.waited = False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                self.waited = True
                return 0

        clock = {"value": 0}

        def fake_time():
            clock["value"] += 5
            return clock["value"]

        processes = [ExitedProcess(), ExitedProcess()]
        page = {
            "type": "page",
            "url": "https://wlan.njmu.edu.cn/guest/wifi_login.php",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/2",
        }
        not_ready = (None, {"cdp_reachable": False, "page_count": 0, "cdp_reason": "connection-refused"})
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        probe_results = iter([False, False, False, False, True])
        with (
            tempfile.TemporaryDirectory() as temp_profile,
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", side_effect=processes) as popen,
            patch("campus_net_assistant.edge._load_saved_edge_ports", return_value=None),
            patch(
                "campus_net_assistant.edge._find_available_loopback_ports",
                return_value=(49236, 49317),
            ) as select_ports,
            patch(
                "campus_net_assistant.edge._portal_page_status",
                side_effect=[not_ready, not_ready, not_ready, ready],
            ),
            patch("campus_net_assistant.edge.event"),
            patch("campus_net_assistant.edge.time.time", side_effect=fake_time),
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = login(
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "user",
                "secret",
                "电信",
                probe=lambda: next(probe_results),
                wait_seconds=120,
                edge_profile_root=Path(temp_profile) / "profile",
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["edge_launch_attempt"], 2)
        select_ports.assert_called_once_with(2)
        self.assertEqual(popen.call_count, 2)
        self.assertTrue(all(process.waited for process in processes))
        self.assertIn("--remote-debugging-port=49236", popen.call_args_list[0].args[0])
        self.assertIn("--remote-debugging-port=49317", popen.call_args_list[1].args[0])
        self.assertTrue(any("profile-retry" in argument for argument in popen.call_args_list[1].args[0]))

    def test_recovery_stops_for_paused_states(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        for stage in (
            "wifi-not-visible",
            "ethernet-unavailable",
            "authentication-paused",
            "portal-allowlist-blocked",
        ):
            with self.subTest(stage=stage):
                with (
                    patch("campus_net_assistant.controller.do_login", return_value=False),
                    patch("campus_net_assistant.controller._active_recovery_config", side_effect=lambda config, mode: config),
                    patch("campus_net_assistant.controller.read_status", return_value={"stage": stage}),
                    patch("campus_net_assistant.controller._restart_wlan") as restart,
                    patch("campus_net_assistant.controller.event"),
                    patch("campus_net_assistant.controller.write_status") as write_status,
                ):
                    self.assertFalse(_recover(AppConfig(), 20, "Monitor"))
                    restart.assert_not_called()
                    self.assertFalse(
                        any(
                            call.args and call.args[0] == "primary-recovery-failed"
                            for call in write_status.call_args_list
                        )
                    )

    def test_monitor_rechecks_window_before_finishing_failed_recovery(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        config = AppConfig()
        with (
            patch("campus_net_assistant.controller.do_login", return_value=False),
            patch("campus_net_assistant.controller.load_config", return_value=config),
            patch("campus_net_assistant.controller._in_monitor_window", side_effect=[True, False]),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller.time.sleep") as sleep,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(_recover(config, 0, "Monitor"))
        sleep.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "monitor-outside-window")

    def test_primary_failure_returns_to_monitor_without_external_fallback(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        config = AppConfig()
        with (
            patch("campus_net_assistant.controller.do_login", return_value=False),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller.time.sleep") as sleep,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(_recover(config, 0, "Morning"))
        sleep.assert_not_called()

    def test_concurrent_recovery_is_skipped_before_login(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        with (
            patch("campus_net_assistant.controller.acquire_recovery_lock", return_value=nullcontext(False)),
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.os.getpid", return_value=4321),
            patch("campus_net_assistant.controller.event") as log_event,
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(_recover(AppConfig(), 0, "Monitor"))
        login.assert_not_called()
        write_status.assert_not_called()
        log_event.assert_called_once_with(
            "recovery-already-running",
            True,
            "另一个程序进程正在执行联网恢复，本监测轮次跳过重复登录",
            mode="Monitor",
            waiting_process_id=4321,
        )

    def test_morning_waits_for_existing_recovery_and_accepts_online_result(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import (
            MORNING_RECOVERY_HANDOFF_WAIT_SECONDS,
            _recover,
        )

        with (
            patch(
                "campus_net_assistant.controller.acquire_recovery_lock",
                side_effect=[nullcontext(False), nullcontext(True)],
            ) as recovery_lock,
            patch("campus_net_assistant.controller.os.getpid", return_value=5432),
            patch("campus_net_assistant.controller._online", return_value=True) as online,
            patch(
                "campus_net_assistant.controller.read_status",
                return_value={"stage": "login-and-probe"},
            ),
            patch("campus_net_assistant.controller.do_login") as login,
            patch("campus_net_assistant.controller.event") as log_event,
        ):
            self.assertTrue(_recover(AppConfig(), 0, "Morning"))

        login.assert_not_called()
        online.assert_called_once()
        self.assertEqual(
            recovery_lock.call_args_list[1].kwargs["timeout_ms"],
            MORNING_RECOVERY_HANDOFF_WAIT_SECONDS * 1000,
        )
        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertEqual(stages, ["recovery-handoff-waiting", "recovery-handoff-succeeded"])
        self.assertEqual(log_event.call_args.kwargs["waiting_process_id"], 5432)
        self.assertEqual(log_event.call_args.kwargs["observed_recovery_stage"], "login-and-probe")

    def test_morning_waits_for_existing_recovery_and_preserves_failure_stage(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        with (
            patch(
                "campus_net_assistant.controller.acquire_recovery_lock",
                side_effect=[nullcontext(False), nullcontext(True)],
            ),
            patch("campus_net_assistant.controller._online", return_value=False),
            patch(
                "campus_net_assistant.controller.read_status",
                return_value={"stage": "dorm-service-selection-timeout"},
            ),
            patch("campus_net_assistant.controller.write_status") as write_status,
            patch("campus_net_assistant.controller.event") as log_event,
        ):
            self.assertFalse(_recover(AppConfig(), 0, "Morning"))

        write_status.assert_not_called()
        self.assertEqual(log_event.call_args.args[0], "recovery-handoff-finished-offline")
        self.assertEqual(
            log_event.call_args.kwargs["observed_recovery_stage"],
            "dorm-service-selection-timeout",
        )

    def test_morning_handoff_timeout_does_not_overwrite_active_recovery(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        with (
            patch(
                "campus_net_assistant.controller.acquire_recovery_lock",
                side_effect=[nullcontext(False), nullcontext(False)],
            ),
            patch(
                "campus_net_assistant.controller.read_status",
                return_value={"stage": "dorm-service-page-waiting"},
            ),
            patch("campus_net_assistant.controller.write_status") as write_status,
            patch("campus_net_assistant.controller.event") as log_event,
        ):
            self.assertIsNone(_recover(AppConfig(), 0, "Morning"))

        write_status.assert_not_called()
        self.assertEqual(log_event.call_args.args[0], "recovery-handoff-timeout")
        self.assertEqual(
            log_event.call_args.kwargs["observed_recovery_stage"],
            "dorm-service-page-waiting",
        )

    def test_second_failed_recovery_does_not_restart_wlan_yet(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        config = AppConfig()
        with (
            patch("campus_net_assistant.controller.do_login", return_value=False),
            patch("campus_net_assistant.controller._active_recovery_config", side_effect=lambda current, mode: current),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller._restart_wlan") as restart,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(_recover(config, 2, "Monitor"))
        restart.assert_not_called()

    def test_third_failed_recovery_restarts_wlan_and_retries(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        config = AppConfig()
        with (
            patch("campus_net_assistant.controller.do_login", side_effect=[False, False]) as login,
            patch("campus_net_assistant.controller._active_recovery_config", side_effect=lambda current, mode: current),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller._restart_wlan", return_value=True) as restart,
            patch("campus_net_assistant.controller.event") as log_event,
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(_recover(config, 3, "Monitor"))
        restart.assert_called_once_with(config.wlan_interface, config.portal.ssid)
        self.assertEqual(login.call_count, 2)
        threshold_events = [
            call for call in log_event.call_args_list
            if call.args and call.args[0] == "wlan-restart-threshold"
        ]
        self.assertEqual(len(threshold_events), 1)
        self.assertEqual(threshold_events[0].kwargs["threshold"], 2)
        self.assertEqual(threshold_events[0].kwargs["recovery_attempts"], 3)

    def test_dorm_ethernet_recovery_never_restarts_wlan(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _recover

        config = AppConfig(connection_mode="dorm_ethernet")
        with (
            patch("campus_net_assistant.controller.do_login", return_value=False) as login,
            patch("campus_net_assistant.controller._active_recovery_config", side_effect=lambda current, mode: current),
            patch("campus_net_assistant.controller.read_status", return_value={"stage": "primary-login-failed"}),
            patch("campus_net_assistant.controller._restart_wlan") as restart,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(_recover(config, 20, "Monitor"))
        login.assert_called_once_with(config, wait_seconds=30)
        restart.assert_not_called()

    def test_wake_coordinator_only_dispatches_to_monitor(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import run_wake_coordinator

        with (
            patch("campus_net_assistant.controller.prune"),
            patch("campus_net_assistant.controller.arm_monitor"),
            patch(
                "campus_net_assistant.controller.create_wake_request",
                return_value={"id": "wake-1"},
            ),
            patch("campus_net_assistant.controller.signal_wake_monitor", return_value=True),
            patch(
                "campus_net_assistant.controller.wait_for_wake_result",
                return_value={"id": "wake-1", "success": True},
            ),
            patch("campus_net_assistant.controller.keep_system_awake", return_value=nullcontext()),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
            patch("campus_net_assistant.controller._start_monitor_task") as start_monitor,
            patch("campus_net_assistant.controller._online") as online,
            patch("campus_net_assistant.controller._recover") as recover,
        ):
            self.assertTrue(run_wake_coordinator(AppConfig(wake_enabled=True)))
        start_monitor.assert_called_once_with("wake-coordinator")
        online.assert_not_called()
        recover.assert_not_called()

    def test_legacy_morning_entry_uses_wake_coordinator(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import run_morning

        with (
            patch("campus_net_assistant.controller.run_wake_coordinator", return_value=True) as coordinator,
            patch("campus_net_assistant.controller.event"),
        ):
            self.assertTrue(run_morning(AppConfig(wake_enabled=True)))
        coordinator.assert_called_once()

    def test_monitor_executes_wake_recovery_for_all_connection_modes(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _process_wake_request

        for connection_mode in ("wireless", "dorm_ethernet", "workstation_ruijie"):
            with self.subTest(connection_mode=connection_mode):
                config = AppConfig(connection_mode=connection_mode)
                request = {"id": f"wake-{connection_mode}", "source": "wake-task"}
                with (
                    patch("campus_net_assistant.controller.mark_wake_request_running", return_value=True),
                    patch("campus_net_assistant.controller._online", return_value=False),
                    patch("campus_net_assistant.controller._recover", return_value=True) as recover,
                    patch(
                        "campus_net_assistant.controller.read_status",
                        return_value={
                            "stage": "primary-login-succeeded",
                            "probe_succeeded_at": "2026-09-16T09:00:05+08:00",
                        },
                    ),
                    patch("campus_net_assistant.controller.save_morning_online_baseline") as baseline,
                    patch("campus_net_assistant.controller.append_connectivity_event"),
                    patch("campus_net_assistant.controller.complete_wake_request") as complete,
                    patch("campus_net_assistant.controller._ensure_uu"),
                    patch("campus_net_assistant.controller.event"),
                    patch("campus_net_assistant.controller.write_status"),
                ):
                    self.assertTrue(_process_wake_request(config, request))
                recover.assert_called_once_with(config, 0, "Wake")
                baseline.assert_called_once()
                complete.assert_called_once_with(
                    request["id"],
                    True,
                    "唤醒后认证及真实联网探测成功",
                )

    def test_monitor_defers_ordinary_recovery_until_wake_request(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        config = AppConfig(wake_enabled=True)
        state = {"armed": True, "policy": "active", "source": "test"}
        with (
            patch("campus_net_assistant.controller.prune"),
            patch("campus_net_assistant.controller.load_config", return_value=config),
            patch("campus_net_assistant.controller.load_monitor_state", return_value=state),
            patch("campus_net_assistant.controller._in_monitor_window", return_value=True),
            patch("campus_net_assistant.controller.open_wake_request", return_value=None),
            patch("campus_net_assistant.controller.create_fallback_request_if_due", return_value=None),
            patch(
                "campus_net_assistant.controller._monitor_probe",
                return_value=(False, "microsoft-connect-test", 2),
            ),
            patch("campus_net_assistant.controller._should_recover", return_value=True),
            patch("campus_net_assistant.controller.wake_priority_delay_seconds", return_value=75),
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
            patch(
                "campus_net_assistant.controller.wait_for_monitor_signal",
                side_effect=RuntimeError("stop-at-wake-gate"),
            ) as wait,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop-at-wake-gate"):
                monitor(config)
        recover.assert_not_called()
        wait.assert_called_once_with(75)

    def test_wake_coordination_priority_and_fallback_are_date_scoped(self):
        from campus_net_assistant import wake_coordination

        app_dir = ROOT / "test-wake-coordination"
        app_dir.mkdir(exist_ok=True)
        try:
            state_path = app_dir / "wake-coordination.json"
            with (
                patch.object(wake_coordination, "APP_DIR", app_dir),
                patch.object(wake_coordination, "STATE_PATH", state_path),
            ):
                base = datetime.now().astimezone().replace(
                    year=2026,
                    month=9,
                    day=16,
                    hour=8,
                    minute=55,
                    second=0,
                    microsecond=0,
                )
                self.assertEqual(
                    wake_coordination.priority_delay_seconds("09:00", base),
                    600,
                )
                fallback = wake_coordination.create_fallback_request_if_due(
                    "09:00", base.replace(hour=9, minute=6)
                )
                self.assertIsNotNone(fallback)
                self.assertEqual(fallback["source"], "monitor-fallback")
                self.assertEqual(
                    wake_coordination.priority_delay_seconds("09:00", base),
                    0,
                )
                self.assertTrue(
                    wake_coordination.complete_request(
                        fallback["id"], True, "ok", base.replace(hour=9, minute=7)
                    )
                )
                self.assertTrue(wake_coordination.result(fallback["id"])["success"])
                repeated = wake_coordination.create_request(
                    "wake-task", base.replace(hour=9, minute=8)
                )
                self.assertNotEqual(repeated["id"], fallback["id"])
                self.assertEqual(repeated["status"], "pending")
                self.assertIsNone(wake_coordination.result(repeated["id"]))
        finally:
            (app_dir / "wake-coordination.json").unlink(missing_ok=True)
            (app_dir / "wake-coordination.tmp").unlink(missing_ok=True)
            app_dir.rmdir()

    def test_start_monitor_task_runs_registered_task(self):
        import subprocess

        from campus_net_assistant.controller import _start_monitor_task

        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            patch("campus_net_assistant.controller.subprocess.run", return_value=completed) as run,
            patch("campus_net_assistant.controller.event"),
        ):
            self.assertTrue(_start_monitor_task())
        self.assertEqual(
            run.call_args.args[0],
            ["schtasks.exe", "/Run", "/TN", "NJMUCampusNetAssistant-Monitor"],
        )

    def test_manual_network_logout_requests_elevated_hidden_entrypoint(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import logout_network_with_elevation

        config = AppConfig()
        with (
            patch("campus_net_assistant.scheduler.is_admin", return_value=False),
            patch("campus_net_assistant.scheduler.os.name", "nt"),
            patch("campus_net_assistant.scheduler._run_elevated", return_value=0) as run_elevated,
        ):
            self.assertTrue(logout_network_with_elevation(config))
        run_elevated.assert_called_once_with("--manual-logout", 300000)

    def test_manual_login_validation_requests_its_own_elevated_entrypoint(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import validate_login_with_elevation

        config = AppConfig()
        with (
            patch("campus_net_assistant.scheduler.is_admin", return_value=False),
            patch("campus_net_assistant.scheduler.os.name", "nt"),
            patch("campus_net_assistant.scheduler._run_elevated", return_value=0) as run_elevated,
        ):
            self.assertTrue(validate_login_with_elevation(config))
        run_elevated.assert_called_once_with("--manual-login-validate", 300000)

    def test_admin_gui_can_logout_without_spawning_another_process(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.scheduler import logout_network_with_elevation

        config = AppConfig()
        with (
            patch("campus_net_assistant.scheduler.is_admin", return_value=True),
            patch("campus_net_assistant.controller.logout_network", return_value=True) as logout_network,
            patch("campus_net_assistant.scheduler._run_elevated") as run_elevated,
        ):
            self.assertTrue(logout_network_with_elevation(config))
        logout_network.assert_called_once_with(config)
        run_elevated.assert_not_called()

    def test_frozen_elevated_command_reuses_same_executable(self):
        from campus_net_assistant.scheduler import _elevated_command

        executable = r"D:\Apps\CampusNetAssistant\CampusNetAssistant.exe"
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "executable", executable),
        ):
            command = _elevated_command("--manual-logout")
        self.assertEqual(
            command,
            (
                executable,
                "--manual-logout",
                r"D:\Apps\CampusNetAssistant",
            ),
        )

    def test_manual_network_logout_cli_returns_real_exit_code(self):
        from campus_net_assistant.cli import main
        from campus_net_assistant.config import AppConfig

        with (
            patch.object(sys, "argv", ["CampusNetAssistant", "--manual-logout"]),
            patch("campus_net_assistant.cli.load_config", return_value=AppConfig()),
            patch("campus_net_assistant.cli.logout_network", return_value=True) as logout_network,
            patch("campus_net_assistant.cli.event"),
        ):
            with self.assertRaises(SystemExit) as exit_context:
                main()
        self.assertEqual(exit_context.exception.code, 0)
        logout_network.assert_called_once()

    def test_wifi_disconnect_recovers_on_first_detection(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        with (
            patch("campus_net_assistant.controller._online_detail", return_value=(False, "wlan-unavailable")),
            patch("campus_net_assistant.controller._recover", return_value=True) as recover,
            patch("campus_net_assistant.controller.read_status", return_value={
                "stage": "wifi-reconnected-online",
                "probe_succeeded_at": "2026-07-28T21:00:00+08:00",
            }),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            monitor(AppConfig(auto_connect_on_startup=True), once=True)
        recover.assert_called_once()

    def test_passive_monitor_waits_without_connecting_or_recovering(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor
        from campus_net_assistant.wlan import WlanEnableResult

        config = AppConfig(wake_enabled=False, hibernate_enabled=False)
        with (
            patch("campus_net_assistant.controller.prune"),
            patch(
                "campus_net_assistant.controller._online_detail",
                return_value=(False, "wlan-unavailable"),
            ),
            patch("campus_net_assistant.controller._monitor_probe") as active_probe,
            patch(
                "campus_net_assistant.controller._ensure_target_wlan_enabled",
                return_value=WlanEnableResult(
                    True,
                    False,
                    "software-radio-already-enabled",
                    "WLAN",
                ),
            ) as enable_wlan,
            patch("campus_net_assistant.controller._request_target_wlan_connection") as connect_wlan,
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            monitor(config, once=True)
        active_probe.assert_not_called()
        enable_wlan.assert_called_once_with(config)
        connect_wlan.assert_not_called()
        recover.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "monitor-passive-waiting")
        self.assertEqual(write_status.call_args.kwargs["monitor_policy"], "passive")

    def test_passive_monitor_opens_disabled_wifi_and_connects_saved_target(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor
        from campus_net_assistant.wlan import WlanEnableResult

        config = AppConfig(wake_enabled=False, hibernate_enabled=False)
        enabled = WlanEnableResult(
            True,
            True,
            "software-radio-enabled",
            "WLAN",
            software_radio_enabled=True,
        )
        with (
            patch("campus_net_assistant.controller.prune"),
            patch(
                "campus_net_assistant.controller._online_detail",
                return_value=(False, "wlan-unavailable"),
            ),
            patch("campus_net_assistant.controller._monitor_probe") as active_probe,
            patch(
                "campus_net_assistant.controller._ensure_target_wlan_enabled",
                return_value=enabled,
            ) as enable_wlan,
            patch(
                "campus_net_assistant.controller._request_target_wlan_connection",
                return_value=(True, True),
            ) as connect_wlan,
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.event") as log_event,
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            monitor(config, once=True)

        active_probe.assert_not_called()
        enable_wlan.assert_called_once_with(config)
        connect_wlan.assert_called_once_with(config)
        recover.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "wlan-connecting")
        self.assertEqual(
            write_status.call_args.kwargs["monitor_policy"],
            "passive-wifi-enable-only",
        )
        passive_recovery_events = [
            call
            for call in log_event.call_args_list
            if call.args and call.args[0] == "monitor-passive-wlan-recovery"
        ]
        self.assertEqual(len(passive_recovery_events), 1)
        self.assertTrue(passive_recovery_events[0].args[1])

    def test_monitor_does_not_probe_during_manual_logout_pause(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        class StopMonitor(RuntimeError):
            pass

        config = AppConfig(wake_enabled=True)
        state = {
            "armed": True,
            "policy": "active",
            "source": "manual-network-logout",
            "monitor_suppression_source": "manual-network-logout",
            "monitor_suppressed_until": (
                datetime.now().astimezone() + timedelta(minutes=5)
            ).isoformat(timespec="milliseconds"),
        }
        with (
            patch("campus_net_assistant.controller.prune"),
            patch("campus_net_assistant.controller.load_config", return_value=config),
            patch("campus_net_assistant.controller.load_monitor_state", return_value=state),
            patch("campus_net_assistant.controller._in_monitor_window", return_value=True),
            patch("campus_net_assistant.controller._online_detail") as passive_probe,
            patch("campus_net_assistant.controller._monitor_probe") as active_probe,
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
            patch("campus_net_assistant.controller.wait_for_monitor_signal", side_effect=StopMonitor),
        ):
            with self.assertRaises(StopMonitor):
                monitor(config)

        passive_probe.assert_not_called()
        active_probe.assert_not_called()
        recover.assert_not_called()
        self.assertEqual(
            write_status.call_args.args[0],
            "monitor-paused-after-manual-logout",
        )

    def test_passive_monitor_arms_after_first_real_campus_online_probe(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        config = AppConfig(
            wake_enabled=False,
            hibernate_enabled=False,
            start_uu=False,
        )
        with (
            patch("campus_net_assistant.controller.prune"),
            patch(
                "campus_net_assistant.controller._online_detail",
                return_value=(True, "microsoft-connect-test"),
            ),
            patch(
                "campus_net_assistant.controller._monitor_probe",
                return_value=(True, "microsoft-connect-test", 1),
            ) as active_probe,
            patch("campus_net_assistant.controller.append_connectivity_event") as append_event,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            monitor(config, once=True)
        active_probe.assert_called_once_with(config)
        first_online_events = [
            call for call in append_event.call_args_list
            if call.args and call.args[0] == "first-campus-online-confirmed"
        ]
        self.assertEqual(len(first_online_events), 1)
        self.assertEqual(write_status.call_args.args[0], "online")
        self.assertEqual(write_status.call_args.kwargs["monitor_policy"], "active")

    def test_failed_active_recovery_retries_after_sixty_seconds(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        config = AppConfig(wake_enabled=True, hibernate_enabled=False)
        active_state = {
            "armed": True,
            "policy": "active",
            "source": "morning",
            "armed_at": "2026-07-30T08:55:00+08:00",
        }
        with (
            patch("campus_net_assistant.controller.prune"),
            patch("campus_net_assistant.controller.load_config", return_value=config),
            patch("campus_net_assistant.controller.load_monitor_state", return_value=active_state),
            patch(
                "campus_net_assistant.controller._monitor_probe",
                return_value=(False, "wlan-unavailable", 1),
            ),
            patch("campus_net_assistant.controller._recover", return_value=False),
            patch(
                "campus_net_assistant.controller.read_status",
                return_value={"stage": "primary-login-failed"},
            ),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
            patch(
                "campus_net_assistant.controller.wait_for_monitor_signal",
                side_effect=RuntimeError("stop-after-first-loop"),
            ) as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop-after-first-loop"):
                monitor(config)
        sleep.assert_called_once_with(60)
        self.assertEqual(write_status.call_args.args[0], "recovery-waiting")
        self.assertEqual(write_status.call_args.kwargs["retry_after_seconds"], 60)

    def test_portal_failure_probes_twice_immediately_then_recovers(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        with (
            patch(
                "campus_net_assistant.controller._online_detail",
                side_effect=[
                    (False, "microsoft-connect-test"),
                    (False, "microsoft-connect-test"),
                ],
            ) as probe,
            patch("campus_net_assistant.controller._recover", return_value=True) as recover,
            patch("campus_net_assistant.controller.read_status", return_value={
                "stage": "primary-login-succeeded",
                "probe_succeeded_at": "2026-07-30T13:30:00+08:00",
            }),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event") as log_event,
            patch("campus_net_assistant.controller.write_status"),
        ):
            monitor(AppConfig(auto_connect_on_startup=True), once=True)
        self.assertEqual(probe.call_count, 2)
        recover.assert_called_once()
        confirmation = [
            call for call in log_event.call_args_list
            if call.args and call.args[0] == "monitor-confirmation-probe"
        ]
        self.assertEqual(len(confirmation), 1)
        self.assertFalse(confirmation[0].args[1])

    def test_portal_allowlist_pause_skips_monitor_recovery(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        config = AppConfig(
            wake_enabled=True,
            auth_paused=True,
            auto_connect_on_startup=True,
            auth_pause_reason="portal-allowlist-blocked",
        )
        with (
            patch(
                "campus_net_assistant.controller._online_detail",
                side_effect=[
                    (False, "all-connectivity-probes-failed"),
                    (False, "all-connectivity-probes-failed"),
                ],
            ),
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            monitor(config, once=True)

        recover.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "portal-allowlist-blocked")
        self.assertTrue(write_status.call_args.kwargs["automatic_submission_paused"])

    def test_portal_failure_second_immediate_probe_can_cancel_recovery(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import monitor

        with (
            patch(
                "campus_net_assistant.controller._online_detail",
                side_effect=[
                    (False, "microsoft-connect-test"),
                    (True, "microsoft-connect-test"),
                ],
            ) as probe,
            patch("campus_net_assistant.controller._recover") as recover,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            monitor(AppConfig(auto_connect_on_startup=True), once=True)
        self.assertEqual(probe.call_count, 2)
        recover.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "online")

    def test_portal_probe_failure_requires_second_detection(self):
        from campus_net_assistant.controller import _should_recover

        self.assertFalse(_should_recover("microsoft-connect-test", 1))
        self.assertTrue(_should_recover("microsoft-connect-test", 2))
        self.assertFalse(_should_recover("all-connectivity-probes-failed", 1))
        self.assertTrue(_should_recover("all-connectivity-probes-failed", 2))
        self.assertTrue(_should_recover("wlan-unavailable", 1))
        self.assertTrue(_should_recover("ssid-mismatch", 1))

    def test_monitor_window_uses_configured_wake_and_sleep(self):
        from datetime import datetime

        from campus_net_assistant.config import AppConfig, apply_schedule
        from campus_net_assistant.controller import _in_monitor_window

        config = AppConfig(
            wake_enabled=True,
            hibernate_enabled=True,
            wake_time="07:30",
            sleep_time="23:40",
        )
        apply_schedule(config)
        self.assertFalse(_in_monitor_window(config, datetime(2026, 7, 28, 7, 29)))
        self.assertTrue(_in_monitor_window(config, datetime(2026, 7, 28, 7, 30)))
        self.assertTrue(_in_monitor_window(config, datetime(2026, 7, 28, 7, 45)))
        self.assertFalse(_in_monitor_window(config, datetime(2026, 7, 28, 23, 40)))
        config.hibernate_enabled = False
        self.assertTrue(_in_monitor_window(config, datetime(2026, 7, 28, 23, 40)))
        config.hibernate_enabled = True
        config.wake_enabled = False
        self.assertTrue(_in_monitor_window(config, datetime(2026, 7, 28, 7, 29)))

    def test_uu_start_is_optional_and_uses_configured_path(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import _ensure_uu

        disabled = AppConfig(start_uu=False, uu_path=r"E:\Tools\UU\GameViewer.exe")
        enabled = AppConfig(start_uu=True, uu_path=r"E:\Tools\UU\GameViewer.exe")
        with (
            patch("campus_net_assistant.controller.ensure_running", return_value=(True, "started")) as ensure,
            patch("campus_net_assistant.controller.event"),
        ):
            _ensure_uu(disabled)
            ensure.assert_not_called()
            _ensure_uu(enabled)
        ensure.assert_called_once_with(Path(r"E:\Tools\UU\GameViewer.exe"))

    def test_hibernate_ends_monitor_task_before_shutdown(self):
        import subprocess

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import run_hibernate

        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            patch(
                "campus_net_assistant.controller.load_config",
                return_value=AppConfig(hibernate_enabled=True),
            ),
            patch("campus_net_assistant.controller.subprocess.run", side_effect=[completed, completed]) as run,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
            patch("campus_net_assistant.controller.prune"),
        ):
            self.assertTrue(run_hibernate())
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["schtasks.exe", "/End", "/TN", "NJMUCampusNetAssistant-Monitor"],
        )
        self.assertEqual(run.call_args_list[1].args[0], ["shutdown.exe", "/h"])

    def test_disabled_hibernate_task_is_safely_ignored(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import run_hibernate

        with (
            patch(
                "campus_net_assistant.controller.load_config",
                return_value=AppConfig(hibernate_enabled=False),
            ),
            patch("campus_net_assistant.controller.subprocess.run") as run,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
            patch("campus_net_assistant.controller.prune"),
        ):
            self.assertTrue(run_hibernate())
        run.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "hibernate-disabled")

    def test_disabled_morning_task_starts_only_passive_monitor(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import run_morning

        config = AppConfig(wake_enabled=False)
        with (
            patch("campus_net_assistant.controller.prune"),
            patch("campus_net_assistant.controller._online") as online,
            patch("campus_net_assistant.controller._start_monitor_task") as start_monitor,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(run_morning(config))
        online.assert_not_called()
        start_monitor.assert_called_once_with("wake-disabled-passive")

    def test_wlan_interface_parser_supports_english_and_chinese_names(self):
        from campus_net_assistant.wlan import _interface_blocks

        output = """
            Name : Wi-Fi
            State : connected
            SSID : NJMU_WLAN

            名称 : WLAN 2
            状态 : 已断开连接

            接口名称：WLAN
            状态：已连接
            SSID：NJMU_WLAN
        """
        self.assertEqual(
            _interface_blocks(output),
            [("Wi-Fi", "NJMU_WLAN"), ("WLAN 2", ""), ("WLAN", "NJMU_WLAN")],
        )

    def test_wlan_parser_falls_back_for_one_adapter_and_one_ssid(self):
        from campus_net_assistant.wlan import _single_interface_fallback

        output = """
            未知的本地化接口标签 : WLAN
            SSID : NJMU_WLAN
        """
        self.assertEqual(
            _single_interface_fallback(output, ["WLAN"]),
            [("WLAN", "NJMU_WLAN")],
        )

    def test_wlan_parser_does_not_guess_when_fallback_is_ambiguous(self):
        from campus_net_assistant.wlan import _single_interface_fallback

        output = """
            SSID : NJMU_WLAN
        """
        self.assertEqual(_single_interface_fallback(output, ["WLAN", "Wi-Fi"]), [])

    def test_gui_module_imports(self):
        import inspect

        from campus_net_assistant.gui import MainWindow, OPERATOR_OPTIONS

        self.assertTrue(MainWindow)
        self.assertEqual(OPERATOR_OPTIONS, ("电信", "移动", "联通", "校园网"))
        source = inspect.getsource(MainWindow)
        self.assertNotIn("log_view", source)
        self.assertIn("停止自动化并退出", source)
        self.assertIn("退出界面（自动化继续）", source)

    def test_both_manual_login_buttons_can_run_repeatedly_after_thread_cleanup(self):
        from PySide6.QtWidgets import QMessageBox

        from campus_net_assistant.gui import MainWindow

        class FakeSignal:
            def __init__(self) -> None:
                self.slots = []

            def connect(self, slot) -> None:
                self.slots.append(slot)

            def emit(self, *args) -> None:
                for slot in tuple(self.slots):
                    slot(*args)

        class FakeButton:
            def __init__(self) -> None:
                self.enabled = True

            def setEnabled(self, enabled: bool) -> None:
                self.enabled = enabled

        class FakeLabel:
            def setText(self, _text: str) -> None:
                pass

        class FakeThread:
            def __init__(self, _parent=None) -> None:
                self.started = FakeSignal()
                self.finished = FakeSignal()
                self.running = False
                self.deleted = False

            def isRunning(self) -> bool:
                if self.deleted:
                    raise RuntimeError("Internal C++ object already deleted")
                return self.running

            def start(self) -> None:
                self.running = True
                self.started.emit()

            def quit(self, *_args) -> None:
                self.running = False
                self.finished.emit()

            def deleteLater(self, *_args) -> None:
                self.deleted = True

        class FakeWorker:
            def __init__(self, _config, _action: str) -> None:
                self.finished = FakeSignal()
                self.deleted = False

            def moveToThread(self, _thread) -> None:
                pass

            def run(self) -> None:
                self.finished.emit(True)

            def deleteLater(self, *_args) -> None:
                self.deleted = True

        class FakeWindow:
            def __init__(self) -> None:
                self.login_thread = None
                self.login_worker = None
                self.manual_action = ""
                self.config = object()
                self.reauthenticate_button = FakeButton()
                self.login_validate_button = FakeButton()
                self.status_label = FakeLabel()
                self.completed_actions = []

            def _manual_action_is_running(self) -> bool:
                return MainWindow._manual_action_is_running(self)

            def _prepare_manual_validation(self) -> bool:
                return True

            def login_finished(self, ok: bool) -> None:
                self.completed_actions.append((self.manual_action, ok))

            def _manual_action_thread_finished(self) -> None:
                MainWindow._manual_action_thread_finished(self)

        window = FakeWindow()
        with (
            patch("campus_net_assistant.gui.QThread", FakeThread),
            patch("campus_net_assistant.gui.LoginWorker", FakeWorker),
            patch("campus_net_assistant.gui.QMessageBox.question", return_value=QMessageBox.Yes),
        ):
            MainWindow._run_manual_action(window, "logout")
            MainWindow._run_manual_action(window, "logout")
            MainWindow._run_manual_action(window, "validate_login")
            MainWindow._run_manual_action(window, "validate_login")

        self.assertEqual(
            window.completed_actions,
            [
                ("logout", True),
                ("logout", True),
                ("validate_login", True),
                ("validate_login", True),
            ],
        )
        self.assertIsNone(window.login_thread)
        self.assertIsNone(window.login_worker)
        self.assertTrue(window.reauthenticate_button.enabled)
        self.assertTrue(window.login_validate_button.enabled)

    def test_operator_combo_ignores_wheel_until_popup_is_open(self):
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from campus_net_assistant.gui import PopupWheelComboBox

        class FakeWheelEvent:
            def __init__(self) -> None:
                self.ignored = False

            def ignore(self) -> None:
                self.ignored = True

        app = QApplication.instance() or QApplication([])
        combo = PopupWheelComboBox()
        combo.addItems(["电信", "移动", "联通", "校园网"])
        combo.setCurrentText("移动")
        event = FakeWheelEvent()

        combo.wheelEvent(event)

        self.assertTrue(event.ignored)
        self.assertEqual(combo.currentText(), "移动")
        combo.deleteLater()
        app.processEvents()

    def test_tray_right_click_does_not_show_main_window(self):
        from PySide6.QtWidgets import QSystemTrayIcon

        from campus_net_assistant.gui import MainWindow

        class FakeWindow:
            def __init__(self) -> None:
                self.shown = False
                self.activated = False

            def showNormal(self) -> None:
                self.shown = True

            def activateWindow(self) -> None:
                self.activated = True

        window = FakeWindow()
        MainWindow.handle_tray_activation(window, QSystemTrayIcon.ActivationReason.Context)
        self.assertFalse(window.shown)

        MainWindow.handle_tray_activation(window, QSystemTrayIcon.ActivationReason.Trigger)
        self.assertTrue(window.shown)
        self.assertTrue(window.activated)

    def test_gui_schedule_switches_control_time_fields_and_mode_hint(self):
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication, QAbstractSpinBox

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.gui import MainWindow

        app = QApplication.instance() or QApplication([])
        config = AppConfig(wake_enabled=False, hibernate_enabled=True)
        with (
            patch("campus_net_assistant.gui.load_config", return_value=config),
            patch("campus_net_assistant.gui.installed_task_names", return_value=[]),
            patch("campus_net_assistant.gui.is_admin", return_value=False),
            patch(
                "campus_net_assistant.gui.read_status",
                return_value={"stage": "not-started", "message": "尚未运行"},
            ),
            patch("campus_net_assistant.gui.load_credentials", side_effect=RuntimeError("missing")),
        ):
            window = MainWindow()
        try:
            self.assertFalse(window.wake_time.isEnabled())
            self.assertTrue(window.sleep_time.isEnabled())
            self.assertEqual(window.wake_time.buttonSymbols(), QAbstractSpinBox.NoButtons)
            self.assertEqual(window.sleep_time.buttonSymbols(), QAbstractSpinBox.NoButtons)
            self.assertTrue(window.wake_time_control.isHidden())
            self.assertFalse(window.sleep_time_control.isHidden())
            self.assertFalse(window.wake_time_up_button.isEnabled())
            self.assertTrue(window.sleep_time_up_button.isEnabled())
            self.assertEqual(window.wake_time_up_button.arrowType(), Qt.UpArrow)
            self.assertEqual(window.wake_time_down_button.arrowType(), Qt.DownArrow)
            self.assertIn("QTimeEdit {", window.styleSheet())
            self.assertGreaterEqual(window.wake_time.minimumHeight(), 0)
            self.assertIn("不定时唤醒", window.schedule_hint.text())
            self.assertIn("每天", window.schedule_hint.text())
            self.assertIn("休眠", window.schedule_hint.text())
            window.hibernate_enabled.setChecked(False)
            self.assertFalse(window.sleep_time.isEnabled())
            self.assertTrue(window.sleep_time_control.isHidden())
            self.assertIn("不自动休眠", window.schedule_hint.text())
        finally:
            window.timer.stop()
            window.tray.hide()
            window._allow_close = True
            window.close()
            app.processEvents()

    def test_password_eye_toggles_visibility_and_rehides_when_editor_closes(self):
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication, QLineEdit

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.gui import MainWindow

        app = QApplication.instance() or QApplication([])
        with (
            patch("campus_net_assistant.gui.load_config", return_value=AppConfig()),
            patch("campus_net_assistant.gui.installed_task_names", return_value=[]),
            patch("campus_net_assistant.gui.is_admin", return_value=False),
            patch(
                "campus_net_assistant.gui.read_status",
                return_value={"stage": "not-started", "message": "尚未运行"},
            ),
            patch("campus_net_assistant.gui.load_credentials", side_effect=RuntimeError("missing")),
        ):
            window = MainWindow()
        try:
            self.assertEqual(window.password.echoMode(), QLineEdit.Password)
            self.assertEqual(window.password_visibility_button.toolTip(), "显示密码")
            self.assertGreater(
                window.password_visibility_button.icon().pixmap(24, 24).toImage().pixelColor(4, 4).alpha(),
                0,
            )
            hidden_icon_key = window.password_visibility_button.icon().cacheKey()
            self.assertFalse(window.password_visibility_button.icon().isNull())
            window.password_visibility_button.setChecked(True)
            self.assertEqual(window.password.echoMode(), QLineEdit.Normal)
            self.assertEqual(window.password_visibility_button.toolTip(), "隐藏密码")
            self.assertEqual(
                window.password_visibility_button.icon().pixmap(24, 24).toImage().pixelColor(4, 4).alpha(),
                0,
            )
            self.assertNotEqual(
                hidden_icon_key,
                window.password_visibility_button.icon().cacheKey(),
            )
            window._set_credentials_editor_visible(False)
            self.assertFalse(window.password_visibility_button.isChecked())
            self.assertEqual(window.password.echoMode(), QLineEdit.Password)
        finally:
            window.timer.stop()
            window.tray.hide()
            window._allow_close = True
            window.close()
            app.processEvents()

    def test_gui_prioritizes_status_and_hides_inactive_or_technical_details(self):
        from PySide6.QtWidgets import QApplication
        from campus_net_assistant.gui import MainWindow
        app = QApplication.instance() or QApplication([])
        from campus_net_assistant.config import AppConfig
        config = AppConfig(wake_enabled=False, hibernate_enabled=False, start_uu=False)
        status = dict(stage="online", success=True, current_online=True, monitor_policy="active")
        with patch("campus_net_assistant.gui.load_config", return_value=config), patch("campus_net_assistant.gui.installed_task_names", return_value=["NJMUCampusNetAssistant-Monitor"]), patch("campus_net_assistant.gui.read_status", return_value=status), patch("campus_net_assistant.gui.is_admin", return_value=False), patch("campus_net_assistant.gui.load_credentials", side_effect=RuntimeError("missing")):
            window = MainWindow()
        try:
            self.assertEqual([window.tabs.tabText(i).removesuffix(" ·") for i in range(window.tabs.count())], ["连接", "自动化", "维护"])
            self.assertEqual(window.configure_button.text(), "保存并应用")
            self.assertEqual(window.status_badge.text(), "已联网")
            self.assertTrue(window.connection_page.isAncestorOf(window.account_card))
            self.assertTrue(window.automation_page.isAncestorOf(window.auto_connect_on_startup))
            self.assertTrue(window.automation_page.isAncestorOf(window.keep_login_page_open))
            self.assertTrue(window.maintenance_page.isAncestorOf(window.stop_automation_button))
            for mode in ("wireless", "dorm_ethernet", "workstation_ruijie"):
                window.connection_mode.setCurrentIndex(window.connection_mode.findData(mode))
                self.assertTrue(window.dorm_protocol_observer_enabled.isHidden())
                self.assertTrue(window.dorm_script_survey_button.isHidden())
                self.assertTrue(window.wireless_http_experimental.isHidden())
                self.assertTrue(window.ruijie_path_row.isHidden())
                self.assertEqual(window.native_verify_button.isHidden(), mode != "workstation_ruijie")
            window.username.setText("draft-account")
            window.tabs.setCurrentIndex(1)
            window.tabs.setCurrentIndex(2)
            window.tabs.setCurrentIndex(0)
            self.assertEqual(window.username.text(), "draft-account")
            self.assertFalse(window.credentials_editor.isHidden())
        finally:
            window.timer.stop()
            window.tray.hide()
            window._allow_close = True
            window.close()
            app.processEvents()

    def test_gui_collapses_saved_credentials_and_reveals_optional_uu_path(self):
        import os

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.gui import MainWindow

        app = QApplication.instance() or QApplication([])
        config = AppConfig(start_uu=False)
        with (
            patch("campus_net_assistant.gui.load_config", return_value=config),
            patch("campus_net_assistant.gui.installed_task_names", return_value=[]),
            patch("campus_net_assistant.gui.is_admin", return_value=False),
            patch(
                "campus_net_assistant.gui.read_status",
                return_value={"stage": "not-started", "message": "尚未运行"},
            ),
            patch("campus_net_assistant.gui.load_credentials", return_value=("user", "secret")),
        ):
            window = MainWindow()
        try:
            self.assertFalse(window.details_container.isHidden())
            self.assertTrue(window.credentials_editor.isHidden())
            self.assertEqual(window.edit_credentials_button.text(), "更换账号或密码")
            self.assertEqual(window.settings_status_label.text(), "设置已保存")
            window.edit_credentials_button.click()
            self.assertFalse(window.credentials_editor.isHidden())
            self.assertEqual(window.edit_credentials_button.text(), "收起账号输入")
            window.start_uu.setChecked(True)
            self.assertFalse(window.uu_path_row.isHidden())
            self.assertEqual(window.settings_status_label.text(), "有未应用的修改（所有标签页）")
        finally:
            window.timer.stop()
            window.tray.hide()
            window._allow_close = True
            window.close()
            app.processEvents()

    def test_monitor_state_survives_resume_but_resets_on_new_boot(self):
        from campus_net_assistant import monitor_state
        from campus_net_assistant.config import AppConfig

        config = AppConfig(wake_enabled=False)
        with tempfile.TemporaryDirectory() as folder:
            state_path = Path(folder) / "monitor-state.json"
            with (
                patch.object(monitor_state, "STATE_PATH", state_path),
                patch.object(monitor_state, "_boot_epoch", return_value=1000.0),
            ):
                monitor_state.arm(config, "manual")
                resumed = monitor_state.load(config)
            self.assertTrue(resumed["armed"])
            self.assertEqual(resumed["source"], "manual")
            with (
                patch.object(monitor_state, "STATE_PATH", state_path),
                patch.object(monitor_state, "_boot_epoch", return_value=2000.0),
            ):
                rebooted = monitor_state.load(config)
            self.assertFalse(rebooted["armed"])
            self.assertEqual(rebooted["policy"], "passive")
            self.assertEqual(rebooted["source"], "new-boot")

    def test_monitor_state_persists_and_clears_manual_logout_pause(self):
        from campus_net_assistant import monitor_state
        from campus_net_assistant.config import AppConfig

        config = AppConfig(wake_enabled=True)
        with tempfile.TemporaryDirectory() as folder:
            state_path = Path(folder) / "monitor-state.json"
            with (
                patch.object(monitor_state, "STATE_PATH", state_path),
                patch.object(monitor_state, "_boot_epoch", return_value=1000.0),
            ):
                paused = monitor_state.suppress(config, "manual-network-logout", 300)
                loaded = monitor_state.load(config)
                remaining = monitor_state.suppression_remaining_seconds(loaded)
            with (
                patch.object(monitor_state, "STATE_PATH", state_path),
                patch.object(monitor_state, "_boot_epoch", return_value=2000.0),
            ):
                rebooted = monitor_state.load(config)
                cleared = monitor_state.clear_suppression(config, "manual-login-succeeded")

        self.assertEqual(paused["monitor_suppression_source"], "manual-network-logout")
        self.assertGreaterEqual(remaining, 299)
        self.assertLessEqual(remaining, 300)
        self.assertEqual(
            rebooted["monitor_suppression_source"],
            "manual-network-logout",
        )
        self.assertGreater(
            monitor_state.suppression_remaining_seconds(rebooted),
            0,
        )
        self.assertIsNone(cleared["monitor_suppressed_until"])
        self.assertEqual(cleared["monitor_suppression_cleared_by"], "manual-login-succeeded")


if __name__ == "__main__":
    unittest.main()
