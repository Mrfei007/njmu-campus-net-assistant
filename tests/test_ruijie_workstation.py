from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch


class RuijieWorkstationTests(unittest.TestCase):
    def test_validated_native_session_is_preferred_over_official_client(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import LinkedEthernetInfo

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
            ruijie_native_auto_enabled=True,
        )
        native_result = {
            "success": True,
            "session_started": True,
            "connectivity_succeeded": True,
            "message": "ok",
        }
        with (
            patch("campus_net_assistant.rawether._service_state", return_value="running"),
            patch("campus_net_assistant.controller.get_ethernet", return_value=None),
            patch("campus_net_assistant.controller._ruijie_submission_rate_limited", return_value=False),
            patch(
                "campus_net_assistant.controller.get_linked_physical_ethernet",
                return_value=LinkedEthernetInfo("Ethernet", "Intel Ethernet", 7),
            ),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.send_private_md5_probe_adapter",
                return_value=native_result,
            ) as native_login,
            patch("campus_net_assistant.controller.authenticate_once") as official_login,
            patch("campus_net_assistant.controller._record_ruijie_submission"),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(do_login(config, wait_seconds=10))
        native_login.assert_called_once_with(
            config.ruijie_path,
            "Intel Ethernet",
            "user",
            "secret",
            "Ethernet",
            persistent_session=True,
        )
        official_login.assert_not_called()

    def test_dialog_classifier_requires_explicit_failure_evidence(self) -> None:
        from campus_net_assistant.ruijie import _classify_authentication_dialog_text

        self.assertIsNone(_classify_authentication_dialog_text("认证成功"))
        self.assertIsNone(_classify_authentication_dialog_text("信息 确定"))
        self.assertIsNone(_classify_authentication_dialog_text("保存密码"))
        self.assertEqual(
            _classify_authentication_dialog_text("用户名或密码错误"),
            "credentials-invalid",
        )
        self.assertEqual(
            _classify_authentication_dialog_text("密码不正确"),
            "password-invalid",
        )
        self.assertEqual(
            _classify_authentication_dialog_text("用户不存在"),
            "account-invalid",
        )
        self.assertEqual(
            _classify_authentication_dialog_text("认证失败"),
            "client-reported-failure",
        )

    def test_dialog_profile_upgrade_clears_only_old_unknown_dialog_pause(self) -> None:
        from campus_net_assistant.config import AppConfig, load_config

        with tempfile.TemporaryDirectory() as folder:
            config_path = Path(folder) / "config.json"
            old = AppConfig(
                auth_paused=True,
                auth_pause_reason="client-reported-failure",
            ).public_dict()
            old.pop("ruijie_dialog_profile_revision")
            config_path.write_text(json.dumps(old, ensure_ascii=False), encoding="utf-8")
            with patch("campus_net_assistant.config.CONFIG_PATH", config_path):
                upgraded = load_config()
            self.assertEqual(upgraded.ruijie_dialog_profile_revision, 2)
            self.assertFalse(upgraded.auth_paused)
            self.assertEqual(upgraded.auth_pause_reason, "")

    def test_legacy_input_clear_does_not_rely_only_on_ctrl_a(self) -> None:
        from campus_net_assistant.ruijie import _clear_text_field

        with (
            patch("campus_net_assistant.ruijie._send_inputs") as send,
            patch("campus_net_assistant.ruijie.time.sleep"),
        ):
            _clear_text_field()

        self.assertEqual(send.call_count, 2)
        fallback = send.call_args_list[1].args[0]
        key_downs = [
            int(item.ki.wVk)
            for item in fallback
            if int(item.type) == 1 and not (int(item.ki.dwFlags) & 0x0002)
        ]
        self.assertEqual(key_downs.count(0x08), 128)
        self.assertEqual(key_downs.count(0x2E), 129)
        self.assertIn(0x23, key_downs)
        self.assertIn(0x24, key_downs)

    def test_layout_profile_upgrade_clears_old_dimension_block(self) -> None:
        from campus_net_assistant.config import AppConfig, load_config

        with tempfile.TemporaryDirectory() as folder:
            config_path = Path(folder) / "config.json"
            old = AppConfig().public_dict()
            old.pop("ruijie_layout_profile_revision")
            old["ruijie_safety_blocked"] = True
            old["ruijie_safety_manual_retry_available"] = False
            config_path.write_text(json.dumps(old, ensure_ascii=False), encoding="utf-8")
            with patch("campus_net_assistant.config.CONFIG_PATH", config_path):
                upgraded = load_config()
            self.assertEqual(upgraded.ruijie_layout_profile_revision, 2)
            self.assertFalse(upgraded.ruijie_safety_blocked)
            self.assertTrue(upgraded.ruijie_safety_manual_retry_available)

    def test_resolve_installation_only_accepts_official_file_names(self) -> None:
        from campus_net_assistant.ruijie import RuijieSafetyError, resolve_installation

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "8021x.exe").write_bytes(b"worker")
            launcher = root / "RuijieSupplicant.exe"
            launcher.write_bytes(b"launcher")
            other = root / "other.exe"
            other.write_bytes(b"other")
            installation = resolve_installation(launcher)
            self.assertEqual(installation.launcher, launcher.resolve())
            self.assertEqual(installation.worker, (root / "8021x.exe").resolve())
            self.assertEqual(len(installation.worker_sha256), 64)
            with self.assertRaises(RuijieSafetyError) as context:
                resolve_installation(other)
            self.assertEqual(context.exception.reason, "client-path-untrusted")

    def test_select_official_window_rejects_wrong_layout_and_ambiguity(self) -> None:
        from campus_net_assistant.ruijie import (
            RuijieInstallation,
            RuijieSafetyError,
            RuijieWindow,
            select_official_window,
        )

        worker = Path(r"D:\Ruijie\8021x.exe")
        installation = RuijieInstallation(worker, worker, "a" * 64)
        valid = RuijieWindow(
            hwnd=100,
            pid=200,
            title="南京医科大学认证客户端 V4.99.20131213",
            process_path=worker,
            visible=True,
            client_width=370,
            client_height=510,
        )
        self.assertEqual(select_official_window([valid], installation, require_visible=True), valid)
        workstation_high_dpi = RuijieWindow(
            **{**valid.__dict__, "client_width": 214, "client_height": 312}
        )
        self.assertEqual(
            select_official_window(
                [workstation_high_dpi], installation, require_visible=True
            ),
            workstation_high_dpi,
        )
        dpi_scaled = RuijieWindow(
            **{**valid.__dict__, "client_width": 740, "client_height": 1020}
        )
        self.assertEqual(
            select_official_window([dpi_scaled], installation, require_visible=True),
            dpi_scaled,
        )
        wrong_layout = RuijieWindow(**{**valid.__dict__, "client_width": 1000})
        with self.assertRaises(RuijieSafetyError) as layout_error:
            select_official_window([wrong_layout], installation, require_visible=True)
        self.assertEqual(layout_error.exception.reason, "client-layout-unrecognized")
        with self.assertRaises(RuijieSafetyError) as ambiguity_error:
            select_official_window([valid, valid], installation, require_visible=True)
        self.assertEqual(ambiguity_error.exception.reason, "client-window-ambiguous")

    def test_layout_error_reports_actual_client_dimensions(self) -> None:
        from campus_net_assistant.ruijie import (
            RuijieInstallation,
            RuijieSafetyError,
            RuijieWindow,
            select_official_window,
        )

        worker = Path(r"D:\Ruijie\8021x.exe")
        installation = RuijieInstallation(worker, worker, "a" * 64)
        window = RuijieWindow(
            hwnd=100,
            pid=200,
            title="南京医科大学认证客户端 V4.99.20131213",
            process_path=worker,
            visible=True,
            client_width=1200,
            client_height=500,
        )
        with self.assertRaises(RuijieSafetyError) as context:
            select_official_window([window], installation, require_visible=True)
        self.assertEqual(context.exception.details["client_width"], 1200)
        self.assertEqual(context.exception.details["client_height"], 500)
        self.assertEqual(context.exception.details["client_aspect"], 2.4)

    def test_background_never_touches_ruijie_before_field_validation(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
            ruijie_auto_enabled=False,
        )
        with (
            patch("campus_net_assistant.controller.get_ethernet", return_value=None),
            patch("campus_net_assistant.controller.authenticate_once") as authenticate,
            patch("campus_net_assistant.controller.write_status") as status,
        ):
            self.assertFalse(do_login(config, wait_seconds=1))
        authenticate.assert_not_called()
        self.assertEqual(status.call_args.args[0], "ruijie-awaiting-field-validation")

    def test_manual_success_arms_exact_client_hash_for_future_automation(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import EthernetInfo, LinkedEthernetInfo
        from campus_net_assistant.ruijie import RuijieSubmission

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        ethernet = EthernetInfo("Ethernet", "Intel Ethernet", "192.0.2.10", "192.0.2.1", 7)
        submission = RuijieSubmission(
            submitted_at=datetime.now().astimezone().isoformat(timespec="milliseconds"),
            process_id=123,
            window_title="南京医科大学认证客户端 V4.99.20131213",
            worker_sha256="b" * 64,
        )
        with (
            patch("campus_net_assistant.controller.get_ethernet", side_effect=[None, ethernet]),
            patch(
                "campus_net_assistant.controller.get_linked_physical_ethernet",
                return_value=LinkedEthernetInfo("Ethernet", "Intel Ethernet", 7),
            ),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch("campus_net_assistant.controller.authenticate_once", return_value=submission) as authenticate,
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch("campus_net_assistant.controller._record_ruijie_submission"),
            patch("campus_net_assistant.controller.save_config") as save,
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(
                do_login(
                    config,
                    wait_seconds=10,
                    require_submission=True,
                    manual_validation=True,
                )
            )
        authenticate.assert_called_once_with(
            config.ruijie_path,
            "user",
            "secret",
            expected_worker_sha256="",
        )
        self.assertTrue(config.ruijie_auto_enabled)
        self.assertEqual(config.ruijie_confirmed_worker_sha256, "b" * 64)
        save.assert_called()

    def test_one_manual_retry_after_ruijie_safety_false_positive_can_succeed(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import EthernetInfo, LinkedEthernetInfo
        from campus_net_assistant.ruijie import RuijieSafetyError, RuijieSubmission

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        ethernet = EthernetInfo("Ethernet", "Intel Ethernet", "192.0.2.10", "192.0.2.1", 7)
        submission = RuijieSubmission(
            submitted_at=datetime.now().astimezone().isoformat(timespec="milliseconds"),
            process_id=123,
            window_title="南京医科大学认证客户端 V4.99.20131213",
            worker_sha256="d" * 64,
        )
        with (
            patch(
                "campus_net_assistant.controller.get_ethernet",
                side_effect=[None, None, ethernet],
            ),
            patch(
                "campus_net_assistant.controller.get_linked_physical_ethernet",
                return_value=LinkedEthernetInfo("Ethernet", "Intel Ethernet", 7),
            ),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.authenticate_once",
                side_effect=[
                    RuijieSafetyError(
                        "client-layout-unrecognized",
                        "layout",
                        client_width=740,
                        client_height=1020,
                    ),
                    submission,
                ],
            ) as authenticate,
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch("campus_net_assistant.controller._record_ruijie_submission"),
            patch("campus_net_assistant.controller.save_config"),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(
                do_login(config, wait_seconds=10, require_submission=True, manual_validation=True)
            )
            self.assertTrue(config.ruijie_safety_blocked)
            self.assertTrue(config.ruijie_safety_manual_retry_available)
            self.assertTrue(
                do_login(config, wait_seconds=10, require_submission=True, manual_validation=True)
            )
        self.assertEqual(authenticate.call_count, 2)
        self.assertFalse(config.ruijie_safety_blocked)
        self.assertTrue(config.ruijie_safety_manual_retry_available)

    def test_second_ruijie_safety_failure_exhausts_manual_retry(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import LinkedEthernetInfo
        from campus_net_assistant.ruijie import RuijieSafetyError

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
            ruijie_safety_blocked=True,
        )
        with (
            patch("campus_net_assistant.controller.get_ethernet", return_value=None),
            patch(
                "campus_net_assistant.controller.get_linked_physical_ethernet",
                return_value=LinkedEthernetInfo("Ethernet", "Intel Ethernet", 7),
            ),
            patch("campus_net_assistant.controller.load", return_value=("user", "secret")),
            patch(
                "campus_net_assistant.controller.authenticate_once",
                side_effect=RuijieSafetyError("client-layout-unrecognized", "layout"),
            ) as authenticate,
            patch("campus_net_assistant.controller.save_config"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as status,
        ):
            self.assertFalse(
                do_login(config, wait_seconds=1, require_submission=True, manual_validation=True)
            )
            self.assertFalse(
                do_login(config, wait_seconds=1, require_submission=True, manual_validation=True)
            )
        authenticate.assert_called_once()
        self.assertTrue(config.ruijie_safety_blocked)
        self.assertFalse(config.ruijie_safety_manual_retry_available)
        self.assertEqual(status.call_args.kwargs["reason"], "ruijie-safety-retry-exhausted")

    def test_client_password_error_pauses_after_exactly_one_submission(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.ethernet import LinkedEthernetInfo
        from campus_net_assistant.ruijie import RuijieSubmission

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        submission = RuijieSubmission(
            submitted_at=datetime.now().astimezone().isoformat(timespec="milliseconds"),
            process_id=123,
            window_title="南京医科大学认证客户端 V4.99.20131213",
            worker_sha256="c" * 64,
        )

        def pause(current, reason):
            current.auth_paused = True
            current.auth_pause_reason = reason

        with (
            patch("campus_net_assistant.controller.get_ethernet", return_value=None),
            patch(
                "campus_net_assistant.controller.get_linked_physical_ethernet",
                return_value=LinkedEthernetInfo("Ethernet", "Intel Ethernet", 7),
            ),
            patch("campus_net_assistant.controller.load", return_value=("user", "wrong")),
            patch("campus_net_assistant.controller.authenticate_once", return_value=submission) as authenticate,
            patch(
                "campus_net_assistant.controller.detect_authentication_dialog",
                return_value=("password-invalid", "认证失败"),
            ),
            patch("campus_net_assistant.controller._record_ruijie_submission"),
            patch("campus_net_assistant.controller._pause_authentication", side_effect=pause),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as status,
        ):
            self.assertFalse(
                do_login(
                    config,
                    wait_seconds=10,
                    require_submission=True,
                    manual_validation=True,
                )
            )
        authenticate.assert_called_once()
        self.assertTrue(config.auth_paused)
        self.assertEqual(config.auth_pause_reason, "password-invalid")
        self.assertEqual(status.call_args.args[0], "authentication-paused")

    def test_workstation_logout_uses_native_logoff_and_confirms_offline(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.ethernet import EthernetInfo

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        ethernet = EthernetInfo(
            "Ethernet", "Intel Ethernet", "10.1.2.3", "10.1.2.1", 7,
            ("10.1.2.53",), 5,
        )
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=True),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.get_ethernet", return_value=ethernet),
            patch("campus_net_assistant.controller._connectivity_online", side_effect=[True, False, False]),
            patch("campus_net_assistant.controller.send_logoff_adapter", return_value={
                "success": True, "frames_sent": 1, "message": "sent",
            }) as logoff,
            patch("campus_net_assistant.controller.suppress_monitor", return_value={
                "monitor_suppressed_until": "2026-09-07T12:05:00+08:00",
            }) as suppress,
            patch("campus_net_assistant.controller.time.sleep"),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(logout_network(config))
        logoff.assert_called_once_with(config.ruijie_path, ethernet.description)
        suppress.assert_called_once_with(config, "manual-network-logout", 300)
        restart.assert_called_once_with()

    def test_workstation_logout_does_not_pause_when_logoff_is_unconfirmed(self) -> None:
        from campus_net_assistant.config import AppConfig, CONNECTION_MODE_WORKSTATION_RUIJIE
        from campus_net_assistant.controller import logout_network
        from campus_net_assistant.ethernet import EthernetInfo

        config = AppConfig(
            connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
            ruijie_path=r"D:\Ruijie\RuijieSupplicant.exe",
        )
        ethernet = EthernetInfo("Ethernet", "Intel Ethernet", "10.1.2.3", "10.1.2.1", 7)
        with (
            patch("campus_net_assistant.controller._stop_monitor_for_manual_reauthentication", return_value=True),
            patch("campus_net_assistant.controller._restart_monitor_after_manual_reauthentication") as restart,
            patch("campus_net_assistant.controller.get_ethernet", return_value=ethernet),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch("campus_net_assistant.controller.send_logoff_adapter", return_value={
                "success": True, "frames_sent": 1, "message": "sent",
            }),
            patch("campus_net_assistant.controller.suppress_monitor") as suppress,
            patch("campus_net_assistant.controller.time.sleep"),
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as status,
        ):
            self.assertFalse(logout_network(config))
        suppress.assert_not_called()
        restart.assert_called_once_with()
        self.assertEqual(status.call_args.args[0], "manual-logout-failed")

    @unittest.skipUnless(os.name == "nt", "Windows-only parser")
    def test_linked_ethernet_detection_does_not_require_ipv4_or_default_route(self) -> None:
        from campus_net_assistant.ethernet import detect_linked_physical_ethernet

        route_output = "  7...00 11 22 33 44 55 ......Intel(R) Ethernet Connection (24)\n"
        interface_output = "  7          5        1500  connected     Ethernet\n"
        with patch(
            "campus_net_assistant.ethernet._run_text",
            side_effect=[route_output, interface_output],
        ):
            linked = detect_linked_physical_ethernet()
        self.assertEqual(linked.ifindex, 7)
        self.assertEqual(linked.interface, "Ethernet")
        self.assertIn("Ethernet Connection (24)", linked.description)


if __name__ == "__main__":
    unittest.main()
