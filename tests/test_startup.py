import unittest
from contextlib import ExitStack, nullcontext
from unittest.mock import Mock, patch

from campus_net_assistant import startup, controller, rawether
from campus_net_assistant.config import AppConfig


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.config = AppConfig(connection_mode="workstation_ruijie", wake_enabled=True,
                                ruijie_native_auto_enabled=True)
        self.state = {"source": "new-boot", "armed": True}
        self.online = Mock(return_value=(False, "dns-error"))
        self.clock = self.stack.enter_context(patch.object(startup.time, "time", return_value=1000))
        self.stack.enter_context(patch.object(startup, "save"))
        self.stack.enter_context(patch.object(startup, "event"))
        self.status = self.stack.enter_context(patch.object(startup, "write_status"))
        self.link = self.stack.enter_context(patch.object(startup, "get_linked_physical_ethernet", return_value=object()))
        self.driver = "stopped"
        self.service = self.stack.enter_context(patch.object(rawether, "_service_state",
            side_effect=lambda name: self.driver if name == "PCASp50" else "running"))
        self.start = self.stack.enter_context(patch.object(startup, "_start_verified_driver", return_value="start-failed"))
        self.lock = self.stack.enter_context(patch.object(startup, "acquire_recovery_lock", return_value=nullcontext(True)))

    def test_driver_is_started_immediately_only_once_while_network_waits(self):
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.clock.return_value = 1119
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()
        self.assertEqual(self.status.call_args.args[0], "boot-preparing")

    def test_one_attempt_persists_across_monitor_restart(self):
        startup.prepare(self.config, self.state, self.online)
        self.clock.return_value = 1120
        self.assertTrue(startup.prepare(self.config, self.state, self.online))
        restarted_state = dict(self.state)
        self.assertTrue(startup.prepare(self.config, restarted_state, self.online))
        self.start.assert_called_once()
        self.assertTrue(restarted_state["boot_driver_start_attempted"])

    def test_driver_starts_before_link_arrives(self):
        self.link.return_value = None
        startup.prepare(self.config, self.state, self.online)
        self.clock.return_value = 1200
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()
        self.link.return_value = object()
        self.assertTrue(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()

    def test_online_or_driver_ready_ends_early(self):
        self.online.return_value = (True, "ok")
        self.assertTrue(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()
        self.start.reset_mock()
        self.state = {"source": "new-boot", "armed": True}
        self.online.return_value = (False, "dns-error")
        self.driver = "running"
        self.assertTrue(startup.prepare(self.config, self.state, self.online))
        self.start.assert_not_called()

    def test_successful_driver_start_allows_auth_without_online_prerequisite(self):
        def start(_config):
            self.driver = "running"
            return "running"
        self.start.side_effect = start
        self.assertTrue(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()
        self.online.assert_not_called()

    def test_pending_driver_is_waited_for_not_started_again(self):
        self.driver = "start-pending"
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.start.assert_not_called()
        self.driver = "running"
        self.assertTrue(startup.prepare(self.config, self.state, self.online))

    def test_non_workstation_modes_do_not_touch_driver(self):
        for mode in ("wireless", "dorm_ethernet"):
            self.config.connection_mode = mode
            self.assertTrue(startup.prepare(self.config, self.state, self.online))
        self.service.assert_not_called()
        self.start.assert_not_called()

    def test_driver_does_not_wait_for_background_service(self):
        self.service.side_effect = lambda name: "stopped"
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.start.assert_called_once()

    def test_busy_lock_and_unknown_driver_never_load(self):
        self.state["boot_prepare_started"] = 800
        self.lock.return_value = nullcontext(False)
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.driver = "unreadable"
        self.assertFalse(startup.prepare(self.config, self.state, self.online))
        self.start.assert_not_called()

    def test_passive_and_wake_session_are_unaffected(self):
        for state in ({"source": "new-boot", "armed": False}, {"source": "wake-request", "armed": True}):
            self.assertTrue(startup.prepare(self.config, state, self.online))
        self.online.assert_not_called()
        self.start.assert_not_called()


class DriverLoadingTests(unittest.TestCase):
    def test_access_denied_is_explicit(self):
        with (patch.object(rawether, "inspect", return_value={"reuse_candidate": True, "bridge_ready": True}),
              patch.object(startup, "_driver_configuration_verified", return_value=True),
              patch.object(rawether, "_service_state", return_value="stopped"),
              patch.object(startup.subprocess, "run", return_value=Mock(returncode=5))):
            self.assertEqual(startup._start_verified_driver(AppConfig()), "access-denied")

    def test_unverified_components_or_config_cannot_execute(self):
        for components, configuration in ((False, True), (True, False)):
            with (patch.object(rawether, "inspect", return_value={"reuse_candidate": components, "bridge_ready": True}),
                  patch.object(startup, "_driver_configuration_verified", return_value=configuration),
                  patch.object(startup.subprocess, "run") as run):
                startup._start_verified_driver(AppConfig())
                run.assert_not_called()

    def test_verified_stopped_driver_uses_only_fixed_start_command(self):
        with (patch.object(rawether, "inspect", return_value={"reuse_candidate": True, "bridge_ready": True}),
              patch.object(startup, "_driver_configuration_verified", return_value=True),
              patch.object(rawether, "_service_state", side_effect=["stopped", "stopped", "running"]),
              patch.object(startup.subprocess, "run", return_value=Mock(returncode=0)) as run):
            self.assertEqual(startup._start_verified_driver(AppConfig()), "running")
            self.assertEqual(run.call_args.args[0], [str(rawether.SYSTEM32 / "sc.exe"), "start", "PCASp50"])


class RecoveryPolicyTests(unittest.TestCase):
    def test_background_fallback_switch_and_manual_bypass(self):
        for manual, enabled, expected in ((False, False, 0), (False, True, 1), (True, False, 1)):
            config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True,
                               ruijie_background_client_fallback=enabled)
            with (patch.object(controller, "get_ethernet", return_value=None),
                  patch.object(controller, "_ruijie_submission_rate_limited", return_value=False),
                  patch.object(controller, "get_linked_physical_ethernet", return_value=Mock()),
                  patch.object(controller, "load", return_value=("test", "test")),
                  patch.object(rawether, "_service_state", return_value="running"),
                  patch.object(controller, "send_private_md5_probe_adapter", return_value={"success": False}),
                  patch.object(controller, "authenticate_once", side_effect=controller.RuijieSafetyError("test", "test")) as official,
                  patch.object(controller, "save_config"), patch.object(controller, "event"), patch.object(controller, "write_status")):
                controller.do_login(config, wait_seconds=0, manual_validation=manual)
                self.assertEqual(official.call_count, expected)

    def test_driver_pending_prevents_native_and_official_authentication(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True,
                           ruijie_background_client_fallback=True)
        with (patch.object(controller, "get_ethernet", return_value=None),
              patch.object(controller, "_ruijie_submission_rate_limited", return_value=False),
              patch.object(controller, "get_linked_physical_ethernet", return_value=Mock()),
              patch.object(controller, "load", return_value=("test", "test")),
              patch.object(rawether, "_service_state", return_value="start-pending"),
              patch.object(controller, "send_private_md5_probe_adapter") as native,
              patch.object(controller, "authenticate_once") as official,
              patch.object(controller, "write_status")):
            self.assertFalse(controller.do_login(config, wait_seconds=0))
            native.assert_not_called()
            official.assert_not_called()
