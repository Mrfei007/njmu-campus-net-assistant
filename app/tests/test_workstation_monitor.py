from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import controller, ethernet, keepalive_status, workstation_monitor
from campus_net_assistant.config import AppConfig
from campus_net_assistant.probe import ProbeResult, detailed_connectivity_probe

NETWORK = ethernet.EthernetInfo("Ethernet", "Intel Ethernet", "172.16.1.2", "172.16.1.1", 19, ("172.16.1.53",), 25)
GOOD = ProbeResult(True, "microsoft-connect-test", "ok")
BAD = ProbeResult(False, "all-connectivity-probes-failed", "timeout")
ROUTE = {"route_mode": "tunnel", "tunnel_detected": True, "path_verified_direct": False}
OUTPUTS = [
    """ 19...02 00 00 00 00 13 ......Intel Ethernet
 44...........................Meta Tunnel
 0.0.0.0 0.0.0.0 172.16.1.1 172.16.1.2 25
 0.0.0.0 0.0.0.0 198.18.0.2 198.18.0.1 0
""",
    "19 25 1500 connected Ethernet\n44 0 9000 connected Mihomo",
    'Configuration for interface "Ethernet"\n IP Address: 172.16.1.2\nConfiguration for interface "Mihomo"\n IP Address: 198.18.0.1',
    'Configuration for interface "Ethernet"\n DNS servers configured through DHCP: 172.16.1.53',
]


class WorkstationMonitoringTests(unittest.TestCase):
    def observation(self, effective=GOOD, bound=GOOD, health=None, network=NETWORK, route=None):
        def probe(ip, *_args):
            return effective if ip is None else bound
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        with (
            patch.object(workstation_monitor, "read_health", return_value=health or {"state": "running", "adapter_description": NETWORK.description}),
            patch.object(workstation_monitor, "inspect_workstation_routes", return_value=route or ROUTE),
            patch.object(workstation_monitor, "detailed_connectivity_probe", side_effect=probe),
            patch.object(workstation_monitor, "detect_linked_physical_ethernet", side_effect=RuntimeError("physical-ethernet-link-not-found")),
            patch.object(workstation_monitor, "_native_verified", return_value=True),
        ):
            return config, workstation_monitor.observe(config, network)

    def test_tun_does_not_disqualify_workstation_but_dorm_remains_strict(self):
        with patch.object(ethernet, "_run_text", side_effect=OUTPUTS):
            selected = ethernet.detect_ethernet_interface(require_preferred=False)
        self.assertEqual(selected.ip, NETWORK.ip)
        with patch.object(ethernet, "_run_text", side_effect=OUTPUTS):
            with self.assertRaisesRegex(RuntimeError, "unique-preferred"):
                ethernet.detect_ethernet_interface()

    def test_competing_physical_adapters_require_session_identity(self):
        outputs = OUTPUTS.copy()
        outputs[0] += " 20...01 02 03 04 05 06 ......Realtek Ethernet\n 0.0.0.0 0.0.0.0 10.1.1.1 10.1.1.2 1\n"
        outputs[1] += "\n20 1 1500 connected Second"
        outputs[2] += '\nConfiguration for interface "Second"\n IP Address: 10.1.1.2'
        outputs[3] += '\nConfiguration for interface "Second"\n DNS servers configured through DHCP: 10.1.1.53'
        with patch.object(ethernet, "_run_text", side_effect=outputs):
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                ethernet.detect_ethernet_interface(require_preferred=False)
        with patch.object(ethernet, "_run_text", side_effect=outputs):
            selected = ethernet.detect_ethernet_interface(require_preferred=False, preferred_description="Intel Ethernet")
        self.assertEqual(selected.ifindex, 19)

    def test_tun_and_split_routes_are_detected(self):
        for route in (OUTPUTS[0], OUTPUTS[0].replace('0.0.0.0 0.0.0.0 198.18.0.2', '0.0.0.0 128.0.0.0 198.18.0.2') + '\n128.0.0.0 128.0.0.0 198.18.0.2 198.18.0.1 100\n'):
            with patch.object(ethernet, "_run_text", side_effect=[route, *OUTPUTS[1:3]]):
                result = ethernet.inspect_workstation_routes(NETWORK)
            self.assertTrue(result["tunnel_detected"])
            self.assertFalse(result["path_verified_direct"])

    def test_disconnected_tun_is_not_reported_as_active(self):
        with patch.object(ethernet, "_run_text", side_effect=[OUTPUTS[0], OUTPUTS[1].replace('44 0 9000 connected', '44 0 9000 disconnected'), OUTPUTS[2]]):
            result = ethernet.inspect_workstation_routes(NETWORK)
        self.assertEqual(result["route_mode"], "ethernet-default")

    def test_successful_tun_does_not_trigger_authentication(self):
        _, obs = self.observation()
        self.assertTrue(obs.available)
        self.assertFalse(obs.recovery_allowed)
        self.assertIn("TUN", obs.message)
        self.assertEqual(obs.fields["authentication_state"], "unverified")

    def test_effective_success_with_bound_failure_remains_available(self):
        _, obs = self.observation(bound=BAD)
        self.assertTrue(obs.available)
        self.assertIn("有线绑定探测异常", obs.message)
        self.assertFalse(obs.recovery_allowed)

    def test_bound_success_with_exit_failure_is_degraded(self):
        _, obs = self.observation(effective=BAD)
        self.assertTrue(obs.available)
        self.assertEqual(obs.state, "exit-degraded")
        self.assertFalse(obs.recovery_allowed)

    def test_dual_failure_with_tun_and_working_keepalive_waits_for_diagnosis(self):
        _, obs = self.observation(BAD, BAD)
        self.assertFalse(obs.available)
        self.assertFalse(obs.recovery_allowed)
        self.assertEqual(obs.state, "access-failed")

    def test_failed_matching_bridge_is_recovery_evidence(self):
        for state in ("send-failed", "exited", "stopped"):
            _, obs = self.observation(BAD, BAD, health={"state": state, "adapter_description": NETWORK.description})
            self.assertTrue(obs.recovery_allowed)
        _, wrong = self.observation(BAD, BAD, health={"state": "send-failed", "adapter_description": "Other Ethernet"})
        self.assertFalse(wrong.recovery_allowed)

    def test_stale_send_health_does_not_authorize_reset(self):
        _, obs = self.observation(BAD, BAD, health={"state": "stale", "adapter_description": NETWORK.description})
        self.assertFalse(obs.recovery_allowed)

    def test_initial_native_session_is_allowed_only_on_default_ethernet(self):
        health = {"state": "unknown", "reason": "no-valid-send-record"}
        _, tunnel = self.observation(BAD, BAD, health=health)
        self.assertFalse(tunnel.recovery_allowed)
        _, ethernet_default = self.observation(BAD, BAD, health=health, route={"route_mode": "ethernet-default", "tunnel_detected": False})
        self.assertTrue(ethernet_default.recovery_allowed)

    def test_read_only_confirmation_does_not_write_log(self):
        config, first = self.observation(BAD, BAD)
        _, second = self.observation(BAD, BAD)
        with patch.object(controller, "_selected_network", return_value=(NETWORK, "workstation-ruijie")), patch.object(controller, "observe_workstation", side_effect=[first, second]), patch.object(controller, "event") as event:
            controller._monitor_probe(config, record=False)
        event.assert_not_called()

    def test_missing_link_with_other_working_exit_is_not_campus_online(self):
        _, obs = self.observation(network=None)
        self.assertFalse(obs.available)
        self.assertTrue(obs.fields["effective_probe"]["success"])
        self.assertEqual(obs.state, "network-unknown")
        self.assertFalse(obs.recovery_allowed)

    def test_unavailable_route_information_is_unknown_and_non_destructive(self):
        with patch.object(workstation_monitor, "inspect_workstation_routes", side_effect=subprocess.CalledProcessError(1, "route")):
            # Use the real observe with all request dependencies controlled.
            with patch.object(workstation_monitor, "read_health", return_value={"state": "unknown"}), patch.object(workstation_monitor, "detailed_connectivity_probe", return_value=BAD):
                obs = workstation_monitor.observe(AppConfig(connection_mode="workstation_ruijie"), NETWORK)
        self.assertEqual(obs.fields["route_mode"], "unknown")
        self.assertFalse(obs.recovery_allowed)

    def test_monitor_confirms_both_failures_before_offline_record(self):
        config, first = self.observation(BAD, BAD)
        _, second = self.observation(BAD, BAD)
        with patch.object(controller, "_selected_network", return_value=(NETWORK, "workstation-ruijie")), patch.object(controller, "observe_workstation", side_effect=[first, second]), patch.object(controller, "event"):
            self.assertEqual(controller._monitor_probe(config), (False, "workstation-access-failed", 2))
        self.assertTrue(second.fields["confirmed_failure"])

    def test_route_or_interface_transition_does_not_confirm_outage(self):
        config, first = self.observation(BAD, BAD)
        _, second = self.observation(BAD, BAD)
        second.fields["ethernet_interface"] = "Other Ethernet"
        with patch.object(controller, "_selected_network", return_value=(NETWORK, "workstation-ruijie")), patch.object(controller, "observe_workstation", side_effect=[first, second]), patch.object(controller, "event"):
            controller._monitor_probe(config)
        self.assertFalse(second.fields["confirmed_failure"])

    def test_unknown_detection_is_not_counted_as_offline(self):
        config, obs = self.observation(network=None)
        with patch.object(controller, "event"), patch.object(controller, "write_status") as status, patch.object(controller, "append_connectivity_event") as events:
            self.assertEqual(controller._record_workstation_observation(config, obs, 1, 0), 0)
        self.assertIsNone(status.call_args.args[1])
        events.assert_not_called()

    def test_active_monitor_invokes_keepalive_watchdog_after_online_observation(self):
        config, obs = self.observation()
        stop_loop = RuntimeError("stop-loop")
        with ExitStack() as stack:
            for name, value in {
                "acquire_monitor_lock": nullcontext(True),
                "load_config": config,
                "load_monitor_state": {"armed": True},
                "_in_monitor_window": True,
                "_monitor_probe": (True, obs.source, 1),
                "suppression_remaining_seconds": 0,
            }.items():
                stack.enter_context(patch.object(controller, name, return_value=value))
            for name in ("event", "write_status", "append_connectivity_event", "prune", "_ensure_uu"):
                stack.enter_context(patch.object(controller, name))
            stack.enter_context(patch.object(
                controller, "_record_workstation_observation", return_value=0))
            watchdog = stack.enter_context(patch.object(controller, "_maybe_restart_keepalive"))
            stack.enter_context(patch.object(
                controller, "wait_for_monitor_signal", side_effect=stop_loop))
            config._workstation_observation = obs
            with self.assertRaises(RuntimeError):
                controller.monitor(config)
        watchdog.assert_called_once()


    def test_confirmed_access_failure_is_distinct_from_authentication_failure(self):
        config, obs = self.observation(BAD, BAD)
        obs.fields["confirmed_failure"] = True
        with patch.object(controller, "event"), patch.object(controller, "write_status") as status, patch.object(controller, "append_connectivity_event") as events:
            self.assertEqual(controller._record_workstation_observation(config, obs, 2, 0), 2)
        self.assertEqual(events.call_args.args[0], "offline-detected")
        self.assertEqual(events.call_args.kwargs["authentication_state"], "unverified")
        self.assertEqual(status.call_args.kwargs["recovery_policy"], "diagnosis-wait")

    def test_active_monitor_does_not_recover_for_tun_outage_or_unknown_information(self):
        for network, effective in ((NETWORK, BAD), (None, GOOD)):
            config, obs = self.observation(effective=effective, bound=BAD, network=network)
            config.wake_enabled = True
            config.auto_connect_on_startup = True
            obs.fields["confirmed_failure"] = network is not None
            with ExitStack() as stack:
                patches = {"acquire_monitor_lock": nullcontext(True), "load_config": config,
                           "load_monitor_state": {"armed": True}, "_in_monitor_window": True,
                           "_monitor_probe": (obs.available, obs.source, 2),
                           "read_status": {}, "suppression_remaining_seconds": 0}
                for name, value in patches.items():
                    stack.enter_context(patch.object(controller, name, return_value=value))
                for name in ("event", "write_status", "append_connectivity_event", "prune", "_ensure_uu"):
                    stack.enter_context(patch.object(controller, name))
                recover = stack.enter_context(patch.object(controller, "_recover"))
                config._workstation_observation = obs
                controller.monitor(config, once=True)
                recover.assert_not_called()

    def test_native_enabled_is_not_mistaken_for_unvalidated_official_ui(self):
        self.assertFalse(controller._should_recover("workstation-ethernet-unavailable", 1))
        config, obs = self.observation(BAD, BAD, health={"state": "exited", "adapter_description": NETWORK.description})
        config.wake_enabled = True
        config.auto_connect_on_startup = True
        obs.fields["confirmed_failure"] = True
        with ExitStack() as stack:
            for name, value in {"acquire_monitor_lock": nullcontext(True), "load_config": config,
                                "load_monitor_state": {"armed": True}, "_in_monitor_window": True,
                                "_monitor_probe": (False, obs.source, 2), "read_status": {}, "suppression_remaining_seconds": 0}.items():
                stack.enter_context(patch.object(controller, name, return_value=value))
            for name in ("event", "write_status", "append_connectivity_event", "prune", "_ensure_uu"):
                stack.enter_context(patch.object(controller, name))
            recover = stack.enter_context(patch.object(controller, "_recover", return_value=False))
            config._workstation_observation = obs
            controller.monitor(config, once=True)
            recover.assert_called_once()


class DetailedProbeTests(unittest.TestCase):
    def test_default_exit_does_not_bind_source_and_stops_after_valid_primary(self):
        with patch("campus_net_assistant.probe.subprocess.run", return_value=Mock(returncode=0, stdout="Microsoft Connect Test\n200")) as run:
            result = detailed_connectivity_probe(None, "http://primary", "Microsoft Connect Test", "http://secondary")
        self.assertTrue(result.success)
        self.assertNotIn("--interface", run.call_args.args[0])
        self.assertEqual(len(result.attempts), 1)

    def test_bound_source_and_distinct_error_reasons(self):
        with patch("campus_net_assistant.probe.subprocess.run", side_effect=[Mock(returncode=6, stdout="\n000"), Mock(returncode=28, stdout="\n000")]) as run:
            result = detailed_connectivity_probe(NETWORK.ip, "http://primary", "expected", "http://secondary")
        self.assertFalse(result.success)
        self.assertEqual([x["reason"] for x in result.attempts], ["dns-error", "timeout"])
        self.assertIn(NETWORK.ip, run.call_args.args[0])

    def test_redirect_is_not_success_and_secondary_can_confirm_access(self):
        with patch("campus_net_assistant.probe.subprocess.run", side_effect=[Mock(returncode=0, stdout="portal\n302"), Mock(returncode=0, stdout="\n204")]):
            result = detailed_connectivity_probe(None, "http://primary", "expected", "http://secondary")
        self.assertTrue(result.success)
        self.assertEqual(result.source, "android-generate-204")
        self.assertEqual(result.attempts[0]["reason"], "redirect")
        self.assertNotIn("portal", str(result.public_dict()))


class KeepaliveHealthTests(unittest.TestCase):
    def setUp(self):
        # Keep test files under the workspace: the DSH file sandbox rejects the
        # 0o700 ACL that Windows tempfile.TemporaryDirectory creates.
        folder = Path(__file__).resolve().parents[1] / ".test-temp"
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / f"health-{time.time_ns()}.json"
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.now = datetime.now(timezone.utc)
        self.record = {"schema_version": 1, "session_id": "b1a2047a-5719-4558-8838-b3a9ead048d8", "process_id": 100,
                       "process_started_at": (self.now - timedelta(hours=1)).isoformat(),
                       "updated_at": self.now.isoformat(), "last_success_at": self.now.isoformat(),
                       "successful_sends": 3, "last_send_status": 0, "state": "running", "adapter_description": "Intel Ethernet"}

    def read(self, process="running", session=False):
        self.path.write_text(json.dumps(self.record), encoding="utf-8")
        with patch.object(keepalive_status, "_process_state", return_value=process), patch.object(keepalive_status, "_session_is_running", return_value=session):
            return keepalive_status.read_health(self.path, self.now)

    def test_recent_success_is_verified_without_claiming_server_receipt(self):
        result = self.read()
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["successful_sends"], 3)
        self.assertEqual(result["server_receipt"], "unverified")

    def test_retry_health_and_persistent_failure_summary(self):
        self.record.update(state="retrying", last_send_status=31,
                           last_failure_at=self.now.isoformat(), last_failure_status=31,
                           send_attempt=2, send_duration_ms=17, failure_driver_state="Running",
                           failure_link_state="Up", retry_recoveries=0)
        result = self.read()
        self.assertEqual(result["state"], "retrying")
        self.assertEqual(result["send_attempt"], 2)
        self.record.update(state="running", last_send_status=0, retry_recoveries=1)
        result = self.read()
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["last_failure_status"], 31)
        self.assertEqual(result["retry_recoveries"], 1)

    def test_retrying_session_does_not_report_running_forever(self):
        self.record.update(state="retrying", last_send_status=31,
                           updated_at=(self.now - timedelta(seconds=31)).isoformat())
        self.assertEqual(self.read()["state"], "stale")

    def test_exited_or_reused_pid_is_not_reported_as_sending(self):
        self.assertEqual(self.read("exited")["state"], "exited")
        self.assertEqual(self.read("unknown")["state"], "unknown")

    def test_old_session_record_cannot_reset_a_new_active_bridge(self):
        self.record.update(state="stopped")
        self.assertEqual(self.read("exited", session=True)["state"], "unknown")
        self.assertEqual(self.read("exited", session=None)["state"], "unknown")

    def test_old_or_future_send_records_are_not_healthy(self):
        self.record["last_success_at"] = (self.now - timedelta(seconds=120)).isoformat()
        self.assertEqual(self.read()["state"], "stale")
        self.record["last_success_at"] = (self.now + timedelta(hours=1)).isoformat()
        self.assertEqual(self.read()["state"], "unknown")

    def test_partial_file_and_missing_file_are_unknown(self):
        self.assertEqual(keepalive_status.read_health(self.path)["state"], "unknown")
        self.path.write_text('{"schema_version":', encoding="utf-8")
        self.assertEqual(keepalive_status.read_health(self.path)["state"], "unknown")

    def test_send_failure_and_stop_are_retained(self):
        self.record.update(state="send-failed", last_send_status=5)
        self.assertEqual(self.read()["state"], "send-failed")
        self.record.update(state="stopped", last_send_status=0)
        self.assertEqual(self.read("exited")["state"], "stopped")

    def test_arbitrary_private_fields_are_not_copied(self):
        self.record.update(password="secret", packet_payload="sensitive")
        result = self.read()
        self.assertNotIn("password", result)
        self.assertNotIn("packet_payload", result)

    def test_authentication_in_progress_and_unsuccessful_exit_are_not_healthy(self):
        self.record.update(state="authenticating", successful_sends=0, last_success_at="")
        self.assertEqual(self.read()["reason"], "authentication-in-progress")
        self.record.update(state="authentication-failed")
        self.assertEqual(self.read("exited")["reason"], "no-native-session")

    def test_read_only_config_loading_does_not_migrate_live_file(self):
        from campus_net_assistant import config
        with patch.object(config, "CONFIG_PATH", self.path), patch.object(config, "save_config") as save:
            self.path.write_text('{"connection_mode":"workstation_ruijie"}', encoding="utf-8")
            value = config.load_config(read_only=True)
        self.assertEqual(value.connection_mode, "workstation_ruijie")
        save.assert_not_called()

    def test_exit_cause_and_record_age_are_exposed(self):
        self.record.update(
            state="exited", exit_reason="exception", exit_code=1,
            exited_at=(self.now - timedelta(seconds=125)).isoformat(),
            updated_at=(self.now - timedelta(seconds=125)).isoformat(),
        )
        result = self.read("exited")
        self.assertEqual(result["state"], "exited")
        self.assertEqual(result["reason"], "bridge-exited")
        self.assertEqual(result["exit_reason"], "exception")
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(result["exited_at"])
        self.assertTrue(result["updated_at"])
        self.assertGreaterEqual(result["record_age_seconds"], 124)


class KeepaliveSuffixTests(unittest.TestCase):
    def suffix(self, config, health):
        return workstation_monitor._keepalive_suffix(config, health)

    def test_unverified_native_mode_is_not_reported_as_unknown_fault(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=False)
        text = self.suffix(config, {"state": "unknown", "reason": "no-valid-send-record"})
        self.assertIn("原生认证尚未完成检查验证", text)
        self.assertNotIn("后台保活状态未知", text)

    def test_native_mode_without_record_is_explained(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        with patch("campus_net_assistant.native_backend_state.primary_status",
                   return_value={"valid": True, "reason": "verified"}):
            text = self.suffix(config, {"state": "unknown", "reason": "no-valid-send-record"})
        self.assertIn("尚无有效记录", text)

    def test_changed_bridge_is_reported_as_needs_reverification(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        with patch("campus_net_assistant.native_backend_state.primary_status",
                   return_value={"valid": False, "reason": "app-version-changed"}):
            text = self.suffix(config, {"state": "unknown", "reason": "no-valid-send-record"})
        self.assertIn("重新验证", text)

    def test_exit_reason_is_included(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        self.assertIn("异常退出", self.suffix(config, {"state": "exited", "exit_reason": "exception"}))
        self.assertIn("链路断开后退出", self.suffix(config, {"state": "exited", "exit_reason": "link-down"}))
        self.assertIn("没有退出原因记录", self.suffix(config, {"state": "exited"}))

    def test_requested_stop_is_distinguished(self):
        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        text = self.suffix(config, {"state": "stopped", "exit_reason": "stop-requested"})
        self.assertIn("按请求停止", text)


class KeepaliveWatchdogTests(unittest.TestCase):
    def config(self, **kwargs):
        values = {"connection_mode": "workstation_ruijie", "ruijie_native_auto_enabled": True}
        values.update(kwargs)
        return AppConfig(**values)

    @staticmethod
    def observation(health, route="ethernet-default", ready=True):
        return workstation_monitor.Observation(
            "online", "microsoft-connect-test", "", True,
            {"route_mode": route, "ethernet_ready": ready, "keepalive": health},
        )

    def invoke(self, config, health, state=None, restart_result=None, lock=True,
               route="ethernet-default", attempts=None, attempt_results=None):
        state = state if state is not None else {}
        result = restart_result or {"success": True, "session_started": True, "message": "ok"}
        link = Mock(description="Intel Ethernet", interface="Ethernet")
        events = []

        def record_event(stage, success, message="", **fields):
            # Same signature as logging_redacted.event: passing a second
            # "message" keyword must fail loudly, not be swallowed.
            events.append((stage, success, message, fields))

        with (
            patch.object(controller, "acquire_recovery_lock", return_value=nullcontext(lock)),
            patch.object(controller, "get_linked_physical_ethernet", return_value=link),
            patch.object(controller, "load", return_value=("user", "pass")),
            patch.object(controller, "_native_verified",
                         return_value=bool(config.ruijie_native_auto_enabled and not state.get("_unverified"))),
            patch.object(controller, "_native_auth_attempts", return_value=attempts or ["npcap"]),
            patch.object(controller, "_attempt_native_auth",
                         side_effect=attempt_results, return_value=result) as restart,
            patch.object(controller, "save_monitor_state"),
            patch.object(controller, "event", side_effect=record_event),
            patch.object(controller, "write_status"),
        ):
            ok = controller._maybe_restart_keepalive(
                config, self.observation(health, route=route), state)
        self.events = events
        return ok, state, restart

    def test_restarts_when_online_but_bridge_exited(self):
        ok, state, restart = self.invoke(self.config(), {"state": "exited", "reason": "bridge-exited"})
        self.assertTrue(ok)
        restart.assert_called_once()
        self.assertIn("keepalive_watchdog_last_attempt", state)
        self.assertEqual(state["keepalive_watchdog_consecutive_failures"], 0)

    def test_restarts_for_missing_native_record(self):
        ok, _, restart = self.invoke(self.config(), {"state": "unknown", "reason": "no-valid-send-record"})
        self.assertTrue(ok)
        restart.assert_called_once()

    def test_restarts_after_a_bridge_was_stopped(self):
        ok, _, restart = self.invoke(
            self.config(), {"state": "stopped", "reason": "session-stopped", "exit_reason": "stop-requested"})
        self.assertTrue(ok)
        restart.assert_called_once()

    def test_falls_back_to_rawether_after_npcap_failure(self):
        attempts = ["npcap", "rawether"]
        results = [
            {"success": False, "session_started": False, "message": "npcap failed"},
            {"success": True, "session_started": True, "message": "rawether ok"},
        ]
        ok, state, attempt = self.invoke(
            self.config(), {"state": "exited", "reason": "bridge-exited"},
            attempts=attempts, attempt_results=results)
        self.assertTrue(ok)
        self.assertEqual(attempt.call_count, 2)
        self.assertEqual(attempt.call_args.args[-1], "rawether")
        self.assertEqual(state["keepalive_watchdog_consecutive_failures"], 0)
        self.assertTrue(any(fields.get("native_backend") == "rawether"
                            for _stage, _success, _message, fields in self.events))

    def test_does_not_restart_healthy_running_bridge(self):
        ok, state, restart = self.invoke(self.config(), {"state": "running", "reason": "recent-send-success"})
        self.assertFalse(ok)
        restart.assert_not_called()
        self.assertNotIn("keepalive_watchdog_last_attempt", state)

    def test_does_not_restart_in_official_client_mode(self):
        ok, _, restart = self.invoke(
            self.config(ruijie_native_auto_enabled=False),
            {"state": "exited", "reason": "bridge-exited"},
        )
        self.assertFalse(ok)
        restart.assert_not_called()

    def test_does_not_restart_while_authentication_is_paused(self):
        ok, _, restart = self.invoke(self.config(auth_paused=True), {"state": "exited", "reason": "bridge-exited"})
        self.assertFalse(ok)
        restart.assert_not_called()

    def test_does_not_restart_on_tunnel_route(self):
        ok, _, restart = self.invoke(
            self.config(), {"state": "exited", "reason": "bridge-exited"}, route="tunnel")
        self.assertFalse(ok)
        restart.assert_not_called()

    def test_rate_limits_repeated_attempts(self):
        state = {"keepalive_watchdog_last_attempt": time.time() - 5}
        ok, _, restart = self.invoke(self.config(), {"state": "exited", "reason": "bridge-exited"}, state=state)
        self.assertFalse(ok)
        restart.assert_not_called()

    def test_failure_increments_backoff_counter(self):
        result = {"success": False, "session_started": False, "message": "auth failed"}
        ok, state, restart = self.invoke(
            self.config(), {"state": "exited", "reason": "bridge-exited"}, restart_result=result)
        self.assertFalse(ok)
        restart.assert_called_once()
        self.assertEqual(state["keepalive_watchdog_consecutive_failures"], 1)

    def test_skips_when_recovery_lock_is_busy(self):
        ok, _, restart = self.invoke(
            self.config(), {"state": "exited", "reason": "bridge-exited"}, lock=False)
        self.assertFalse(ok)
        restart.assert_not_called()

    def test_unknown_reason_that_indicates_live_session_is_not_restarted(self):
        for reason in ("process-unverified", "session-record-mismatch", "authentication-in-progress"):
            ok, _, restart = self.invoke(self.config(), {"state": "unknown", "reason": reason})
            self.assertFalse(ok, reason)
            restart.assert_not_called()

    def test_backoff_interval_grows_and_is_capped(self):
        now = 1_000_000.0
        self.assertFalse(controller._keepalive_watchdog_due(
            {"keepalive_watchdog_last_attempt": now - 60}, now=now))
        self.assertTrue(controller._keepalive_watchdog_due(
            {"keepalive_watchdog_last_attempt": now - controller.KEEPALIVE_WATCHDOG_RETRY_SECONDS - 1}, now=now))
        self.assertFalse(controller._keepalive_watchdog_due(
            {"keepalive_watchdog_last_attempt": now - controller.KEEPALIVE_WATCHDOG_RETRY_SECONDS - 1,
             "keepalive_watchdog_consecutive_failures": 1}, now=now))
        self.assertFalse(controller._keepalive_watchdog_due(
            {"keepalive_watchdog_last_attempt": now - controller.KEEPALIVE_WATCHDOG_MAX_BACKOFF_SECONDS + 1,
             "keepalive_watchdog_consecutive_failures": 9}, now=now))
        self.assertTrue(controller._keepalive_watchdog_due(
            {"keepalive_watchdog_last_attempt": now - controller.KEEPALIVE_WATCHDOG_MAX_BACKOFF_SECONDS - 1,
             "keepalive_watchdog_consecutive_failures": 9}, now=now))

