"""1.6.1：桥报 link-down 后的快速发现与"等链路就绪再恢复"。

这两个信号都来自一次工位观测的 fields，是纯函数，直接按矩阵覆盖：
- accelerate：桥刚因 link-down 退出（5 分钟内）→ 立刻探测，缩短发现时间；
- defer：本机链路/地址未就绪（ethernet_ready=False）→ 只探测，不发起认证恢复。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import controller, native_backend_state, workstation_monitor
from campus_net_assistant.config import AppConfig


def observation(fields=None):
    return SimpleNamespace(fields=dict(fields or {}))


def health(**overrides):
    base = {"state": "exited", "exit_reason": "link-down", "record_age_seconds": 30}
    base.update(overrides)
    return base


class LinkDownSignalTests(unittest.TestCase):
    def test_fresh_link_down_record_asks_for_a_faster_probe(self):
        accelerate, defer = controller._link_down_signals(
            observation({"keepalive": health(), "ethernet_ready": True})
        )
        self.assertTrue(accelerate)
        self.assertFalse(defer)

    def test_stale_link_down_record_no_longer_accelerates(self):
        accelerate, defer = controller._link_down_signals(
            observation({"keepalive": health(record_age_seconds=controller.LINK_DOWN_SIGNAL_MAX_RECORD_AGE + 1)})
        )
        self.assertFalse(accelerate)
        self.assertFalse(defer)

    def test_other_exit_reasons_do_not_accelerate(self):
        for reason in ("stop-requested", "keepalive-send-failed", "exception", ""):
            with self.subTest(reason=reason):
                accelerate, defer = controller._link_down_signals(
                    observation({"keepalive": health(exit_reason=reason)})
                )
                self.assertFalse(accelerate)
                self.assertFalse(defer)

    def test_running_session_never_accelerates(self):
        accelerate, defer = controller._link_down_signals(
            observation({"keepalive": {"state": "running", "record_age_seconds": 3}, "ethernet_ready": True})
        )
        self.assertFalse(accelerate)
        self.assertFalse(defer)

    def test_missing_ethernet_defers_recovery(self):
        accelerate, defer = controller._link_down_signals(observation({"ethernet_ready": False}))
        self.assertFalse(accelerate)
        self.assertTrue(defer)

    def test_unplugged_cable_with_dead_bridge_both_accelerates_and_defers(self):
        accelerate, defer = controller._link_down_signals(
            observation({"keepalive": health(record_age_seconds=5), "ethernet_ready": False})
        )
        self.assertTrue(accelerate)
        self.assertTrue(defer)

    def test_no_observation_means_no_signal(self):
        self.assertEqual(controller._link_down_signals(None), (False, False))

    def test_fast_probe_interval_is_shorter_than_regular_monitor(self):
        config = AppConfig(connection_mode="workstation_ruijie")
        self.assertLess(controller.LINK_DOWN_FAST_PROBE_SECONDS, config.monitor_interval_seconds)


class KeepaliveWordingTests(unittest.TestCase):
    def setUp(self):
        self.config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)

    def suffix(self, health):
        # 验证状态必须视为有效，否则任何非 running 记录都会先命中
        # "程序或 NpcapBridge 已更新，请重新验证原生认证"（版本升级后的真实行为）。
        with patch.object(native_backend_state, "primary_status",
                          return_value={"valid": True, "reason": "ok"}):
            return workstation_monitor._keepalive_suffix(self.config, health)

    def test_unknown_without_recent_success_explains_the_likely_cause(self):
        text = self.suffix({"state": "unknown", "reason": "no-successful-send", "verdict_basis": "record"})
        self.assertIn("没有成功发送", text)
        self.assertIn("链路", text)

    def test_link_down_exit_says_why_the_bridge_stopped(self):
        text = self.suffix({"state": "exited", "reason": "bridge-gone",
                            "verdict_basis": "absent", "exit_reason": "link-down"})
        self.assertIn("链路断开后退出", text)


class MonitorLoopDeferTests(unittest.TestCase):
    """链路未就绪时，监测循环必须只探测、不发起认证恢复。"""

    def run_once(self, observation_fields, health_age=10):
        from contextlib import ExitStack
        from unittest.mock import patch

        config = AppConfig(connection_mode="workstation_ruijie", ruijie_native_auto_enabled=True)
        config.wake_enabled = False
        # once=True 时监测状态由 auto_connect_on_startup 决定；必须已 armed，
        # 否则会先走"首次联网确认"分支去做真实探测。
        config.auto_connect_on_startup = True
        fields = {
            "confirmed_failure": True,
            "route_mode": "ethernet-default",
            "ethernet_interface": "Ethernet",
            "keepalive": {"state": "exited", "exit_reason": "link-down",
                          "record_age_seconds": health_age},
        }
        fields.update(observation_fields)
        obs = workstation_monitor.Observation(
            "access-failed", "workstation-access-failed", "", False, fields, recovery_allowed=True)
        statuses, events = [], []
        with ExitStack() as stack:
            from contextlib import nullcontext

            for name, value in {
                "acquire_monitor_lock": nullcontext(True),
                "load_config": config,
                "load_monitor_state": {"armed": True},
                "_in_monitor_window": True,
                "_monitor_probe": (False, obs.source, 2),
                "read_status": {},
                "suppression_remaining_seconds": 0,
            }.items():
                stack.enter_context(patch.object(controller, name, return_value=value))
            stack.enter_context(patch.object(
                controller, "event",
                side_effect=lambda stage, ok, message="", **kw: events.append(stage)))
            stack.enter_context(patch.object(
                controller, "write_status",
                side_effect=lambda stage, ok, message="", **kw: statuses.append(stage)))
            stack.enter_context(patch.object(controller, "append_connectivity_event"))
            stack.enter_context(patch.object(controller, "prune"))
            stack.enter_context(patch.object(controller, "_ensure_uu"))
            recover = stack.enter_context(patch.object(controller, "_recover", return_value=True))
            config._workstation_observation = obs
            controller.monitor(config, once=True)
        return recover, statuses, events

    def test_link_not_ready_skips_recovery_and_reports_waiting(self):
        recover, statuses, events = self.run_once({"ethernet_ready": False})
        recover.assert_not_called()
        self.assertIn("link-down-waiting", statuses)
        self.assertIn("monitor-recovery-deferred-link-down", events)

    def test_link_ready_still_runs_recovery(self):
        recover, statuses, events = self.run_once({"ethernet_ready": True})
        recover.assert_called_once()
        self.assertNotIn("link-down-waiting", statuses)
        self.assertNotIn("monitor-recovery-deferred-link-down", events)


class LinkDownPollingTests(unittest.TestCase):
    """1.6.2：等待期间轮询桥记录；桥已报 link-down 时跳过第二次确认探测。"""

    def setUp(self):
        from datetime import datetime, timezone

        self.state_file = ROOT / "tests" / ".tmp-keepalive-state.json"
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: self.state_file.unlink(missing_ok=True))
        self.now = datetime.now(timezone.utc)
        self._patch = patch.object(controller, "KEEPALIVE_STATUS_PATH", self.state_file)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def write_state(self, **fields):
        import json

        record = {"schema_version": 2, "state": "exited", "exit_reason": "", "exited_at": ""}
        record.update(fields)
        self.state_file.write_text(json.dumps(record), encoding="utf-8")

    def test_marker_only_accepts_link_down_exits(self):
        self.write_state(exit_reason="link-down", exited_at="2026-10-21T12:41:59+00:00")
        self.assertEqual(controller._bridge_link_down_marker(), "2026-10-21T12:41:59+00:00")
        self.write_state(exit_reason="stop-requested", exited_at="2026-10-21T12:41:59+00:00")
        self.assertEqual(controller._bridge_link_down_marker(), "")
        self.state_file.write_text("{not json", encoding="utf-8")
        self.assertEqual(controller._bridge_link_down_marker(), "")

    def test_fresh_window_rejects_old_or_unparseable_records(self):
        from datetime import timedelta

        self.write_state(exit_reason="link-down", exited_at=self.now.isoformat())
        self.assertTrue(controller._bridge_link_down_fresh())
        self.write_state(exit_reason="link-down",
                         exited_at=(self.now - timedelta(minutes=10)).isoformat())
        self.assertFalse(controller._bridge_link_down_fresh())
        self.write_state(exit_reason="link-down", exited_at="not-a-time")
        self.assertFalse(controller._bridge_link_down_fresh())

    def test_wait_returns_early_when_the_bridge_records_link_down(self):
        waits, events = [], []
        with (
            patch.object(controller, "wait_for_monitor_signal",
                         side_effect=lambda seconds: waits.append(seconds) or False),
            patch.object(controller, "_bridge_link_down_marker",
                         side_effect=["", "", "2026-10-21T12:41:59+00:00"]),
            patch.object(controller, "event",
                         side_effect=lambda stage, ok, message="", **kw: events.append((stage, kw))),
        ):
            controller._wait_for_next_probe(120)
        self.assertEqual(len(waits), 2)
        self.assertEqual([stage for stage, _ in events], ["monitor-probe-accelerated"])
        self.assertGreater(events[0][1]["skipped_seconds"], 100)

    def test_wait_uses_the_whole_interval_without_a_signal(self):
        waits = []
        with (
            patch.object(controller, "wait_for_monitor_signal",
                         side_effect=lambda seconds: waits.append(seconds) or False),
            patch.object(controller, "_bridge_link_down_marker", return_value=""),
            patch.object(controller, "event") as event,
        ):
            controller._wait_for_next_probe(120)
        self.assertEqual(len(waits), 24)
        event.assert_not_called()

    def test_wake_signal_hands_control_back_immediately(self):
        calls = []
        with (
            patch.object(controller, "wait_for_monitor_signal",
                         side_effect=lambda seconds: calls.append(seconds) or True),
            patch.object(controller, "_bridge_link_down_marker", return_value=""),
            patch.object(controller, "event") as event,
        ):
            controller._wait_for_next_probe(120)
        self.assertEqual(len(calls), 1)
        event.assert_not_called()

    def test_confirmation_probe_is_skipped_when_the_bridge_reported_link_down(self):
        config = AppConfig(connection_mode="workstation_ruijie")
        events = []
        detail = Mock(return_value=(False, "workstation-access-failed"))
        with (
            patch.object(controller, "_online_detail", detail),
            patch.object(controller, "_bridge_link_down_fresh", return_value=True),
            patch.object(controller, "event",
                         side_effect=lambda stage, ok, message="", **kw: events.append((stage, kw))),
        ):
            online, source, attempts = controller._monitor_probe(
                config, allow_link_down_shortcut=True)
        self.assertFalse(online)
        self.assertEqual(source, "workstation-access-failed")
        self.assertEqual(attempts, 2)
        self.assertEqual(detail.call_count, 1)
        self.assertEqual(events[0][1]["second_probe_source"], "bridge-link-down")


class _Stop(Exception):
    """跳出监测循环。"""


def _observation(ethernet_ready, source, message, **extra):
    fields = {
        "confirmed_failure": False,
        "ethernet_ready": ethernet_ready,
        "ethernet_interface": "Ethernet",
        "route_mode": "ethernet-default",
        "connectivity_scope": "effective-or-source-bound-access",
        "keepalive": {"state": "exited", "exit_reason": "link-down", "record_age_seconds": 60},
    }
    fields.update(extra)
    return workstation_monitor.Observation(
        "access-failed" if source == "workstation-access-failed" else "network-unknown",
        source, message, False, fields, recovery_allowed=False)


class LinkRecoveryConfirmationTests(unittest.TestCase):
    """1.6.3：断链复通后探测仍失败，必须在同一轮确认故障并恢复。"""

    def test_shortcut_marks_the_failure_as_confirmed(self):
        config = AppConfig(connection_mode="workstation_ruijie",
                           ruijie_native_auto_enabled=True)
        config.auto_connect_on_startup = True
        obs = _observation(True, "workstation-access-failed", "两组联网探测失败，原因待确认")

        def detail(target):
            target._workstation_observation = obs
            return False, "workstation-access-failed"

        events = []
        with (
            patch.object(controller, "_online_detail", side_effect=detail),
            patch.object(controller, "_bridge_link_down_fresh", return_value=True),
            patch.object(controller, "event",
                         side_effect=lambda stage, ok, message="", **kw: events.append((stage, kw))),
        ):
            online, source, attempts = controller._monitor_probe(
                config, allow_link_down_shortcut=True)
        self.assertFalse(online)
        self.assertEqual(source, "workstation-access-failed")
        self.assertEqual(attempts, 2)
        self.assertIs(obs.fields["confirmed_failure"], True)
        self.assertTrue(obs.recovery_allowed)
        self.assertIn("原生认证会话需要重建", obs.message)
        self.assertEqual(events[0][1]["second_probe_source"], "bridge-link-down")
        self.assertTrue(controller._should_recover(source, attempts))

    def test_without_the_episode_the_second_probe_still_runs(self):
        config = AppConfig(connection_mode="workstation_ruijie",
                           ruijie_native_auto_enabled=True)
        calls = []

        def detail(target):
            calls.append(1)
            target._workstation_observation = _observation(
                True, "workstation-access-failed", "两组联网探测失败，原因待确认")
            return False, "workstation-access-failed"

        with (
            patch.object(controller, "_online_detail", side_effect=detail),
            patch.object(controller, "_bridge_link_down_fresh", return_value=True),
            patch.object(controller, "event"),
        ):
            controller._monitor_probe(config)
        self.assertEqual(len(calls), 2)

    def test_monitor_recovers_on_the_first_cycle_after_the_link_returns(self):
        from contextlib import ExitStack, nullcontext

        config = AppConfig(connection_mode="workstation_ruijie",
                           ruijie_native_auto_enabled=True)
        config.wake_enabled = False
        config.auto_connect_on_startup = True
        pending = [
            _observation(False, "workstation-network-unverified", "工位有线未连接，等待网线连接"),
            _observation(True, "workstation-access-failed", "两组联网探测失败，原因待确认"),
        ]

        def detail(target):
            target._workstation_observation = pending[0] if len(pending) == 1 else pending.pop(0)
            return False, target._workstation_observation.source

        statuses = []
        recovered = []

        def wait(seconds):
            if recovered:
                raise _Stop()
            return False

        with ExitStack() as stack:
            for name, value in {
                "acquire_monitor_lock": nullcontext(True),
                "load_config": config,
                "load_monitor_state": {"armed": True},
                "_in_monitor_window": True,
                "read_status": {},
                "suppression_remaining_seconds": 0,
            }.items():
                stack.enter_context(patch.object(controller, name, return_value=value))
            stack.enter_context(patch.object(controller, "_online_detail", side_effect=detail))
            stack.enter_context(patch.object(controller, "_bridge_link_down_fresh", return_value=True))
            stack.enter_context(patch.object(
                controller, "wait_for_monitor_signal", side_effect=wait))
            stack.enter_context(patch.object(
                controller, "write_status",
                side_effect=lambda stage, ok, message="", **kw: statuses.append(stage)))
            for name in ("event", "append_connectivity_event", "prune", "_ensure_uu"):
                stack.enter_context(patch.object(controller, name))
            recover = stack.enter_context(patch.object(
                controller, "_recover",
                side_effect=lambda *a, **k: recovered.append(1) or True))
            with self.assertRaises(_Stop):
                controller.monitor(config)
        recover.assert_called_once()
        self.assertIn("workstation-network-unverified", statuses)
        self.assertIn("recovered", statuses)


if __name__ == "__main__":
    unittest.main()