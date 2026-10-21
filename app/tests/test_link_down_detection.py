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
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()