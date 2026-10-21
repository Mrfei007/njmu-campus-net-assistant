"""1.6 会话互斥体的真实所有权协议（跨进程集成测试）。

判定"有没有活会话"不能靠"我创建了一个同名对象"，必须依赖内核对象的所有权：
  * 另一个会话持有 → 拒绝启动（exit_reason=session-already-active，退出码 78），且不写状态文件；
  * 持有者异常退出（abandoned）→ 接管，并记录 takeover_from；
  * 无人持有 → 正常获取。
"""
from __future__ import annotations

import base64
import ctypes
import subprocess
import sys
import time
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from campus_net_assistant import npcap_bridge  # noqa: E402

MUTEX = r"Local\NJMUCampusNetAssistant-TestSession"

HOLDER = r"""
import ctypes, sys, time
from ctypes import wintypes
api = ctypes.WinDLL("kernel32", use_last_error=True)
api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
api.CreateMutexW.restype = wintypes.HANDLE
handle = api.CreateMutexW(None, True, sys.argv[1])
if not handle:
    sys.exit(3)
open(sys.argv[2], "w").write("ready")
time.sleep(float(sys.argv[3]))
"""


def _open_mutex():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    api.OpenMutexW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    return api, api.OpenMutexW(0x100001, False, MUTEX)


class MutexOwnershipTests(unittest.TestCase):
    def setUp(self):
        folder = ROOT / ".test-temp"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = time.time_ns()
        self.ready = folder / f"mutex-ready-{stamp}.txt"
        self.state = folder / f"mutex-state-{stamp}.json"
        self.addCleanup(lambda: self.ready.unlink(missing_ok=True))
        self.addCleanup(lambda: self.state.unlink(missing_ok=True))
        self.patches = [
            patch.object(npcap_bridge, "SESSION_MUTEX_NAME", MUTEX),
            patch.object(npcap_bridge, "STATE_PATH", self.state),
            patch.object(npcap_bridge, "TELEMETRY_DIR", folder),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def start_holder(self, seconds: float = 30.0) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-P", "-c", HOLDER, MUTEX, str(self.ready), str(seconds)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.ready.exists():
                return process
            time.sleep(0.05)
        self.fail("holder process did not become ready")

    def session(self):
        session = npcap_bridge.Session("run-private-session", 15000, "Intel Ethernet")
        self.addCleanup(session.cleanup)
        return session

    def test_third_party_session_blocks_start_without_touching_state(self):
        holder = self.start_holder()
        session = self.session()
        self.assertFalse(session.acquire_session_mutex())
        self.assertEqual(session.exit_reason, "session-already-active")
        self.assertEqual(session.exit_code, npcap_bridge.EXIT_SESSION_ALREADY_ACTIVE)
        self.assertFalse(self.state.exists(), "被拒绝的实例不得改写状态文件")
        holder.kill()
        holder.wait(timeout=10)

    def test_abandoned_mutex_is_taken_over(self):
        self.state.write_text('{"process_id": 987654}', encoding="utf-8")
        holder = self.start_holder()
        # 先自己开一个句柄，保证持有者被杀后内核对象仍然存在（真正的 abandoned）。
        api, keepalive = _open_mutex()
        self.assertTrue(keepalive, "无法打开测试互斥体")
        self.addCleanup(api.CloseHandle, keepalive)
        holder.kill()
        holder.wait(timeout=10)
        session = self.session()
        self.assertTrue(session.acquire_session_mutex())
        self.assertTrue(session.mutex_owned)
        self.assertEqual(session.takeover_from, "987654")

    def test_free_mutex_is_acquired_without_takeover(self):
        session = self.session()
        self.assertTrue(session.acquire_session_mutex())
        self.assertEqual(session.takeover_from, "")


class BridgeExitCodeTests(unittest.TestCase):
    def test_already_running_returns_78(self):
        adapter = "Intel Ethernet"
        encoded = base64.b64encode(adapter.encode("mbcs")).decode("ascii")
        session = npcap_bridge.Session("run-private-session", 15000, adapter)
        session.persistent = True
        session.exit_reason = "session-already-active"
        with (
            patch.object(npcap_bridge, "Session", return_value=session),
            patch.object(session, "acquire_session_mutex", return_value=False),
            patch.object(sys, "argv",
                         ["NpcapBridge.exe", "run-private-session", "path", encoded, "15000"]),
        ):
            code = npcap_bridge.main()
        self.assertEqual(code, npcap_bridge.EXIT_SESSION_ALREADY_ACTIVE)


if __name__ == "__main__":
    unittest.main()