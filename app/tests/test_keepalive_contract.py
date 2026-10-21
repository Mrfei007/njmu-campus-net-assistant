import os
import subprocess
import unittest
from pathlib import Path


class CompiledKeepaliveTests(unittest.TestCase):
    def test_compiled_retry_sequence_and_stop_contract(self):
        root = Path(__file__).resolve().parents[1]
        output = root / "output" / "startup-validation" / "keepalive-contract"
        output.mkdir(parents=True, exist_ok=True)
        compiler = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        bridge = output / "RawetherBridge.exe"
        harness = output / "KeepaliveContract.exe"
        for source, target, references in (
            (root / "src/campus_net_assistant/native/RawetherBridge.cs", bridge, ["/reference:System.ServiceProcess.dll"]),
            (root / "tests/KeepaliveContract.cs", harness, []),
        ):
            result = subprocess.run([str(compiler), "/nologo", "/platform:x64", "/target:exe", *references,
                                     f"/out:{target}", str(source)], capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        # 子进程（.NET 控制台）按 UTF-8 输出；用系统 GBK 解码会在中文 stderr 上直接 UnicodeDecodeError，
        # 把真正的失败原因（例如程序集加载异常）变成一句看不懂的解码错误。
        result = subprocess.run([str(harness), str(bridge)], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=20)
        self.assertEqual(result.returncode, 0, (result.stdout or "") + (result.stderr or ""))
        self.assertIn("checks passed", result.stdout)
        self.assertNotIn("FAILED", result.stdout)


if __name__ == "__main__":
    unittest.main()
