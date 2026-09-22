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
        result = subprocess.run([str(harness), str(bridge)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("checks passed", result.stdout)
