"""Run tests with isolated app data and writable temporary files."""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

root = Path(__file__).resolve().parents[1]
runtime = root / "output" / "startup-validation" / "runtime"
runtime.mkdir(parents=True, exist_ok=True)
os.environ["LOCALAPPDATA"] = str(runtime)
os.environ["QT_QPA_PLATFORM"] = "offscreen"
tempfile.tempdir = str(runtime)
sys.path[:0] = [str(root), str(root / "src"), str(root.parent / "campus-net-assistant" / "vendor")]
suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern=sys.argv[1] if len(sys.argv) > 1 else "test*.py")
with (runtime.parent / "tests.txt").open("w", encoding="utf-8") as stream:
    from campus_net_assistant.wireless_http import WirelessHttpFallback
    # Legacy browser-flow tests must not reach real HTTP when default priority changes.
    # Provider-specific tests supply their own nested mocks and test real parsing separately.
    with patch("campus_net_assistant.controller.login_wireless_http", side_effect=WirelessHttpFallback("isolated-test-browser-flow")):
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
print(f"Tests: {result.testsRun}; failures: {len(result.failures)}; errors: {len(result.errors)}")
for name, detail in result.failures + result.errors:
    print(name, detail[:1600])
raise SystemExit(not result.wasSuccessful())
