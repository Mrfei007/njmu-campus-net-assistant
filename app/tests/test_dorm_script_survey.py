from __future__ import annotations

import json
import secrets
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class _WorkspaceFolder:
    def __enter__(self) -> Path:
        self.path = ROOT / ".test-output" / f"dorm-script-survey-{secrets.token_hex(6)}"
        self.path.mkdir(parents=True)
        return self.path

    def __exit__(self, exc_type, exc, traceback) -> None:
        expected_parent = (ROOT / ".test-output").resolve()
        if self.path.resolve().parent != expected_parent:
            raise AssertionError("test cleanup target escaped .test-output")
        for path in sorted(self.path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        self.path.rmdir()


def _write_capture(path: Path, *, complete: bool = True) -> None:
    records = [
        {
            "event": "capture-started",
            "privacy_profile": "metadata-only-v1",
            "portal_host": "202.195.176.60",
        },
        {
            "event": "request",
            "method": "POST",
            "target": {
                "scheme": "http",
                "host": "202.195.176.60",
                "path": "/eportal/network/serviceLogin",
                "query_fields": ["ttbYz9WP"],
            },
            "body": {"fields": ["sessionId", "service"]},
            "ignored_secret": "session-secret-must-not-be-copied",
        },
        {
            "event": "response",
            "status": 200,
            "mime_type": "application/javascript",
            "target": {
                "scheme": "http",
                "host": "202.195.176.60",
                "path": "/portal/7243.419d7f3f5d4cfcb769b0.js",
                "query_fields": [],
            },
        },
        {
            "event": "response",
            "status": 200,
            "mime_type": "application/javascript",
            "target": {
                "scheme": "http",
                "host": "202.195.176.60",
                "path": "/portal/9387.50a7fa9fd6a94a23beb0.js",
                "query_fields": [],
            },
        },
        {
            "event": "response",
            "status": 200,
            "mime_type": "application/javascript",
            "target": {
                "scheme": "https",
                "host": "202.195.176.60",
                "path": "/portal/unsafe.js",
                "query_fields": [],
            },
        },
        {
            "event": "response",
            "status": 200,
            "mime_type": "application/json",
            "target": {
                "scheme": "http",
                "host": "202.195.176.60",
                "path": "/eportal/network/serviceLogin",
                "query_fields": ["ttbYz9WP"],
            },
        },
        {
            "event": "capture-stopped",
            "reason": "online-confirmed",
            "complete": complete,
        },
    ]
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )


class DormStaticScriptSurveyTests(unittest.TestCase):
    def test_collects_only_observed_official_static_javascript_and_builds_safe_zip(self):
        from campus_net_assistant.dorm_script_survey import (
            ScriptDownload,
            collect_dorm_static_scripts,
        )

        with _WorkspaceFolder() as folder:
            captures = folder / "captures"
            captures.mkdir()
            _write_capture(captures / "capture-success.jsonl")
            seen: list[tuple[str, str]] = []

            def fetch(path: str, interface_ip: str) -> ScriptDownload:
                seen.append((path, interface_ip))
                if path.startswith("/portal/7243"):
                    body = b'const flowKey="runtime";const login="/cas-sso/login";'
                else:
                    body = b'const queryName="ttbYz9WP";const sessionId="runtime";'
                return ScriptDownload(
                    status=200,
                    content_type="application/javascript; charset=UTF-8",
                    body=body,
                )

            result = collect_dorm_static_scripts(
                "10.0.0.2",
                capture_dir=captures,
                output_root=folder / "survey",
                fetcher=fetch,
            )

            self.assertEqual(
                seen,
                [
                    ("/portal/7243.419d7f3f5d4cfcb769b0.js", "10.0.0.2"),
                    ("/portal/9387.50a7fa9fd6a94a23beb0.js", "10.0.0.2"),
                ],
            )
            self.assertEqual(result.script_count, 2)
            self.assertTrue(result.archive_path.is_file())
            with zipfile.ZipFile(result.archive_path) as archive:
                names = set(archive.namelist())
                self.assertIn("manifest.json", names)
                self.assertIn("analysis.json", names)
                manifest = json.loads(archive.read("manifest.json"))
                analysis = json.loads(archive.read("analysis.json"))
                combined = b"".join(archive.read(name) for name in names)
            self.assertEqual(manifest["privacy_profile"], "official-static-javascript-only-v1")
            self.assertEqual(manifest["script_count"], 2)
            self.assertEqual(analysis["identifiers"]["flowKey"][0]["count"], 1)
            self.assertEqual(analysis["identifiers"]["ttbYz9WP"][0]["count"], 1)
            self.assertNotIn(b"session-secret-must-not-be-copied", combined)
            self.assertNotIn(b"Cookie", combined)

    def test_incomplete_capture_is_not_accepted(self):
        from campus_net_assistant.dorm_script_survey import (
            DormScriptSurveyError,
            find_latest_complete_capture,
        )

        with _WorkspaceFolder() as folder:
            _write_capture(folder / "capture-incomplete.jsonl", complete=False)
            with self.assertRaisesRegex(DormScriptSurveyError, "完整"):
                find_latest_complete_capture(folder)

    def test_rejects_non_javascript_download_even_for_whitelisted_path(self):
        from campus_net_assistant.dorm_script_survey import (
            DormScriptSurveyError,
            ScriptDownload,
            collect_dorm_static_scripts,
        )

        with _WorkspaceFolder() as folder:
            captures = folder / "captures"
            captures.mkdir()
            _write_capture(captures / "capture-success.jsonl")

            def fetch(_path: str, _interface_ip: str) -> ScriptDownload:
                return ScriptDownload(200, "text/html", b"<html>not script</html>")

            with self.assertRaisesRegex(DormScriptSurveyError, "JavaScript"):
                collect_dorm_static_scripts(
                    "10.0.0.2",
                    capture_dir=captures,
                    output_root=folder / "survey",
                    fetcher=fetch,
                )

    def test_http_fetch_binds_interface_and_sends_no_cookie_or_referer(self):
        from campus_net_assistant.dorm_script_survey import _fetch_script_http

        calls: dict[str, object] = {}

        class FakeResponse:
            status = 200

            @staticmethod
            def getheader(name: str, default: str = "") -> str:
                return {
                    "Content-Type": "application/javascript",
                    "Content-Encoding": "identity",
                    "Content-Length": "18",
                }.get(name, default)

            @staticmethod
            def read(_amount: int) -> bytes:
                return b"const flowKey = 1;"

        class FakeConnection:
            def __init__(self, host, port, timeout, source_address):
                calls["init"] = (host, port, timeout, source_address)

            def request(self, method, path, headers):
                calls["request"] = (method, path, headers)

            @staticmethod
            def getresponse():
                return FakeResponse()

            @staticmethod
            def close():
                calls["closed"] = True

        with patch("campus_net_assistant.dorm_script_survey.http.client.HTTPConnection", FakeConnection):
            download = _fetch_script_http("/portal/app.js", "10.0.0.2")
        self.assertEqual(calls["init"][3], ("10.0.0.2", 0))
        headers = calls["request"][2]
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Referer", headers)
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(download.status, 200)

    def test_controller_collects_only_while_dorm_ethernet_is_already_online(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import collect_dorm_static_script_survey
        from campus_net_assistant.dorm_script_survey import DormScriptSurveyResult
        from campus_net_assistant.ethernet import EthernetInfo

        ethernet = EthernetInfo(
            "以太网",
            "Realtek PCIe GbE Family Controller",
            "10.0.0.2",
            "10.0.0.1",
            7,
            ("10.0.0.53",),
            10,
        )
        result = DormScriptSurveyResult(
            archive_path=Path("survey-result.zip"),
            output_dir=Path("survey-result"),
            script_count=8,
            total_bytes=12345,
            source_capture="capture-complete.jsonl",
        )
        config = AppConfig(connection_mode="dorm_ethernet")
        with (
            patch("campus_net_assistant.controller.get_ethernet", return_value=ethernet),
            patch("campus_net_assistant.controller._connectivity_online", return_value=True),
            patch(
                "campus_net_assistant.controller.collect_dorm_static_scripts",
                return_value=result,
            ) as collect,
            patch("campus_net_assistant.controller.event") as log_event,
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertTrue(collect_dorm_static_script_survey(config))
        collect.assert_called_once_with(ethernet.ip)
        self.assertEqual(write_status.call_args.args[0], "dorm-static-script-survey-succeeded")
        self.assertEqual(write_status.call_args.kwargs["archive_file"], "survey-result.zip")
        self.assertTrue(log_event.call_args.args[1])

    def test_controller_does_not_contact_portal_when_current_mode_is_not_dorm(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import collect_dorm_static_script_survey

        with (
            patch("campus_net_assistant.controller.get_ethernet") as get_ethernet,
            patch("campus_net_assistant.controller.collect_dorm_static_scripts") as collect,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status") as write_status,
        ):
            self.assertFalse(collect_dorm_static_script_survey(AppConfig()))
        get_ethernet.assert_not_called()
        collect.assert_not_called()
        self.assertEqual(write_status.call_args.args[0], "dorm-static-script-survey-unavailable")


if __name__ == "__main__":
    unittest.main()
