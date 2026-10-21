from __future__ import annotations

import json
import queue
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
        self.path = ROOT / ".test-output" / f"dorm-observer-{secrets.token_hex(6)}"
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


class DormCaptureSanitizerTests(unittest.TestCase):
    def test_url_keeps_names_and_ephemeral_equality_tags_not_values(self):
        from campus_net_assistant.dorm_observer import DormCaptureSanitizer

        sanitizer = DormCaptureSanitizer(b"x" * 32)
        first = sanitizer.url(
            "http://202.195.176.60/portal/portal-main?sessionId=secret-session&nasIp=10.0.0.1"
        )
        second = sanitizer.url(
            "http://202.195.176.60/cas-sso/login?flowSessionId=secret-session&ticket=secret-ticket"
        )
        self.assertEqual(first["value_tags"]["sessionId"], second["value_tags"]["flowSessionId"])
        serialized = json.dumps([first, second], ensure_ascii=False)
        self.assertNotIn("secret-session", serialized)
        self.assertNotIn("secret-ticket", serialized)
        self.assertNotIn("10.0.0.1", serialized)
        self.assertIn("sessionId", serialized)
        self.assertIsNone(sanitizer.url("https://202.195.176.60/portal/portal-main"))
        self.assertIsNone(sanitizer.url("http://example.org/portal/portal-main"))
        self.assertIsNone(sanitizer.url("http://user:password@202.195.176.60/portal/portal-main"))
        dynamic_path = sanitizer.url(
            "http://202.195.176.60/portal/assets/abcdefghijklmnopqrstuvwxyz0123456789.js"
        )
        self.assertEqual(dynamic_path["path"], "/portal/assets/[dynamic]")

    def test_headers_and_body_use_strict_allowlist(self):
        from campus_net_assistant.dorm_observer import DormCaptureSanitizer

        sanitizer = DormCaptureSanitizer(b"y" * 32)
        headers = sanitizer.headers({
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "http://202.195.176.60",
            "Referer": "http://202.195.176.60/portal/entry/pc/serviceSelection?sessionId=secret",
            "isPortal": "true",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cookie": "SESSION=secret-cookie",
            "Authorization": "secret-auth",
        })
        body = sanitizer.body(
            "username=student&password=secret-password&_eventId=submit&type=account&"
            "geolocation=&captcha_code=&captcha_payload=&sessionId=secret-session",
            "application/x-www-form-urlencoded",
        )
        serialized = json.dumps({"headers": headers, "body": body}, ensure_ascii=False)
        for secret in ("secret-cookie", "secret-auth", "secret-password", "student", "secret-session"):
            self.assertNotIn(secret, serialized)
        self.assertIn("cookie", [name.lower() for name in headers["names"]])
        self.assertEqual(headers["cookie_names"], ["SESSION"])
        self.assertEqual(headers["safe_values"]["isPortal"], "true")
        self.assertEqual(body["safe_values"], {"_eventId": "submit", "type": "account"})
        self.assertEqual(
            body["empty_fields"], ["captcha_code", "captcha_payload", "geolocation"]
        )

    def test_recorder_writes_only_sanitized_request_and_response_shape(self):
        from campus_net_assistant.dorm_observer import DormCaptureSanitizer, DormProtocolRecorder

        with _WorkspaceFolder() as folder:
            path = folder / "events.jsonl"
            recorder = DormProtocolRecorder(path, sanitizer=DormCaptureSanitizer(b"z" * 32))
            commands = recorder.handle_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "request-secret-id",
                    "request": {
                        "url": "http://202.195.176.60/eportal/workFlow/getCurrentNode?ttbYz9WP=dynamic-secret",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json", "Cookie": "secret-cookie"},
                        "postData": '{"sessionId":"session-secret","flowKey":"flow-secret"}',
                    },
                    "initiator": {
                        "type": "script",
                        "stack": {"callFrames": [{
                            "functionName": "loadNode",
                            "url": "http://202.195.176.60/portal/assets/app.js?token=script-secret",
                            "lineNumber": 10,
                            "columnNumber": 2,
                        }]},
                    },
                },
            })
            self.assertEqual(commands, [])
            recorder.handle_event({
                "method": "Network.responseReceived",
                "params": {
                    "requestId": "request-secret-id",
                    "response": {
                        "url": "http://202.195.176.60/eportal/workFlow/getCurrentNode?ttbYz9WP=dynamic-secret",
                        "status": 200,
                        "mimeType": "application/json",
                        "headers": {"Content-Type": "application/json"},
                    },
                },
            })
            commands = recorder.handle_event({
                "method": "Network.loadingFinished",
                "params": {"requestId": "request-secret-id", "encodedDataLength": 128},
            })
            self.assertEqual(commands[0][0], "Network.getResponseBody")
            recorder.handle_command_response(commands[0][2], {
                "result": {"body": '{"code":200,"data":{"sessionId":"session-secret","flowKey":"flow-secret"}}'}
            })
            text = path.read_text(encoding="utf-8")
            for secret in (
                "dynamic-secret", "session-secret", "flow-secret", "secret-cookie",
                "request-secret-id", "script-secret",
            ):
                self.assertNotIn(secret, text)
            self.assertIn("ttbYz9WP", text)
            self.assertIn("data.sessionId", text)
            self.assertIn("loadNode", text)

    def test_inline_request_source_is_read_once_and_only_redacted_analysis_is_written(self):
        from campus_net_assistant.dorm_observer import DormCaptureSanitizer, DormProtocolRecorder

        with _WorkspaceFolder() as folder:
            path = folder / "events.jsonl"
            recorder = DormProtocolRecorder(path, sanitizer=DormCaptureSanitizer(b"i" * 32))
            request_event = {
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "request-secret-id",
                    "request": {
                        "url": "http://202.195.176.60/eportal/network/serviceLogin?ttbYz9WP=dynamic-secret",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json", "Cookie": "SESSION=secret-cookie"},
                        "postData": '{"sessionId":"secret-session","service":"中国电信"}',
                    },
                    "initiator": {
                        "type": "script",
                        "stack": {"callFrames": [{
                            "functionName": "_$dP",
                            "scriptId": "inline-secret-script-id",
                            "url": "",
                            "lineNumber": 0,
                            "columnNumber": 0,
                        }]},
                    },
                },
            }
            commands = recorder.handle_event(request_event)
            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][0], "Debugger.getScriptSource")
            self.assertEqual(commands[0][1], {"scriptId": "inline-secret-script-id"})
            self.assertEqual(commands[0][2]["kind"], "inline-wrapper-source")
            self.assertEqual(recorder.handle_event(request_event), [])

            source = (
                'function _$dP(url){/* secret-comment */'
                'const cookie="SESSION=secret-cookie";'
                'const session="secret-session";'
                'const key="ttbYz9WP";'
                'return url+key+Date.now()+Math.random()+document.cookie;}'
            )
            recorder.handle_command_response(commands[0][2], {
                "result": {"scriptSource": source},
            })
            text = path.read_text(encoding="utf-8")
            for secret in (
                "inline-secret-script-id",
                "request-secret-id",
                "dynamic-secret",
                "secret-comment",
                "secret-cookie",
                "secret-session",
                source,
            ):
                self.assertNotIn(secret, text)
            records = [json.loads(line) for line in text.splitlines()]
            analyses = [item for item in records if item.get("event") == "inline-wrapper-analysis"]
            self.assertEqual(len(analyses), 1)
            analysis = analyses[0]
            self.assertEqual(analysis["function"], "_$dP")
            self.assertEqual(analysis["target"]["query_fields"], ["ttbYz9WP"])
            self.assertGreater(analysis["features"]["date_now"], 0)
            self.assertGreater(analysis["features"]["math_random"], 0)
            self.assertGreater(analysis["features"]["document_cookie"], 0)
            self.assertIn("str:ttbYz9WP", analysis["token_window"]["tokens"])
            self.assertLessEqual(len(analysis["token_window"]["tokens"]), 384)

    def test_external_and_non_official_initiators_are_not_read_as_inline_source(self):
        from campus_net_assistant.dorm_observer import DormProtocolRecorder

        with _WorkspaceFolder() as folder:
            recorder = DormProtocolRecorder(folder / "events.jsonl")
            recorder.handle_event({
                "method": "Debugger.scriptParsed",
                "params": {
                    "scriptId": "external-script-id",
                    "url": "http://202.195.176.60/portal/assets/app.js",
                },
            })
            official = recorder.handle_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "official",
                    "request": {
                        "url": "http://202.195.176.60/eportal/network/serviceLogin?ttbYz9WP=x",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                    },
                    "initiator": {"type": "script", "stack": {"callFrames": [{
                        "functionName": "externalCall",
                        "scriptId": "external-script-id",
                        "url": "",
                    }]}},
                },
            })
            non_official = recorder.handle_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "outside",
                    "request": {"url": "http://example.org/api?ttbYz9WP=x", "method": "GET"},
                    "initiator": {"type": "script", "stack": {"callFrames": [{
                        "functionName": "outside",
                        "scriptId": "outside-script-id",
                        "url": "",
                    }]}},
                },
            })
            self.assertEqual(official, [])
            self.assertEqual(non_official, [])

    def test_oversized_or_unavailable_inline_source_fails_closed(self):
        from campus_net_assistant.dorm_observer import (
            MAX_INLINE_SOURCE_BYTES,
            DormProtocolRecorder,
        )

        with _WorkspaceFolder() as folder:
            path = folder / "events.jsonl"
            recorder = DormProtocolRecorder(path)
            context = {
                "kind": "inline-wrapper-source",
                "script_id": "secret-id",
                "script_tag": recorder.sanitizer.tag("secret-id"),
                "function": "_$dP",
                "line": 0,
                "column": 0,
                "target": {
                    "scheme": "http",
                    "host": "202.195.176.60",
                    "path": "/eportal/network/serviceLogin",
                    "query_fields": ["ttbYz9WP"],
                },
            }
            recorder.handle_command_response(context, {"error": {"message": "secret-error"}})
            recorder.handle_command_response(context, {
                "result": {"scriptSource": "x" * (MAX_INLINE_SOURCE_BYTES + 1)},
            })
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("secret-id", text)
            self.assertNotIn("secret-error", text)
            self.assertNotIn("x" * 100, text)
            self.assertNotIn('"event":"inline-wrapper-analysis"', text)
            self.assertEqual(text.count('"event":"inline-wrapper-skipped"'), 2)


class _FakeSocket:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.messages: queue.Queue[str] = queue.Queue()
        self.closed = False

    def send(self, value: str) -> None:
        self.sent.append(json.loads(value))

    def recv(self) -> str:
        if self.closed:
            raise ConnectionError("closed")
        try:
            return self.messages.get(timeout=0.02)
        except queue.Empty as error:
            raise TimeoutError from error

    def close(self) -> None:
        self.closed = True


class _FakeCdp:
    instances = []

    def __init__(self, url: str) -> None:
        self.url = url
        self.socket = _FakeSocket()
        self.calls: list[str] = []
        self.call_params: list[tuple[str, dict | None]] = []
        self.__class__.instances.append(self)

    def call_result(self, method: str, params: dict | None = None) -> dict:
        self.calls.append(method)
        self.call_params.append((method, params))
        return {}

    def close(self) -> None:
        self.socket.close()


class DormProtocolObserverTests(unittest.TestCase):
    def test_lightweight_records_failures_and_pending_without_active_reads(self):
        from campus_net_assistant.dorm_observer import DormProtocolRecorder

        with _WorkspaceFolder() as folder:
            recorder = DormProtocolRecorder(folder / "events.jsonl", lightweight=True)
            for ident in ("failed", "finished", "pending"):
                commands = recorder.handle_event({"method": "Network.requestWillBeSent", "params": {
                    "requestId": ident, "request": {
                        "url": "http://202.195.176.60/eportal/network/serviceLogin?ttbYz9WP=private-token",
                        "method": "POST", "headers": {},
                    },
                    "initiator": {"type": "script", "stack": {"callFrames": [{"url": "", "scriptId": "private-script"}]}},
                }})
                self.assertEqual(commands, [])
            self.assertEqual(recorder.handle_event({"method": "Network.loadingFailed", "params": {
                "requestId": "failed", "errorText": "net::ERR_BLOCKED_BY_CLIENT https://secret.invalid/private",
                "canceled": True, "blockedReason": "inspector",
            }}), [])
            self.assertEqual(recorder.handle_event({"method": "Network.loadingFinished", "params": {
                "requestId": "finished", "encodedDataLength": 12,
            }}), [])
            recorder.record_pending()
            payload = recorder.output_path.read_text(encoding="utf-8")
            records = [json.loads(line) for line in payload.splitlines()]
            failed = next(row for row in records if row["event"] == "request-failed")
            self.assertEqual(failed["error_code"], "net::ERR_BLOCKED_BY_CLIENT")
            self.assertTrue(failed["canceled"])
            self.assertEqual(failed["blocked_reason"], "inspector")
            pending = [row for row in records if row["event"] == "request-pending-at-stop"]
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["request_id"], recorder.sanitizer.tag("pending"))
            for secret in ("private-token", "private-script", "secret.invalid", "/private"):
                self.assertNotIn(secret, payload)

    def test_observer_is_ready_only_after_required_domains_enabled(self):
        from campus_net_assistant.dorm_observer import DormProtocolObserver

        _FakeCdp.instances.clear()
        with _WorkspaceFolder() as folder, patch(
            "campus_net_assistant.edge.Cdp", _FakeCdp
        ):
            observer = DormProtocolObserver("ws://local/page", output_dir=folder).start()
            self.assertEqual(
                _FakeCdp.instances[-1].calls,
                [
                    "Network.enable",
                    "Page.enable",
                ],
            )
            self.assertEqual(
                _FakeCdp.instances[-1].call_params[-1],
                ("Page.enable", None),
            )
            self.assertTrue(observer.healthy)
            observer.stop("test-complete", complete=True)
            self.assertFalse(observer.healthy)
            text = observer.recorder.output_path.read_text(encoding="utf-8")
            self.assertIn('"event":"capture-started"', text)
            self.assertIn('"privacy_profile":"metadata-only-v2"', text)
            self.assertIn('"observation_mode":"lightweight-network-v1"', text)
            self.assertIsNone(observer.survey_archive_path)
            self.assertIn('"event":"capture-stopped"', text)
            self.assertIn('"complete":true', text)

    def test_script_id_is_mapped_to_official_external_script_without_source_body(self):
        from campus_net_assistant.dorm_observer import DormProtocolRecorder

        with _WorkspaceFolder() as folder:
            recorder = DormProtocolRecorder(folder / "events.jsonl")
            recorder.handle_event({
                "method": "Debugger.scriptParsed",
                "params": {
                    "scriptId": "42-secret-id",
                    "url": "http://202.195.176.60/portal/9387.50a7fa9fd6a94a23beb0.js",
                },
            })
            recorder.handle_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "request-id",
                    "request": {
                        "url": "http://202.195.176.60/eportal/workFlow/getCurrentNode?ttbYz9WP=secret",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "postData": '{"sessionId":"secret","flowKey":"secret"}',
                    },
                    "initiator": {
                        "type": "script",
                        "stack": {"callFrames": [{
                            "functionName": "makeRequest",
                            "scriptId": "42-secret-id",
                            "url": "",
                            "lineNumber": 1,
                            "columnNumber": 2,
                        }]},
                    },
                },
            })
            text = (folder / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn('"event":"script-mapped"', text)
            self.assertIn("/portal/9387.50a7fa9fd6a94a23beb0.js", text)
            self.assertIn('"function":"makeRequest"', text)
            self.assertNotIn("42-secret-id", text)

    def test_complete_observer_capture_auto_exports_source_free_survey(self):
        from campus_net_assistant.dorm_inline_survey import build_inline_wrapper_survey
        from campus_net_assistant.dorm_observer import DormProtocolObserver

        _FakeCdp.instances.clear()
        with _WorkspaceFolder() as folder, patch(
            "campus_net_assistant.edge.Cdp", _FakeCdp
        ), patch(
            "campus_net_assistant.dorm_inline_survey.build_inline_wrapper_survey",
            side_effect=lambda capture: build_inline_wrapper_survey(
                capture,
                output_root=folder / "survey",
            ),
        ):
            observer = DormProtocolObserver("ws://local/page", output_dir=folder / "capture").start()
            # Offline legacy analysis remains compatible; live mode never enables it.
            observer.recorder.lightweight = False
            commands = observer.recorder.handle_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "request-secret",
                    "request": {
                        "url": "http://202.195.176.60/eportal/network/serviceLogin?ttbYz9WP=dynamic-secret",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"},
                        "postData": '{"sessionId":"session-secret"}',
                    },
                    "initiator": {"type": "script", "stack": {"callFrames": [{
                        "functionName": "_$dP",
                        "scriptId": "inline-secret-id",
                        "url": "",
                        "lineNumber": 0,
                        "columnNumber": 0,
                    }]}},
                },
            })
            source = 'function _$dP(u){return u+"ttbYz9WP"+Date.now()+"source-secret";}'
            observer.recorder.handle_command_response(commands[0][2], {
                "result": {"scriptSource": source},
            })
            observer.stop("online-confirmed", complete=True)
            self.assertIsNotNone(observer.survey_archive_path)
            with zipfile.ZipFile(observer.survey_archive_path) as archive:
                payload = "\n".join(
                    archive.read(name).decode("utf-8") for name in archive.namelist()
                )
            for secret in (
                "dynamic-secret",
                "session-secret",
                "inline-secret-id",
                "source-secret",
                source,
            ):
                self.assertNotIn(secret, payload)
            self.assertIn("ttbYz9WP", payload)
            capture_text = observer.recorder.output_path.read_text(encoding="utf-8")
            self.assertIn('"event":"inline-wrapper-survey-created"', capture_text)

    def test_empty_websocket_frame_ends_observer_without_json_decode_error(self):
        from campus_net_assistant.dorm_observer import DormProtocolObserver

        _FakeCdp.instances.clear()
        with _WorkspaceFolder() as folder, patch(
            "campus_net_assistant.edge.Cdp", _FakeCdp
        ):
            observer = DormProtocolObserver("ws://local/page", output_dir=folder).start()
            _FakeCdp.instances[-1].socket.messages.put("")
            observer._thread.join(timeout=1)
            self.assertFalse(observer.healthy)
            observer.stop("test-complete", complete=True)
            text = observer.recorder.output_path.read_text(encoding="utf-8")
            self.assertIn('"event":"capture-ended"', text)
            self.assertNotIn("JSONDecodeError", text)
            self.assertNotIn('"event":"capture-error"', text)

    def test_dorm_login_arms_observer_before_entry_navigation(self):
        from campus_net_assistant.edge import login

        class FakeProcess:
            def __init__(self) -> None:
                self.running = True

            def poll(self):
                return None if self.running else 0

            def terminate(self):
                self.running = False

            def wait(self, timeout=None):
                self.running = False
                return 0

            def kill(self):
                self.running = False

        class FakeControlCdp:
            instances = []

            def __init__(self, _url: str) -> None:
                self.calls = []
                self.__class__.instances.append(self)

            def call(self, method: str, params=None):
                self.calls.append((method, params))
                return None

            def close(self):
                return None

        class FakeObserver:
            instances = []

            def __init__(self, websocket_url: str) -> None:
                self.websocket_url = websocket_url
                self.public_name = "capture-test.jsonl"
                self.stopped = False
                self.stop_calls = []
                self.__class__.instances.append(self)

            @property
            def healthy(self) -> bool:
                return not self.stopped

            def start(self):
                return self

            def stop(self, reason: str, *, complete: bool) -> None:
                self.stop_calls.append((reason, complete))
                self.stopped = True

        process = FakeProcess()
        bootstrap = {
            "type": "page",
            "title": "ignored-by-patch",
            "url": "data:text/html,observer",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/observer",
        }
        portal_page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/entry/pc/authenticate",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/observer",
        }
        ready = (portal_page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        confirmed = False

        def confirm(_client):
            nonlocal confirmed
            confirmed = True
            return True

        page_states = [
            {
                "url": "http://202.195.176.60/portal/portal-main",
                "hasPassword": False,
                "passwordUrls": [],
                "pageText": "",
            },
            {"url": portal_page["url"], "hasPassword": True, "passwordUrls": [portal_page["url"]], "pageText": ""},
            {"url": portal_page["url"], "hasPassword": True, "passwordUrls": [portal_page["url"]], "pageText": ""},
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
            {"url": "http://202.195.176.60/portal/entry/pc/serviceSelection", "hasPassword": False, "pageText": ""},
        ]
        FakeObserver.instances.clear()
        with (
            _WorkspaceFolder() as folder,
            patch("campus_net_assistant.edge._discover_login_url", return_value=portal_page["url"]),
            patch("campus_net_assistant.edge._add_routes", return_value=([], {})),
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.websocket", object()),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=process) as popen,
            patch("campus_net_assistant.edge._page_with_title", return_value=bootstrap),
            patch("campus_net_assistant.edge._navigate_page", return_value=True) as navigate,
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeControlCdp),
            patch("campus_net_assistant.dorm_observer.DormProtocolObserver", FakeObserver),
            patch("campus_net_assistant.edge._page_state", side_effect=page_states),
            patch("campus_net_assistant.edge._fill_dorm_credentials", return_value=True),
            patch("campus_net_assistant.edge._submit_dorm_credentials", return_value=True),
            patch("campus_net_assistant.edge._select_dorm_operator", return_value=True),
            patch("campus_net_assistant.edge._click_dorm_confirmation", side_effect=confirm),
            patch("campus_net_assistant.edge.DORM_CREDENTIAL_PAGE_FALLBACK_SECONDS", 0.0, create=True),
            patch("campus_net_assistant.edge.append_connectivity_event"),
            patch("campus_net_assistant.edge.event") as log_event,
            patch("campus_net_assistant.edge.time.sleep"),
        ):
            result = login(
                "http://www.msftconnecttest.com/connecttest.txt",
                "user",
                "secret",
                "电信",
                probe=lambda: confirmed,
                wait_seconds=10,
                interface_ip="10.0.0.2",
                route_gateway="10.0.0.1",
                route_ifindex=7,
                dorm_ethernet_flow=True,
                include_wireless_portal_host=False,
                keep_page_open=False,
                edge_profile_root=folder / "profile",
                edge_port=49236,
                dorm_protocol_observer_enabled=True,
            )
        self.assertTrue(result["success"])
        self.assertTrue(popen.call_args_list[0].args[0][-1].startswith("data:text/html,<title>NJMU-Dorm-Observer-"))
        navigate.assert_called_once_with(
            bootstrap["webSocketDebuggerUrl"],
            portal_page["url"],
        )
        observer = FakeObserver.instances[-1]
        self.assertEqual(observer.stop_calls, [("browser-attempt-ended", False)])
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(popen.call_args.args[0][-1], portal_page["url"])
        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertLess(stages.index("dorm-protocol-observer-ready"), stages.index("dorm-observer-ordinary-login-retry"))
        self.assertLess(stages.index("dorm-observer-ordinary-login-retry"), stages.index("portal-form-fill"))
        fallback_calls = [
            call for instance in FakeControlCdp.instances for call in instance.calls
            if call[0] == "Page.navigate"
        ]
        self.assertEqual(fallback_calls, [])

    def test_dorm_observer_no_password_page_falls_back_once_then_logs_safe_timeout(self):
        from campus_net_assistant.edge import EdgeLoginError, login

        class FakeProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        class FakeControlCdp:
            instances = []

            def __init__(self, _url: str) -> None:
                self.calls = []
                self.__class__.instances.append(self)

            def call(self, method: str, params=None):
                self.calls.append((method, params))
                return None

            def close(self):
                return None

        class FakeObserver:
            def __init__(self, _url: str) -> None:
                self.public_name = "capture-timeout.jsonl"
                self.stopped = False

            @property
            def healthy(self) -> bool:
                return not self.stopped

            def start(self):
                return self

            def stop(self, _reason: str, *, complete: bool) -> None:
                self.stopped = True

        login_url = "http://202.195.176.60/portal/entry/pc/authenticate"
        page = {
            "type": "page",
            "url": "http://202.195.176.60/portal/portal-main",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/observer",
        }
        ready = (page, {"cdp_reachable": True, "page_count": 1, "cdp_reason": "reachable"})
        safe_diagnostic = {
            "frame_contexts": 1,
            "frame_reads_ok": 1,
            "page_roles": {"official-portal-main": 1},
            "passwordFields": 0,
        }
        with (
            _WorkspaceFolder() as folder,
            patch("campus_net_assistant.edge.websocket", object()),
            patch("campus_net_assistant.edge._discover_login_url", return_value=login_url),
            patch("campus_net_assistant.edge._add_routes", return_value=([], {})),
            patch("campus_net_assistant.edge._edge_path", return_value="chrome.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=FakeProcess()) as popen,
            patch("campus_net_assistant.edge._page_with_title", return_value=page),
            patch("campus_net_assistant.edge._navigate_page", return_value=True),
            patch("campus_net_assistant.edge._portal_page_status", return_value=ready),
            patch("campus_net_assistant.edge.Cdp", FakeControlCdp),
            patch("campus_net_assistant.dorm_observer.DormProtocolObserver", FakeObserver),
            patch("campus_net_assistant.edge._page_state", return_value={
                "url": page["url"],
                "hasPassword": False,
                "passwordUrls": [],
                "pageText": "",
                "frameCount": 1,
            }),
            patch("campus_net_assistant.edge._dorm_service_page_diagnostic", return_value=safe_diagnostic),
            patch("campus_net_assistant.edge.DORM_CREDENTIAL_PAGE_FALLBACK_SECONDS", -1.0, create=True),
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            with self.assertRaisesRegex(EdgeLoginError, "未在主页面或内嵌页面找到账号密码框"):
                login(
                    "http://www.msftconnecttest.com/connecttest.txt",
                    "user",
                    "secret",
                    "电信",
                    probe=lambda: False,
                    wait_seconds=1.5,
                    interface_ip="10.0.0.2",
                    route_gateway="10.0.0.1",
                    route_ifindex=7,
                    dorm_ethernet_flow=True,
                    include_wireless_portal_host=False,
                    keep_page_open=False,
                    edge_profile_root=folder / "profile",
                    edge_port=49236,
                    dorm_protocol_observer_enabled=True,
                )
        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertEqual(stages.count("dorm-observer-ordinary-login-retry"), 1)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(popen.call_args.args[0][-1], login_url)
        self.assertIn("dorm-credential-page-timeout", stages)
        timeout_call = next(
            call for call in log_event.call_args_list
            if call.args[0] == "dorm-credential-page-timeout"
        )
        self.assertEqual(timeout_call.kwargs["diagnostic"], safe_diagnostic)
        fallback_calls = [
            call for instance in FakeControlCdp.instances for call in instance.calls
            if call[0] == "Page.navigate"
        ]
        self.assertEqual(fallback_calls, [])

    def test_enabled_observer_failure_stops_before_navigation_and_credentials(self):
        from campus_net_assistant.edge import EdgeLoginError, login

        class FakeProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        bootstrap = {
            "type": "page",
            "title": "observer",
            "url": "data:text/html,observer",
            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/observer",
        }
        with (
            _WorkspaceFolder() as folder,
            patch("campus_net_assistant.edge.websocket", object()),
            patch("campus_net_assistant.edge._discover_login_url", return_value="http://202.195.176.60/portal/portal-main"),
            patch("campus_net_assistant.edge._add_routes", return_value=([], {})),
            patch("campus_net_assistant.edge._edge_path", return_value="msedge.exe"),
            patch("campus_net_assistant.edge.subprocess.Popen", return_value=FakeProcess()) as popen,
            patch("campus_net_assistant.edge._page_with_title", return_value=bootstrap),
            patch("campus_net_assistant.edge._close_browser_on_port", return_value=True),
            patch("campus_net_assistant.edge._navigate_page") as navigate,
            patch(
                "campus_net_assistant.dorm_observer.DormProtocolObserver",
                side_effect=RuntimeError("observer unavailable"),
            ),
            patch("campus_net_assistant.edge._fill_dorm_credentials") as fill,
            patch("campus_net_assistant.edge.event") as log_event,
        ):
            with self.assertRaises(EdgeLoginError):
                login(
                    "http://www.msftconnecttest.com/connecttest.txt",
                    "user",
                    "secret",
                    "电信",
                    probe=lambda: False,
                    wait_seconds=1.5,
                    interface_ip="10.0.0.2",
                    route_gateway="10.0.0.1",
                    route_ifindex=7,
                    dorm_ethernet_flow=True,
                    include_wireless_portal_host=False,
                    edge_profile_root=folder / "profile",
                    edge_port=49236,
                    dorm_protocol_observer_enabled=True,
                )
        navigate.assert_not_called()
        fill.assert_not_called()
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(popen.call_args.args[0][-1], "http://202.195.176.60/portal/portal-main")
        stages = [call.args[0] for call in log_event.call_args_list]
        self.assertIn("dorm-protocol-observer-not-ready", stages)


if __name__ == "__main__":
    unittest.main()
