from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class DormProtocolTests(unittest.TestCase):
    def test_observed_workflow_shape_keeps_encoding_uncommitted(self):
        from campus_net_assistant.dorm_protocol import (
            WORKFLOW_PATH,
            portal_api_request_url,
            workflow_request_fields,
            workflow_response_accepted,
        )

        url = portal_api_request_url(WORKFLOW_PATH, dynamic_value="fresh-opaque-value")
        self.assertEqual(urllib.parse.urlsplit(url).path, WORKFLOW_PATH)
        self.assertEqual(
            urllib.parse.parse_qs(urllib.parse.urlsplit(url).query),
            {"ttbYz9WP": ["fresh-opaque-value"]},
        )
        self.assertEqual(
            workflow_request_fields("current-session", "current-flow"),
            {"flowKey": "current-flow", "sessionId": "current-session"},
        )
        response = b'{"code":200,"data":{"sessionId":"current-session","flowKey":"current-flow"}}'
        self.assertTrue(workflow_response_accepted(
            200, response, session_id="current-session", flow_key="current-flow"
        ))
        self.assertFalse(workflow_response_accepted(
            200, response, session_id="other-session", flow_key="current-flow"
        ))

    def test_observed_operator_request_target_and_metadata(self):
        from campus_net_assistant.dorm_protocol import (
            SERVICE_LOGIN_PATH,
            SERVICE_SELECTION_PATH,
            operator_request_metadata_accepted,
            operator_request_url,
        )

        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "Origin": "http://202.195.176.60",
            "Referer": "http://202.195.176.60/portal/entry/pc/serviceSelection",
            "isPortal": "observed-but-value-not-relied-on",
        }
        for path in (SERVICE_SELECTION_PATH, SERVICE_LOGIN_PATH):
            url = operator_request_url(path, dynamic_value="fresh-opaque-value")
            self.assertEqual(
                urllib.parse.parse_qs(urllib.parse.urlsplit(url).query),
                {"ttbYz9WP": ["fresh-opaque-value"]},
            )
            self.assertTrue(operator_request_metadata_accepted(url, headers))

    def test_operator_metadata_fails_closed_on_unobserved_shape(self):
        from campus_net_assistant.dorm_protocol import (
            DormProtocolUnsupported,
            SERVICE_LOGIN_PATH,
            WORKFLOW_PATH,
            operator_request_metadata_accepted,
            operator_request_url,
            portal_api_request_url,
            workflow_request_fields,
        )

        good_url = operator_request_url(SERVICE_LOGIN_PATH, dynamic_value="fresh")
        good_headers = {
            "Content-Type": "application/json",
            "Origin": "http://202.195.176.60",
            "Referer": "http://202.195.176.60/portal/entry/pc/serviceSelection",
            "isPortal": "unknown-value",
        }
        bad_urls = (
            good_url.replace("http://", "https://"),
            good_url.replace("202.195.176.60", "example.org"),
            good_url.replace("ttbYz9WP", "other"),
            good_url + "&extra=value",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                self.assertFalse(operator_request_metadata_accepted(url, good_headers))
        for missing in good_headers:
            headers = dict(good_headers)
            headers.pop(missing)
            with self.subTest(missing=missing):
                self.assertFalse(operator_request_metadata_accepted(good_url, headers))
        for value in ("", "bad\nvalue", "x" * 1025):
            with self.subTest(value=value[:20]), self.assertRaises(DormProtocolUnsupported):
                operator_request_url(SERVICE_LOGIN_PATH, dynamic_value=value)
        with self.assertRaises(DormProtocolUnsupported):
            operator_request_url("/eportal/network/other", dynamic_value="fresh")
        with self.assertRaises(DormProtocolUnsupported):
            operator_request_url(WORKFLOW_PATH, dynamic_value="fresh")
        with self.assertRaises(DormProtocolUnsupported):
            portal_api_request_url("/eportal/network/other", dynamic_value="fresh")
        with self.assertRaises(DormProtocolUnsupported):
            workflow_request_fields("session", "bad\nflow")

    def test_sso_action_preserves_page_query_and_reuses_flow_session(self):
        from campus_net_assistant.dorm_protocol import sso_login_action

        page = (
            "http://202.195.176.60/cas-sso/login?appType=pc&"
            "flowSessionId=session-example&nasIp=10.0.0.1&timer=123"
        )
        action, session = sso_login_action(page, accept_language="zh-CN")
        parsed = urllib.parse.urlsplit(action)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path),
                         ("http", "202.195.176.60", "/cas-sso/login"))
        self.assertEqual(session, "session-example")
        self.assertEqual(urllib.parse.parse_qs(parsed.query), {
            "appType": ["pc"], "flowSessionId": ["session-example"],
            "nasIp": ["10.0.0.1"], "timer": ["123"],
            "accept-language": ["zh-CN"],
        })

    def test_sso_action_rejects_untrusted_or_ambiguous_page(self):
        from campus_net_assistant.dorm_protocol import DormProtocolUnsupported, sso_login_action

        pages = (
            "https://202.195.176.60/cas-sso/login?flowSessionId=s",
            "http://example.com/cas-sso/login?flowSessionId=s",
            "http://202.195.176.60.evil.test/cas-sso/login?flowSessionId=s",
            "http://202.195.176.60/other?flowSessionId=s",
            "http://202.195.176.60/cas-sso/login",
            "http://202.195.176.60/cas-sso/login?flowSessionId=a&flowSessionId=b",
            "http://202.195.176.60/cas-sso/login?flowSessionId=s&accept-language=en-US",
            "http://202.195.176.60/cas-sso/login?flowSessionId=s#fragment",
        )
        for page in pages:
            with self.subTest(page=page), self.assertRaises(DormProtocolUnsupported):
                sso_login_action(page, accept_language="zh-CN")

    @unittest.skipUnless(os.name == "nt", "Windows CNG is required")
    def test_observed_sso_form_shape_uses_fresh_page_values(self):
        from campus_net_assistant.dorm_protocol import sso_login_body

        encoded = sso_login_body(
            "student@ctcc", "test", croypto="AAECAwQFBgcICQoLDA0ODw==",
            execution="fresh-execution", event_id="submit", login_type="account",
        )
        fields = urllib.parse.parse_qs(encoded.decode("utf-8"), keep_blank_values=True)
        self.assertEqual(set(fields), {
            "username", "password", "type", "_eventId", "geolocation", "execution",
            "captcha_code", "croypto", "captcha_payload",
        })
        self.assertEqual(fields["username"], ["student"])
        self.assertEqual(fields["password"], ["rzIqecVRld6ytjwJ6R5lRQ=="])
        self.assertEqual(fields["captcha_payload"], ["XjROMe16mC4WGbUXWRQLQA=="])
        self.assertEqual(fields["captcha_code"], [""])
        self.assertEqual(fields["execution"], ["fresh-execution"])
        self.assertNotIn(b"password=test", encoded)

    def test_sso_form_declines_captcha_and_uncertain_whitespace(self):
        from campus_net_assistant.dorm_protocol import DormProtocolUnsupported, sso_login_body

        page = {
            "croypto": "AAECAwQFBgcICQoLDA0ODw==",
            "execution": "fresh-execution", "event_id": "submit", "login_type": "account",
        }
        with self.assertRaises(DormProtocolUnsupported):
            sso_login_body("student", "test", captcha_required=True, **page)
        with self.assertRaises(DormProtocolUnsupported):
            sso_login_body("student", " test ", **page)

    def test_observed_telecom_json_request_shapes(self):
        from campus_net_assistant.dorm_protocol import service_login_body, service_selection_body

        self.assertEqual(json.loads(service_selection_body("session-example")), {"sessionId": "session-example"})
        self.assertEqual(
            json.loads(service_login_body("session-example", "电信")),
            {"service": "中国电信", "sessionId": "session-example"},
        )

    def test_unverified_operators_and_invalid_sessions_fail_closed(self):
        from campus_net_assistant.dorm_protocol import (
            DormProtocolUnsupported, service_login_body, service_selection_body,
        )

        for operator in ("移动", "联通", "校园网", "unknown"):
            with self.subTest(operator=operator), self.assertRaises(DormProtocolUnsupported):
                service_login_body("session-example", operator)
        for session in ("", "bad\nvalue", "x" * 1025):
            with self.subTest(session=session[:20]), self.assertRaises(DormProtocolUnsupported):
                service_selection_body(session)

    def test_success_requires_exact_business_response_not_just_http_200(self):
        from campus_net_assistant.dorm_protocol import (
            service_login_accepted, service_selection_accepted,
        )

        self.assertTrue(service_selection_accepted(200, b'{"code":200,"data":{},"message":"ok"}'))
        self.assertFalse(service_selection_accepted(200, b'{"code":false}'))
        self.assertTrue(service_login_accepted(200, b'{"code":200,"data":{"authResult":"success"}}'))
        for status, body in (
            (500, b'{"code":200,"data":{"authResult":"success"}}'),
            (200, b'{"code":200,"data":{"authResult":"failed"}}'),
            (200, b'{"code":"200","data":{"authResult":"success"}}'),
            (200, b'{"code":200}'),
            (200, b'not-json'),
        ):
            with self.subTest(status=status, body=body):
                self.assertFalse(service_login_accepted(status, body))


if __name__ == "__main__":
    unittest.main()
