from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


ENTRY = "http://202.195.176.60/portal/portal-main?sessionId=current-session&nasIp=10.0.0.1"
SSO = "http://202.195.176.60/cas-sso/login?flowSessionId=current-session&language=zh-CN"
HTML = """<html><body>
<div id="login-croypto">AAECAwQFBgcICQoLDA0ODw==</div>
<span id="login-page-flowkey">fresh-flow-key</span>
<form method="post"><input name="_eventId" value="submit">
<input name="type" value="account"><input name="geolocation" value=""></form>
</body></html>"""


class DormPreflightTests(unittest.TestCase):
    def test_entry_discovery_accepts_only_official_portal_main(self):
        from campus_net_assistant.dorm_preflight import discover_dorm_entry_url
        from campus_net_assistant.dorm_protocol import DormProtocolUnsupported

        calls = []

        def discover(interface_ip):
            calls.append(interface_ip)
            return ENTRY

        self.assertEqual(discover_dorm_entry_url("10.2.3.4", discover=discover), ENTRY)
        self.assertEqual(calls, ["10.2.3.4"])
        with self.assertRaises(DormProtocolUnsupported):
            discover_dorm_entry_url("not-an-ip", discover=discover)
        with self.assertRaises(DormProtocolUnsupported):
            discover_dorm_entry_url("10.2.3.4", discover=lambda _: SSO)
        with self.assertRaises(DormProtocolUnsupported):
            discover_dorm_entry_url("10.2.3.4", discover=lambda _: ENTRY.replace("http://", "https://"))

    def test_matching_fresh_pages_yield_in_memory_snapshot(self):
        from campus_net_assistant.dorm_preflight import inspect_dorm_pages

        snapshot = inspect_dorm_pages(ENTRY, SSO, HTML, accept_language="zh-CN")
        self.assertEqual(snapshot.session_id, "current-session")
        self.assertEqual(snapshot.execution, "fresh-flow-key")
        self.assertEqual(snapshot.event_id, "submit")
        self.assertEqual(snapshot.login_type, "account")
        self.assertIn("accept-language=zh-CN", snapshot.action_url)
        self.assertNotIn("current-session", repr(snapshot))
        self.assertNotIn("fresh-flow-key", repr(snapshot))

    def test_mismatched_session_and_wrong_origin_fail_closed(self):
        from campus_net_assistant.dorm_preflight import inspect_dorm_pages
        from campus_net_assistant.dorm_protocol import DormProtocolUnsupported

        for entry, sso in (
            (ENTRY, SSO.replace("current-session", "other-session")),
            (ENTRY.replace("202.195.176.60", "example.org"), SSO),
            (ENTRY, SSO.replace("/cas-sso/login", "/cas-sso/logout")),
        ):
            with self.subTest(entry=entry, sso=sso), self.assertRaises(DormProtocolUnsupported):
                inspect_dorm_pages(entry, sso, HTML, accept_language="zh-CN")

    def test_missing_or_ambiguous_page_fields_fail_closed(self):
        from campus_net_assistant.dorm_preflight import inspect_dorm_pages
        from campus_net_assistant.dorm_protocol import DormProtocolUnsupported

        for html in (
            HTML.replace('id="login-croypto"', 'id="other"'),
            HTML.replace('name="_eventId"', 'name="other"'),
            HTML.replace('value="account"', 'value=""'),
            HTML.replace('</body>', '<input name="type" value="other"></body>'),
            HTML.replace('</body>', '<div id="login-croypto">second</div></body>'),
        ):
            with self.subTest(html=html[:45]), self.assertRaises(DormProtocolUnsupported):
                inspect_dorm_pages(ENTRY, SSO, html, accept_language="zh-CN")


if __name__ == "__main__":
    unittest.main()
