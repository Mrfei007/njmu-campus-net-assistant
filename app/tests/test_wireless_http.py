from __future__ import annotations

import sys
import socket
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


WIRELESS_FORM = """
<!doctype html>
<form action="/guest/wifi_login.php" method="post">
  <input type="hidden" name="csrf" value="opaque-value">
  <input type="text" name="username">
  <input type="password" name="password">
  <select name="service">
    <option value="campus">校园网</option>
    <option value="ctcc">中国电信</option>
    <option value="cmcc">中国移动</option>
  </select>
  <button type="submit">登录</button>
</form>
"""
NJMU_REDIRECT = """
<script>window.top.location.href = "\\/guest\\/wifi_login.php?_browser=1";</script>
<meta http-equiv="Refresh" content="0; URL=/guest/wifi_login.php?_browser=1">
"""
NJMU_STAGED_FORM = """
<form id="form1">
  <input name="username" type="text">
  <input name="password" type="password">
  <select name="zrhs">
    <option value="@internet">校园网</option>
    <option value="@ctcc">电信</option>
    <option value="@cucc">联通</option>
    <option value="@cmcc">移动</option>
  </select>
</form>
<form id="cp_form" method="post" action="https://captiveportal-login.njmu.edu.cn/auth/index.html/u">
  <input id="cp_user" name="username" type="text">
  <input id="cp_password" name="password" type="password">
</form>
<script>
  $("#submit1").click(function () {
    var arr = $('#form1').serializeArray();
    $('#cp_user').val(arr[0]['value'] + arr[2]['value'])
    $('#cp_password').val(arr[1]['value'])
    $('#cp_form').submit()
  });
</script>
<script>/* Here is an example of how to use Backstretch as a slideshow. */</script>
"""


class _Response:
    def __init__(self, body: str, url: str, status: int = 200):
        self._body = body.encode("utf-8")
        self._url = url
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"

    def read(self, _size: int = -1) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Opener:
    def __init__(self, responses: list[_Response]):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout: int):
        self.requests.append((request, timeout))
        return self.responses.pop(0)


class WirelessHttpTests(unittest.TestCase):
    def test_njmu_client_redirect_and_staged_form_follow_observed_flow(self):
        from campus_net_assistant.wireless_http import _choose_form, _preflight_page

        page_url = "https://wlan.njmu.edu.cn/guest/wifi_login.php"
        browser_url = page_url + "?_browser=1"
        opener = _Opener([
            _Response(NJMU_REDIRECT, page_url),
            _Response(NJMU_STAGED_FORM, browser_url),
        ])
        body, resolved_url = _preflight_page(opener, page_url)
        self.assertEqual(resolved_url, browser_url)
        self.assertEqual(len(opener.requests), 2)
        action, fields = _choose_form(body, resolved_url, "student", "secret", "电信")
        self.assertEqual(
            action,
            "https://captiveportal-login.njmu.edu.cn/auth/index.html/u",
        )
        self.assertEqual(fields, [("username", "student@ctcc"), ("password", "secret")])

    def test_njmu_staged_form_blocks_changed_script_or_destination(self):
        from campus_net_assistant.edge import PortalAllowlistError
        from campus_net_assistant.wireless_http import WirelessHttpFallback, _choose_form

        page_url = "https://wlan.njmu.edu.cn/guest/wifi_login.php?_browser=1"
        with self.assertRaisesRegex(WirelessHttpFallback, "staged-form-script-changed"):
            _choose_form(
                NJMU_STAGED_FORM.replace("arr[0]['value'] + arr[2]['value']", "arr[0]['value']"),
                page_url,
                "student",
                "secret",
                "电信",
            )
        with self.assertRaises(PortalAllowlistError):
            _choose_form(
                NJMU_STAGED_FORM.replace(
                    "https://captiveportal-login.njmu.edu.cn/auth/index.html/u",
                    "https://example.test/collect",
                ),
                page_url,
                "student",
                "secret",
                "电信",
            )
        with self.assertRaisesRegex(WirelessHttpFallback, "staged-form-schema-changed"):
            _choose_form(
                NJMU_STAGED_FORM.replace(
                    '<input name="username" type="text">\n  <input name="password" type="password">',
                    '<input name="password" type="password">\n  <input name="username" type="text">',
                ),
                page_url,
                "student",
                "secret",
                "电信",
            )

    def test_client_redirect_refuses_non_school_target(self):
        from campus_net_assistant.edge import PortalAllowlistError
        from campus_net_assistant.wireless_http import _client_redirect

        with self.assertRaises(PortalAllowlistError):
            _client_redirect(
                '<meta http-equiv="Refresh" content="0; URL=https://example.test/collect">',
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
            )

    def test_bound_https_handler_uses_python_312_supported_arguments(self):
        from campus_net_assistant.wireless_http import _BoundHTTPSHandler

        handler = _BoundHTTPSHandler("192.0.2.10")
        request = urllib.request.Request(
            "https://wlan.njmu.edu.cn/guest/wifi_login.php"
        )
        with patch.object(handler, "do_open", return_value="opened") as do_open:
            self.assertEqual(handler.https_open(request), "opened")
        self.assertIn("context", do_open.call_args.kwargs)
        self.assertNotIn("check_hostname", do_open.call_args.kwargs)

    def test_bound_https_handler_pins_official_dns_and_keeps_tls_hostname(self):
        from campus_net_assistant.wireless_http import _BoundHTTPSHandler

        handler = _BoundHTTPSHandler(
            "192.0.2.10",
            {
                "wlan.njmu.edu.cn": "192.0.2.20",
                "captiveportal-login.njmu.edu.cn": "192.0.2.30",
                "example.test": "192.0.2.40",
            },
        )
        request = urllib.request.Request(
            "https://captiveportal-login.njmu.edu.cn/auth/index.html/u"
        )
        with (
            patch("campus_net_assistant.wireless_http.socket.create_connection") as connect,
            patch.object(handler, "do_open", side_effect=lambda factory, *_args, **_kwargs: factory(
                "captiveportal-login.njmu.edu.cn", timeout=3
            )),
        ):
            connection = handler.https_open(request)
            connection._create_connection(
                (connection.host, 443), connection.timeout, connection.source_address
            )
        self.assertEqual(connection.host, "captiveportal-login.njmu.edu.cn")
        self.assertEqual(connection.source_address, ("192.0.2.10", 0))
        self.assertEqual(connect.call_args.args[0], ("192.0.2.30", 443))
        self.assertEqual(connect.call_args.args[2], ("192.0.2.10", 0))

        with (
            patch("campus_net_assistant.wireless_http.socket.create_connection") as connect,
            patch.object(handler, "do_open", side_effect=lambda factory, *_args, **_kwargs: factory(
                "example.test", timeout=3
            )),
        ):
            other = handler.https_open(request)
            other._create_connection((other.host, 443), other.timeout, other.source_address)
        self.assertEqual(connect.call_args.args[0], ("example.test", 443))

    def test_transport_error_category_distinguishes_dns_without_logging_details(self):
        from campus_net_assistant.wireless_http import _transport_error_category

        error = urllib.error.URLError(socket.gaierror(11001, "secret-host failed"))
        self.assertEqual(_transport_error_category(error), "dns-resolution-failed")

    def test_form_parser_preserves_hidden_fields_and_matches_operator(self):
        from campus_net_assistant.wireless_http import _choose_form

        action, fields = _choose_form(
            WIRELESS_FORM,
            "https://wlan.njmu.edu.cn/guest/wifi_login.php?session=private",
            "student@example",
            "secret",
            "电信",
        )
        self.assertEqual(action, "https://wlan.njmu.edu.cn/guest/wifi_login.php")
        self.assertEqual(
            fields,
            [
                ("csrf", "opaque-value"),
                ("username", "student"),
                ("password", "secret"),
                ("service", "ctcc"),
            ],
        )

    def test_preflight_declines_captcha_and_client_side_password_transform(self):
        from campus_net_assistant.wireless_http import WirelessHttpFallback, _choose_form

        with self.assertRaisesRegex(WirelessHttpFallback, "captcha-observed"):
            _choose_form(
                WIRELESS_FORM.replace("</form>", '<input name="captcha">验证码</form>'),
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "student",
                "secret",
                "电信",
            )
        with self.assertRaisesRegex(WirelessHttpFallback, "password-transform"):
            _choose_form(
                WIRELESS_FORM + "<script>password = encrypt(password)</script>",
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "student",
                "secret",
                "电信",
            )
        with self.assertRaisesRegex(WirelessHttpFallback, "password-transform"):
            _choose_form(
                WIRELESS_FORM.replace(
                    "</form>",
                    '</form><script src="/static/password-encrypt.js"></script>',
                ),
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "student",
                "secret",
                "电信",
            )

    def test_form_action_must_remain_on_strict_credential_path(self):
        from campus_net_assistant.edge import PortalAllowlistError
        from campus_net_assistant.wireless_http import _choose_form

        hostile = WIRELESS_FORM.replace(
            'action="/guest/wifi_login.php"',
            'action="https://example.test/collect"',
        )
        with self.assertRaises(PortalAllowlistError):
            _choose_form(
                hostile,
                "https://wlan.njmu.edu.cn/guest/wifi_login.php",
                "student",
                "secret",
                "电信",
            )

    def test_http_provider_submits_once_and_requires_real_probe(self):
        from campus_net_assistant.wireless_http import login_wireless_http

        page_url = "https://wlan.njmu.edu.cn/guest/wifi_login.php"
        opener = _Opener([
            _Response(WIRELESS_FORM, page_url),
            _Response("<html>正在认证</html>", page_url),
        ])
        probes = iter((False, True))
        submitted = []
        with (
            patch(
                "campus_net_assistant.wireless_http._discover_login_url",
                return_value=page_url,
            ),
            patch("campus_net_assistant.wireless_http._add_routes", return_value=([], {})),
            patch("campus_net_assistant.wireless_http._delete_routes"),
            patch("campus_net_assistant.wireless_http.event"),
            patch("campus_net_assistant.wireless_http.append_connectivity_event"),
        ):
            result = login_wireless_http(
                "http://www.msftconnecttest.com/connecttest.txt",
                "student",
                "secret",
                "电信",
                lambda: next(probes),
                interface_ip="192.0.2.10",
                route_gateway="192.0.2.1",
                route_ifindex=15,
                dns_servers=("192.0.2.53",),
                submission_callback=submitted.append,
                opener=opener,
            )
        self.assertEqual(result["provider"], "wireless-http")
        self.assertEqual(len(submitted), 1)
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(opener.requests[1][0].get_method(), "POST")
        posted = opener.requests[1][0].data.decode("utf-8")
        self.assertIn("username=student", posted)
        self.assertIn("service=ctcc", posted)

    def test_http_provider_follows_school_redirect_and_posts_staged_fields_once(self):
        from campus_net_assistant.wireless_http import login_wireless_http

        page_url = "https://wlan.njmu.edu.cn/guest/wifi_login.php"
        submission_url = "https://captiveportal-login.njmu.edu.cn/auth/index.html/u"
        opener = _Opener([
            _Response(NJMU_REDIRECT, page_url),
            _Response(NJMU_STAGED_FORM, page_url + "?_browser=1"),
            _Response("<html><template>登录失败</template>正在认证</html>", submission_url),
        ])
        probes = iter((False, True))
        with (
            patch("campus_net_assistant.wireless_http._discover_login_url", return_value=page_url),
            patch("campus_net_assistant.wireless_http._add_routes", return_value=([], {})),
            patch("campus_net_assistant.wireless_http._delete_routes"),
            patch("campus_net_assistant.wireless_http.event"),
            patch("campus_net_assistant.wireless_http.append_connectivity_event"),
        ):
            result = login_wireless_http(
                "http://www.msftconnecttest.com/connecttest.txt",
                "student",
                "secret",
                "电信",
                lambda: next(probes),
                interface_ip="192.0.2.10",
                route_gateway="192.0.2.1",
                route_ifindex=15,
                dns_servers=("192.0.2.53",),
                opener=opener,
            )
        self.assertEqual(result["provider"], "wireless-http")
        self.assertEqual([req.get_method() for req, _ in opener.requests], ["GET", "GET", "POST"])
        self.assertEqual(opener.requests[-1][0].full_url, submission_url)
        self.assertEqual(
            opener.requests[-1][0].data.decode("utf-8"),
            "username=student%40ctcc&password=secret",
        )

    def test_http_provider_uses_wlan_resolved_addresses_and_logs_post_failure_phase(self):
        from campus_net_assistant.edge import LoginOutcomeUnknownError
        from campus_net_assistant.wireless_http import login_wireless_http

        page_url = "https://wlan.njmu.edu.cn/guest/wifi_login.php"
        resolved = {
            "wlan.njmu.edu.cn": "192.0.2.20",
            "captiveportal-login.njmu.edu.cn": "192.0.2.30",
        }
        opener = _Opener([_Response(NJMU_STAGED_FORM, page_url)])
        def fail_post(request, timeout):
            if request.get_method() == "POST":
                raise urllib.error.URLError(socket.gaierror(11001, "secret-host failed"))
            return _Response(NJMU_STAGED_FORM, page_url)
        opener.open = fail_post
        with (
            patch("campus_net_assistant.wireless_http._discover_login_url", return_value=page_url),
            patch("campus_net_assistant.wireless_http._add_routes", return_value=([], resolved)),
            patch("campus_net_assistant.wireless_http._delete_routes"),
            patch("campus_net_assistant.wireless_http._build_opener", return_value=opener) as build,
            patch("campus_net_assistant.wireless_http.event") as event,
            patch("campus_net_assistant.wireless_http.append_connectivity_event"),
        ):
            with self.assertRaises(LoginOutcomeUnknownError):
                login_wireless_http(
                    "http://www.msftconnecttest.com/connecttest.txt",
                    "student", "secret", "电信", lambda: False,
                    interface_ip="192.0.2.10", route_gateway="192.0.2.1",
                    route_ifindex=15, dns_servers=("192.0.2.53",),
                )
        build.assert_called_once_with("192.0.2.10", resolved)
        error_call = next(call for call in event.call_args_list if call.args[0] == "wireless-http-request-error")
        self.assertEqual(error_call.kwargs["request_phase"], "credential-request")
        self.assertEqual(error_call.kwargs["error_category"], "dns-resolution-failed")
        self.assertNotIn("secret-host", str(error_call))

    def test_controller_falls_back_only_for_pre_submission_decline(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.wireless_http import WirelessHttpFallback
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig(wireless_http_experimental=True)
        wlan = WlanInfo(
            "WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15, ("192.0.2.53",)
        )
        browser_result = {
            "login_submitted_at": "2026-09-23T12:00:00+08:00",
            "probe_succeeded_at": "2026-09-23T12:00:01+08:00",
        }
        with (
            patch(
                "campus_net_assistant.controller._wait_for_target_wlan",
                return_value=(wlan, False, "connected"),
            ),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("student", "secret")),
            patch(
                "campus_net_assistant.controller.login_wireless_http",
                side_effect=WirelessHttpFallback("captcha-observed"),
            ),
            patch("campus_net_assistant.controller.login", return_value=browser_result) as browser,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.append_connectivity_event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertTrue(do_login(config))
        browser.assert_called_once()

    def test_controller_does_not_fall_back_after_unknown_submitted_result(self):
        from campus_net_assistant.config import AppConfig
        from campus_net_assistant.controller import do_login
        from campus_net_assistant.edge import LoginOutcomeUnknownError
        from campus_net_assistant.wlan import WlanInfo

        config = AppConfig(wireless_http_experimental=True)
        wlan = WlanInfo("WLAN", "NJMU_WLAN", "192.0.2.10", "192.0.2.1", 15)
        with (
            patch(
                "campus_net_assistant.controller._wait_for_target_wlan",
                return_value=(wlan, False, "connected"),
            ),
            patch("campus_net_assistant.controller._connectivity_online", return_value=False),
            patch("campus_net_assistant.controller.load", return_value=("student", "secret")),
            patch(
                "campus_net_assistant.controller.login_wireless_http",
                side_effect=LoginOutcomeUnknownError("submitted-once"),
            ),
            patch("campus_net_assistant.controller.login") as browser,
            patch("campus_net_assistant.controller.event"),
            patch("campus_net_assistant.controller.write_status"),
        ):
            self.assertFalse(do_login(config))
        browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
