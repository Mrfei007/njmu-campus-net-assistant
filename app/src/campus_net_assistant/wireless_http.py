from __future__ import annotations

import http.client
import http.cookiejar
import html
import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser

from .edge import (
    AuthenticationRejectedError,
    LoginOutcomeUnknownError,
    PortalAllowlistError,
    WIRELESS_LOGIN_HOST,
    WIRELESS_PORTAL_HOST,
    _add_routes,
    _authentication_rejection,
    _delete_routes,
    _discover_login_url,
    _portal_url_allowed,
)
from .logging_redacted import append_connectivity_event, event
from .product import EVENT_SOURCE


MAX_RESPONSE_BYTES = 1024 * 1024
USER_AGENT = "NJMUCampusNetAssistant/experimental-wireless-http"
SUPPORTED_ENCTYPE = "application/x-www-form-urlencoded"
CAPTCHA_PATTERN = re.compile(
    r"captcha|verify(?:code)?|verification|checkcode|验证码|校验码",
    re.IGNORECASE,
)
CLIENT_TRANSFORM_PATTERN = re.compile(
    r"(?:encrypt|\b(?:rsa|aes|des)\b|cryptojs|md5|sha\s*[-_]?\s*(?:1|256)|"
    r"setpassword|password\s*=\s*[^;]+\()",
    re.IGNORECASE,
)
OPERATOR_ALIASES = {
    "电信": ("电信", "中国电信", "telecom", "ctcc", "@ctcc"),
    "移动": ("移动", "中国移动", "mobile", "cmcc", "@cmcc"),
    "联通": ("联通", "中国联通", "unicom", "cucc", "@cucc"),
    "校园网": ("校园网", "校园", "campus", "local"),
}
NJMU_OPERATOR_SUFFIXES = {
    "电信": "@ctcc",
    "移动": "@cmcc",
    "联通": "@cucc",
    "校园网": "@internet",
}
NJMU_SUBMISSION_URL = "https://captiveportal-login.njmu.edu.cn/auth/index.html/u"


class WirelessHttpFallback(RuntimeError):
    """The experimental provider declined before sending credentials."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Option:
    value: str
    label: str = ""
    selected: bool = False


@dataclass
class _Control:
    tag: str
    name: str
    identifier: str = ""
    type: str = "text"
    value: str = ""
    checked: bool = False
    options: list[_Option] = field(default_factory=list)


@dataclass
class _Form:
    action: str
    method: str
    enctype: str
    identifier: str = ""
    controls: list[_Control] = field(default_factory=list)


class _PortalFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self._form: _Form | None = None
        self._select: _Control | None = None
        self._option: _Option | None = None
        self._option_text: list[str] = []
        self._in_script = False
        self.script_text: list[str] = []
        self.captcha_observed = False
        self.client_transform_observed = False

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(key).lower(): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = self._attrs(attrs)
        tag = tag.lower()
        if tag == "form":
            if self._form is not None:
                self.captcha_observed = True
                return
            self._form = _Form(
                action=values.get("action", ""),
                method=values.get("method", "get").lower(),
                enctype=values.get("enctype", SUPPORTED_ENCTYPE).lower(),
                identifier=values.get("id", ""),
            )
            if CLIENT_TRANSFORM_PATTERN.search(values.get("onsubmit", "")):
                self.client_transform_observed = True
            return
        if tag == "script":
            self._in_script = True
            if CLIENT_TRANSFORM_PATTERN.search(values.get("src", "")):
                self.client_transform_observed = True
        combined = " ".join(
            values.get(key, "") for key in ("name", "id", "src", "alt", "title", "class")
        )
        if CAPTCHA_PATTERN.search(combined):
            self.captcha_observed = True
        if CLIENT_TRANSFORM_PATTERN.search(
            " ".join(values.get(key, "") for key in ("onclick", "onchange", "onblur"))
        ):
            self.client_transform_observed = True
        if self._form is None:
            return
        if tag == "input":
            self._form.controls.append(
                _Control(
                    tag="input",
                    name=values.get("name", ""),
                    identifier=values.get("id", ""),
                    type=values.get("type", "text").lower(),
                    value=values.get("value", ""),
                    checked="checked" in values,
                )
            )
        elif tag == "select":
            self._select = _Control(
                tag="select",
                name=values.get("name", ""),
                identifier=values.get("id", ""),
                type="select",
            )
            self._form.controls.append(self._select)
        elif tag == "option" and self._select is not None:
            self._option = _Option(
                value=values.get("value", ""),
                selected="selected" in values,
            )
            self._option_text = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_text.append(data)
        if self._option is not None:
            self._option_text.append(data)
        if CAPTCHA_PATTERN.search(data):
            self.captcha_observed = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script":
            self._in_script = False
        elif tag == "option" and self._option is not None and self._select is not None:
            self._option.label = " ".join("".join(self._option_text).split())
            if not self._option.value:
                self._option.value = self._option.label
            self._select.options.append(self._option)
            self._option = None
            self._option_text = []
        elif tag == "select":
            self._select = None
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


class _BoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, interface_ip: str, resolved_hosts: dict[str, str] | None = None):
        super().__init__()
        self.interface_ip = interface_ip
        self.resolved_hosts = _official_resolved_hosts(resolved_hosts)

    def http_open(self, request):
        interface_ip = self.interface_ip

        class Connection(http.client.HTTPConnection):
            def __init__(self, host, **kwargs):
                kwargs["source_address"] = (interface_ip, 0)
                super().__init__(host, **kwargs)
                _pin_connection_dns(self, resolved_hosts)

        resolved_hosts = self.resolved_hosts
        return self.do_open(Connection, request)


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, interface_ip: str, resolved_hosts: dict[str, str] | None = None):
        super().__init__(context=ssl.create_default_context())
        self.interface_ip = interface_ip
        self.resolved_hosts = _official_resolved_hosts(resolved_hosts)

    def https_open(self, request):
        interface_ip = self.interface_ip

        class Connection(http.client.HTTPSConnection):
            def __init__(self, host, **kwargs):
                kwargs["source_address"] = (interface_ip, 0)
                super().__init__(host, **kwargs)
                _pin_connection_dns(self, resolved_hosts)

        resolved_hosts = self.resolved_hosts
        return self.do_open(
            Connection,
            request,
            context=self._context,
        )


class _OfficialRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        normalized = urllib.parse.urljoin(request.full_url, newurl)
        if not _portal_url_allowed(normalized, False):
            raise PortalAllowlistError("无浏览器认证被重定向到官方允许列表之外")
        return super().redirect_request(request, fp, code, msg, headers, normalized)


def _official_resolved_hosts(resolved_hosts: dict[str, str] | None) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for host in (WIRELESS_LOGIN_HOST, WIRELESS_PORTAL_HOST):
        address = (resolved_hosts or {}).get(host)
        if not address:
            continue
        try:
            pinned[host] = str(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError as error:
            raise WirelessHttpFallback("portal-resolved-address-invalid") from error
    return pinned


def _pin_connection_dns(connection, resolved_hosts: dict[str, str]) -> None:
    original = connection._create_connection

    def create_connection(address, timeout=None, source_address=None):
        hostname, port = address
        pinned_address = resolved_hosts.get(str(hostname).lower().rstrip("."))
        target = (pinned_address or hostname, port)
        return original(target, timeout, source_address)

    connection._create_connection = create_connection


def _build_opener(interface_ip: str, resolved_hosts: dict[str, str] | None = None):
    cookie_jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _BoundHTTPHandler(interface_ip, resolved_hosts),
        _BoundHTTPSHandler(interface_ip, resolved_hosts),
        _OfficialRedirectHandler(),
        urllib.request.HTTPCookieProcessor(cookie_jar),
    )


def _transport_error_category(error: Exception) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"http-status-{error.code}"
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "certificate-verification-failed"
    if isinstance(reason, ssl.SSLError):
        return "tls-error"
    if isinstance(reason, socket.gaierror):
        return "dns-resolution-failed"
    if isinstance(reason, TimeoutError):
        return "timeout"
    if isinstance(reason, ConnectionRefusedError):
        return "connection-refused"
    if isinstance(reason, OSError):
        return f"os-error-{reason.errno}"
    return type(reason).__name__


def _read_response(response) -> tuple[str, str, int]:
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise WirelessHttpFallback("portal-response-too-large")
    content_type = response.headers.get_content_charset() or "utf-8"
    body = payload.decode(content_type, errors="replace")
    return body, response.geturl(), int(getattr(response, "status", 200) or 200)


def _normalized(value: str) -> str:
    return re.sub(r"\s+", "", value or "").strip().lower()


def _operator_matches(operator: str, *values: str) -> bool:
    aliases = OPERATOR_ALIASES.get(operator, (operator,))
    normalized_values = tuple(_normalized(value) for value in values)
    return any(
        _normalized(alias) in value
        for alias in aliases
        for value in normalized_values
        if value
    )


def _staged_form(
    parser: _PortalFormParser, page_url: str, username: str, password: str, operator: str
) -> tuple[str, list[tuple[str, str]]]:
    forms = {form.identifier: form for form in parser.forms}
    if len(parser.forms) != 2 or set(forms) != {"form1", "cp_form"}:
        raise WirelessHttpFallback("credential-form-not-unique")
    source, destination = forms["form1"], forms["cp_form"]
    source_controls = {(item.tag, item.name, item.type): item for item in source.controls if item.name}
    destination_controls = {(item.tag, item.name, item.type): item for item in destination.controls if item.name}
    expected_source = [
        ("input", "username", "text"),
        ("input", "password", "password"),
        ("select", "zrhs", "select"),
    ]
    expected_destination = [
        ("input", "username", "text"),
        ("input", "password", "password"),
    ]
    if (
        [(item.tag, item.name, item.type) for item in source.controls] != expected_source
        or [(item.tag, item.name, item.type) for item in destination.controls] != expected_destination
        or source.method != "get"
        or destination.method != "post"
        or destination.enctype.split(";", 1)[0].strip() != SUPPORTED_ENCTYPE
        or destination_controls[("input", "username", "text")].identifier != "cp_user"
        or destination_controls[("input", "password", "password")].identifier != "cp_password"
    ):
        raise WirelessHttpFallback("staged-form-schema-changed")
    action_url = urllib.parse.urljoin(page_url, destination.action)
    if action_url != NJMU_SUBMISSION_URL:
        raise PortalAllowlistError("无浏览器认证的最终提交地址不是已核验的学校地址")
    script = re.sub(r"\s+", "", "\n".join(parser.script_text))
    expected_script_parts = (
        "$('#form1').serializeArray()",
        "$('#cp_user').val(arr[0]['value']+arr[2]['value'])",
        "$('#cp_password').val(arr[1]['value'])",
        "$('#cp_form').submit()",
    )
    if not all(part in script for part in expected_script_parts):
        raise WirelessHttpFallback("staged-form-script-changed")
    suffix = NJMU_OPERATOR_SUFFIXES.get(operator)
    service = source_controls[("select", "zrhs", "select")]
    if not suffix or not any(
        option.value == suffix and _operator_matches(operator, option.label, option.value)
        for option in service.options
    ):
        raise WirelessHttpFallback("operator-control-not-matched")
    account = username.strip().split("@", 1)[0]
    if not account or not password:
        raise WirelessHttpFallback("credentials-empty")
    return action_url, [("username", account + suffix), ("password", password)]


def _choose_form(html_text: str, page_url: str, username: str, password: str, operator: str):
    parser = _PortalFormParser()
    parser.feed(html_text)
    parser.close()
    if parser.captcha_observed:
        raise WirelessHttpFallback("captcha-observed")
    if parser.client_transform_observed or CLIENT_TRANSFORM_PATTERN.search(
        "\n".join(parser.script_text)
    ):
        raise WirelessHttpFallback("client-side-password-transform-observed")
    candidates = [
        form for form in parser.forms
        if any(control.type == "password" and control.name for control in form.controls)
    ]
    if len(candidates) == 2:
        return _staged_form(parser, page_url, username, password, operator)
    if len(candidates) != 1:
        raise WirelessHttpFallback("credential-form-not-unique")
    form = candidates[0]
    if form.method != "post":
        raise WirelessHttpFallback("credential-form-method-unsupported")
    if form.enctype.split(";", 1)[0].strip() != SUPPORTED_ENCTYPE:
        raise WirelessHttpFallback("credential-form-enctype-unsupported")
    action_url = urllib.parse.urljoin(page_url, form.action or page_url)
    if not _portal_url_allowed(action_url, False, credentials=True):
        raise PortalAllowlistError("无浏览器认证表单提交地址不在官方凭据允许列表内")
    if urllib.parse.urlparse(action_url).scheme.lower() != "https":
        raise WirelessHttpFallback("credential-form-not-https")

    passwords = [item for item in form.controls if item.type == "password" and item.name]
    accounts = [
        item for item in form.controls
        if item.name and item.type not in {"hidden", "password", "submit", "button", "checkbox", "radio"}
        and item.tag == "input"
    ]
    if len(passwords) != 1 or not accounts:
        raise WirelessHttpFallback("credential-fields-not-supported")
    account = sorted(
        accounts,
        key=lambda item: 0 if re.search(r"user|account|login|学号|账号", item.name, re.IGNORECASE) else 1,
    )[0]

    fields: list[tuple[str, str]] = []
    operator_matched = False
    for control in form.controls:
        if not control.name:
            continue
        if control is account:
            fields.append((control.name, username.strip().split("@", 1)[0]))
        elif control is passwords[0]:
            fields.append((control.name, password))
        elif control.type == "hidden":
            fields.append((control.name, control.value))
        elif control.tag == "select":
            option = next(
                (item for item in control.options if _operator_matches(operator, item.label, item.value)),
                None,
            )
            if option is not None:
                fields.append((control.name, option.value))
                operator_matched = True
            else:
                selected = next((item for item in control.options if item.selected), None)
                if selected is not None:
                    fields.append((control.name, selected.value))
        elif control.type == "radio" and _operator_matches(
            operator, control.name, control.value
        ):
            fields.append((control.name, control.value))
            operator_matched = True
        elif control.type == "checkbox" and control.checked:
            fields.append((control.name, control.value or "on"))
    if not operator_matched:
        raise WirelessHttpFallback("operator-control-not-matched")
    return action_url, fields


def _client_redirect(body: str, page_url: str) -> str | None:
    targets: list[str] = []
    for tag in re.findall(r"<meta\b[^>]*>", body, re.IGNORECASE | re.DOTALL):
        if not re.search(r"http-equiv\s*=\s*(['\"]?)refresh\1", tag, re.IGNORECASE):
            continue
        content = re.search(r"content\s*=\s*(['\"])(.*?)\1", tag, re.IGNORECASE | re.DOTALL)
        if content:
            match = re.search(r"(?:^|;)\s*url\s*=\s*(.+)$", content.group(2), re.IGNORECASE)
            if match:
                targets.append(match.group(1).strip())
    for match in re.finditer(
        r"(?:window\.)?(?:top\.)?location(?:\.href)?\s*=\s*(['\"])(.*?)\1",
        body,
        re.IGNORECASE | re.DOTALL,
    ):
        targets.append(match.group(2).replace("\\/", "/"))
    if not targets:
        return None
    urls = [urllib.parse.urljoin(page_url, html.unescape(value.strip().strip("'\""))) for value in targets]
    if len(set(urls)) != 1:
        raise WirelessHttpFallback("portal-client-redirect-ambiguous")
    target = urls[0]
    parsed = urllib.parse.urlparse(target)
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != WIRELESS_LOGIN_HOST
        or parsed.path.lower() != "/guest/wifi_login.php"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise PortalAllowlistError("无浏览器认证的页面内跳转不在学校无线凭据页")
    return target


def _preflight_page(session, login_url: str) -> tuple[str, str]:
    visited: set[str] = set()
    current_url = login_url
    for _ in range(3):
        if current_url in visited:
            raise WirelessHttpFallback("portal-client-redirect-loop")
        visited.add(current_url)
        with _request(session, current_url) as response:
            body, response_url, status = _read_response(response)
        if status >= 400:
            raise WirelessHttpFallback("portal-preflight-http-error")
        if not _portal_url_allowed(response_url, False, credentials=True):
            raise PortalAllowlistError("无浏览器认证凭据页面不在官方允许列表内")
        if urllib.parse.urlparse(response_url).scheme.lower() != "https":
            raise WirelessHttpFallback("credential-page-not-https")
        redirect = _client_redirect(body, response_url)
        if redirect is None:
            return body, response_url
        current_url = redirect
    raise WirelessHttpFallback("portal-client-redirect-limit")


def _request(opener, url: str, *, data: bytes | None = None):
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            **({"Content-Type": SUPPORTED_ENCTYPE} if data is not None else {}),
        },
        method="POST" if data is not None else "GET",
    )
    return opener.open(request, timeout=15)


def login_wireless_http(
    portal_url: str,
    username: str,
    password: str,
    operator: str,
    probe,
    *,
    interface_ip: str,
    route_gateway: str,
    route_ifindex: int,
    dns_servers: tuple[str, ...],
    wait_seconds: int = 30,
    submission_callback=None,
    opener=None,
) -> dict:
    """Attempt the restricted NJMU wireless form without launching a browser.

    Any unsupported page characteristic aborts before credential submission so
    the caller may safely fall back to the existing Chromium flow. Once a POST
    is attempted, an uncertain result is terminal for this recovery round.
    """
    routes: list[str] = []
    submitted_at: str | None = None
    request_phase = "preflight"
    try:
        login_url = _discover_login_url(interface_ip, portal_url, dorm_ethernet_flow=False)
        if not _portal_url_allowed(login_url, False, credentials=True):
            raise PortalAllowlistError("无浏览器认证最终页面不在官方凭据允许列表内")
        if urllib.parse.urlparse(login_url).scheme.lower() != "https":
            raise WirelessHttpFallback("credential-page-not-https")
        routes, resolved_hosts = _add_routes(
            [WIRELESS_LOGIN_HOST, WIRELESS_PORTAL_HOST],
            route_gateway,
            route_ifindex,
            interface_ip=interface_ip,
            dns_servers=dns_servers,
        )
        session = opener or _build_opener(interface_ip, resolved_hosts)
        body, response_url = _preflight_page(session, login_url)
        if probe():
            confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
            return {
                "login_submitted_at": None,
                "probe_succeeded_at": confirmed_at,
                "provider": "wireless-http",
                "login_page_retained": False,
            }
        action_url, fields = _choose_form(body, response_url, username, password, operator)
        encoded = urllib.parse.urlencode(fields).encode("utf-8")
        submitted_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
        if submission_callback is not None:
            submission_callback(submitted_at)
        append_connectivity_event(
            "login-submitted",
            source=EVENT_SOURCE,
            login_submitted_at=submitted_at,
            provider="wireless-http",
        )
        event(
            "login-submitted",
            True,
            "无浏览器通道已开始发送一次登录请求，结果待确认",
            login_submitted_at=submitted_at,
            provider="wireless-http",
        )
        request_phase = "credential-request"
        with _request(session, action_url, data=encoded) as response:
            request_phase = "credential-response"
            result_body, _, _ = _read_response(response)
        request_phase = "connectivity-probe"
        rejection = _authentication_rejection(re.sub(r"<[^>]+>", " ", result_body))
        deadline = time.monotonic() + max(1, wait_seconds)
        while time.monotonic() < deadline:
            if probe():
                confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
                return {
                    "login_submitted_at": submitted_at,
                    "probe_succeeded_at": confirmed_at,
                    "provider": "wireless-http",
                    "login_page_retained": False,
                }
            time.sleep(1)
        if rejection:
            raise AuthenticationRejectedError(rejection, submitted=True)
        raise LoginOutcomeUnknownError("无浏览器通道已提交一次，但真实联网探测未确认结果")
    except (AuthenticationRejectedError, LoginOutcomeUnknownError, PortalAllowlistError):
        raise
    except WirelessHttpFallback:
        raise
    except Exception as error:
        event(
            "wireless-http-request-error",
            False,
            "无浏览器通道遇到网络或响应错误",
            provider="wireless-http",
            request_phase=request_phase,
            error_category=_transport_error_category(error),
            credential_attempt_recorded=submitted_at is not None,
        )
        if submitted_at is not None:
            raise LoginOutcomeUnknownError(
                f"无浏览器通道提交后发生 {type(error).__name__}，本轮停止再次提交"
            ) from error
        raise WirelessHttpFallback(f"preflight-{type(error).__name__}") from error
    finally:
        _delete_routes(routes, route_gateway, route_ifindex)
