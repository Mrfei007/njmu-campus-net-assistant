"""Offline, credential-free checks for a captured dorm portal page pair.

This module performs no HTTP requests.  In particular it cannot turn a portal
entry URL into an SSO page URL while the initial workflow remains unexplained.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .dorm_protocol import DORM_PORTAL_HOST, DormProtocolUnsupported, sso_login_action


@dataclass(frozen=True)
class DormPreflightSnapshot:
    """Fresh page values kept in memory only; never serialize or log this object."""

    action_url: str = field(repr=False)
    session_id: str = field(repr=False)
    croypto: str = field(repr=False)
    execution: str = field(repr=False)
    event_id: str = field(repr=False)
    login_type: str = field(repr=False)
    geolocation: str = field(repr=False)


class _SsoPageParser(HTMLParser):
    TEXT_IDS = {"login-croypto", "login-page-flowkey"}
    FORM_FIELDS = {"_eventId", "type", "geolocation"}
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.texts: dict[str, list[str]] = {}
        self.inputs: dict[str, list[str]] = {}
        self._active_id: str | None = None
        self._active_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if self._active_id is not None and tag not in self.VOID_TAGS:
            self._active_depth += 1
        elif values.get("id") in self.TEXT_IDS:
            self._active_id = values["id"]
            self._active_depth = 1
            self.texts.setdefault(self._active_id, []).append("")
        if tag == "input" and values.get("name") in self.FORM_FIELDS:
            self.inputs.setdefault(values["name"], []).append(values.get("value") or "")

    def handle_data(self, data: str) -> None:
        if self._active_id is not None:
            self.texts[self._active_id][-1] += data

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self._active_id is not None:
            self._active_depth -= 1
            if self._active_depth <= 0:
                self._active_id = None
                self._active_depth = 0


def _portal_main_session(page_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(page_url)
        if (
            parsed.scheme.lower() != "http"
            or parsed.hostname != DORM_PORTAL_HOST
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or parsed.path != "/portal/portal-main"
            or len(page_url) > 4096
        ):
            raise DormProtocolUnsupported("门户入口不是已核验的官方页面")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, AttributeError, TypeError) as error:
        raise DormProtocolUnsupported("门户入口地址无效") from error
    sessions = [value for key, value in query if key == "sessionId"]
    if len(sessions) != 1 or not sessions[0] or len(sessions[0]) > 1024:
        raise DormProtocolUnsupported("门户入口缺少唯一的 sessionId")
    if any(ord(char) < 33 or ord(char) == 127 for char in sessions[0]):
        raise DormProtocolUnsupported("门户入口会话参数无效")
    return sessions[0]


def discover_dorm_entry_url(interface_ip: str, *, discover=None) -> str:
    """Read only the existing portal redirects, then require a known entry URL.

    The existing discoverer issues unauthenticated reads bound to the selected
    interface.  It never submits a username or password.  Nothing in this
    function guesses the subsequent SSO navigation or sends a POST.
    """
    try:
        ipaddress.IPv4Address(interface_ip)
    except (ipaddress.AddressValueError, TypeError) as error:
        raise DormProtocolUnsupported("有线网接口地址无效") from error
    if discover is None:
        from .edge import DORM_ETHERNET_PORTAL_URL, _discover_login_url

        entry_url = _discover_login_url(
            interface_ip, DORM_ETHERNET_PORTAL_URL, dorm_ethernet_flow=True
        )
    else:
        entry_url = discover(interface_ip)
    _portal_main_session(entry_url)
    return entry_url


def inspect_dorm_pages(
    portal_main_url: str,
    sso_page_url: str,
    sso_html: str,
    *,
    accept_language: str,
) -> DormPreflightSnapshot:
    """Validate a same-session page pair without sending any network request.

    The caller must obtain both URLs and the HTML from the current session.
    This function does not infer a missing URL, token, query field or header.
    """
    entry_session = _portal_main_session(portal_main_url)
    action_url, sso_session = sso_login_action(sso_page_url, accept_language=accept_language)
    if entry_session != sso_session:
        raise DormProtocolUnsupported("门户入口与登录页的会话参数不一致")
    if not isinstance(sso_html, str) or len(sso_html) > 1024 * 1024:
        raise DormProtocolUnsupported("宿舍登录页面内容无效或过大")
    parser = _SsoPageParser()
    parser.feed(sso_html)
    parser.close()
    for identifier in parser.TEXT_IDS:
        values = parser.texts.get(identifier, [])
        if len(values) != 1 or not values[0].strip():
            raise DormProtocolUnsupported("宿舍登录页面缺少唯一的动态参数")
    for name in parser.FORM_FIELDS:
        if len(parser.inputs.get(name, [])) != 1:
            raise DormProtocolUnsupported("宿舍登录页面缺少唯一的固定表单字段")
    if not parser.inputs["_eventId"][0] or not parser.inputs["type"][0]:
        raise DormProtocolUnsupported("宿舍登录页面固定表单字段为空")
    return DormPreflightSnapshot(
        action_url=action_url,
        session_id=sso_session,
        croypto=parser.texts["login-croypto"][0].strip(),
        execution=parser.texts["login-page-flowkey"][0].strip(),
        event_id=parser.inputs["_eventId"][0],
        login_type=parser.inputs["type"][0],
        geolocation=parser.inputs["geolocation"][0],
    )
