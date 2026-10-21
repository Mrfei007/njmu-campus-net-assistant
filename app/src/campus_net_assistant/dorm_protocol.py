"""Verified, offline-only pieces of the NJMU dorm Ethernet portal protocol.

No function in this module sends a request.  The operator API's dynamic query
field name is established, but its per-session value source and the initial
SSO page flow are not, so browser login remains the only active provider.
"""

from __future__ import annotations

import json
import urllib.parse

from .dorm_crypto import DormCryptoError, encrypt_dorm_sso_value


VERIFIED_OPERATOR_SERVICES = {"电信": "中国电信"}
DORM_PORTAL_HOST = "202.195.176.60"
DORM_PORTAL_ORIGIN = f"http://{DORM_PORTAL_HOST}"
SSO_LOGIN_PATH = "/cas-sso/login"
WORKFLOW_PATH = "/eportal/workFlow/getCurrentNode"
SERVICE_SELECTION_PATH = "/eportal/network/serviceSelection"
SERVICE_LOGIN_PATH = "/eportal/network/serviceLogin"
SERVICE_SELECTION_REFERER_PATH = "/portal/entry/pc/serviceSelection"
DYNAMIC_QUERY_FIELD = "ttbYz9WP"


class DormProtocolUnsupported(ValueError):
    """Observed portal data is incomplete or differs from the verified flow."""


def _session_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise DormProtocolUnsupported("宿舍门户会话参数无效")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise DormProtocolUnsupported("宿舍门户会话参数包含控制字符")
    return value


def _opaque_page_value(value: str, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise DormProtocolUnsupported(f"{description}无效")
    return value


def sso_login_action(page_url: str, *, accept_language: str) -> tuple[str, str]:
    """Copy this login page's query to its POST action, as the observed script does.

    Return the page's flowSessionId for later sessionId reuse.  This does not
    invent an initial session ID or generate the unexplained dynamic query key.
    """
    try:
        parsed = urllib.parse.urlsplit(page_url)
        if (
            parsed.scheme.lower() != "http"
            or parsed.hostname != DORM_PORTAL_HOST
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or parsed.path != SSO_LOGIN_PATH
            or len(page_url) > 4096
        ):
            raise DormProtocolUnsupported("宿舍门户登录页地址不是已核验的官方路径")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, AttributeError, TypeError) as error:
        raise DormProtocolUnsupported("宿舍门户登录页地址或查询项无效") from error
    sessions = [value for key, value in query if key == "flowSessionId"]
    if len(sessions) != 1:
        raise DormProtocolUnsupported("登录页缺少唯一的 flowSessionId")
    session_id = _session_id(sessions[0])
    if not isinstance(accept_language, str) or not accept_language or len(accept_language) > 64:
        raise DormProtocolUnsupported("登录页语言参数无效")
    if not all(char.isalnum() or char in "-,;=. " for char in accept_language):
        raise DormProtocolUnsupported("登录页语言参数无效")
    if any(key == "accept-language" for key, _ in query):
        raise DormProtocolUnsupported("登录页已有重复的语言查询项")
    query.append(("accept-language", accept_language))
    action = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, SSO_LOGIN_PATH, urllib.parse.urlencode(query), "")
    )
    return action, session_id


def portal_api_request_url(path: str, *, dynamic_value: str) -> str:
    """Build an observed API POST target from a fresh, externally supplied value.

    The value source is intentionally outside this module until it is observed.
    """
    if path not in {WORKFLOW_PATH, SERVICE_SELECTION_PATH, SERVICE_LOGIN_PATH}:
        raise DormProtocolUnsupported("宿舍门户接口路径未经现场验证")
    dynamic_value = _opaque_page_value(dynamic_value, "门户接口动态查询值")
    query = urllib.parse.urlencode({DYNAMIC_QUERY_FIELD: dynamic_value})
    return f"{DORM_PORTAL_ORIGIN}{path}?{query}"


def operator_request_url(path: str, *, dynamic_value: str) -> str:
    if path not in {SERVICE_SELECTION_PATH, SERVICE_LOGIN_PATH}:
        raise DormProtocolUnsupported("宿舍门户运营商接口路径未经现场验证")
    return portal_api_request_url(path, dynamic_value=dynamic_value)


def workflow_request_fields(session_id: str, flow_key: str) -> dict[str, str]:
    """Return verified field names without guessing the unknown body encoding."""
    return {
        "flowKey": _opaque_page_value(flow_key, "宿舍门户工作流参数"),
        "sessionId": _session_id(session_id),
    }


def workflow_response_accepted(
    http_status: int,
    body: bytes,
    *,
    session_id: str,
    flow_key: str,
) -> bool:
    """Require the observed success code and continuity of both workflow values."""
    if http_status != 200:
        return False
    try:
        result = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False
    data = result.get("data") if isinstance(result, dict) else None
    return (
        type(result.get("code")) is int
        and result["code"] == 200
        and isinstance(data, dict)
        and data.get("sessionId") == session_id
        and data.get("flowKey") == flow_key
    )


def operator_request_metadata_accepted(
    url: str,
    headers: dict[str, str],
) -> bool:
    """Check the shape actually observed in a successful browser session.

    This is an observation check, not a claim that every header is mandatory
    to the server. Header values are never returned or logged.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, AttributeError, TypeError):
        return False
    if (
        parsed.scheme.lower() != "http"
        or parsed.hostname != DORM_PORTAL_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
        or parsed.path not in {SERVICE_SELECTION_PATH, SERVICE_LOGIN_PATH}
        or len(query) != 1
        or query[0][0] != DYNAMIC_QUERY_FIELD
        or not query[0][1]
    ):
        return False
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    if normalized.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return False
    if normalized.get("origin", "").rstrip("/") != DORM_PORTAL_ORIGIN:
        return False
    referer = urllib.parse.urlsplit(normalized.get("referer", ""))
    if (
        referer.scheme.lower() != "http"
        or referer.hostname != DORM_PORTAL_HOST
        or referer.path != SERVICE_SELECTION_REFERER_PATH
    ):
        return False
    return "isportal" in normalized


def service_selection_body(session_id: str) -> bytes:
    """Encode the observed application/json request body; do not log its value."""
    return json.dumps({"sessionId": _session_id(session_id)}, separators=(",", ":")).encode("utf-8")


def sso_login_body(
    username: str,
    password: str,
    *,
    croypto: str,
    execution: str,
    event_id: str,
    login_type: str,
    geolocation: str = "",
    captcha_required: bool = False,
) -> bytes:
    """Encode the observed form fields using values from this very SSO page.

    The caller must verify the official form action and obtain every page value
    fresh; nothing here performs HTTP or caches a session token.
    """
    account = username.strip().split("@", 1)[0] if isinstance(username, str) else ""
    if not account or not password or not isinstance(password, str):
        raise DormProtocolUnsupported("宿舍门户账号或密码为空")
    if password != password.strip():
        raise DormProtocolUnsupported("密码首尾空白的页面处理尚未确认")
    if captcha_required:
        raise DormProtocolUnsupported("宿舍门户要求验证码，不能自动提交")
    if not all(isinstance(value, str) and value for value in (croypto, execution, event_id, login_type)):
        raise DormProtocolUnsupported("宿舍门户页面缺少本次会话所需参数")
    if not isinstance(geolocation, str):
        raise DormProtocolUnsupported("宿舍门户地理位置字段无效")
    try:
        encrypted_password = encrypt_dorm_sso_value(password, croypto)
        encrypted_captcha = encrypt_dorm_sso_value("{}", croypto)
    except DormCryptoError as error:
        raise DormProtocolUnsupported("宿舍门户本次页面加密参数无效") from error
    fields = (
        ("username", account),
        ("password", encrypted_password),
        ("type", login_type),
        ("_eventId", event_id),
        ("geolocation", geolocation),
        ("execution", execution),
        ("captcha_code", ""),
        ("croypto", croypto),
        ("captcha_payload", encrypted_captcha),
    )
    return urllib.parse.urlencode(fields).encode("utf-8")


def service_login_body(session_id: str, operator: str) -> bytes:
    """Only the telecom service value has been observed in a successful POST."""
    try:
        service = VERIFIED_OPERATOR_SERVICES[operator]
    except (KeyError, TypeError) as error:
        raise DormProtocolUnsupported("所选运营商尚无现场验证的宿舍门户服务值") from error
    return json.dumps(
        {"service": service, "sessionId": _session_id(session_id)},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def service_selection_accepted(http_status: int, body: bytes) -> bool:
    """HTTP 200 and an integer JSON code=200 are both required."""
    if http_status != 200:
        return False
    try:
        result = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False
    return isinstance(result, dict) and type(result.get("code")) is int and result["code"] == 200


def service_login_accepted(http_status: int, body: bytes) -> bool:
    """Portal acceptance only; a separate real internet probe remains mandatory."""
    if http_status != 200:
        return False
    try:
        result = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False
    if not isinstance(result, dict) or type(result.get("code")) is not int or result["code"] != 200:
        return False
    data = result.get("data")
    return isinstance(data, dict) and data.get("authResult") == "success"
