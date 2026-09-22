from __future__ import annotations

import json
import html
import ipaddress
import re
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from .config import APP_DIR
from .logging_redacted import append_connectivity_event, event
from .product import EVENT_SOURCE

try:
    import websocket
except ImportError as error:  # pragma: no cover - exercised only on an incomplete install
    websocket = None
    WEBSOCKET_ERROR = error
else:
    WEBSOCKET_ERROR = None


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
EDGE_PROFILE_ROOT = APP_DIR / "edge-login-profile"
EDGE_CDP_PORTS_PATH = EDGE_PROFILE_ROOT.parent / "edge-cdp-ports.json"
DORM_ETHERNET_PORTAL_URL = "http://202.195.176.60"
DORM_LOGOUT_PROFILE_ROOT = APP_DIR / "edge-dorm-logout-profile"
WIRELESS_PORTAL_HOST = "captiveportal-login.njmu.edu.cn"
WIRELESS_LOGIN_HOST = "wlan.njmu.edu.cn"
DORM_PORTAL_HOST = "202.195.176.60"
DORM_STAGE_DIAGNOSTIC_INTERVAL_SECONDS = 30.0
WIRELESS_NAVIGATION_PATHS = {
    WIRELESS_LOGIN_HOST: ("/guest/",),
    WIRELESS_PORTAL_HOST: ("/auth/",),
}
DORM_NAVIGATION_PATHS = ("/eportal/", "/portal/", "/cas-sso/", "/sam-sso/")
WIRELESS_CREDENTIAL_PATHS = {
    WIRELESS_LOGIN_HOST: ("/guest/wifi_login.php",),
}
class EdgeLoginError(RuntimeError):
    pass


class AuthenticationRejectedError(EdgeLoginError):
    def __init__(self, reason: str, *, submitted: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.submitted = submitted


class PortalAllowlistError(EdgeLoginError):
    pass


class LoginOutcomeUnknownError(EdgeLoginError):
    """Credentials were submitted once, but neither success nor rejection was proved."""

    pass


class CdpHandshakeRejectedError(EdgeLoginError):
    def __init__(self, status_code: int | None):
        super().__init__(f"Edge CDP WebSocket 握手被拒绝（HTTP {status_code or 'unknown'}）")
        self.status_code = status_code


AUTHENTICATION_REJECTION_PATTERNS = (
    ("credentials-invalid", r"账号或密码(?:错误|不正确|无效)"),
    ("credentials-invalid", r"用户名或密码(?:错误|不正确|无效)"),
    ("credentials-invalid", r"invalid\s+(?:user|username)\s+or\s+password"),
    ("account-invalid", r"(?:账号|用户名|用户)(?:不存在|错误|无效|未注册|已停用|已禁用|被冻结|被锁定)"),
    ("account-invalid", r"invalid\s+(?:user|username|account)|user\s+not\s+found|unknown\s+user"),
    ("password-invalid", r"(?:密码|口令)(?:错误|不正确|无效|已过期)"),
    ("password-invalid", r"invalid\s+password|incorrect\s+password|wrong\s+password"),
    ("credentials-invalid", r"认证失败|登录失败|authentication\s+failed"),
    ("credentials-invalid", r"invalid\s+credentials"),
)


def _authentication_rejection(text: str) -> str | None:
    normalized = re.sub(r"\s+", " ", text or "").strip()
    for reason, pattern in AUTHENTICATION_REJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return reason
    return None


def _path_allowed(path: str, allowed_paths: tuple[str, ...]) -> bool:
    normalized = "/" + path.lstrip("/")
    lowered = normalized.lower()
    for allowed in allowed_paths:
        rule = allowed.lower()
        if rule.endswith("/"):
            if lowered.startswith(rule):
                return True
        elif lowered == rule or lowered.startswith(rule + "/"):
            return True
    return False


def _portal_url_allowed(url: str, dorm_ethernet_flow: bool, *, credentials: bool = False) -> bool:
    """Allow official navigation origins while keeping credential paths strict."""
    parsed = urllib.parse.urlparse(url or "")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    path = parsed.path or "/"
    if dorm_ethernet_flow:
        if host != DORM_PORTAL_HOST:
            return False
        # The dorm portal moves the same login form among several internal
        # application routes. Keep the official-origin boundary, but do not
        # couple navigation or credential filling to a changing path.
        return True
    if not credentials:
        # Navigation paths on the two official wireless origins can change.
        # Credential writes remain restricted to WIRELESS_CREDENTIAL_PATHS.
        return host in WIRELESS_NAVIGATION_PATHS
    return host in WIRELESS_CREDENTIAL_PATHS and _path_allowed(
        path,
        WIRELESS_CREDENTIAL_PATHS[host],
    )


def _portal_navigation_path_observed(url: str, dorm_ethernet_flow: bool) -> bool:
    """Return whether an official navigation URL still uses a recorded path."""
    if not _portal_url_allowed(url, dorm_ethernet_flow):
        return False
    parsed = urllib.parse.urlparse(url or "")
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or "/"
    if dorm_ethernet_flow:
        return path == "/" or _path_allowed(path, DORM_NAVIGATION_PATHS)
    return _path_allowed(path, WIRELESS_NAVIGATION_PATHS[host])


def _redacted_navigation_target(url: str) -> dict[str, str]:
    """Keep only scheme, host and path; never log portal query/session data."""
    parsed = urllib.parse.urlparse(url or "")
    path = (parsed.path or "/").split(";", 1)[0]
    return {
        "navigation_scheme": parsed.scheme.lower(),
        "navigation_host": (parsed.hostname or "").lower().rstrip("."),
        "navigation_path": path,
    }


def _log_navigation_path_bypass(
    url: str,
    dorm_ethernet_flow: bool,
    *,
    discovery_stage: str,
) -> None:
    event(
        "portal-navigation-allowlist-bypassed",
        True,
        "门户导航路径不在旧列表内，已继续等待并严格校验官方凭据页面",
        discovery_stage=discovery_stage,
        portal_flow="dorm-ethernet" if dorm_ethernet_flow else "wireless",
        credential_origin_check_active=True,
        **_redacted_navigation_target(url),
    )


def _validate_final_navigation_target(
    url: str,
    dorm_ethernet_flow: bool,
    *,
    discovery_stage: str,
) -> None:
    if not _portal_url_allowed(url, dorm_ethernet_flow):
        event(
            "portal-navigation-allowlist-rejected",
            False,
            "门户最终导航地址不是已确认的学校官方来源",
            discovery_stage=discovery_stage,
            credential_origin_check_active=True,
            **_redacted_navigation_target(url),
        )
        raise PortalAllowlistError("校园网最终登录地址不在官方允许列表内")
    if not _portal_navigation_path_observed(url, dorm_ethernet_flow):
        _log_navigation_path_bypass(
            url,
            dorm_ethernet_flow,
            discovery_stage=discovery_stage,
        )


def _credential_targets_allowed(state: dict, dorm_ethernet_flow: bool) -> bool:
    """Allow navigation changes, but keep credential writes on official pages only."""
    if not state.get("hasPassword"):
        return True
    password_urls = list(state.get("passwordUrls") or [state.get("url") or ""])
    return any(
        _portal_url_allowed(url, dorm_ethernet_flow, credentials=True)
        for url in password_urls
    )


class Cdp:
    def __init__(self, url: str):
        try:
            self.socket = websocket.create_connection(
                url,
                timeout=8,
                http_no_proxy=["*"],
                suppress_origin=True,
            )
        except websocket.WebSocketBadStatusException as error:
            status_code = getattr(error, "status_code", None)
            if status_code == 403:
                raise CdpHandshakeRejectedError(status_code) from error
            raise
        self.counter = 0

    def call_result(self, method: str, params: dict | None = None) -> dict:
        self.counter += 1
        ident = self.counter
        self.socket.send(json.dumps({"id": ident, "method": method, "params": params or {}}))
        while True:
            message = json.loads(self.socket.recv())
            if message.get("id") == ident:
                if message.get("error"):
                    error_message = str(message["error"].get("message") or "unknown")
                    raise EdgeLoginError(f"Edge CDP 命令失败：{error_message}")
                result = message.get("result", {})
                if "exceptionDetails" in result:
                    raise EdgeLoginError("Edge 页面脚本执行失败")
                return result

    def call(self, method: str, params: dict | None = None):
        return self.call_result(method, params).get("result", {}).get("value")

    def evaluate(self, expression: str, *, context_id: int | None = None):
        params = {"expression": expression, "returnByValue": True}
        if context_id is not None:
            params["contextId"] = context_id
        return self.call("Runtime.evaluate", params)

    def close(self):
        self.socket.close()


def _pages_status(port: int) -> tuple[bool, list[dict], str]:
    """Return CDP reachability separately from the current page list."""
    try:
        with NO_PROXY_OPENER.open(f"http://127.0.0.1:{port}/json/list", timeout=2) as response:
            pages = json.load(response)
        if not isinstance(pages, list):
            return True, [], "invalid-page-list"
        return True, pages, "reachable"
    except urllib.error.URLError as error:
        reason = getattr(error, "reason", None)
        if isinstance(reason, ConnectionRefusedError):
            return False, [], "connection-refused"
        return False, [], "url-error"
    except TimeoutError:
        return False, [], "timeout"
    except (ConnectionError, OSError):
        return False, [], "connection-error"
    except json.JSONDecodeError:
        return True, [], "invalid-json"


def _pages(port: int) -> list[dict]:
    """Return Edge CDP pages, treating startup connection refusal as not-ready."""
    return _pages_status(port)[1]


def _find_available_loopback_ports(count: int = 2) -> tuple[int, ...]:
    """Ask Windows for distinct unused TCP ports bound only to loopback."""
    if count < 1:
        raise ValueError("端口数量必须大于零")
    reservations: list[socket.socket] = []
    try:
        for _ in range(count):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if exclusive is not None:
                    reservation.setsockopt(socket.SOL_SOCKET, exclusive, 1)
                reservation.bind(("127.0.0.1", 0))
                reservation.listen(1)
            except OSError:
                reservation.close()
                raise
            reservations.append(reservation)
        return tuple(int(item.getsockname()[1]) for item in reservations)
    except OSError as error:
        raise EdgeLoginError(f"无法为专用 Edge 分配本机调试端口：{error}") from error
    finally:
        for reservation in reservations:
            reservation.close()


def _load_saved_edge_ports() -> tuple[int, int] | None:
    try:
        payload = json.loads(EDGE_CDP_PORTS_PATH.read_text(encoding="utf-8"))
        ports = tuple(int(port) for port in payload.get("ports", ()))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if len(ports) != 2 or len(set(ports)) != 2:
        return None
    if any(port < 1 or port > 65535 for port in ports):
        return None
    return ports


def _save_edge_ports(ports: tuple[int, int]) -> bool:
    try:
        EDGE_CDP_PORTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = EDGE_CDP_PORTS_PATH.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(
                {
                    "ports": list(ports),
                    "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary_path.replace(EDGE_CDP_PORTS_PATH)
        return True
    except OSError:
        return False


def _loopback_port_available(port: int) -> bool:
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            candidate.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        candidate.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        candidate.close()


def _saved_edge_ports_usable(ports: tuple[int, int]) -> bool:
    for port in ports:
        if _loopback_port_available(port):
            continue
        if _pages_status(port)[2] != "reachable":
            return False
    return True


def _select_edge_attempt_ports(edge_port: int | None) -> tuple[tuple[int, int], str]:
    if edge_port is None:
        saved_ports = _load_saved_edge_ports()
        if saved_ports is not None and _saved_edge_ports_usable(saved_ports):
            return saved_ports, "saved"
        mode = "automatic-reselected" if saved_ports is not None else "automatic-first-run"
        first, second = _find_available_loopback_ports(2)
        return (first, second), mode
    if not 1 <= edge_port <= 65534:
        raise EdgeLoginError("显式 Edge 调试端口必须位于 1 至 65534")
    return (edge_port, edge_port + 1), "explicit"


def _edge_path() -> str:
    candidates = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise EdgeLoginError("未找到 Microsoft Edge")


def _curl(interface_ip: str, url: str, *, headers: bool = False) -> str:
    command = [
        "curl.exe",
        "--noproxy",
        "*",
        "--interface",
        interface_ip,
        "--connect-timeout",
        "8",
        "--max-time",
        "12",
        "-sS",
    ]
    if headers:
        command.extend(["-D", "-", "-o", "NUL"])
    command.append(url)
    try:
        return subprocess.check_output(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.CalledProcessError as error:
        # Do not let CalledProcessError stringify the complete captive-portal
        # URL into the formal log; it can contain per-session NAS parameters.
        raise EdgeLoginError(f"校园网门户请求失败（curl 退出码 {error.returncode}）") from error


def _normalized_http_url(value: str, base_url: str) -> str | None:
    decoded = urllib.parse.unquote(html.unescape(value.strip().strip("'\"")))
    candidate = urllib.parse.urljoin(base_url, decoded)
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return candidate


def _extract_login_redirect(body: str, base_url: str) -> str:
    candidates: list[str] = []

    # Prefer an actual meta-refresh target.  A broad ``url=`` search also
    # matches the ePortal ``userurl=`` query parameter; its opaque value is
    # not a URL and causes curl exit code 3 before Edge can be opened.
    for tag in re.findall(r"<meta\b[^>]*>", body, re.IGNORECASE | re.DOTALL):
        if not re.search(r"http-equiv\s*=\s*(['\"]?)refresh\1", tag, re.IGNORECASE):
            continue
        content = re.search(r"content\s*=\s*(['\"])(.*?)\1", tag, re.IGNORECASE | re.DOTALL)
        if content:
            target = re.search(r"(?:^|;)\s*url\s*=\s*(.+)$", content.group(2), re.IGNORECASE)
            if target:
                candidates.append(target.group(1))

    javascript_patterns = (
        r"(?:top\.)?(?:self\.)?(?:window\.)?location(?:\.href)?\s*=\s*(['\"])(.*?)\1",
        r"(?:window\.)?location\.(?:assign|replace)\(\s*(['\"])(.*?)\1\s*\)",
    )
    for pattern in javascript_patterns:
        candidates.extend(match.group(2) for match in re.finditer(pattern, body, re.IGNORECASE | re.DOTALL))

    # Last-resort support for non-meta portal responses, while requiring a
    # real parameter boundary so ``userurl=`` cannot be mistaken for ``url=``.
    candidates.extend(
        match.group(1)
        for match in re.finditer(r"(?:^|[;?&\s\"'])url\s*=\s*([^'\"<>\s]+)", body, re.IGNORECASE)
    )

    for value in candidates:
        normalized = _normalized_http_url(value, base_url)
        if normalized:
            return normalized
    raise EdgeLoginError("校园网门户没有返回有效的登录跳转地址")


def _discover_login_url(
    interface_ip: str,
    check_url: str,
    *,
    dorm_ethernet_flow: bool | None = None,
) -> str:
    body = _curl(interface_ip, check_url)
    intermediate_url = _extract_login_redirect(body, check_url)
    if (
        dorm_ethernet_flow is not None
        and not _portal_navigation_path_observed(intermediate_url, dorm_ethernet_flow)
    ):
        # This request carries no account/password. The final Edge target and
        # every credential-bearing frame are still validated independently.
        _log_navigation_path_bypass(
            intermediate_url,
            dorm_ethernet_flow,
            discovery_stage="intermediate-no-credentials",
        )
    headers = _curl(interface_ip, intermediate_url, headers=True)
    location = re.search(r"^Location:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)
    if not location:
        raise EdgeLoginError("校园网门户没有返回最终登录页面")
    final_url = _normalized_http_url(location.group(1), intermediate_url)
    if not final_url:
        raise EdgeLoginError("校园网门户返回了无效的最终登录页面")
    if dorm_ethernet_flow is not None:
        _validate_final_navigation_target(
            final_url,
            dorm_ethernet_flow,
            discovery_stage="final-edge-target",
        )
    return final_url


def _resolve_from_wlan(hostname: str, interface_ip: str, dns_servers: tuple[str, ...]) -> list[str]:
    def encode(name: str) -> bytes:
        return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"

    def skip_name(message: bytes, position: int) -> int:
        while position < len(message) and message[position] != 0:
            if message[position] & 0xC0 == 0xC0:
                return position + 2
            position += 1 + message[position]
        return position + 1

    query = struct.pack("!HHHHHH", 0x5123, 0x0100, 1, 0, 0, 0) + encode(hostname) + struct.pack("!HH", 1, 1)
    for dns_server in dns_servers:
        try:
            socket.inet_aton(dns_server)
        except OSError:
            continue
        resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver.settimeout(4)
        try:
            resolver.bind((interface_ip, 0))
            resolver.sendto(query, (dns_server, 53))
            message, _ = resolver.recvfrom(4096)
            _, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", message[:12])
            if flags & 15:
                continue
            position = 12
            for _ in range(questions):
                position = skip_name(message, position) + 4
            addresses: list[str] = []
            for _ in range(answers):
                position = skip_name(message, position)
                record_type, record_class, _, length = struct.unpack("!HHIH", message[position:position + 10])
                position += 10
                payload = message[position:position + length]
                position += length
                if record_type == 1 and record_class == 1 and length == 4:
                    addresses.append(socket.inet_ntoa(payload))
            if addresses:
                return sorted(set(addresses))
        except (OSError, ValueError, struct.error, IndexError):
            continue
        finally:
            resolver.close()
    raise EdgeLoginError("无法通过所选校园网接口的 DNS 解析校园网门户")


def logout_current_session(
    interface_ip: str,
    dns_servers: tuple[str, ...],
    probe,
    *,
    wait_seconds: int = 20,
) -> dict:
    """Log out the current IP-bound campus session without using a proxy."""
    logout_host = "captiveportal-login.njmu.edu.cn"
    logout_addresses = _resolve_from_wlan(logout_host, interface_ip, dns_servers)
    confirmed_by_portal = False
    for address in logout_addresses:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(12)
        try:
            connection.bind((interface_ip, 0))
            connection.connect((address, 80))
            connection.sendall(
                (
                    "GET /auth/logout.html HTTP/1.1\r\n"
                    f"Host: {logout_host}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = bytearray()
            while len(response) < 1024 * 1024:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
            if b"Logout Successful" in response:
                confirmed_by_portal = True
                break
        except OSError:
            continue
        finally:
            connection.close()
    if not confirmed_by_portal:
        raise EdgeLoginError("校园网下线接口未确认注销")

    deadline = time.monotonic() + max(1, wait_seconds)
    consecutive_offline_probes = 0
    probe_attempts = 0
    while time.monotonic() < deadline:
        probe_attempts += 1
        if probe():
            consecutive_offline_probes = 0
        else:
            consecutive_offline_probes += 1
            if consecutive_offline_probes >= 2:
                return {
                    "success": True,
                    "logout_confirmed_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                    "probe_attempts": probe_attempts,
                }
        time.sleep(1)
    raise EdgeLoginError("校园网已确认下线，但真实联网探测未连续确认离线")


def _login_route_hosts(login_url: str, include_wireless_portal_host: bool) -> list[str]:
    host = urllib.parse.urlparse(login_url).hostname
    hosts = [host] if host else []
    if include_wireless_portal_host:
        hosts.append(WIRELESS_PORTAL_HOST)
    return list(dict.fromkeys(hosts))


def _add_routes(
    hosts: list[str],
    gateway: str,
    ifindex: int,
    *,
    interface_ip: str = "",
    dns_servers: tuple[str, ...] = (),
) -> tuple[list[str], dict[str, str]]:
    if not gateway or not ifindex:
        return [], {}
    resolved_hosts: dict[str, str] = {}
    host_addresses: dict[str, list[str]] = {}
    for host in dict.fromkeys(item for item in hosts if item):
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if literal.version != 4:
                raise EdgeLoginError("校园网门户临时路由仅支持 IPv4")
            addresses = [str(literal)]
        elif interface_ip and dns_servers:
            addresses = _resolve_from_wlan(host, interface_ip, dns_servers)
        else:
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_INET)})
            except socket.gaierror:
                addresses = []
        if not addresses:
            raise EdgeLoginError("校园网门户主机名未能解析")
        host_addresses[host] = addresses
        resolved_hosts[host] = addresses[0]
    routes: list[str] = []
    try:
        for address in sorted({address for addresses in host_addresses.values() for address in addresses}):
            result = subprocess.run(
                ["route.exe", "add", address, "mask", "255.255.255.255", gateway, "if", str(ifindex)],
                capture_output=True,
                text=True,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                raise EdgeLoginError(f"无法为校园网门户添加临时路由：{result.stderr or result.stdout}")
            routes.append(address)
    except Exception:
        _delete_routes(routes, gateway, ifindex)
        raise
    return routes, resolved_hosts


def _delete_routes(routes: list[str], gateway: str = "", ifindex: int = 0) -> None:
    for address in routes:
        command = ["route.exe", "delete", address, "mask", "255.255.255.255"]
        if gateway:
            command.append(gateway)
        if ifindex:
            command.extend(["if", str(ifindex)])
        subprocess.run(command, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)


def _portal_page(port: int, allowed_hosts: set[str]) -> dict | None:
    return _portal_page_status(port, allowed_hosts)[0]


def _portal_page_status(port: int, allowed_hosts: set[str]) -> tuple[dict | None, dict]:
    reachable, pages, reason = _pages_status(port)
    page_count = 0
    for page in pages:
        if page.get("type") != "page":
            continue
        page_count += 1
        host = urllib.parse.urlparse(str(page.get("url") or "")).hostname
        if host in allowed_hosts:
            return page, {
                "cdp_reachable": reachable,
                "page_count": page_count,
                "cdp_reason": reason,
            }
    return None, {
        "cdp_reachable": reachable,
        "page_count": page_count,
        "cdp_reason": reason,
    }


def _navigate_first_page(port: int, url: str) -> bool:
    for page in _pages(port):
        if page.get("type") != "page":
            continue
        websocket_url = str(page.get("webSocketDebuggerUrl") or "")
        if not websocket_url:
            continue
        client: Cdp | None = None
        try:
            client = Cdp(websocket_url)
            client.call("Page.navigate", {"url": url})
            return True
        except Exception:
            return False
        finally:
            _disconnect_client(client)
    return False


def _page_state(client: Cdp) -> dict:
    expression = r"""JSON.stringify((()=>{
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&(e.offsetParent||e.getClientRects().length));
      return {url:location.href,hasPassword:all('input[type=password]').some(visible),pageText:(document.body?.innerText||'').slice(0,4000)}
    })())"""
    states = [item for item in _evaluate_in_frames(client, expression) if isinstance(item[1], dict)]
    if not states:
        return {}
    page_text = "\n".join(
        str(state.get("pageText") or "")
        for _, state in states
        if isinstance(state, dict)
    )[:4000]
    return {
        "url": str(states[0][1].get("url") or ""),
        "hasPassword": any(bool(state.get("hasPassword")) for _, state in states),
        "passwordUrls": [
            str(state.get("url") or "")
            for _, state in states
            if bool(state.get("hasPassword"))
        ],
        "pageText": page_text,
        "frameCount": len(states),
    }


def _walk_frame_tree(frame_tree: dict, parent_id: str | None = None) -> list[tuple[str, str | None]]:
    frame = frame_tree.get("frame") or {}
    frame_id = str(frame.get("id") or "")
    if not frame_id:
        return []
    frames = [(frame_id, parent_id)]
    for child in frame_tree.get("childFrames") or ():
        frames.extend(_walk_frame_tree(child, frame_id))
    return frames


def _frame_content_offset(client: Cdp, frame_id: str, parent_id: str | None) -> tuple[float, float]:
    if parent_id is None:
        return 0.0, 0.0
    owner = client.call_result("DOM.getFrameOwner", {"frameId": frame_id})
    backend_node_id = owner.get("backendNodeId")
    if not backend_node_id:
        return 0.0, 0.0
    box = client.call_result("DOM.getBoxModel", {"backendNodeId": backend_node_id})
    model = box.get("model") or {}
    quad = model.get("content") or model.get("border") or ()
    if len(quad) < 8:
        return 0.0, 0.0
    return float(min(quad[0::2])), float(min(quad[1::2]))


def _frame_contexts(client: Cdp) -> list[dict]:
    # Lightweight test doubles and older callers still use the main document only.
    if not hasattr(client, "call_result"):
        return [{"frame_id": "", "context_id": None, "offset_x": 0.0, "offset_y": 0.0}]
    try:
        tree = client.call_result("Page.getFrameTree").get("frameTree") or {}
        frames = _walk_frame_tree(tree)
    except Exception:
        return [{"frame_id": "", "context_id": None, "offset_x": 0.0, "offset_y": 0.0}]
    contexts: list[dict] = []
    for frame_id, parent_id in frames:
        try:
            world = client.call_result(
                "Page.createIsolatedWorld",
                {
                    "frameId": frame_id,
                    "worldName": "NJMUCampusNetAssistant",
                    "grantUniveralAccess": False,
                },
            )
            context_id = int(world["executionContextId"])
            offset_x, offset_y = _frame_content_offset(client, frame_id, parent_id)
        except (EdgeLoginError, KeyError, TypeError, ValueError):
            continue
        contexts.append(
            {
                "frame_id": frame_id,
                "context_id": context_id,
                "offset_x": offset_x,
                "offset_y": offset_y,
            }
        )
    return contexts or [{"frame_id": "", "context_id": None, "offset_x": 0.0, "offset_y": 0.0}]


def _evaluate_in_frames(client: Cdp, expression: str) -> list[tuple[dict, object]]:
    results: list[tuple[dict, object]] = []
    for frame in _frame_contexts(client):
        try:
            if frame["context_id"] is None:
                value = client.evaluate(expression)
            else:
                value = client.evaluate(expression, context_id=frame["context_id"])
            if isinstance(value, str):
                value = json.loads(value)
            results.append((frame, value))
        except (EdgeLoginError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return results


def _credential_frame_guard(expression: str, dorm_ethernet_flow: bool) -> str:
    """Run a credential action only inside an allowlisted official frame."""
    rules = {} if dorm_ethernet_flow else WIRELESS_CREDENTIAL_PATHS
    serialized_rules = json.dumps(rules, ensure_ascii=False)
    dorm_host = json.dumps(DORM_PORTAL_HOST)
    host_only = json.dumps(dorm_ethernet_flow)
    return r"""JSON.stringify((()=>{
      const rules=%s;
      const dormHost=%s;
      const hostOnly=%s;
      let current;
      try{current=new URL(location.href)}catch(_error){return {allowed:false,value:null}}
      const scheme=current.protocol.toLowerCase();
      const host=current.hostname.toLowerCase().replace(/\.$/,'');
      const path=(current.pathname||'/').split(';',1)[0].toLowerCase();
      const officialFrame=hostOnly
        ?host===dormHost
        :Object.entries(rules).some(([ruleHost,paths])=>
          host===ruleHost.toLowerCase()&&paths.some(raw=>{
            const rule=raw.toLowerCase();
            return rule.endsWith('/')?path.startsWith(rule):(path===rule||path.startsWith(rule+'/'));
          })
        );
      const allowed=(scheme==='http:'||scheme==='https:')&&officialFrame;
      if(!allowed)return {allowed:false,value:null};
      return {allowed:true,value:(%s)};
    })())""" % (serialized_rules, dorm_host, host_only, expression)


def _evaluate_in_credential_frames(
    client: Cdp,
    expression: str,
    dorm_ethernet_flow: bool,
):
    """Yield results while the JavaScript guard prevents writes in other frames."""
    guarded_expression = _credential_frame_guard(expression, dorm_ethernet_flow)
    for frame in _frame_contexts(client):
        try:
            if frame["context_id"] is None:
                envelope = client.evaluate(guarded_expression)
            else:
                envelope = client.evaluate(
                    guarded_expression,
                    context_id=frame["context_id"],
                )
            if isinstance(envelope, str):
                envelope = json.loads(envelope)
            if not isinstance(envelope, dict) or not envelope.get("allowed"):
                continue
            value = envelope.get("value")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
            yield frame, value
        except (EdgeLoginError, TypeError, ValueError, json.JSONDecodeError):
            continue


def _first_credential_frame_coordinates(
    client: Cdp,
    expression: str,
    dorm_ethernet_flow: bool,
) -> dict | None:
    for frame, coordinates in _evaluate_in_credential_frames(
        client,
        expression,
        dorm_ethernet_flow,
    ):
        if not isinstance(coordinates, dict):
            continue
        try:
            adjusted = dict(coordinates)
            adjusted["x"] = float(coordinates["x"]) + float(frame["offset_x"])
            adjusted["y"] = float(coordinates["y"]) + float(frame["offset_y"])
            return adjusted
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _first_frame_coordinates(client: Cdp, expression: str) -> dict | None:
    for frame, coordinates in _evaluate_in_frames(client, expression):
        if not isinstance(coordinates, dict):
            continue
        try:
            adjusted = dict(coordinates)
            adjusted["x"] = float(coordinates["x"]) + float(frame["offset_x"])
            adjusted["y"] = float(coordinates["y"]) + float(frame["offset_y"])
            return adjusted
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _dorm_logout_page_state(client: Cdp) -> dict:
    """Read only privacy-safe state from the official dorm portal page."""
    expression = r"""JSON.stringify((()=>{
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&(e.offsetParent||e.getClientRects().length));
      const text=(e)=>(e?.innerText||e?.textContent||e?.value||e?.getAttribute?.('aria-label')||'').replace(/\s+/g,'').trim();
      const body=(document.body?.innerText||'').replace(/\s+/g,'');
      const actions=all('app-function-link,[aria-label="rg-menu"],button,a,[role=button]');
      const buttons=all('button,[role=button],input[type=button],input[type=submit]');
      return {
        url:location.href,
        online:body.includes('您已成功连接网络'),
        hasLogoutAction:actions.some(e=>visible(e)&&text(e).includes('我要下线')),
        confirmVisible:buttons.some(e=>visible(e)&&text(e)==='确定'),
        offlineSuccess:location.pathname.toLowerCase().includes('/offlinesuccess')||body.includes('成功下线')||body.includes('下线成功')||body.toLowerCase().includes('successfullyoffline'),
        hasPassword:all('input[type=password]').some(e=>visible(e))
      };
    })())"""
    return json.loads(client.evaluate(expression) or "{}")


def _dispatch_mouse_click(client: Cdp, coordinates: object) -> bool:
    if not isinstance(coordinates, dict):
        return False
    x = float(coordinates["x"])
    y = float(coordinates["y"])
    client.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
    client.call(
        "Input.dispatchMouseEvent",
        {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1},
    )
    client.call(
        "Input.dispatchMouseEvent",
        {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1},
    )
    return True


def _complete_dom_or_coordinate_click(client: Cdp, action: object) -> dict | None:
    """Prefer the page's DOM click and retain CDP coordinates as a safe fallback."""
    if not isinstance(action, dict):
        return None
    completed = dict(action)
    if completed.get("domClicked"):
        completed["click_method"] = "dom"
        return completed
    if not _dispatch_mouse_click(client, completed):
        return None
    completed["click_method"] = "coordinate-fallback"
    return completed


def _click_dorm_logout(client: Cdp) -> bool:
    expression = r"""JSON.stringify((()=>{
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&(e.offsetParent||e.getClientRects().length));
      const text=(e)=>(e?.innerText||e?.textContent||e?.value||e?.getAttribute?.('aria-label')||'').replace(/\s+/g,'').trim();
      const component=all('app-function-link').find(e=>visible(e)&&text(e).includes('我要下线'));
      const candidates=all('[aria-label="rg-menu"],button,a,[role=button]').filter(e=>visible(e)&&text(e).includes('我要下线'));
      const target=component?(component.querySelector('[aria-label="rg-menu"],button,a,[role=button]')||component):candidates.sort((a,b)=>text(a).length-text(b).length)[0];
      if(!target)return null;
      target.scrollIntoView({block:'center'});
      const rect=target.getBoundingClientRect();
      if(rect.width<=0||rect.height<=0)return null;
      return {x:rect.left+rect.width/2,y:rect.top+rect.height/2};
    })())"""
    return _dispatch_mouse_click(client, json.loads(client.evaluate(expression) or "null"))


def _click_dorm_confirmation(client: Cdp, *, prefer_dom: bool = True) -> dict | None:
    expression = r"""JSON.stringify((()=>{
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&(e.offsetParent||e.getClientRects().length));
      const text=(e)=>(e?.innerText||e?.textContent||'').replace(/\s+/g,'').trim();
      const buttons=all('button.ant-btn-primary,button,[role=button]');
      const target=buttons.find(e=>visible(e)&&text(e)==='确定');
      if(!target)return null;
      target.scrollIntoView({block:'center'});
      const rect=target.getBoundingClientRect();
      if(rect.width<=0||rect.height<=0)return null;
      let domClicked=false;
      if(%s){
        try{
          target.focus({preventScroll:true});
          for(const type of ['pointerdown','mousedown','pointerup','mouseup','click'])target.dispatchEvent(new MouseEvent(type,{bubbles:true,cancelable:true,view:window}));
          target.click();domClicked=true;
        }catch(_error){domClicked=false}
      }
      return {x:rect.left+rect.width/2,y:rect.top+rect.height/2,domClicked};
    })())""" % ("true" if prefer_dom else "false")
    return _complete_dom_or_coordinate_click(
        client,
        _first_frame_coordinates(client, expression),
    )


def _confirm_dorm_logout(client: Cdp) -> bool:
    return bool(_click_dorm_confirmation(client, prefer_dom=False))


def _fill_dorm_credentials(client: Cdp, username: str, password: str) -> bool:
    expression = r"""(()=>{
      const user=%s,password=%s,inputs=[];
      const walk=(root)=>{inputs.push(...root.querySelectorAll('input'));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);
      const account=inputs.find(e=>!['password','hidden','submit','button','checkbox','radio'].includes((e.type||'').toLowerCase())&&!e.disabled),secret=inputs.find(e=>(e.type||'').toLowerCase()==='password'&&!e.disabled);
      if(!account||!secret)return false;
      const set=(element,value)=>{const descriptor=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');descriptor.set.call(element,value);element.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));element.dispatchEvent(new Event('change',{bubbles:true}));element.dispatchEvent(new Event('blur',{bubbles:true}));};
      set(account,user);set(secret,password);return true;
    })()""" % (
        json.dumps(username, ensure_ascii=False),
        json.dumps(password, ensure_ascii=False),
    )
    return any(
        bool(value)
        for _, value in _evaluate_in_credential_frames(
            client,
            expression,
            dorm_ethernet_flow=True,
        )
    )


def _submit_dorm_credentials(client: Cdp) -> dict | None:
    expression = r"""JSON.stringify((()=>{
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&(e.offsetParent||e.getClientRects().length));
      const text=(e)=>(e?.innerText||e?.textContent||e?.value||e?.getAttribute?.('aria-label')||'').replace(/\s+/g,'').trim();
      const labels=['点击登录','立即登录','登录'];
      const nodes=all('button,input[type=submit],input[type=button],a,[role=button],div,span');
      const exact=nodes.filter(e=>visible(e)&&labels.includes(text(e))).sort((a,b)=>a.children.length-b.children.length)[0];
      const exactTarget=exact?(exact.closest('button,input[type=submit],input[type=button],a,[role=button]')||exact):null;
      const submits=all('button[type=submit],input[type=submit]').filter(visible);
      const target=exactTarget||(submits.length===1?submits[0]:null);
      if(!target)return null;
      target.scrollIntoView({block:'center'});const rect=target.getBoundingClientRect();
      if(rect.width<=0||rect.height<=0)return null;
      let domClicked=false;
      try{
        target.focus({preventScroll:true});
        for(const type of ['pointerdown','mousedown','pointerup','mouseup','click'])target.dispatchEvent(new MouseEvent(type,{bubbles:true,cancelable:true,view:window}));
        target.click();domClicked=true;
      }catch(_error){domClicked=false}
      return {
        x:rect.left+rect.width/2,
        y:rect.top+rect.height/2,
        domClicked,
        recognizedLabel:exact?text(exact):'',
        matchStrategy:exact?'exact-login-label':'unique-submit',
        controlTag:(target.tagName||'').toLowerCase(),
        controlType:(target.type||'').toLowerCase()
      };
    })())"""
    target = _first_credential_frame_coordinates(
        client,
        expression,
        dorm_ethernet_flow=True,
    )
    action = _complete_dom_or_coordinate_click(client, target)
    if not action:
        return None
    return {
        "click_method": str(action.get("click_method") or "unknown"),
        "recognized_label": str(action.get("recognizedLabel") or ""),
        "match_strategy": str(action.get("matchStrategy") or "unknown"),
        "control_tag": str(action.get("controlTag") or ""),
        "control_type": str(action.get("controlType") or ""),
    }


def _select_dorm_operator(client: Cdp, operator: str) -> dict | None:
    expression = r"""JSON.stringify((()=>{
      const wanted=%s;
      const aliases={
        '电信':['电信','中国电信','telecom','ctcc','@ctcc'],
        '移动':['移动','中国移动','mobile','cmcc','@cmcc'],
        '联通':['联通','中国联通','unicom','cucc','@cucc'],
        '校园网':['校园网','校园','campus','local']
      }[wanted]||[wanted];
      const normalized=(value)=>(value||'').toString().trim().toLowerCase().replace(/\s+/g,'');
      const nodes=[];const walk=(root)=>{nodes.push(...root.querySelectorAll('button,[role=option],[role=radio],label,li,a,div,span'));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);
      const exact=nodes.filter(e=>(e.offsetParent||e.getClientRects().length)&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&aliases.some(alias=>normalized(e.textContent||e.getAttribute('aria-label'))===normalized(alias)));
      const node=exact.sort((a,b)=>a.children.length-b.children.length)[0];
      if(!node)return null;
      const target=node.closest('button,[role=option],[role=radio],label,li,a')||node;
      target.scrollIntoView({block:'center'});const rect=target.getBoundingClientRect();
      if(rect.width<=0||rect.height<=0)return null;
      let domClicked=false;
      try{
        target.focus({preventScroll:true});
        for(const type of ['pointerdown','mousedown','pointerup','mouseup','click'])target.dispatchEvent(new MouseEvent(type,{bubbles:true,cancelable:true,view:window}));
        target.click();domClicked=true;
      }catch(_error){domClicked=false}
      return {x:rect.left+rect.width/2,y:rect.top+rect.height/2,domClicked};
    })())""" % json.dumps(operator, ensure_ascii=False)
    return _complete_dom_or_coordinate_click(
        client,
        _first_frame_coordinates(client, expression),
    )


def _dorm_page_role(url: str, has_password: bool = False) -> str:
    """Classify a portal frame without retaining its URL or query parameters."""
    try:
        parsed = urllib.parse.urlparse(url or "")
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return "unknown"
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return "unknown"
    if host != DORM_PORTAL_HOST:
        return "external"
    if has_password:
        return "official-credential"
    path = (parsed.path or "/").lower()
    if "serviceselection" in path or "service-selection" in path:
        return "official-service-selection"
    if "offlinesuccess" in path:
        return "official-offline-success"
    if "success" in path:
        return "official-success"
    return "official-transition"


def _dorm_service_page_diagnostic(client: Cdp, operator: str) -> dict:
    """Return privacy-safe structure counts for the dorm service-selection stage."""
    expression = r"""JSON.stringify((()=>{
      const wanted=%s;
      const aliases={
        '电信':['电信','中国电信','telecom','ctcc','@ctcc'],
        '移动':['移动','中国移动','mobile','cmcc','@cmcc'],
        '联通':['联通','中国联通','unicom','cucc','@cucc'],
        '校园网':['校园网','校园','campus','local']
      }[wanted]||[wanted];
      const normalized=(value)=>(value||'').toString().trim().toLowerCase().replace(/\s+/g,'');
      const all=(selector)=>{const out=[];const walk=(root)=>{out.push(...root.querySelectorAll(selector));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);return out};
      const visible=(e)=>!!(e&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&(e.offsetParent||e.getClientRects().length));
      const nodes=all('button,[role=option],[role=radio],label,li,a,div,span');
      const exact=nodes.filter(e=>aliases.some(alias=>normalized(e.textContent||e.getAttribute('aria-label'))===normalized(alias)));
      const visibleExact=exact.filter(visible);
      const clickable=visibleExact.map(node=>node.closest('button,[role=option],[role=radio],label,li,a')||node);
      const boxed=clickable.filter(target=>{const rect=target.getBoundingClientRect();return rect.width>0&&rect.height>0});
      const buttons=all('button.ant-btn-primary,button,[role=button]');
      const confirmations=buttons.filter(e=>normalized(e.innerText||e.textContent)==='确定');
      const passwords=all('input[type=password]');
      const loginLabels=['点击登录','立即登录','登录'];
      const loginNodes=all('button,input[type=submit],input[type=button],a,[role=button],div,span');
      const loginExact=loginNodes.filter(e=>loginLabels.includes((e.innerText||e.textContent||e.value||e.getAttribute?.('aria-label')||'').replace(/\s+/g,'').trim()));
      const visibleLoginExact=loginExact.filter(visible);
      const loginClickable=visibleLoginExact.map(node=>node.closest('button,input[type=submit],input[type=button],a,[role=button]')||node);
      const loginBoxed=loginClickable.filter(target=>{const rect=target.getBoundingClientRect();return rect.width>0&&rect.height>0});
      const visibleSubmitControls=all('button[type=submit],input[type=submit]').filter(visible);
      const loading=all('.ant-spin,.ant-skeleton,[aria-busy=true],[role=progressbar]').filter(visible);
      const dialogs=all('[role=dialog],.ant-modal').filter(visible);
      return {
        url:location.href,
        readyState:document.readyState||'unknown',
        bodyPresent:!!document.body,
        bodyTextCharacters:(document.body?.innerText||'').length,
        iframeElements:all('iframe').length,
        passwordFields:passwords.length,
        visiblePasswordFields:passwords.filter(visible).length,
        loginExactCandidates:loginExact.length,
        loginVisibleCandidates:visibleLoginExact.length,
        loginClickableCandidates:loginClickable.length,
        loginBoxCandidates:loginBoxed.length,
        visibleSubmitControls:visibleSubmitControls.length,
        operatorExactCandidates:exact.length,
        operatorVisibleCandidates:visibleExact.length,
        operatorClickableCandidates:clickable.length,
        operatorBoxCandidates:boxed.length,
        confirmationCandidates:confirmations.length,
        visibleConfirmationCandidates:confirmations.filter(visible).length,
        visibleLoadingIndicators:loading.length,
        visibleDialogs:dialogs.length
      };
    })())""" % json.dumps(operator, ensure_ascii=False)
    frames = _frame_contexts(client)
    states: list[dict] = []
    error_types: set[str] = set()
    for frame in frames:
        try:
            if frame["context_id"] is None:
                value = client.evaluate(expression)
            else:
                value = client.evaluate(expression, context_id=frame["context_id"])
            if isinstance(value, str):
                value = json.loads(value)
            if isinstance(value, dict):
                states.append(value)
            else:
                error_types.add("InvalidDiagnosticResult")
        except Exception as error:  # Diagnostic collection must never expose or break the login flow.
            error_types.add(type(error).__name__)

    page_roles: dict[str, int] = {}
    ready_states: dict[str, int] = {}
    for state in states:
        role = _dorm_page_role(
            str(state.get("url") or ""),
            bool(state.get("visiblePasswordFields") or state.get("passwordFields")),
        )
        page_roles[role] = page_roles.get(role, 0) + 1
        ready_state = str(state.get("readyState") or "unknown").lower()
        if ready_state not in {"loading", "interactive", "complete"}:
            ready_state = "unknown"
        ready_states[ready_state] = ready_states.get(ready_state, 0) + 1

    count_fields = (
        "bodyTextCharacters",
        "iframeElements",
        "passwordFields",
        "visiblePasswordFields",
        "loginExactCandidates",
        "loginVisibleCandidates",
        "loginClickableCandidates",
        "loginBoxCandidates",
        "visibleSubmitControls",
        "operatorExactCandidates",
        "operatorVisibleCandidates",
        "operatorClickableCandidates",
        "operatorBoxCandidates",
        "confirmationCandidates",
        "visibleConfirmationCandidates",
        "visibleLoadingIndicators",
        "visibleDialogs",
    )
    def safe_count(value: object) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError, OverflowError):
            return 0

    totals = {
        field: sum(safe_count(state.get(field)) for state in states)
        for field in count_fields
    }
    return {
        "frame_contexts": len(frames),
        "frame_reads_ok": len(states),
        "frame_read_errors": max(0, len(frames) - len(states)),
        "frame_error_types": sorted(error_types),
        "page_roles": page_roles,
        "document_ready_states": ready_states,
        "body_present_frames": sum(bool(state.get("bodyPresent")) for state in states),
        **totals,
    }


def _emit_dorm_stage_diagnostic(
    stage: str,
    message: str,
    client: Cdp,
    operator: str,
    *,
    launch_attempt: int,
    elapsed_seconds: float,
    action_attempts: int,
) -> dict:
    try:
        diagnostic = _dorm_service_page_diagnostic(client, operator)
    except Exception as error:  # Logging must not turn a recoverable portal delay into a login failure.
        diagnostic = {
            "diagnostic_collection_failed": True,
            "diagnostic_error_type": type(error).__name__,
        }
    event(
        stage,
        False,
        message,
        launch_attempt=launch_attempt,
        elapsed_seconds=round(max(0.0, elapsed_seconds), 3),
        action_attempts=action_attempts,
        diagnostic=diagnostic,
    )
    return diagnostic


def _fill_form(client: Cdp, username: str, password: str, operator: str) -> dict:
    expression = r"""(()=>{
      const user=%s,password=%s,wantedOperator=%s,inputs=[],selects=[];
      const walk=(root)=>{inputs.push(...root.querySelectorAll('input'));selects.push(...root.querySelectorAll('select'));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);
      const account=inputs.find(e=>!['password','hidden','submit','button','checkbox','radio'].includes((e.type||'').toLowerCase())&&!e.disabled),secret=inputs.find(e=>e.type==='password'&&!e.disabled);
      if(!account||!secret)return JSON.stringify({filled:false,operatorMatched:false,operatorStrategy:'form-not-ready'});
      const set=(element,value)=>{const descriptor=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');descriptor.set.call(element,value);element.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));element.dispatchEvent(new Event('change',{bubbles:true}));element.dispatchEvent(new Event('blur',{bubbles:true}));};
      set(account,user);set(secret,password);
      const aliases={
        '电信':['电信','中国电信','telecom','ctcc','@ctcc'],
        '移动':['移动','中国移动','mobile','cmcc','@cmcc'],
        '联通':['联通','中国联通','unicom','cucc','@cucc'],
        '校园网':['校园网','校园','campus','local']
      }[wantedOperator]||[wantedOperator];
      const normalized=(value)=>(value||'').toString().trim().toLowerCase().replace(/\s+/g,'');
      const matches=(...values)=>values.some(value=>aliases.some(alias=>normalized(value).includes(normalized(alias))));
      let operatorMatched=false,operatorStrategy='none';
      for(const select of selects.filter(e=>!e.disabled)){
        const option=[...select.options].find(o=>matches(o.textContent,o.label,o.value));
        if(!option)continue;
        const descriptor=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value');
        if(descriptor&&descriptor.set)descriptor.set.call(select,option.value);else select.value=option.value;
        for(const type of ['input','change','blur'])select.dispatchEvent(new Event(type,{bubbles:true}));
        operatorMatched=true;operatorStrategy='select';break;
      }
      if(!operatorMatched){
        const radios=inputs.filter(e=>(e.type||'').toLowerCase()==='radio'&&!e.disabled);
        const radio=radios.find(e=>{const label=e.id?document.querySelector(`label[for="${CSS.escape(e.id)}"]`):null;return matches(e.value,e.name,e.id,label?.textContent,e.parentElement?.textContent)});
        if(radio){radio.focus({preventScroll:true});radio.click();radio.dispatchEvent(new Event('change',{bubbles:true}));operatorMatched=true;operatorStrategy='radio';}
      }
      if(!operatorMatched){
        const nodes=[];const collect=(root)=>{nodes.push(...root.querySelectorAll('button,[role=option],[role=radio],label,li,a,div,span'));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)collect(e.shadowRoot)};collect(document);
        const exact=nodes.filter(e=>e.offsetParent&&!e.disabled&&aliases.some(alias=>normalized(e.textContent||e.getAttribute('aria-label'))===normalized(alias)));
        const node=exact.sort((a,b)=>a.children.length-b.children.length)[0];
        if(node){const target=node.closest('button,[role=option],[role=radio],label,li,a')||node;target.focus({preventScroll:true});target.click();operatorMatched=true;operatorStrategy='clickable-label';}
      }
      return JSON.stringify({filled:true,operatorMatched,operatorStrategy})
    })()""" % (
        json.dumps(username, ensure_ascii=False),
        json.dumps(password, ensure_ascii=False),
        json.dumps(operator, ensure_ascii=False),
    )
    return json.loads(client.evaluate(expression) or "{}")


def _submit_form(client: Cdp) -> bool:
    expression = r"""(()=>{
      const wanted=['提交','立即登录','登录','确定'],nodes=[];
      const walk=(root)=>{nodes.push(...root.querySelectorAll('button,input[type=submit],input[type=button],a,[role=button],div,span'));for(const e of root.querySelectorAll('*'))if(e.shadowRoot)walk(e.shadowRoot)};walk(document);
      const node=nodes.find(e=>wanted.includes((e.innerText||e.value||e.getAttribute('aria-label')||'').trim())&&e.offsetParent);
      if(node){const target=node.closest('button,input[type=submit],input[type=button],a,[role=button]')||node;if(target.disabled||target.getAttribute('aria-disabled')==='true'||target.classList.contains('disabled'))return false;target.focus({preventScroll:true});for(const type of ['pointerdown','mousedown','pointerup','mouseup','click'])target.dispatchEvent(new MouseEvent(type,{bubbles:true,cancelable:true,view:window}));target.click();return true}
      if(document.forms[0]){document.forms[0].requestSubmit();return true}
      return false
    })()"""
    return bool(client.evaluate(expression))


def _transient_cdp_error(error: Exception) -> bool:
    if isinstance(error, CdpHandshakeRejectedError):
        return False
    if websocket is not None and isinstance(error, websocket.WebSocketBadStatusException):
        status_code = getattr(error, "status_code", None)
        return bool(status_code and status_code >= 500)
    return isinstance(error, OSError) or bool(
        websocket is not None and isinstance(error, websocket.WebSocketException)
    )


def _disconnect_client(client: Cdp | None) -> None:
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass


def _close_client(client: Cdp | None) -> None:
    if client is None:
        return
    try:
        client.call("Browser.close")
    except Exception:
        pass
    _disconnect_client(client)


def _close_browser_on_port(port: int) -> bool:
    pages = _pages(port)
    ordered = sorted(pages, key=lambda page: page.get("type") != "page")
    for page in ordered:
        websocket_url = str(page.get("webSocketDebuggerUrl") or "")
        if not websocket_url:
            continue
        client: Cdp | None = None
        try:
            client = Cdp(websocket_url)
            client.call("Browser.close")
            return True
        except Exception:
            continue
        finally:
            _disconnect_client(client)
    return False


def _stop_process(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    try:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    except OSError:
        pass


def _completion_resolver_rule(success_page_url: str, resolved_hosts: dict[str, str]) -> str:
    """Pin only the post-authentication host required by the primary flow."""
    completion_host = urllib.parse.urlparse(success_page_url).hostname
    completion_address = resolved_hosts.get(completion_host or "")
    if not completion_host or not completion_address:
        return ""
    return f"MAP {completion_host} {completion_address}"


def _open_retained_success_page(
    edge_path: str,
    profile: str,
    port: int,
    success_page_url: str,
    resolved_hosts: dict[str, str],
) -> bool:
    if not success_page_url:
        return False
    arguments = [
        edge_path,
        "--new-window",
        "--no-proxy-server",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-size=900,700",
    ]
    resolver_rule = _completion_resolver_rule(success_page_url, resolved_hosts)
    if resolver_rule:
        arguments.append(f"--host-resolver-rules={resolver_rule}")
    arguments.append(success_page_url)
    try:
        subprocess.Popen(
            arguments,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except OSError:
        return False


def logout_dorm_ethernet_session(
    interface_ip: str,
    probe,
    *,
    wait_seconds: int = 45,
    portal_url: str = DORM_ETHERNET_PORTAL_URL,
    edge_profile_root: str | Path | None = None,
    edge_port: int | None = None,
) -> dict:
    """Log out a dorm Ethernet session through the official ePortal UI.

    The ePortal entry issues a fresh, short-lived session id on every visit.
    Reusing a session id captured during an earlier login can return HTTP 200
    without terminating the current NAS session, so this flow always navigates
    from the portal root and operates the official logout controls.
    """
    if websocket is None:
        raise EdgeLoginError(f"缺少 websocket-client 依赖：{WEBSOCKET_ERROR}")
    if not interface_ip:
        raise EdgeLoginError("宿舍有线网卡尚未取得 IPv4 地址")
    portal_host = urllib.parse.urlparse(portal_url).hostname
    if not portal_host:
        raise EdgeLoginError("宿舍有线门户地址无效")

    edge_path = _edge_path()
    attempt_ports, port_selection_mode = _select_edge_attempt_ports(edge_port)
    event(
        "dorm-logout-edge-ports-selected",
        True,
        "已为宿舍有线官方下线页面选择专用 Edge 调试端口",
        cdp_ports=list(attempt_ports),
        selection_mode=port_selection_mode,
    )
    deadline = time.time() + max(10, wait_seconds)
    last_error: EdgeLoginError | None = None
    allowed_hosts = {portal_host}

    for launch_attempt, port in enumerate(attempt_ports, start=1):
        if time.time() >= deadline:
            break
        base_profile = Path(edge_profile_root) if edge_profile_root is not None else DORM_LOGOUT_PROFILE_ROOT
        profile_path = base_profile if launch_attempt == 1 else base_profile.with_name(base_profile.name + "-retry")
        profile_path.mkdir(parents=True, exist_ok=True)
        process: subprocess.Popen | None = None
        client: Cdp | None = None
        client_url = ""
        logout_clicked = False
        confirm_clicked = False
        portal_confirmed_at: str | None = None
        consecutive_offline_probes = 0
        probe_attempts = 0
        try:
            page, cdp_status = _portal_page_status(port, allowed_hosts)
            if cdp_status["cdp_reachable"] and cdp_status["page_count"] > 0:
                if not _navigate_first_page(port, portal_url):
                    raise EdgeLoginError("已有专用 Edge 页面，但未能刷新宿舍有线门户会话")
                event(
                    "dorm-logout-portal-navigation",
                    True,
                    "已刷新宿舍有线门户入口并取得本次新会话",
                    launch_attempt=launch_attempt,
                    cdp_port=port,
                    reused_edge=True,
                )
            else:
                process = subprocess.Popen(
                    [
                        edge_path,
                        "--new-window",
                        "--no-proxy-server",
                        f"--remote-debugging-port={port}",
                        f"--user-data-dir={profile_path}",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-features=EdgeFirstRunExperience,HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,HttpsFirstModeForTypicallySecureUsers",
                        "--window-size=900,700",
                        portal_url,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            ready_deadline = min(deadline, time.time() + 20)
            page = None
            navigation_attempted = False
            while time.time() < ready_deadline:
                page, cdp_status = _portal_page_status(port, allowed_hosts)
                if page:
                    break
                if (
                    cdp_status["cdp_reachable"]
                    and cdp_status["page_count"] > 0
                    and not navigation_attempted
                ):
                    navigation_attempted = True
                    _navigate_first_page(port, portal_url)
                if process is not None and process.poll() is not None and not cdp_status["cdp_reachable"]:
                    break
                time.sleep(0.5)
            if not page:
                raise EdgeLoginError("专用 Edge 未能打开宿舍有线官方门户")

            event(
                "dorm-logout-edge-ready",
                True,
                "宿舍有线官方下线页面已就绪",
                launch_attempt=launch_attempt,
                cdp_port=port,
            )
            while time.time() < deadline:
                page, _ = _portal_page_status(port, allowed_hosts)
                if not page:
                    time.sleep(0.5)
                    continue
                websocket_url = str(page.get("webSocketDebuggerUrl") or "")
                if not websocket_url:
                    time.sleep(0.5)
                    continue
                if client is None or websocket_url != client_url:
                    _disconnect_client(client)
                    client = Cdp(websocket_url)
                    client_url = websocket_url

                state = _dorm_logout_page_state(client)
                if state.get("offlineSuccess"):
                    if portal_confirmed_at is None:
                        portal_confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
                        event(
                            "dorm-logout-portal-confirmed",
                            True,
                            "宿舍有线官方门户已显示下线成功",
                            launch_attempt=launch_attempt,
                        )
                elif not logout_clicked and state.get("online") and state.get("hasLogoutAction"):
                    logout_clicked = _click_dorm_logout(client)
                    event(
                        "dorm-logout-action",
                        logout_clicked,
                        "已点击官方门户的我要下线" if logout_clicked else "未能点击官方门户的我要下线",
                        launch_attempt=launch_attempt,
                    )
                elif logout_clicked and not confirm_clicked:
                    # The confirmation dialog may live in a portal overlay or
                    # shadow root whose text is absent from document.body.
                    # Poll the exact visible “确定” control directly instead of
                    # making the click depend on page-text detection.
                    confirm_clicked = _confirm_dorm_logout(client)
                    if confirm_clicked:
                        event(
                            "dorm-logout-confirmation",
                            True,
                            "已确认宿舍有线下线",
                            launch_attempt=launch_attempt,
                        )
                elif not logout_clicked and state.get("hasPassword"):
                    raise EdgeLoginError("宿舍有线官方门户未识别到当前在线会话")

                if portal_confirmed_at is not None:
                    probe_attempts += 1
                    if probe():
                        consecutive_offline_probes = 0
                    else:
                        consecutive_offline_probes += 1
                        if consecutive_offline_probes >= 2:
                            return {
                                "success": True,
                                "logout_confirmed_at": portal_confirmed_at,
                                "probe_attempts": probe_attempts,
                                "method": "dorm-official-portal-ui",
                            }
                    time.sleep(1)
                else:
                    time.sleep(0.5)

            if portal_confirmed_at is not None:
                last_error = EdgeLoginError("宿舍门户已显示下线成功，但真实联网探测未连续确认离线")
            elif confirm_clicked:
                last_error = EdgeLoginError("已确认宿舍有线下线，但门户未显示下线成功")
            elif logout_clicked:
                last_error = EdgeLoginError("已打开宿舍有线下线确认框，但未能完成确认")
            else:
                last_error = EdgeLoginError("宿舍有线官方门户未出现可操作的我要下线")
        except CdpHandshakeRejectedError:
            raise
        except EdgeLoginError as error:
            last_error = error
        except Exception as error:
            if _transient_cdp_error(error):
                last_error = EdgeLoginError("宿舍有线官方下线页面连接暂时中断")
            else:
                raise
        finally:
            if client is not None:
                _close_client(client)
            else:
                _close_browser_on_port(port)
            _stop_process(process)

    if last_error is not None:
        raise last_error
    raise EdgeLoginError("宿舍有线官方下线流程未能在限定时间内完成")


def _success_result(
    submitted_at: float | None,
    edge_ready_seconds: float | None,
    edge_launch_attempt: int,
    url: str,
    login_page_retained: bool = False,
) -> dict:
    return {
        "success": True,
        "login_submitted_at": (
            datetime.fromtimestamp(submitted_at).astimezone().isoformat(timespec="milliseconds")
            if submitted_at
            else None
        ),
        "probe_succeeded_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "edge_ready_seconds": edge_ready_seconds,
        "edge_launch_attempt": edge_launch_attempt,
        "url": url,
        "login_page_retained": login_page_retained,
    }


def login(
    portal_url: str,
    username: str,
    password: str,
    operator: str,
    probe,
    wait_seconds: int = 150,
    *,
    interface_ip: str = "",
    route_gateway: str = "",
    route_ifindex: int = 0,
    dns_servers: tuple[str, ...] = (),
    include_wireless_portal_host: bool = True,
    dorm_ethernet_flow: bool = False,
    keep_page_open: bool = True,
    success_page_url: str = "https://captiveportal-login.njmu.edu.cn/auth/index.html/u",
    edge_profile_root: str | Path | None = None,
    edge_port: int | None = None,
    submission_callback=None,
) -> dict:
    if websocket is None:
        raise EdgeLoginError(f"缺少 websocket-client 依赖：{WEBSOCKET_ERROR}")
    # 门户会依据运营商选项自行附加服务后缀，账号输入框只填写基础账号。
    username = username.strip().split("@", 1)[0]
    routes: list[str] = []
    resolved_hosts: dict[str, str] = {}
    login_url = portal_url
    credential_submission_attempted = False
    try:
        if interface_ip:
            login_url = _discover_login_url(
                interface_ip,
                portal_url,
                dorm_ethernet_flow=dorm_ethernet_flow,
            )
            if not _portal_url_allowed(login_url, dorm_ethernet_flow):
                raise PortalAllowlistError("校园网登录地址不在官方允许列表内")
            hosts = _login_route_hosts(login_url, include_wireless_portal_host)
            routes, resolved_hosts = _add_routes(
                hosts,
                route_gateway,
                route_ifindex,
                interface_ip=interface_ip,
                dns_servers=dns_servers,
            )
        elif not _portal_url_allowed(login_url, dorm_ethernet_flow):
            raise PortalAllowlistError("校园网登录地址不在官方允许列表内")
        allowed_hosts = set(resolved_hosts)
        login_host = urllib.parse.urlparse(login_url).hostname
        if login_host:
            allowed_hosts.add(login_host)
        edge_path = _edge_path()
        attempt_ports, port_selection_mode = _select_edge_attempt_ports(edge_port)
        event(
            "edge-cdp-ports-selected",
            True,
            {
                "automatic-first-run": "首次运行已自动选择两个空闲的本机 Edge 调试端口",
                "automatic-reselected": "原保存端口已被其他程序占用，已重新选择两个空闲端口",
                "saved": "已复用首次登录成功后保存的 Edge 调试端口",
                "explicit": "已使用显式指定的 Edge 调试端口",
            }[port_selection_mode],
            cdp_ports=list(attempt_ports),
            selection_mode=port_selection_mode,
        )
        deadline = time.time() + wait_seconds
        launch_failures: list[int | None] = []
        for launch_attempt in range(1, 3):
            if credential_submission_attempted:
                raise LoginOutcomeUnknownError("本轮已经提交过一次账号密码，结果尚未确认，已停止再次提交")
            if time.time() >= deadline:
                break
            port = attempt_ports[launch_attempt - 1]
            base_profile = Path(edge_profile_root) if edge_profile_root is not None else EDGE_PROFILE_ROOT
            profile_path = base_profile if launch_attempt == 1 else base_profile.with_name(base_profile.name + "-retry")
            profile_path.mkdir(parents=True, exist_ok=True)
            profile = str(profile_path)
            edge_arguments = [
                edge_path,
                "--new-window",
                "--no-proxy-server",
                f"--remote-debugging-port={port}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--window-size=900,700",
            ]
            if not keep_page_open:
                edge_arguments.append("--headless=new")
            resolver_rule = _completion_resolver_rule(success_page_url, resolved_hosts)
            if resolver_rule:
                edge_arguments.append(f"--host-resolver-rules={resolver_rule}")
            edge_arguments.append(login_url)
            process: subprocess.Popen | None = None
            client: Cdp | None = None
            client_url = ""
            submitted_at: float | None = None
            edge_ready_seconds: float | None = None
            filled = False
            dorm_login_click_dispatched = False
            dorm_login_click_started_at: float | None = None
            dorm_credentials_submitted = False
            dorm_operator_selected = False
            dorm_service_wait_started_at: float | None = None
            dorm_confirmation_wait_started_at: float | None = None
            dorm_login_action_attempts = 0
            dorm_service_action_attempts = 0
            dorm_confirmation_action_attempts = 0
            last_dorm_diagnostic_at = 0.0
            last_url = login_url
            launch_started = time.monotonic()
            launcher_exit_code: int | None = None
            retain_login_page = False
            navigation_attempted = False
            navigation_allowlist_notice_logged = False
            last_cdp_status = {
                "cdp_reachable": False,
                "page_count": 0,
                "cdp_reason": "not-checked",
            }
            try:
                process = subprocess.Popen(
                    edge_arguments,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                ready_deadline = min(deadline, time.time() + 20)
                page = None
                while time.time() < ready_deadline:
                    if probe():
                        return _success_result(None, None, launch_attempt, last_url)
                    page, last_cdp_status = _portal_page_status(port, allowed_hosts)
                    if page:
                        edge_ready_seconds = round(time.monotonic() - launch_started, 3)
                        event(
                            "edge-ready",
                            True,
                            "专用 Edge 调试页面已就绪",
                            launch_attempt=launch_attempt,
                            profile_slot=launch_attempt,
                            cdp_port=port,
                            edge_ready_seconds=edge_ready_seconds,
                            launcher_exit_code=launcher_exit_code,
                        )
                        break
                    if (
                        last_cdp_status["cdp_reachable"]
                        and last_cdp_status["page_count"] > 0
                        and not navigation_attempted
                    ):
                        navigation_attempted = True
                        navigated = _navigate_first_page(port, login_url)
                        event(
                            "edge-page-navigation",
                            navigated,
                            (
                                "Edge CDP 已就绪但未停留在校园门户，已主动导航到当前登录页"
                                if navigated
                                else "Edge CDP 已就绪但未能导航到校园门户"
                            ),
                            launch_attempt=launch_attempt,
                            profile_slot=launch_attempt,
                            cdp_port=port,
                            cdp_page_count=last_cdp_status["page_count"],
                        )
                    current_exit_code = process.poll()
                    if current_exit_code is not None:
                        launcher_exit_code = current_exit_code
                    time.sleep(0.5)
                if not page:
                    launch_failures.append(launcher_exit_code)
                    failure_kind = (
                        "portal-page-not-found"
                        if last_cdp_status["cdp_reachable"]
                        else "cdp-unreachable"
                    )
                    event(
                        "edge-launch-retry",
                        False,
                        (
                            "专用 Edge 调试端口可达，但未出现校园门户页面，准备切换备用浏览器配置"
                            if last_cdp_status["cdp_reachable"]
                            else "专用 Edge 调试端口未就绪，准备切换备用浏览器配置"
                        ),
                        launch_attempt=launch_attempt,
                        profile_slot=launch_attempt,
                        cdp_port=port,
                        failure_kind=failure_kind,
                        cdp_reason=last_cdp_status["cdp_reason"],
                        cdp_page_count=last_cdp_status["page_count"],
                        launcher_exit_code=launcher_exit_code,
                    )
                    continue

                last_page_seen = time.monotonic()
                restart_requested = False
                while time.time() < deadline:
                    # 页面可能在提交后关闭，因而每轮必须先做权威的 WLAN 联网探测。
                    if probe():
                        if submitted_at and keep_page_open:
                            retained_page = _portal_page(port, allowed_hosts)
                            retain_login_page = bool(retained_page)
                            if not retain_login_page and _portal_url_allowed(
                                success_page_url,
                                dorm_ethernet_flow,
                            ):
                                retain_login_page = _open_retained_success_page(
                                    edge_path,
                                    profile,
                                    port,
                                    success_page_url,
                                    resolved_hosts,
                                )
                            event(
                                "edge-page-retained",
                                retain_login_page,
                                (
                                    "网页认证成功，专用 Edge 页面已保留，可由用户手动关闭"
                                    if retain_login_page
                                    else "网页认证成功，但未能保留专用 Edge 页面"
                                ),
                                launch_attempt=launch_attempt,
                                profile_slot=launch_attempt,
                                cdp_port=port,
                            )
                        if submitted_at and port_selection_mode != "explicit":
                            ports_saved = _save_edge_ports(attempt_ports)
                            event(
                                "edge-cdp-ports-saved",
                                ports_saved,
                                (
                                    "主流程认证成功，已保存本机 Edge 调试端口"
                                    if ports_saved
                                    else "主流程认证成功，但未能保存本机 Edge 调试端口"
                                ),
                                cdp_ports=list(attempt_ports),
                            )
                        return _success_result(
                            submitted_at,
                            edge_ready_seconds,
                            launch_attempt,
                            last_url,
                            login_page_retained=retain_login_page,
                        )
                    page, last_cdp_status = _portal_page_status(port, allowed_hosts)
                    if not page:
                        if not submitted_at and time.monotonic() - last_page_seen >= 10:
                            launch_failures.append(process.poll())
                            event(
                                "edge-launch-retry",
                                False,
                                "登录前门户页面消失，准备重新启动专用 Edge",
                                launch_attempt=launch_attempt,
                                profile_slot=launch_attempt,
                                cdp_port=port,
                                cdp_reachable=last_cdp_status["cdp_reachable"],
                                cdp_page_count=last_cdp_status["page_count"],
                                launcher_exit_code=process.poll(),
                            )
                            restart_requested = True
                            break
                        time.sleep(1)
                        continue
                    last_page_seen = time.monotonic()
                    websocket_url = str(page.get("webSocketDebuggerUrl") or "")
                    if not websocket_url:
                        time.sleep(0.5)
                        continue
                    if client is None or websocket_url != client_url:
                        _disconnect_client(client)
                        client = None
                        try:
                            client = Cdp(websocket_url)
                            client_url = websocket_url
                        except CdpHandshakeRejectedError as error:
                            event(
                                "cdp-websocket-rejected",
                                False,
                                "Edge 拒绝本地主程序的 CDP WebSocket 连接，已停止无意义重试",
                                launch_attempt=launch_attempt,
                                profile_slot=launch_attempt,
                                cdp_port=port,
                                http_status=error.status_code,
                            )
                            raise
                        except Exception as error:
                            if _transient_cdp_error(error):
                                time.sleep(0.5)
                                continue
                            raise
                    try:
                        state = _page_state(client)
                    except Exception as error:
                        if _transient_cdp_error(error):
                            _disconnect_client(client)
                            client = None
                            client_url = ""
                            time.sleep(0.5)
                            continue
                        raise
                    last_url = str(state.get("url") or last_url)
                    if not _credential_targets_allowed(state, dorm_ethernet_flow):
                        raise PortalAllowlistError("账号密码框不在官方校园网凭据页面允许列表内")
                    if (
                        not navigation_allowlist_notice_logged
                        and not _portal_navigation_path_observed(last_url, dorm_ethernet_flow)
                    ):
                        navigation_allowlist_notice_logged = True
                        event(
                            "portal-navigation-allowlist-bypassed",
                            True,
                            "门户顶层过渡页面不在旧导航允许列表内，已继续等待经校验的官方凭据页面",
                            launch_attempt=launch_attempt,
                            credential_origin_check_active=True,
                        )
                    rejection_reason = _authentication_rejection(state.get("pageText", ""))
                    if (submitted_at or credential_submission_attempted) and rejection_reason:
                        raise AuthenticationRejectedError(
                            rejection_reason,
                            submitted=credential_submission_attempted,
                        )
                    if dorm_ethernet_flow:
                        if state.get("hasPassword") and not filled:
                            filled = _fill_dorm_credentials(client, username, password)
                            event(
                                "portal-form-fill",
                                filled,
                                "已填写宿舍有线账号密码" if filled else "未能填写宿舍有线账号密码",
                                form_filled=filled,
                                operator_matched=False,
                                operator_selection_strategy="deferred-service-page",
                                portal_frame_count=int(state.get("frameCount") or 1),
                            )
                        elif state.get("hasPassword") and filled and not dorm_login_click_dispatched:
                            dorm_login_action_attempts += 1
                            login_action = _submit_dorm_credentials(client)
                            if login_action:
                                login_click_method = (
                                    str(login_action.get("click_method") or "unknown")
                                    if isinstance(login_action, dict)
                                    else "legacy-test-double"
                                )
                                dorm_login_click_dispatched = True
                                credential_submission_attempted = True
                                credential_submitted_iso = datetime.now().astimezone().isoformat(timespec="milliseconds")
                                if submission_callback is not None:
                                    submission_callback(credential_submitted_iso)
                                event(
                                    "dorm-login-click-dispatched",
                                    True,
                                    (
                                        "已通过页面内 DOM 点击宿舍有线登录按钮，等待页面跳转确认"
                                        if login_click_method == "dom"
                                        else "DOM 点击不可用，已通过坐标后备点击宿舍有线登录按钮，等待页面跳转确认"
                                    ),
                                    launch_attempt=launch_attempt,
                                    action_attempts=dorm_login_action_attempts,
                                    click_method=login_click_method,
                                    recognized_label=(
                                        str(login_action.get("recognized_label") or "")
                                        if isinstance(login_action, dict)
                                        else ""
                                    ),
                                    match_strategy=(
                                        str(login_action.get("match_strategy") or "unknown")
                                        if isinstance(login_action, dict)
                                        else "legacy-test-double"
                                    ),
                                    control_tag=(
                                        str(login_action.get("control_tag") or "")
                                        if isinstance(login_action, dict)
                                        else ""
                                    ),
                                    control_type=(
                                        str(login_action.get("control_type") or "")
                                        if isinstance(login_action, dict)
                                        else ""
                                    ),
                                )
                                dorm_login_click_started_at = time.monotonic()
                                last_dorm_diagnostic_at = 0.0
                            else:
                                now_monotonic = time.monotonic()
                                if (
                                    last_dorm_diagnostic_at == 0.0
                                    or now_monotonic - last_dorm_diagnostic_at
                                    >= DORM_STAGE_DIAGNOSTIC_INTERVAL_SECONDS
                                ):
                                    _emit_dorm_stage_diagnostic(
                                        "dorm-login-button-waiting",
                                        "账号密码已填写，但尚未识别到“点击登录”按钮",
                                        client,
                                        operator,
                                        launch_attempt=launch_attempt,
                                        elapsed_seconds=max(0.0, now_monotonic - launch_started),
                                        action_attempts=dorm_login_action_attempts,
                                    )
                                    last_dorm_diagnostic_at = now_monotonic
                        elif dorm_login_click_dispatched and not dorm_credentials_submitted:
                            if not state.get("hasPassword"):
                                dorm_credentials_submitted = True
                                transition_elapsed = (
                                    time.monotonic() - dorm_login_click_started_at
                                    if dorm_login_click_started_at is not None
                                    else 0.0
                                )
                                event(
                                    "dorm-credentials-submitted",
                                    True,
                                    "已确认点击登录后离开账号密码页，开始等待运营商选择页",
                                    launch_attempt=launch_attempt,
                                    transition_verified=True,
                                    elapsed_seconds=round(max(0.0, transition_elapsed), 3),
                                )
                                dorm_service_wait_started_at = time.monotonic()
                                last_dorm_diagnostic_at = 0.0
                            else:
                                now_monotonic = time.monotonic()
                                if (
                                    last_dorm_diagnostic_at == 0.0
                                    or now_monotonic - last_dorm_diagnostic_at
                                    >= DORM_STAGE_DIAGNOSTIC_INTERVAL_SECONDS
                                ):
                                    _emit_dorm_stage_diagnostic(
                                        "dorm-login-transition-waiting",
                                        "已点击“点击登录”按钮，但账号密码页仍然可见，尚未确认提交成功",
                                        client,
                                        operator,
                                        launch_attempt=launch_attempt,
                                        elapsed_seconds=(
                                            now_monotonic - dorm_login_click_started_at
                                            if dorm_login_click_started_at is not None
                                            else 0.0
                                        ),
                                        action_attempts=dorm_login_action_attempts,
                                    )
                                    last_dorm_diagnostic_at = now_monotonic
                        elif dorm_credentials_submitted and not dorm_operator_selected:
                            dorm_service_action_attempts += 1
                            try:
                                service_action = _select_dorm_operator(client, operator)
                            except Exception as error:
                                event(
                                    "dorm-service-selection-error",
                                    False,
                                    "扫描或点击宿舍有线运营商控件时发生异常",
                                    launch_attempt=launch_attempt,
                                    action_attempts=dorm_service_action_attempts,
                                    error_type=type(error).__name__,
                                )
                                raise
                            if service_action:
                                service_click_method = (
                                    str(service_action.get("click_method") or "unknown")
                                    if isinstance(service_action, dict)
                                    else "legacy-test-double"
                                )
                                dorm_operator_selected = True
                                service_elapsed = (
                                    time.monotonic() - dorm_service_wait_started_at
                                    if dorm_service_wait_started_at is not None
                                    else 0.0
                                )
                                event(
                                    "dorm-service-selected",
                                    True,
                                    (
                                        "已通过页面内 DOM 点击选择宿舍有线运营商"
                                        if service_click_method == "dom"
                                        else "DOM 点击不可用，已通过坐标后备选择宿舍有线运营商"
                                    ),
                                    launch_attempt=launch_attempt,
                                    elapsed_seconds=round(max(0.0, service_elapsed), 3),
                                    action_attempts=dorm_service_action_attempts,
                                    click_method=service_click_method,
                                )
                                dorm_confirmation_wait_started_at = time.monotonic()
                                last_dorm_diagnostic_at = 0.0
                            else:
                                now_monotonic = time.monotonic()
                                if (
                                    last_dorm_diagnostic_at == 0.0
                                    or now_monotonic - last_dorm_diagnostic_at
                                    >= DORM_STAGE_DIAGNOSTIC_INTERVAL_SECONDS
                                ):
                                    _emit_dorm_stage_diagnostic(
                                        "dorm-service-page-waiting",
                                        "账号密码已提交，但尚未识别到可点击的宿舍有线运营商控件",
                                        client,
                                        operator,
                                        launch_attempt=launch_attempt,
                                        elapsed_seconds=(
                                            now_monotonic - dorm_service_wait_started_at
                                            if dorm_service_wait_started_at is not None
                                            else 0.0
                                        ),
                                        action_attempts=dorm_service_action_attempts,
                                    )
                                    last_dorm_diagnostic_at = now_monotonic
                        elif dorm_operator_selected and submitted_at is None:
                            dorm_confirmation_action_attempts += 1
                            try:
                                confirmation_action = _click_dorm_confirmation(client)
                            except Exception as error:
                                event(
                                    "dorm-confirmation-error",
                                    False,
                                    "扫描或点击宿舍有线确认按钮时发生异常",
                                    launch_attempt=launch_attempt,
                                    action_attempts=dorm_confirmation_action_attempts,
                                    error_type=type(error).__name__,
                                )
                                raise
                            if confirmation_action:
                                confirmation_click_method = (
                                    str(confirmation_action.get("click_method") or "unknown")
                                    if isinstance(confirmation_action, dict)
                                    else "legacy-test-double"
                                )
                                submitted_at = time.time()
                                submitted_iso = datetime.fromtimestamp(submitted_at).astimezone().isoformat(timespec="milliseconds")
                                append_connectivity_event(
                                    "login-submitted",
                                    source=EVENT_SOURCE,
                                    login_submitted_at=submitted_iso,
                                    click_method=confirmation_click_method,
                                )
                                event(
                                    "login-submitted",
                                    True,
                                    (
                                        "已通过页面内 DOM 点击确认宿舍有线运营商并提交登录"
                                        if confirmation_click_method == "dom"
                                        else "DOM 点击不可用，已通过坐标后备确认宿舍有线运营商并提交登录"
                                    ),
                                    launch_attempt=launch_attempt,
                                    login_submitted_at=submitted_iso,
                                    click_method=confirmation_click_method,
                                )
                            else:
                                now_monotonic = time.monotonic()
                                if (
                                    last_dorm_diagnostic_at == 0.0
                                    or now_monotonic - last_dorm_diagnostic_at
                                    >= DORM_STAGE_DIAGNOSTIC_INTERVAL_SECONDS
                                ):
                                    _emit_dorm_stage_diagnostic(
                                        "dorm-confirmation-waiting",
                                        "已选择宿舍有线运营商，但尚未识别到可点击的确定按钮",
                                        client,
                                        operator,
                                        launch_attempt=launch_attempt,
                                        elapsed_seconds=(
                                            now_monotonic - dorm_confirmation_wait_started_at
                                            if dorm_confirmation_wait_started_at is not None
                                            else 0.0
                                        ),
                                        action_attempts=dorm_confirmation_action_attempts,
                                    )
                                    last_dorm_diagnostic_at = now_monotonic
                    elif state.get("hasPassword") and not filled:
                        result = _fill_form(client, username, password, operator)
                        event(
                            "portal-form-fill",
                            bool(result.get("filled")) and bool(result.get("operatorMatched")),
                            (
                                "已填写校园网账号并选择运营商"
                                if result.get("filled") and result.get("operatorMatched")
                                else "未能完成校园网账号填写或运营商选择"
                            ),
                            form_filled=bool(result.get("filled")),
                            operator_matched=bool(result.get("operatorMatched")),
                            operator_selection_strategy=result.get("operatorStrategy", "unknown"),
                        )
                        if not result.get("operatorMatched", True):
                            raise AuthenticationRejectedError("operator-invalid")
                        filled = bool(result.get("filled"))
                    elif state.get("hasPassword") and filled and submitted_at is None:
                        if _submit_form(client):
                            submitted_at = time.time()
                            credential_submission_attempted = True
                            submitted_iso = datetime.fromtimestamp(submitted_at).astimezone().isoformat(timespec="milliseconds")
                            if submission_callback is not None:
                                submission_callback(submitted_iso)
                            append_connectivity_event(
                                "login-submitted",
                                source=EVENT_SOURCE,
                                login_submitted_at=submitted_iso,
                            )
                            event(
                                "login-submitted",
                                True,
                                "主流程已向校园网门户提交登录",
                                launch_attempt=launch_attempt,
                                login_submitted_at=submitted_iso,
                            )
                    time.sleep(2)
                if submitted_at:
                    raise LoginOutcomeUnknownError("主流程已提交门户登录，但未能确认认证成功或失败，已停止再次提交")
                if dorm_ethernet_flow and not restart_requested:
                    if not filled:
                        raise EdgeLoginError("宿舍有线登录页已打开，但未在主页面或内嵌页面找到账号密码框")
                    if not dorm_login_click_dispatched:
                        _emit_dorm_stage_diagnostic(
                            "dorm-login-button-timeout",
                            "账号密码已填写，但在限定时间内未能识别并点击“点击登录”按钮",
                            client,
                            operator,
                            launch_attempt=launch_attempt,
                            elapsed_seconds=max(0.0, time.monotonic() - launch_started),
                            action_attempts=dorm_login_action_attempts,
                        )
                        raise EdgeLoginError("已填写宿舍有线账号密码，但未能识别并点击“点击登录”按钮")
                    if not dorm_credentials_submitted:
                        transition_elapsed = (
                            time.monotonic() - dorm_login_click_started_at
                            if dorm_login_click_started_at is not None
                            else 0.0
                        )
                        _emit_dorm_stage_diagnostic(
                            "dorm-login-transition-timeout",
                            "已点击“点击登录”按钮，但在限定时间内未确认页面离开账号密码阶段",
                            client,
                            operator,
                            launch_attempt=launch_attempt,
                            elapsed_seconds=transition_elapsed,
                            action_attempts=dorm_login_action_attempts,
                        )
                        raise LoginOutcomeUnknownError("已点击一次宿舍有线登录按钮，但页面未跳转，已停止再次点击")
                    if not dorm_operator_selected:
                        service_elapsed = (
                            time.monotonic() - dorm_service_wait_started_at
                            if dorm_service_wait_started_at is not None
                            else 0.0
                        )
                        _emit_dorm_stage_diagnostic(
                            "dorm-service-selection-timeout",
                            "账号密码已提交，但在限定时间内未能选择宿舍有线运营商",
                            client,
                            operator,
                            launch_attempt=launch_attempt,
                            elapsed_seconds=service_elapsed,
                            action_attempts=dorm_service_action_attempts,
                        )
                        raise LoginOutcomeUnknownError("已提交一次宿舍有线账号密码，但未能选择运营商，已停止再次提交")
                    confirmation_elapsed = (
                        time.monotonic() - dorm_confirmation_wait_started_at
                        if dorm_confirmation_wait_started_at is not None
                        else 0.0
                    )
                    _emit_dorm_stage_diagnostic(
                        "dorm-confirmation-timeout",
                        "已选择宿舍有线运营商，但在限定时间内未能点击确定",
                        client,
                        operator,
                        launch_attempt=launch_attempt,
                        elapsed_seconds=confirmation_elapsed,
                        action_attempts=dorm_confirmation_action_attempts,
                    )
                    raise LoginOutcomeUnknownError("已提交一次宿舍有线账号密码，但未能确认最终结果，已停止再次提交")
                if not restart_requested:
                    raise EdgeLoginError("专用 Edge 已启动，但未能在限定时间内完成门户表单提交")
            finally:
                if retain_login_page:
                    _disconnect_client(client)
                else:
                    if client is not None:
                        _close_client(client)
                    else:
                        _close_browser_on_port(port)
                    _stop_process(process)
        exit_codes = ["running" if code is None else str(code) for code in launch_failures]
        detail = ",".join(exit_codes) if exit_codes else "unknown"
        raise EdgeLoginError(f"专用 Edge 两个浏览器配置均未出现可用门户页面（退出状态：{detail}）")
    finally:
        _delete_routes(routes, route_gateway, route_ifindex)
