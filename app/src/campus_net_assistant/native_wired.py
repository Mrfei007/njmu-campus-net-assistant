"""Staged Ruijie wired-protocol diagnostics and capture-profile import.

The current UI performs only read-only component checks and redacted pcapng
profile import. Legacy PEAP restore helpers remain so an older unfinished
trial can be rolled back, while new PEAP trials are permanently fail-closed.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from .config import APP_DIR, AppConfig
from .ethernet import _decode_output, detect_linked_physical_ethernet, get_ethernet
from .probe import connectivity_probe
from .rawether import inspect as inspect_rawether
from .recovery_lock import acquire_recovery_lock
from .ruijie import resolve_installation
from .ruijie_protocol import (
    PROFILE_PATH_NAME,
    RuijieProtocolError,
    extract_compatibility_profile,
    load_profile as load_ruijie_profile,
    profile_json as ruijie_profile_json,
)
from .ruijie_profiles import NJMU_PROFILE_ID, builtin_profile_for_client

PROFILE_PATH = APP_DIR / "native-wired-test-profile.xml"
REPORT_PATH = APP_DIR / "native-wired-test-result.json"
STATE_PATH = APP_DIR / "native-wired-test-restore.json"
RUIJIE_PROFILE_PATH = APP_DIR / PROFILE_PATH_NAME
CHANNEL = "Microsoft-Windows-Wired-AutoConfig/Operational"
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
LAN = "http://www.microsoft.com/networking/LAN/profile/v1"
ONEX = "http://www.microsoft.com/networking/OneX/v1"
EAPHOST = "http://www.microsoft.com/provisioning/EapHostConfig"
COMMON = "http://www.microsoft.com/provisioning/EapCommon"
BASE = "http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"
PEAP = "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"
CHAP = "http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"


class NativeWiredError(RuntimeError):
    """Messages are deliberately independent of command output and credentials."""


@dataclass(frozen=True)
class TrustSettings:
    servers: str
    roots: tuple[str, ...]


def _xml(text: str) -> ET.Element:
    if len(text) > 128_000 or re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise NativeWiredError("配置文件过大或包含不支持的 XML 声明")
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        raise NativeWiredError("无法读取有线认证 XML 配置") from None


def parse_profile(text: str) -> TrustSettings:
    root = _xml(text)
    if root.tag != f"{{{LAN}}}LANProfile":
        raise NativeWiredError("请选择 Windows 导出的有线 LANProfile 配置，不是无线配置")
    security = root.find(f"{{{LAN}}}MSM/{{{LAN}}}security")
    if security is None or security.findtext(f"{{{LAN}}}OneXEnabled") != "true":
        raise NativeWiredError("配置没有启用有线 802.1X 认证")
    host = security.find(f"{{{ONEX}}}OneX/{{{ONEX}}}EAPConfig/{{{EAPHOST}}}EapHostConfig")
    if host is None or host.findtext(f"{{{EAPHOST}}}EapMethod/{{{COMMON}}}Type") != "25":
        raise NativeWiredError("本试验入口目前只支持 PEAP / MS-CHAPv2")
    method = host.find(f"{{{EAPHOST}}}EapMethod")
    if any((method.findtext(f"{{{COMMON}}}{field}") or "0") != "0" for field in ("AuthorId", "VendorId", "VendorType")):
        raise NativeWiredError("配置使用厂商提供的 EAP 方法，不能替换成 Windows 标准 PEAP")
    outer = host.find(f"{{{EAPHOST}}}Config/{{{BASE}}}Eap")
    if outer is None or outer.findtext(f"{{{BASE}}}Type") != "25":
        raise NativeWiredError("配置的 PEAP 方法不一致")
    peap = outer.find(f"{{{PEAP}}}EapType")
    if peap is None or peap.findtext(f"{{{BASE}}}Eap/{{{BASE}}}Type") != "26":
        raise NativeWiredError("本试验入口目前只支持 PEAP / MS-CHAPv2")
    validation = peap.find(f"{{{PEAP}}}ServerValidation")
    if validation is None:
        raise NativeWiredError("配置缺少认证服务器及 CA 证书信息")
    servers = (validation.findtext(f"{{{PEAP}}}ServerNames") or "").strip()
    names = servers.split(";")
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", n)
               and "." in n and ".." not in n for n in names):
        raise NativeWiredError("请使用学校提供的明确认证服务器域名，不能留空或使用通配符")
    roots = tuple(re.sub(r"\s", "", n.text or "").upper()
                  for n in validation.findall(f"{{{PEAP}}}TrustedRootCA"))
    if not roots or not all(re.fullmatch(r"[0-9A-F]{40}", value) for value in roots):
        raise NativeWiredError("配置缺少有效的 CA 证书 SHA-1 指纹，请向学校获取配置")
    # Rebuild from this small allowlist; never import arbitrary supplied XML.
    return TrustSettings(servers, roots)


def profile_xml(trust: TrustSettings) -> str:
    roots = "".join(f"<TrustedRootCA>{value}</TrustedRootCA>" for value in trust.roots)
    return f'''<?xml version="1.0" encoding="utf-8"?>
<LANProfile xmlns="{LAN}"><MSM><security>
<OneXEnforced>true</OneXEnforced><OneXEnabled>true</OneXEnabled>
<OneX xmlns="{ONEX}"><heldPeriod>3600</heldPeriod><maxAuthFailures>1</maxAuthFailures><authMode>user</authMode>
<EAPConfig><EapHostConfig xmlns="{EAPHOST}"><EapMethod>
<Type xmlns="{COMMON}">25</Type><AuthorId xmlns="{COMMON}">0</AuthorId>
</EapMethod><Config><Eap xmlns="{BASE}"><Type>25</Type><EapType xmlns="{PEAP}">
<ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
<ServerNames>{escape(trust.servers)}</ServerNames>{roots}</ServerValidation>
<FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional>
<Eap xmlns="{BASE}"><Type>26</Type><EapType xmlns="{CHAP}">
<UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap>
<EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding>
<PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>
<AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName>
</PeapExtensions></EapType></Eap></Config></EapHostConfig></EAPConfig>
</OneX></security></MSM></LANProfile>'''


def import_profile(path: Path) -> TrustSettings:
    if path.stat().st_size > 128_000:
        raise NativeWiredError("配置文件过大")
    raw = path.read_bytes()
    text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    trust = parse_profile(text)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(profile_xml(trust), encoding="utf-8")
    return trust


def credentials_xml(username: str, password: str) -> str:
    if not username.strip() or not password or any(ord(c) < 32 for c in username + password):
        raise NativeWiredError("账号密码为空或包含不支持的控制字符")
    user, secret = escape(username), escape(password)
    return f'''<?xml version="1.0" encoding="utf-8"?>
<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials"
 xmlns:c="{COMMON}" xmlns:b="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1"
 xmlns:p="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1"
 xmlns:m="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1">
<EapMethod><c:Type>25</c:Type><c:AuthorId>0</c:AuthorId></EapMethod>
<Credentials><b:Eap><b:Type>25</b:Type><p:EapType><p:RoutingIdentity>{user}</p:RoutingIdentity>
<b:Eap><b:Type>26</b:Type><m:EapType><m:Username>{user}</m:Username>
<m:Password>{secret}</m:Password><m:LogonDomain></m:LogonDomain></m:EapType></b:Eap>
</p:EapType></b:Eap></Credentials></EapHostUserCredentials>'''


def _run(args: list[str], timeout: int = 25) -> str:
    result = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    if result.returncode:
        raise NativeWiredError(f"Windows 操作未完成（退出码 {result.returncode}），已停止本轮测试")
    return _decode_output(result.stdout)


def _ps(script: str) -> str:
    modules = str(SYSTEM32 / "WindowsPowerShell/v1.0/Modules").replace("'", "''")
    prefix = ("$ErrorActionPreference='Stop'; "
              f"$env:PSModulePath='{modules}'; "
              "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); ")
    return _run([str(SYSTEM32 / "WindowsPowerShell/v1.0/powershell.exe"), "-NoProfile", "-NonInteractive",
                 "-Command", prefix + script]).strip()


def _lan(*args: str) -> str:
    return _run([str(SYSTEM32 / "netsh.exe"), "lan", *args])


def _service_running() -> bool:
    return _ps("(Get-Service dot3svc).Status.ToString()") == "Running"


def _interface_guid(index: int) -> str:
    luid = ctypes.c_ulonglong()
    guid = (ctypes.c_ubyte * 16)()
    api = ctypes.WinDLL(str(SYSTEM32 / "iphlpapi.dll"))
    api.ConvertInterfaceIndexToLuid.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulonglong)]
    api.ConvertInterfaceLuidToGuid.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p]
    if api.ConvertInterfaceIndexToLuid(index, ctypes.byref(luid)) or api.ConvertInterfaceLuidToGuid(ctypes.byref(luid), guid):
        raise NativeWiredError("无法确认有线网卡标识")
    return str(uuid.UUID(bytes_le=bytes(guid)))


def _private_directory() -> Path:
    # Create the directory with a protected DACL from its first instant.
    sid = _ps("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise NativeWiredError("无法确认当前 Windows 用户")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    path = APP_DIR / ("native-wired-private-" + uuid.uuid4().hex)
    class SA(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("descriptor", ctypes.c_void_p), ("inherit", ctypes.c_int)]
    advapi = ctypes.WinDLL(str(SYSTEM32 / "advapi32.dll"), use_last_error=True)
    kernel = ctypes.WinDLL(str(SYSTEM32 / "kernel32.dll"), use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(SA)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})", 1, ctypes.byref(descriptor), None
    ):
        raise NativeWiredError("无法创建受保护的临时目录")
    try:
        sa = SA(ctypes.sizeof(SA), descriptor, 0)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(sa)):
            raise NativeWiredError("无法创建受保护的临时目录")
    finally:
        kernel.LocalFree(descriptor)
    return path


def _events(after: int = 0) -> list[dict]:
    # Do not return identity, account, domain, MAC, certificate contents or raw XML.
    script = f'''$filter="*[System[(EventID=15503 or EventID=15504 or EventID=15505 or EventID=15514 or EventID=15500 or EventID=15506) and EventRecordID > {int(after)}]]";
    $items=@(Get-WinEvent -LogName '{CHANNEL}' -FilterXPath $filter -MaxEvents 100 -ErrorAction SilentlyContinue);
    @($items | ForEach-Object {{
      $doc=[xml]$_.ToXml(); $fields=@{{}};
      foreach($node in $doc.Event.EventData.Data) {{$fields[$node.Name]=$node.'#text'}};
      @{{record_id=$_.RecordId; event_id=$_.Id; time=$_.TimeCreated.ToUniversalTime().ToString('o');
      guid=$fields['InterfaceGuid']; connection=$fields['ConnectionID']; reason=$fields['ReasonCode']; error=$fields['ErrorCode']}}
    }}) | ConvertTo-Json -Compress'''
    value = json.loads(_ps(script) or "[]")
    return value if isinstance(value, list) else [value]


def authentication_evidence(events: list[dict], guid: str, after: int, started: str) -> dict | None:
    start = datetime.fromisoformat(started.replace("Z", "+00:00"))
    selected = []
    for item in events:
        try:
            stamp = datetime.fromisoformat(item["time"].replace("Z", "+00:00"))
            if int(item["record_id"]) > after and stamp >= start and str(item.get("guid", "")).strip("{}").lower() == guid.lower():
                selected.append(item)
        except (KeyError, TypeError, ValueError):
            continue
    selected.sort(key=lambda item: int(item["record_id"]))
    current_connection = None
    result = None
    for item in selected:
        if item["event_id"] in (15503, 15504):
            current_connection = item.get("connection")
            result = None
        elif item["event_id"] in (15500, 15506, 15514):
            result = dict(item, authenticated=False)
        elif item["event_id"] == 15505 and current_connection and item.get("connection") == current_connection:
            result = dict(item, authenticated=True)
    return result


def environment_report(configured_path: str | Path = "") -> dict:
    result = {
        "profile_ready": False,
        "profile_message": "实测协议为 EAP-MD5 加锐捷私有扩展，Windows PEAP 配置入口已停用",
        "protocol_confirmed": True,
        "protocol": "802.1X / EAPOL / EAP-MD5 / Ruijie private extension",
        "peap_trial_retired": True,
        "link_ready": False,
        "restore_pending": STATE_PATH.exists(),
        "rawether": inspect_rawether(configured_path),
        "capture_profile_ready": False,
        "compatibility_profile_ready": False,
        "compatibility_profile_source": "none",
    }
    try:
        installation = resolve_installation(configured_path)
        result.update(
            client_path=str(getattr(installation, "launcher", "")),
            worker_sha256=getattr(installation, "worker_sha256", ""),
        )
        builtin = builtin_profile_for_client(installation.worker_sha256)
        if builtin is not None:
            result.update(
                capture_profile_ready=True,
                compatibility_profile_ready=True,
                compatibility_profile_source="built-in",
                compatibility_profile_id=NJMU_PROFILE_ID,
                capture_profile_count=0,
                capture_profile_message="南医工位兼容资料已内置，客户端版本已匹配",
            )
        elif RUIJIE_PROFILE_PATH.is_file():
            profile = load_ruijie_profile(RUIJIE_PROFILE_PATH.read_text(encoding="utf-8"))
            matched = profile.client_sha256 == installation.worker_sha256
            result.update(
                capture_profile_ready=matched,
                compatibility_profile_ready=matched,
                compatibility_profile_source="local-import" if matched else "none",
                capture_profile_count=len(profile.capture_hashes),
                capture_profile_message=(
                    "本机导入的兼容资料已就绪"
                    if matched else "当前锐捷客户端版本尚未纳入支持列表"
                ),
            )
        else:
            result["capture_profile_message"] = "当前锐捷客户端版本尚未纳入支持列表"
    except (OSError, UnicodeError, RuijieProtocolError, RuntimeError):
        result["capture_profile_message"] = "请先安装学校提供的锐捷客户端并选择其主程序"
    try:
        link = detect_linked_physical_ethernet()
        result["link_ready"] = True
        result["adapter"] = link.description
    except (RuntimeError, OSError, subprocess.SubprocessError):
        result["adapter"] = "未检测到唯一已连接的物理有线网卡"
    try:
        result["service_running"] = _service_running()
        result["ruijie_running"] = _ps("[bool](Get-Process -Name '8021x','RuijieSupplicant' -ErrorAction SilentlyContinue)") == "True"
    except (NativeWiredError, OSError, subprocess.SubprocessError):
        result["service_running"] = None
        result["ruijie_running"] = None
    return result


def import_ruijie_captures(paths: list[Path], configured_path: str | Path) -> dict:
    """Create the redacted compatibility profile used by a later field trial."""
    installation = resolve_installation(configured_path)
    profile = extract_compatibility_profile(paths, installation.worker)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temporary = RUIJIE_PROFILE_PATH.with_suffix(".tmp")
    temporary.write_text(ruijie_profile_json(profile), encoding="utf-8")
    load_ruijie_profile(temporary.read_text(encoding="utf-8"))
    temporary.replace(RUIJIE_PROFILE_PATH)
    return {
        "success": True,
        "message": (
            "已从成功抓包生成锐捷兼容资料；未保存账号、密码派生值、MAC/IP、"
            "硬件标识、服务端结果报文或原始抓包"
        ),
        "capture_profile_ready": True,
        "capture_profile_count": len(profile.capture_hashes),
    }


def _save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def restore_pending() -> None:
    if not STATE_PATH.exists():
        return
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    folder = Path(state["folder"]).resolve()
    if folder.parent != APP_DIR.resolve() or not re.fullmatch(r"native-wired-private-[0-9a-f]{32}", folder.name):
        raise NativeWiredError("恢复目录校验失败，未更改网络设置")
    (folder / "credentials.xml").unlink(missing_ok=True)
    if state.get("backup"):
        backup = folder / "previous.xml"
        if hashlib.sha256(backup.read_bytes()).hexdigest() != state["backup_hash"]:
            raise NativeWiredError("原有线配置备份校验失败")
    if state.get("profile_changed"):
        if _interface_guid(int(state["ifindex"])) != state["guid"]:
            raise NativeWiredError("原有线网卡不在当前接口位置，请接回原网卡后点击恢复")
        _ps("Start-Service dot3svc")
        _lan("delete", "profile", f"interface={state['interface']}")
        if state.get("backup"):
            backup = folder / "previous.xml"
            _lan("add", "profile", f"filename={backup}", f"interface={state['interface']}")
    if not state["service_was_running"]:
        _ps("Stop-Service dot3svc")
    STATE_PATH.unlink()
    # Known nonrecursive files only. Keep any unexpected file for inspection.
    for name in ("previous.xml", "trial.xml"):
        (folder / name).unlink(missing_ok=True)
    try:
        folder.rmdir()
    except OSError:
        pass


def _trial(config: AppConfig, report: dict, wait_seconds: int) -> None:
    if STATE_PATH.exists():
        raise NativeWiredError("上一次测试有待恢复的设置，请先点击“恢复原有有线设置”")
    ready = environment_report()
    if not ready["profile_ready"]:
        raise NativeWiredError(ready["profile_message"])
    if ready.get("ruijie_running") is not False:
        raise NativeWiredError("请先完全退出锐捷认证客户端，再测试 Windows 原生认证")
    link = detect_linked_physical_ethernet()
    guid = _interface_guid(link.ifindex)
    from .credentials import load
    username, password = load()
    user_xml = credentials_xml(username, password)
    trust = parse_profile(PROFILE_PATH.read_text(encoding="utf-8"))
    folder = _private_directory()
    state = {"folder": str(folder), "interface": link.interface, "ifindex": link.ifindex, "guid": guid,
             "service_was_running": _service_running(), "profile_changed": False, "backup": False}
    _save_state(state)
    try:
        _ps("Start-Service dot3svc")
        enabled = _ps(f"(Get-WinEvent -ListLog '{CHANNEL}').IsEnabled")
        if enabled != "True":
            raise NativeWiredError("Windows 有线认证事件日志未启用，无法核验认证结果")
        # Export before touching the adapter. Export failures are fail-closed.
        _lan("export", "profile", f"folder={folder}", f"interface={link.interface}")
        exported = list(folder.glob("*.xml"))
        if len(exported) > 1:
            raise NativeWiredError("发现多个有线配置，无法确定应恢复的配置")
        if exported:
            previous = exported[0]
            root = ET.parse(previous).getroot()
            enabled_node = root.find(f"{{{LAN}}}MSM/{{{LAN}}}security/{{{LAN}}}OneXEnabled")
            if enabled_node is None or enabled_node.text != "false":
                raise NativeWiredError("此网卡已有启用的 Windows 802.1X 配置；为保留其凭据，本试验不覆盖它")
            previous.rename(folder / "previous.xml")
            state["backup"] = True
            state["backup_hash"] = hashlib.sha256((folder / "previous.xml").read_bytes()).hexdigest()
        # Do not enable adapter autoconfiguration implicitly. Windows' own
        # profile import/reconnect must succeed; no global blockperiod changes.
        baseline = max((int(item["record_id"]) for item in _events()), default=0)
        started = datetime.now(timezone.utc).isoformat()
        report.update(authentication_started_at=started, authentication_succeeded=False, connectivity_succeeded=False)
        (folder / "trial.xml").write_text(profile_xml(trust), encoding="utf-8")
        state["profile_changed"] = True
        _save_state(state)  # crash recovery is durable before the first mutation
        _lan("add", "profile", f"filename={folder / 'trial.xml'}", f"interface={link.interface}")
        secret_path = folder / "credentials.xml"
        try:
            secret_path.write_text(user_xml, encoding="utf-8")
            _lan("set", "eapuserdata", f"filename={secret_path}", "allusers=no", f"interface={link.interface}")
        finally:
            secret_path.unlink(missing_ok=True)
            user_xml = password = ""
        # Only accept a new authentication session after credential import.
        baseline = max((int(item["record_id"]) for item in _events()), default=baseline)
        started = datetime.now(timezone.utc).isoformat()
        report["authentication_started_at"] = started
        _lan("reconnect", f"interface={link.interface}")
        report["request_dispatched"] = True
        deadline = time.monotonic() + min(max(wait_seconds, 1), 90)
        while time.monotonic() < deadline:
            evidence = authentication_evidence(_events(baseline), guid, baseline, started)
            if evidence and not evidence["authenticated"]:
                report["authentication_event_id"] = evidence["event_id"]
                raise NativeWiredError("Windows 报告有线认证失败、暂停或链路断开；本轮不再重试")
            if evidence and evidence["authenticated"]:
                report.update(authentication_succeeded=True, authentication_event_id=15505,
                              authentication_record_id=evidence["record_id"], authentication_succeeded_at=evidence["time"])
                network = get_ethernet()
                if network and network.ifindex == link.ifindex and _interface_guid(network.ifindex) == guid:
                    # Strict Microsoft evidence, irrespective of the normal dual-target policy.
                    online, source = connectivity_probe(network.ip, config.portal.check_url, config.portal.success_text, "")
                    if online:
                        report.update(connectivity_succeeded=True, probe_succeeded_at=datetime.now(timezone.utc).isoformat(), probe_source=source)
                        return
            time.sleep(2)
        raise NativeWiredError("等待超时：尚未取得本轮 Windows 认证成功与有线联网成功的完整证据")
    finally:
        restore_pending()
        report["settings_restored"] = True


def run_trial(config: AppConfig, wait_seconds: int = 60) -> dict:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    report = {"success": False, "request_dispatched": False, "authentication_succeeded": False,
              "connectivity_succeeded": False, "settings_restored": not STATE_PATH.exists(),
              "started_at": datetime.now(timezone.utc).isoformat(), "scope": "retired-native-peap-trial",
              "message": "抓包已确认工位不是 Windows 标准 PEAP；该测试已停用，未读取凭据或更改网络"}
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def run_restore() -> dict:
    report = {"success": False, "settings_restored": False}
    try:
        with acquire_recovery_lock(timeout_ms=15000) as acquired:
            if not acquired:
                raise NativeWiredError("另一个联网流程正在运行，请稍后恢复")
            restore_pending()
        report.update(success=True, settings_restored=True, message="原有有线设置已恢复")
    except NativeWiredError as error:
        report["message"] = str(error)
    except Exception as error:
        report["message"] = "恢复未完成（" + type(error).__name__ + "）"
    APP_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
