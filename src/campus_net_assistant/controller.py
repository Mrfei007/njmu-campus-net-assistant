from __future__ import annotations

import ctypes
import os
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from .config import (
    CONNECTION_MODE_DORM_ETHERNET,
    CONNECTION_MODE_WORKSTATION_RUIJIE,
    CONNECTION_MODE_WIRELESS,
    AppConfig,
    load_config,
    save_config,
)
from .credentials import load
from .edge import (
    AuthenticationRejectedError,
    LoginOutcomeUnknownError,
    PortalAllowlistError,
    login,
    logout_current_session,
    logout_dorm_ethernet_session,
)
from .ethernet import EthernetInfo, get_ethernet, get_linked_physical_ethernet
from .keepalive_status import read_health as read_keepalive_health
from .workstation_monitor import Observation, observe as observe_workstation
from .logging_redacted import append_connectivity_event, event, prune, save_morning_online_baseline
from .monitor_state import arm as arm_monitor
from .monitor_state import clear_suppression as clear_monitor_suppression
from .monitor_state import load as load_monitor_state
from .monitor_state import suppress as suppress_monitor
from .monitor_state import suppression_remaining_seconds
from .probe import connectivity_probe
from .product import EVENT_SOURCE, MONITOR_TASK_NAME
from .recovery_lock import acquire_monitor_lock, acquire_recovery_lock
from .rawether import send_logoff_adapter, send_private_md5_probe_adapter
from .ruijie import RuijieSafetyError, authenticate_once, detect_authentication_dialog
from .status import read as read_status, write as write_status
from .startup import prepare as prepare_workstation_startup
from .uu import ensure_running
from .wake_coordination import (
    SystemAwakeLease,
    complete_request as complete_wake_request,
    create_fallback_request_if_due,
    create_request as create_wake_request,
    keep_system_awake,
    mark_running as mark_wake_request_running,
    open_request as open_wake_request,
    priority_delay_seconds as wake_priority_delay_seconds,
    signal_monitor as signal_wake_monitor,
    wait_for_monitor_signal,
    wait_for_result as wait_for_wake_result,
)
from .wlan import (
    WlanEnableResult,
    WlanInfo,
    connect_wlan,
    ensure_wlan_enabled,
    get_wlan,
    resolve_wlan_interface,
    ssid_visible,
)


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
NetworkInfo = WlanInfo | EthernetInfo
MAX_LOGIN_SUBMISSIONS = 2
LOGIN_SUBMISSION_WINDOW = timedelta(minutes=15)
MAX_RUIJIE_SUBMISSIONS = 1
RUIJIE_SUBMISSION_WINDOW = timedelta(minutes=5)
MANUAL_LOGOUT_MONITOR_PAUSE_SECONDS = 5 * 60
MORNING_RECOVERY_HANDOFF_WAIT_SECONDS = 330
VALID_OPERATORS = {"电信", "移动", "联通", "校园网"}
PORTAL_ALLOWLIST_PAUSE_REASON = "portal-allowlist-blocked"
AUTH_REASON_MESSAGES = {
    "account-invalid": "校园网门户提示账号错误或账号不存在",
    "password-invalid": "校园网门户提示密码错误",
    "credentials-invalid": "校园网门户提示账号或密码错误",
    "operator-invalid": "未能匹配所选运营商",
    "submission-rate-limit": "15 分钟内提交次数已达到上限",
    "result-unknown": "账号密码已提交，但认证结果无法确认",
    "client-reported-failure": "官方锐捷客户端提示认证未成功",
    "client-version-changed": "官方锐捷客户端文件已变化",
    PORTAL_ALLOWLIST_PAUSE_REASON: "认证页面未通过官方门户允许列表校验",
}


def _auth_reason_message(reason: str) -> str:
    return AUTH_REASON_MESSAGES.get(reason, "校园网门户拒绝了本次认证")


def _recent_login_submissions(config: AppConfig, now: datetime | None = None) -> list[str]:
    current = now or datetime.now().astimezone()
    cutoff = current - LOGIN_SUBMISSION_WINDOW
    recent: list[str] = []
    for value in config.login_submission_timestamps:
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
        except (TypeError, ValueError):
            continue
        if parsed >= cutoff:
            recent.append(parsed.isoformat(timespec="milliseconds"))
    return recent[-MAX_LOGIN_SUBMISSIONS:]


def _submission_rate_limited(config: AppConfig) -> bool:
    config.login_submission_timestamps = _recent_login_submissions(config)
    return len(config.login_submission_timestamps) >= MAX_LOGIN_SUBMISSIONS


def _record_login_submission(config: AppConfig, submitted_at: str) -> None:
    config.login_submission_timestamps = _recent_login_submissions(config)
    config.login_submission_timestamps.append(str(submitted_at))
    config.login_submission_timestamps = config.login_submission_timestamps[-MAX_LOGIN_SUBMISSIONS:]
    save_config(config)


def _recent_ruijie_submissions(config: AppConfig, now: datetime | None = None) -> list[str]:
    current = now or datetime.now().astimezone()
    cutoff = current - RUIJIE_SUBMISSION_WINDOW
    recent: list[str] = []
    for value in config.ruijie_submission_timestamps:
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
        except (TypeError, ValueError):
            continue
        if parsed >= cutoff:
            recent.append(parsed.isoformat(timespec="milliseconds"))
    return recent[-MAX_RUIJIE_SUBMISSIONS:]


def _ruijie_submission_rate_limited(config: AppConfig) -> bool:
    config.ruijie_submission_timestamps = _recent_ruijie_submissions(config)
    return len(config.ruijie_submission_timestamps) >= MAX_RUIJIE_SUBMISSIONS


def _record_ruijie_submission(config: AppConfig, submitted_at: str) -> None:
    config.ruijie_submission_timestamps = _recent_ruijie_submissions(config)
    config.ruijie_submission_timestamps.append(str(submitted_at))
    config.ruijie_submission_timestamps = config.ruijie_submission_timestamps[-MAX_RUIJIE_SUBMISSIONS:]
    save_config(config)


def _pause_authentication(config: AppConfig, reason: str) -> None:
    config.auth_paused = True
    config.auth_pause_reason = reason
    config.auth_paused_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    save_config(config)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _online(config: AppConfig) -> bool:
    return _online_detail(config)[0]


def _connectivity_detail(config: AppConfig, interface_ip: str) -> tuple[bool, str]:
    return connectivity_probe(
        interface_ip,
        config.portal.check_url,
        config.portal.success_text,
        config.portal.secondary_check_url,
    )


def _connectivity_online(config: AppConfig, interface_ip: str) -> bool:
    return _connectivity_detail(config, interface_ip)[0]


def _online_detail(config: AppConfig) -> tuple[bool, str]:
    network, reason = _selected_network(config)
    if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
        observation = observe_workstation(config, network)
        config._workstation_observation = observation
        return observation.available, observation.source
    if not network:
        return False, reason
    return _connectivity_detail(config, network.ip)


def _selected_network(config: AppConfig) -> tuple[NetworkInfo | None, str]:
    if config.connection_mode in {
        CONNECTION_MODE_DORM_ETHERNET,
        CONNECTION_MODE_WORKSTATION_RUIJIE,
    }:
        if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
            health = read_keepalive_health()
            preferred = str(health.get("adapter_description", "")) if health["state"] in {"running", "stale"} else ""
            ethernet = get_ethernet(require_preferred=False, preferred_description=preferred)
        else:
            ethernet = get_ethernet()
        if ethernet:
            source = (
                "workstation-ruijie"
                if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                else "dorm-ethernet"
            )
            return ethernet, source
        reason = (
            "workstation-ethernet-unavailable"
            if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
            else "ethernet-unavailable"
        )
        return None, reason
    wlan = get_wlan(config.wlan_interface, config.portal.ssid)
    if not wlan:
        return None, "wlan-unavailable"
    if wlan.ssid != config.portal.ssid:
        return None, "ssid-mismatch"
    return wlan, "wireless"


def _ensure_target_wlan_enabled(config: AppConfig) -> WlanEnableResult:
    enabled = ensure_wlan_enabled(config.wlan_interface, config.portal.ssid)
    if enabled.success:
        message = (
            "已启用 Wi-Fi，立即连接目标校园网络"
            if enabled.changed
            else "Wi-Fi 已开启，立即检查并连接目标校园网络"
        )
    elif enabled.hardware_radio_blocked:
        message = "硬件无线开关或飞行模式阻止程序开启 Wi-Fi"
    else:
        message = "Windows 未允许程序开启 Wi-Fi"
    event(
        "wlan-enable",
        enabled.success,
        message,
        reason=enabled.reason,
        interface=enabled.interface,
        changed=enabled.changed,
        adapter_enabled=enabled.adapter_enabled,
        software_radio_enabled=enabled.software_radio_enabled,
        hardware_radio_blocked=enabled.hardware_radio_blocked,
    )
    if enabled.success and enabled.changed:
        write_status("wlan-enabled", None, "已开启 Wi-Fi，正在连接目标校园网络")
    elif enabled.hardware_radio_blocked:
        write_status("wlan-hardware-radio-off", False, message)
    return enabled


def _request_target_wlan_connection(config: AppConfig) -> tuple[bool, bool | None]:
    visible, visibility_reason = ssid_visible(config.wlan_interface, config.portal.ssid)
    if visible is False:
        event(
            "wifi-visibility",
            False,
            "当前区域未扫描到目标校园 Wi-Fi，本次不连接且不重启网卡",
            reason=visibility_reason,
        )
        write_status("wifi-not-visible", False, "当前区域搜不到校园 Wi-Fi，已降低自动恢复频率")
        return False, visible
    requested, reason = connect_wlan(config.wlan_interface, config.portal.ssid)
    event(
        "wlan-connect",
        requested,
        "已请求 Windows 连接目标校园 Wi-Fi" if requested else "Windows 无法请求连接目标校园 Wi-Fi",
        reason=reason,
        visibility="visible" if visible else "scan-unavailable",
    )
    if requested:
        write_status("wlan-connecting", None, "正在请求 Windows 连接目标校园 Wi-Fi")
    return requested, visible


def _wait_for_target_wlan(config: AppConfig, wait_seconds: int) -> tuple[WlanInfo | None, bool, str]:
    _ensure_target_wlan_enabled(config)

    deadline = time.monotonic() + max(0, wait_seconds)
    last = None
    next_connect_attempt = 0.0
    connection_requested = False
    last_visibility: bool | None = None
    while True:
        last = get_wlan(config.wlan_interface, config.portal.ssid)
        if last and last.ssid == config.portal.ssid and last.ip and last.gateway and last.ifindex:
            return last, connection_requested, "connected"
        now = time.monotonic()
        if now >= next_connect_attempt:
            requested, visible = _request_target_wlan_connection(config)
            last_visibility = visible
            connection_requested = connection_requested or requested
            next_connect_attempt = now + 30
        if now >= deadline:
            reason = "ssid-not-visible" if last_visibility is False else "connection-timeout"
            return last, connection_requested, reason
        time.sleep(3)


def _wait_for_dorm_ethernet(config: AppConfig, wait_seconds: int) -> tuple[EthernetInfo | None, bool, str]:
    # 有线网无需主动拨号，只等待 Windows 从宿舍网口取得完整 DHCP 信息。
    # 晨间任务即使传入 300 秒也最多等待 15 秒，避免未插网线时长期占用恢复锁。
    deadline = time.monotonic() + min(max(0, wait_seconds), 15)
    while True:
        ethernet = get_ethernet()
        if ethernet:
            return ethernet, False, "connected"
        if time.monotonic() >= deadline:
            return None, False, "ethernet-unavailable"
        time.sleep(2)


def _wait_for_selected_network(config: AppConfig, wait_seconds: int) -> tuple[NetworkInfo | None, bool, str]:
    if config.connection_mode == CONNECTION_MODE_DORM_ETHERNET:
        return _wait_for_dorm_ethernet(config, wait_seconds)
    return _wait_for_target_wlan(config, wait_seconds)


def _do_workstation_ruijie_login(
    config: AppConfig,
    wait_seconds: int,
    *,
    require_submission: bool,
    manual_validation: bool,
) -> bool:
    write_status(
        "workstation-ruijie-login",
        None,
        "正在检查工位有线认证条件",
        connection_mode=config.connection_mode,
    )
    ethernet = get_ethernet()
    if ethernet and _connectivity_online(config, ethernet.ip):
        confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
        if require_submission:
            write_status(
                "manual-login-validation-requires-offline",
                False,
                "工位有线已经联网，账号密码没有被提交",
                current_online=True,
            )
            return False
        write_status(
            "workstation-ruijie-already-online",
            True,
            "当前联网探测成功，未重复执行工位认证",
            probe_succeeded_at=confirmed_at,
        )
        return True
    observation = getattr(config, "_workstation_observation", None)
    if (not manual_validation and observation is not None
            and observation.fields.get("route_mode") in {"tunnel", "alternate-route"}
            and not observation.available and not observation.recovery_allowed):
        write_status("workstation-diagnosis-wait", None,
                     "当前出口访问异常，校园网认证失效尚未确认，暂不重新认证",
                     **observation.fields)
        return False
    if not manual_validation and not (
        config.ruijie_auto_enabled or config.ruijie_native_auto_enabled
    ):
        write_status(
            "ruijie-awaiting-field-validation",
            False,
            "工位锐捷自动认证尚未通过现场验证，后台不会提交认证",
            automatic_submission_paused=True,
        )
        return False
    if config.auth_paused:
        reason = config.auth_pause_reason or "authentication-rejected"
        write_status(
            "authentication-paused",
            False,
            f"{_auth_reason_message(reason)}；工位锐捷自动填写已暂停",
            reason=reason,
        )
        return False
    if _ruijie_submission_rate_limited(config):
        write_status(
            "ruijie-submission-backoff",
            False,
            "5 分钟内已执行过一次工位认证，本轮不会再次提交",
            reason="submission-rate-limit",
        )
        return False
    link = get_linked_physical_ethernet()
    if link is None:
        write_status(
            "ruijie-ethernet-link-unavailable",
            False,
            "未检测到唯一已连接的物理有线网卡，未启动工位认证",
        )
        return False
    try:
        username, password = load()
    except Exception:
        write_status("manual-login-credentials-missing", False, "尚未保存校园网账号和密码")
        return False
    if not username.strip() or not password:
        write_status("manual-login-credentials-missing", False, "校园网账号或密码为空，请重新输入并保存")
        return False

    if config.ruijie_native_auto_enabled:
        if not manual_validation:
            from .rawether import _service_state
            driver_state = _service_state("PCASp50")
            if driver_state != "running":
                write_status("ruijie-driver-wait", None,
                             "锐捷驱动尚未就绪，等待后续监测，不提交认证",
                             driver_state=driver_state)
                return False
        write_status(
            "ruijie-native-login",
            None,
            "正在使用已通过现场验证的原生锐捷认证，并启动后台保活",
            adapter=link.description,
        )
        try:
            native_result = send_private_md5_probe_adapter(
                config.ruijie_path,
                link.description,
                username,
                password,
                link.interface,
                persistent_session=True,
            )
        except Exception as error:
            native_result = {
                "success": False,
                "message": f"原生锐捷认证未完成（{type(error).__name__}）",
            }
        if native_result.get("success") and native_result.get("session_started"):
            submitted_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
            _record_ruijie_submission(config, submitted_at)
            append_connectivity_event(
                "portal-login-probe-succeeded",
                source="native-ruijie-session",
                login_submitted_at=submitted_at,
                probe_succeeded_at=submitted_at,
            )
            event(
                "ruijie-native-session-started",
                True,
                "原生锐捷认证、后台保活和真实联网验证均成功",
                adapter=link.description,
                keepalive_interval_seconds=30,
            )
            write_status(
                "workstation-ruijie-login-succeeded",
                True,
                "原生锐捷认证成功，后台将每 30 秒保活，真实联网验证成功",
                login_submitted_at=submitted_at,
                probe_succeeded_at=submitted_at,
                current_online=True,
                authentication_backend="native-ruijie-session",
            )
            return True
        if not manual_validation and not config.ruijie_background_client_fallback:
            event("ruijie-native-recovery-deferred", False,
                  "原生认证未成功；后台客户端回退已关闭",
                  reason=str(native_result.get("message", "native-session-failed")))
            write_status("ruijie-native-recovery-deferred", False,
                         "原生认证未成功；后台客户端回退已关闭，稍后重新检查")
            return False
        event(
            "ruijie-native-session-started",
            False,
            "原生锐捷认证未能建立持续会话，准备使用官方客户端回退",
            adapter=link.description,
            reason=str(native_result.get("message", "native-session-failed")),
        )
        write_status(
            "ruijie-native-fallback",
            None,
            "原生认证未成功，正在回退到官方锐捷客户端",
        )

    if config.ruijie_safety_blocked:
        if manual_validation and config.ruijie_safety_manual_retry_available:
            config.ruijie_safety_blocked = False
            config.ruijie_safety_manual_retry_available = False
            save_config(config)
            event(
                "ruijie-ui-safety-manual-retry",
                True,
                "用户触发一次工位锐捷完整安全复核；不会跳过标题、进程、路径或布局校验",
            )
        else:
            write_status(
                "ruijie-ui-safety-check-failed",
                False,
                "官方锐捷客户端仍处于安全暂停状态；本次允许的人工复核已用完，请重新保存设置后再验证",
                reason="ruijie-safety-retry-exhausted",
                automatic_submission_paused=True,
                manual_retry_available=False,
            )
            return False
    expected_hash = "" if manual_validation else config.ruijie_confirmed_worker_sha256
    try:
        submission = authenticate_once(
            config.ruijie_path,
            username,
            password,
            expected_worker_sha256=expected_hash,
        )
    except RuijieSafetyError as error:
        config.ruijie_auto_enabled = False
        config.ruijie_confirmed_worker_sha256 = ""
        config.ruijie_safety_blocked = True
        save_config(config)
        event(
            "ruijie-ui-safety-check",
            False,
            "官方锐捷客户端未通过自动填写安全校验",
            reason=error.reason,
            adapter=link.description,
            manual_retry_available=config.ruijie_safety_manual_retry_available,
            **error.details,
        )
        write_status(
            "ruijie-ui-safety-check-failed",
            False,
            (
                f"{error}；账号密码尚未填写，可再次点击“立即认证并检查联网”进行一次完整安全复核"
                if config.ruijie_safety_manual_retry_available
                else f"{error}；本次允许的人工安全复核已用完"
            ),
            reason=error.reason,
            automatic_submission_paused=True,
            manual_retry_available=config.ruijie_safety_manual_retry_available,
            **error.details,
        )
        return False
    except Exception as error:
        config.ruijie_auto_enabled = False
        config.ruijie_confirmed_worker_sha256 = ""
        save_config(config)
        event("ruijie-ui-submit", False, type(error).__name__)
        write_status("ruijie-ui-submit-failed", False, "未能操作官方锐捷客户端，账号密码不会重复提交")
        return False

    _record_ruijie_submission(config, submission.submitted_at)
    event(
        "ruijie-ui-login-submitted",
        True,
        "已在官方锐捷客户端完成一次账号密码填写和认证点击",
        login_submitted_at=submission.submitted_at,
        adapter=link.description,
        client_title=submission.window_title,
    )
    write_status(
        "ruijie-ui-login-submitted",
        None,
        "官方锐捷客户端已填写并提交一次，正在等待工位有线联网结果",
        login_submitted_at=submission.submitted_at,
    )
    deadline = time.monotonic() + max(10, wait_seconds)
    while time.monotonic() < deadline:
        current = get_ethernet()
        if current and _connectivity_online(config, current.ip):
            confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
            if manual_validation:
                config.ruijie_auto_enabled = True
                config.ruijie_confirmed_worker_sha256 = submission.worker_sha256
                config.ruijie_safety_blocked = False
                config.ruijie_safety_manual_retry_available = True
                save_config(config)
            append_connectivity_event(
                "portal-login-probe-succeeded",
                source="official-ruijie-client",
                login_submitted_at=submission.submitted_at,
                probe_succeeded_at=confirmed_at,
            )
            write_status(
                "workstation-ruijie-login-succeeded",
                True,
                (
                    "工位锐捷自动填写已通过现场验证，后续允许后台自动使用官方客户端"
                    if manual_validation
                    else "官方锐捷客户端认证后，工位有线真实联网探测成功"
                ),
                login_submitted_at=submission.submitted_at,
                probe_succeeded_at=confirmed_at,
                current_online=True,
                ruijie_auto_enabled=config.ruijie_auto_enabled,
            )
            return True
        dialog = detect_authentication_dialog(submission.process_id)
        if dialog is not None:
            reason, _dialog_title = dialog
            _pause_authentication(config, reason)
            event(
                "ruijie-ui-authentication-rejected",
                False,
                "官方锐捷客户端出现明确认证失败提示，已停止本轮验证",
                reason=reason,
                login_submitted_at=submission.submitted_at,
            )
            write_status(
                "authentication-paused",
                False,
                f"{_auth_reason_message(reason)}；不会继续自动重试",
                reason=reason,
                login_submitted_at=submission.submitted_at,
                current_online=False,
            )
            return False
        time.sleep(2)
    _pause_authentication(config, "result-unknown")
    write_status(
        "authentication-paused",
        False,
        "官方锐捷客户端已提交一次，但未能确认联网结果；为避免重复提交，自动填写已暂停",
        reason="result-unknown",
        login_submitted_at=submission.submitted_at,
        current_online=False,
    )
    return False


def do_login(
    config: AppConfig,
    wait_seconds: int = 30,
    *,
    require_submission: bool = False,
    manual_validation: bool = False,
) -> bool:
    if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
        return _do_workstation_ruijie_login(
            config,
            wait_seconds,
            require_submission=require_submission,
            manual_validation=manual_validation,
        )
    dorm_ethernet = config.connection_mode == CONNECTION_MODE_DORM_ETHERNET
    write_status(
        "primary-login",
        None,
        "主流程正在检查宿舍有线网" if dorm_ethernet else "主流程正在检查校园 Wi-Fi",
        connection_mode=config.connection_mode,
    )
    network, connection_requested, network_reason = _wait_for_selected_network(config, wait_seconds)
    if not network or not network.ip or not network.gateway or not network.ifindex:
        if dorm_ethernet:
            event(
                "ethernet-detection",
                False,
                "未找到唯一优先的物理有线网卡，或有线网卡尚未获得完整网络信息",
                wait_seconds=min(max(0, wait_seconds), 15),
            )
            write_status(
                "ethernet-unavailable",
                False,
                "宿舍有线网卡、网线或 DHCP 尚未就绪；不会改用工位锐捷连接",
                connection_mode=config.connection_mode,
            )
            return False
        if network_reason == "ssid-not-visible":
            event("wifi-not-visible", False, "当前区域未扫描到目标校园 Wi-Fi，暂停本轮恢复")
            write_status("wifi-not-visible", False, "当前区域搜不到校园 Wi-Fi，将降低重试频率且不会重启网卡")
            return False
        event("wifi-detection", False, "WLAN 尚未获得有效 IPv4、网关或接口信息", wait_seconds=wait_seconds)
        write_status("primary-login-failed", False, "WLAN 尚未获得有效 IPv4、网关或接口信息")
        return False
    if isinstance(network, WlanInfo) and network.ssid != config.portal.ssid:
        if network_reason == "ssid-not-visible":
            event("wifi-not-visible", False, "当前连接的不是校园 Wi-Fi，且当前区域未扫描到目标校园 Wi-Fi")
            write_status("wifi-not-visible", False, "当前区域搜不到校园 Wi-Fi，将降低重试频率且不会重启网卡")
            return False
        event("wifi-detection", False, "检测到 WLAN 但 SSID 不是目标校园网络", wait_seconds=wait_seconds)
        write_status("primary-login-failed", False, "检测到 WLAN 但 SSID 不是目标校园网络")
        return False
    # 手动断开后重新关联同一 SSID 时，校园网认证会话可能仍然有效。
    # 必须先做真实联网探测，只有未联网时才打开门户并提交凭据。
    if _connectivity_online(config, network.ip):
        confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
        if require_submission:
            event(
                "manual-login-validation-not-run",
                False,
                "当前已经联网，未提交账号密码，因此不能把本次操作算作登录认证",
                probe_succeeded_at=confirmed_at,
            )
            write_status(
                "manual-login-validation-requires-offline",
                False,
                "当前已经联网，无需重复认证；需要下线时请使用“断开校园网认证”",
                current_online=True,
                login_submitted_at=None,
                probe_succeeded_at=confirmed_at,
            )
            return False
        if dorm_ethernet:
            stage = "ethernet-already-online"
            message = "宿舍有线网已在线，真实联网探测成功，未打开门户"
        else:
            stage = "wifi-reconnected-online" if connection_requested else "wireless-already-online"
            message = (
                "已主动连接校园 Wi-Fi，认证仍有效，真实联网探测成功，未打开门户"
                if connection_requested
                else "校园 Wi-Fi 已恢复在线，真实联网探测成功，未打开门户"
            )
        event(
            "post-connect-probe",
            True,
            message,
            connection_requested=connection_requested,
            connection_mode=config.connection_mode,
            probe_succeeded_at=confirmed_at,
        )
        write_status(
            stage,
            True,
            message,
            connection_requested=connection_requested,
            connection_mode=config.connection_mode,
            probe_succeeded_at=confirmed_at,
        )
        return True
    if (
        manual_validation
        and config.auth_paused
        and config.auth_pause_reason == PORTAL_ALLOWLIST_PAUSE_REASON
        and config.portal_allowlist_manual_retry_available
    ):
        config.portal_allowlist_manual_retry_available = False
        config.auth_paused = False
        config.auth_pause_reason = ""
        config.auth_paused_at = ""
        save_config(config)
        event(
            "portal-allowlist-manual-retry",
            True,
            "用户触发一次官方门户允许列表完整复核；不会绕过允许列表校验",
        )
    if config.auth_paused:
        reason = config.auth_pause_reason or "authentication-rejected"
        if reason == PORTAL_ALLOWLIST_PAUSE_REASON:
            event(
                "portal-allowlist-paused",
                False,
                "认证页面此前未通过官方门户允许列表校验，自动填写和提交保持暂停",
                reason=reason,
            )
            write_status(
                "portal-allowlist-blocked",
                False,
                "认证页面未通过官方门户允许列表校验，自动登录已暂停且不会重复打开页面",
                reason=reason,
                automatic_submission_paused=True,
            )
            return False
        event(
            "authentication-paused",
            False,
            "门户认证曾明确拒绝凭据，已暂停自动提交；请在主界面重新输入",
            reason=reason,
        )
        write_status(
            "authentication-paused",
            False,
            "账号、密码或运营商需要重新确认，自动登录已暂停",
            reason=reason,
        )
        return False
    if _submission_rate_limited(config):
        _pause_authentication(config, "submission-rate-limit")
        event(
            "authentication-rate-limited",
            False,
            "15 分钟内已提交两次账号密码，已暂停继续提交",
            submission_count=len(config.login_submission_timestamps),
        )
        write_status(
            "authentication-paused",
            False,
            "15 分钟内已提交两次账号密码，已暂停自动登录；请确认账号密码后重新保存",
            reason="submission-rate-limit",
        )
        return False
    try:
        username, password = load()
    except Exception as error:
        event("credentials", False, type(error).__name__)
        write_status("primary-login-failed", False, "未读取到 Windows Credential Manager 凭据")
        return False
    try:
        result = login(
            config.portal.check_url,
            username,
            password,
            config.portal.operator,
            lambda: _connectivity_online(config, network.ip),
            interface_ip=network.ip,
            route_gateway=network.gateway,
            route_ifindex=network.ifindex,
            dns_servers=network.dns_servers,
            include_wireless_portal_host=not dorm_ethernet,
            dorm_ethernet_flow=dorm_ethernet,
            keep_page_open=config.keep_login_page_open,
            success_page_url=config.portal.success_page_url,
            submission_callback=lambda submitted_at: _record_login_submission(config, submitted_at),
        )
        if not result.get("login_submitted_at"):
            event(
                "pre-submit-probe",
                True,
                "门户提交前检测到网络已由外部或并发流程恢复，主流程未提交凭据",
                probe_succeeded_at=result["probe_succeeded_at"],
                edge_launch_attempt=result.get("edge_launch_attempt"),
            )
            append_connectivity_event(
                "online-confirmed",
                source="external-or-concurrent-flow",
                cause="online-confirmed-before-main-submit",
                confirmed_at=result["probe_succeeded_at"],
            )
            write_status(
                "manual-login-not-validated" if require_submission else "online-confirmed-before-submit",
                False if require_submission else True,
                (
                    "网络在提交前由其他流程恢复，本次没有验证账号密码"
                    if require_submission
                    else "真实联网探测已恢复，但主流程未提交凭据；仅记录在线确认"
                ),
                probe_succeeded_at=result["probe_succeeded_at"],
                login_submitted_at=None,
            )
            return not require_submission
        event(
            "login-and-probe",
            True,
            "登录后连通性探测成功",
            probe_succeeded_at=result["probe_succeeded_at"],
            edge_ready_seconds=result.get("edge_ready_seconds"),
            edge_launch_attempt=result.get("edge_launch_attempt"),
            login_page_retained=result.get("login_page_retained", False),
        )
        append_connectivity_event(
            "portal-login-probe-succeeded",
            source=EVENT_SOURCE,
            login_submitted_at=result["login_submitted_at"],
            probe_succeeded_at=result["probe_succeeded_at"],
        )
        write_status(
            "primary-login-succeeded",
            True,
            "主流程登录和真实联网探测成功",
            login_submitted_at=result["login_submitted_at"],
            probe_succeeded_at=result["probe_succeeded_at"],
            login_page_retained=result.get("login_page_retained", False),
        )
        if not config.portal_allowlist_manual_retry_available:
            config.portal_allowlist_manual_retry_available = True
            save_config(config)
        return True
    except AuthenticationRejectedError as error:
        _pause_authentication(config, error.reason)
        reason_message = _auth_reason_message(error.reason)
        event(
            "authentication-rejected",
            False,
            f"{reason_message}，已暂停自动提交",
            reason=error.reason,
        )
        write_status(
            "authentication-paused",
            False,
            f"{reason_message}；自动登录已暂停，请在主界面更正后重新保存",
            reason=error.reason,
        )
        return False
    except LoginOutcomeUnknownError as error:
        if manual_validation:
            _pause_authentication(config, "result-unknown")
        event(
            "login-result-unknown",
            False,
            str(error),
            automatic_submission_paused=manual_validation,
        )
        write_status(
            "authentication-paused" if manual_validation else "primary-login-result-unknown",
            False,
            (
                "账号密码已提交一次，但未能确认成功或失败；为避免重复提交，自动登录已暂停"
                if manual_validation
                else "账号密码已提交一次，但未能确认成功或失败，本轮不会再次提交"
            ),
            reason="result-unknown",
        )
        return False
    except PortalAllowlistError as error:
        _pause_authentication(config, PORTAL_ALLOWLIST_PAUSE_REASON)
        event(
            "portal-allowlist-blocked",
            False,
            str(error),
            automatic_submission_paused=True,
            manual_retry_available=config.portal_allowlist_manual_retry_available,
        )
        write_status(
            "portal-allowlist-blocked",
            False,
            "认证页面不在官方门户允许列表内，程序已停止填写和提交账号密码；后台认证已暂停",
            reason=PORTAL_ALLOWLIST_PAUSE_REASON,
            automatic_submission_paused=True,
            manual_retry_available=config.portal_allowlist_manual_retry_available,
        )
        return False
    except Exception as error:
        event("login-and-probe", False, f"{type(error).__name__}: {error}")
        write_status("primary-login-failed", False, f"主流程登录或联网探测失败：{type(error).__name__}")
        return False


def _in_monitor_window(config: AppConfig, now: datetime | None = None) -> bool:
    if config.auto_connect_on_startup:
        return True
    if not (config.wake_enabled and config.hibernate_enabled):
        return True
    current = (now or datetime.now()).strftime("%H:%M")
    start = config.monitor_window_start
    end = config.monitor_window_end
    if start < end:
        return start <= current < end
    return current >= start or current < end


def _should_recover(failure_source: str, failures: int) -> bool:
    # Wi-Fi 关联丢失不是门户探测抖动：第一次发现就应主动连接。
    if failure_source in {"wlan-unavailable", "ssid-mismatch"}:
        return True
    # 宿舍有线未取得唯一默认路由时，程序没有安全的认证目标；等待网线/DHCP
    # 就绪即可，不尝试门户，更不能借机重启无线网卡。
    if failure_source == "ethernet-unavailable":
        return False
    if failure_source == "workstation-ethernet-unavailable":
        return False
    # 仍连接目标 SSID 但互联网探测失败时，Monitor 会在同一轮连续探测两次。
    return failures >= 2


def _monitor_probe(config: AppConfig, *, record: bool = True) -> tuple[bool, str, int]:
    if hasattr(config, "_workstation_observation"):
        del config._workstation_observation
    online, probe_source = _online_detail(config)
    first_observation = getattr(config, "_workstation_observation", None)
    if online or probe_source not in {"microsoft-connect-test", "all-connectivity-probes-failed", "workstation-access-failed"}:
        return online, probe_source, 1
    second_online, second_source = _online_detail(config)
    second_observation = getattr(config, "_workstation_observation", None)
    if first_observation is not None and second_observation is not None:
        second_observation.fields["confirmed_failure"] = (
            first_observation.state == second_observation.state == "access-failed"
            and first_observation.fields["ethernet_interface"] == second_observation.fields["ethernet_interface"]
        )
    if record:
        event(
            "monitor-confirmation-probe",
            second_online,
            (
                "第一次联网探测失败，连续第二次探测成功，不启动恢复"
                if second_online
                else "连续两次联网探测失败，按故障类别决定是否恢复"
            ),
            probe_attempts=2,
            first_failure_source=probe_source,
            second_probe_source=second_source,
        )
    return second_online, second_source, 2


def _record_workstation_observation(config: AppConfig, observation: Observation,
                                    attempts: int, failures: int, policy: str = "active") -> int:
    """Record verified access failures separately from unavailable observation."""
    fields = observation.fields
    if observation.available:
        name = "reconnected" if failures else "online-confirmed"
        append_connectivity_event(name, source=EVENT_SOURCE, connection_mode=config.connection_mode,
                                  cause="access-failed" if failures else "probe-success",
                                  probe_attempts=attempts, connectivity_scope=fields["connectivity_scope"])
        failures = 0
        stage, success = ("online" if observation.state == "online" else "network-exit-degraded"), True
    elif observation.state == "access-failed" and fields["confirmed_failure"]:
        if not failures:
            append_connectivity_event("offline-detected", source=observation.source,
                                      connection_mode=config.connection_mode, authentication_state="unverified",
                                      probe_attempts=attempts, recovery_policy="diagnosis-wait")
        failures += attempts
        stage, success = "workstation-access-failed", False
    else:
        stage, success = "workstation-network-unverified", None
    recovery_policy = "diagnosis-wait" if not observation.available else "observe"
    event("monitor", success, observation.message, probe_attempts=attempts,
          probe_source=observation.source, consecutive_failures=failures,
          recovery_policy=recovery_policy, monitor_policy=policy, **fields)
    write_status(stage, success, observation.message, probe_source=observation.source,
                 consecutive_failures=failures, recovery_policy=recovery_policy, monitor_policy=policy, **fields)
    return failures


def _active_recovery_config(config: AppConfig, mode: str) -> AppConfig | None:
    if mode != "Monitor":
        return config
    current = load_config()
    if _in_monitor_window(current):
        return current
    event(
        "monitor-recovery-aborted",
        True,
        "监测窗口已结束，停止本轮恢复",
        monitor_window_start=current.monitor_window_start,
        monitor_window_end=current.monitor_window_end,
    )
    write_status(
        "monitor-outside-window",
        True,
        f"当前不在 {current.monitor_window_start}–{current.monitor_window_end} 监测窗口，已停止恢复",
    )
    return None


def _recovery_source(stage: str | None) -> str:
    if stage == "online-confirmed-before-submit":
        return "external-or-concurrent-flow"
    return EVENT_SOURCE


def _restart_wlan(interface: str, target_ssid: str) -> bool:
    interface = resolve_wlan_interface(interface, target_ssid)
    if not interface:
        event("wlan-restart", False, "未找到可用的无线网卡，无法执行重启")
        return False
    safe_interface = interface.replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f"Disable-NetAdapter -Name '{safe_interface}' -Confirm:$false; "
        "Start-Sleep -Seconds 5; "
        f"Enable-NetAdapter -Name '{safe_interface}' -Confirm:$false; "
        "Start-Sleep -Seconds 5"
    )
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], check=True, capture_output=True, timeout=45, creationflags=CREATE_NO_WINDOW)
        enabled = ensure_wlan_enabled(interface, target_ssid)
        success = enabled.success
        event(
            "wlan-restart",
            success,
            (
                "连续恢复失败后已重启 WLAN 适配器并确认 Wi-Fi 开启"
                if success
                else "WLAN 适配器已重启，但未能确认 Wi-Fi 开启"
            ),
            reason=enabled.reason,
            hardware_radio_blocked=enabled.hardware_radio_blocked,
        )
        return success
    except (OSError, subprocess.SubprocessError) as error:
        event("wlan-restart", False, type(error).__name__)
        return False


def _ensure_uu(config: AppConfig) -> None:
    if not config.start_uu:
        return
    configured_path = config.uu_path.strip()
    if not configured_path:
        event("uu-remote", False, "已启用 UU 远程，但尚未配置运行文件路径")
        return
    ok, message = ensure_running(Path(configured_path))
    event("uu-remote", ok, message)


def _start_monitor_task(source: str = "morning") -> bool:
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/Run", "/TN", MONITOR_TASK_NAME],
            capture_output=True,
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = completed.returncode == 0
        event(
            "monitor-task-start",
            ok,
            (
                "已确保后台联网监测任务启动"
                if ok
                else "未能立即启动后台监测；计划任务会在下一次触发时再次尝试"
            ),
            monitor_started_by=source,
            task_returncode=completed.returncode,
        )
        return ok
    except (OSError, subprocess.SubprocessError) as error:
        event(
            "monitor-task-start",
            False,
            "启动后台监测任务时发生异常",
            monitor_started_by=source,
            error_type=type(error).__name__,
        )
        return False


def _stop_monitor_for_manual_reauthentication() -> bool:
    """Stop the scheduled monitor only when it is currently running."""
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/End", "/TN", MONITOR_TASK_NAME],
            capture_output=True,
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        was_running = completed.returncode == 0
        event(
            "monitor-stop-for-manual-action",
            True,
            "已暂停正在运行的后台监测以执行手动联网操作" if was_running else "后台监测当前未运行，无需暂停",
            task_returncode=completed.returncode,
            monitor_was_running=was_running,
        )
        return was_running
    except (OSError, subprocess.SubprocessError) as error:
        event(
            "monitor-stop-for-manual-action",
            False,
            "暂停后台监测时发生异常",
            error_type=type(error).__name__,
        )
        return False


def _restart_monitor_after_manual_reauthentication() -> bool:
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/Run", "/TN", MONITOR_TASK_NAME],
            capture_output=True,
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = completed.returncode == 0
        event(
            "monitor-restart-after-manual-action",
            ok,
            (
                "已重新启动后台任务；若处于手动注销暂停期将只等待"
                if ok
                else "未能重新启动后台联网监测任务"
            ),
            task_returncode=completed.returncode,
        )
        return ok
    except (OSError, subprocess.SubprocessError) as error:
        event(
            "monitor-restart-after-manual-action",
            False,
            "恢复后台监测时发生异常",
            error_type=type(error).__name__,
        )
        return False


def _manual_validation_preflight(config: AppConfig) -> bool:
    if config.auth_paused:
        reason = config.auth_pause_reason or "authentication-rejected"
        if reason == PORTAL_ALLOWLIST_PAUSE_REASON:
            if config.portal_allowlist_manual_retry_available:
                # 这里只允许人工流程继续；真正打开门户前才消耗一次复核机会，
                # 避免注销或网卡检测失败白白用掉机会。
                pass
            else:
                write_status(
                    "portal-allowlist-blocked",
                    False,
                    "认证页面仍未通过官方门户允许列表校验；本次允许的人工复核已用完",
                    reason=reason,
                    automatic_submission_paused=True,
                    manual_retry_available=False,
                )
                return False
        else:
            write_status(
                "authentication-paused",
                False,
                f"{_auth_reason_message(reason)}；请更正账号、密码或运营商后重新保存",
                reason=reason,
            )
            return False
    if _submission_rate_limited(config):
        _pause_authentication(config, "submission-rate-limit")
        write_status(
            "authentication-paused",
            False,
            "15 分钟内已提交两次账号密码；请确认账号密码后重新保存再验证",
            reason="submission-rate-limit",
        )
        return False
    if config.portal.operator not in VALID_OPERATORS:
        write_status(
            "manual-login-settings-invalid",
            False,
            "所选运营商无效，请重新选择电信、移动、联通或校园网",
            reason="operator-invalid",
        )
        return False
    try:
        username, password = load()
    except Exception:
        write_status("manual-login-credentials-missing", False, "尚未保存校园网账号和密码")
        return False
    if not username.strip() or not password:
        write_status("manual-login-credentials-missing", False, "校园网账号或密码为空，请重新输入并保存")
        return False
    return True


def _finish_manual_failure(config: AppConfig, *, logout_confirmed: bool) -> None:
    status = read_status()
    stage = str(status.get("stage") or "")
    reason = str(status.get("reason") or config.auth_pause_reason or "")
    network, _ = _selected_network(config)
    current_online = bool(network and network.ip and _connectivity_online(config, network.ip))
    if stage == "authentication-paused":
        prefix = "注销已成功，当前仍处于离线状态；" if logout_confirmed and not current_online else ""
        write_status(
            "authentication-paused",
            False,
            f"{prefix}{_auth_reason_message(reason)}，不会继续自动重试",
            reason=reason,
            logout_confirmed=logout_confirmed,
            current_online=current_online,
        )
        return
    if stage == "portal-allowlist-blocked":
        manual_retry_available = bool(config.portal_allowlist_manual_retry_available)
        write_status(
            "portal-allowlist-blocked",
            False,
            (
                "注销已成功且当前仍离线；认证页面不在官方门户允许列表内，账号密码未被填写或提交"
                if logout_confirmed and not current_online
                else "认证页面不在官方门户允许列表内，账号密码未被填写或提交"
            )
            + (
                "；可再次点击手动验证按钮进行一次完整允许列表复核"
                if manual_retry_available
                else "；本次允许的人工复核已用完"
            ),
            reason=PORTAL_ALLOWLIST_PAUSE_REASON,
            logout_confirmed=logout_confirmed,
            current_online=current_online,
            automatic_submission_paused=True,
            manual_retry_available=manual_retry_available,
        )
        return
    write_status(
        "manual-login-validation-failed",
        False,
        "本轮登录认证未成功，程序没有重复提交账号密码",
        reason=reason or stage or "manual-validation-failed",
        logout_confirmed=logout_confirmed,
        current_online=current_online,
    )


def logout_network(config: AppConfig) -> bool:
    """Logout the selected network and pause monitoring after real confirmation."""
    write_status("manual-network-logout", None, "正在准备注销校园网络")
    monitor_was_running = _stop_monitor_for_manual_reauthentication()
    try:
        with acquire_recovery_lock(timeout_ms=15000) as acquired:
            if not acquired:
                event(
                    "manual-recovery-lock-timeout",
                    False,
                    "暂停后台监测后仍有旧进程占用联网恢复锁，本次未执行注销",
                    wait_seconds=15,
                )
                write_status(
                    "manual-recovery-lock-timeout",
                    False,
                    "检测到遗留联网进程，请重新保存设置后再试",
                )
                return False
            return _logout_network_locked(config)
    finally:
        if monitor_was_running:
            _restart_monitor_after_manual_reauthentication()


def reauthenticate(config: AppConfig, wait_seconds: int = 60) -> bool:
    """Backward-compatible name for the manual network logout action."""
    return logout_network(config)


def _logout_network_locked(config: AppConfig) -> bool:
    """Run strict online -> logout validation without automatically logging in."""
    network, network_reason = _selected_network(config)
    currently_online = bool(
        network
        and network.ip
        and _connectivity_online(config, network.ip)
    )
    if not currently_online or network is None:
        event(
            "manual-network-logout-requires-online",
            False,
            "当前所选校园网未联网，未执行注销",
            reason=network_reason if network is None else "already-offline",
        )
        write_status(
            "manual-network-logout-requires-online",
            False,
            "当前没有在线认证可注销；需要联网时请使用“立即认证并检查联网”",
            current_online=False,
        )
        return False

    write_status("manual-logout", None, "正在注销现有校园网认证")
    try:
        probe = lambda: _connectivity_online(config, network.ip)
        if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
            sent = send_logoff_adapter(config.ruijie_path, network.description)
            if not sent.get("success"):
                raise RuntimeError(str(sent.get("message") or "EAPOL 注销报文未发送"))
            consecutive_offline = 0
            attempts = 0
            for attempts in range(1, 5):
                time.sleep(2)
                if probe():
                    consecutive_offline = 0
                else:
                    consecutive_offline += 1
                    if consecutive_offline >= 2:
                        break
            if consecutive_offline < 2:
                raise RuntimeError("EAPOL-Logoff 已发送，但真实联网探测仍在线")
            logout_result = {
                "success": True,
                "logout_confirmed_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "probe_attempts": attempts,
                "method": "standard-eapol-logoff",
            }
        elif config.connection_mode == CONNECTION_MODE_DORM_ETHERNET:
            logout_result = logout_dorm_ethernet_session(network.ip, probe)
        else:
            logout_result = logout_current_session(network.ip, network.dns_servers, probe)
    except Exception as error:
        event("manual-logout", False, f"{type(error).__name__}: {error}")
        write_status(
            "manual-logout-failed",
            False,
            (
                "工位注销未能通过连续真实联网探测确认；未进入注销暂停期"
                if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                else "未能确认现有校园网认证已注销"
            ),
        )
        return False

    confirmed_at = str(logout_result["logout_confirmed_at"])
    event(
        "manual-logout",
        True,
        "现有校园网认证已注销，并通过连续真实联网探测确认离线",
        logout_confirmed_at=confirmed_at,
        probe_attempts=logout_result["probe_attempts"],
        logout_method=logout_result.get("method", "wireless-http-logout"),
    )
    append_connectivity_event(
        "authentication-logout-confirmed",
        source=EVENT_SOURCE,
        confirmed_at=confirmed_at,
        probe_attempts=logout_result["probe_attempts"],
        logout_method=logout_result.get("method", "wireless-http-logout"),
    )
    pause_state = suppress_monitor(
        config,
        "manual-network-logout",
        MANUAL_LOGOUT_MONITOR_PAUSE_SECONDS,
    )
    resume_at = pause_state.get("monitor_suppressed_until")
    write_status(
        "manual-network-logout-succeeded",
        True,
        "校园网络已注销，5 分钟内暂停联网监测和自动恢复",
        logout_confirmed_at=confirmed_at,
        monitor_suppressed_until=resume_at,
        monitor_pause_seconds=MANUAL_LOGOUT_MONITOR_PAUSE_SECONDS,
        current_online=False,
    )
    event(
        "manual-network-logout",
        True,
        "程序已确认网络注销，并暂停联网监测 5 分钟",
        logout_confirmed_at=confirmed_at,
        monitor_suppressed_until=resume_at,
        monitor_pause_seconds=MANUAL_LOGOUT_MONITOR_PAUSE_SECONDS,
    )
    return True


def validate_login(config: AppConfig, wait_seconds: int = 60) -> bool:
    """Validate one credential submission only while the selected network is offline."""
    write_status("manual-login-validation", None, "正在准备登录认证")
    monitor_was_running = _stop_monitor_for_manual_reauthentication()
    try:
        with acquire_recovery_lock(timeout_ms=15000) as acquired:
            if not acquired:
                write_status("manual-recovery-lock-timeout", False, "另一个联网流程正在运行，请稍后再试")
                return False
            if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
                ok = do_login(
                    config,
                    wait_seconds=wait_seconds,
                    require_submission=True,
                    manual_validation=True,
                )
                if ok:
                    clear_monitor_suppression(config, "manual-workstation-login-succeeded")
                    arm_monitor(config, "manual-workstation-ruijie-validation")
                    _ensure_uu(config)
                event(
                    "manual-workstation-ruijie-validation",
                    ok,
                    "工位锐捷现场验证成功" if ok else "工位锐捷现场验证未成功，本轮不会重复提交",
                )
                return ok
            network, _ = _selected_network(config)
            if network and network.ip and _connectivity_online(config, network.ip):
                write_status(
                    "manual-login-validation-requires-offline",
                    False,
                    "当前已经联网，无需重复认证；需要下线时请使用“断开校园网认证”",
                    current_online=True,
                )
                return False
            if not _manual_validation_preflight(config):
                return False
            ok = do_login(
                config,
                wait_seconds=wait_seconds,
                require_submission=True,
                manual_validation=True,
            )
            if ok:
                clear_monitor_suppression(config, "manual-login-succeeded")
                arm_monitor(config, "manual-login-validation")
                _ensure_uu(config)
                login_status = read_status()
                write_status(
                    "manual-login-validation-succeeded",
                    True,
                    "账号密码已提交一次并通过真实联网探测，登录验证成功",
                    login_submitted_at=login_status.get("login_submitted_at"),
                    probe_succeeded_at=login_status.get("probe_succeeded_at"),
                    current_online=True,
                )
            else:
                _finish_manual_failure(config, logout_confirmed=False)
            event(
                "manual-login-validation",
                ok,
                "登录认证成功" if ok else "登录认证未成功，本轮不会重复提交账号密码",
            )
            return ok
    finally:
        if monitor_was_running:
            _restart_monitor_after_manual_reauthentication()


def _wait_for_existing_recovery(config: AppConfig, mode: str) -> bool | None:
    """Let a wake/manual flow observe recovery owned by another process.

    True/False means the owner finished and connectivity was checked. None means
    the owner still held the mutex after the bounded wait; the monitor remains
    responsible and the morning task must not overwrite its in-progress status.
    """
    waiting_process_id = os.getpid()
    event(
        "recovery-handoff-waiting",
        True,
        "已有程序进程正在执行联网恢复，唤醒恢复流程等待其结果且不会重复登录",
        mode=mode,
        waiting_process_id=waiting_process_id,
        wait_seconds=MORNING_RECOVERY_HANDOFF_WAIT_SECONDS,
    )
    with acquire_recovery_lock(
        timeout_ms=MORNING_RECOVERY_HANDOFF_WAIT_SECONDS * 1000
    ) as acquired:
        if not acquired:
            event(
                "recovery-handoff-timeout",
                False,
                "等待现有联网恢复结束超时，唤醒恢复流程不覆盖其状态并交由后台监测继续处理",
                mode=mode,
                waiting_process_id=waiting_process_id,
                wait_seconds=MORNING_RECOVERY_HANDOFF_WAIT_SECONDS,
                observed_recovery_stage=read_status().get("stage"),
            )
            return None

        observed_recovery_stage = read_status().get("stage")
        online = _online(config)
        event(
            "recovery-handoff-succeeded" if online else "recovery-handoff-finished-offline",
            online,
            (
                "现有联网恢复结束后已通过真实联网探测，唤醒恢复流程确认接管成功"
                if online
                else "现有联网恢复已经结束，但真实联网探测仍未通过"
            ),
            mode=mode,
            waiting_process_id=waiting_process_id,
            observed_recovery_stage=observed_recovery_stage,
        )
        return online


def _recover(config: AppConfig, recovery_attempts: int, mode: str) -> bool | None:
    process_id = os.getpid()
    with acquire_recovery_lock() as acquired:
        if not acquired:
            if mode in {"Morning", "Wake"}:
                return _wait_for_existing_recovery(config, mode)
            event(
                "recovery-already-running",
                True,
                "另一个程序进程正在执行联网恢复，本监测轮次跳过重复登录",
                mode=mode,
                waiting_process_id=process_id,
            )
            return False
        event(
            "recovery-lock-acquired",
            True,
            "本进程已取得联网恢复互斥锁",
            mode=mode,
            recovery_process_id=process_id,
            recovery_attempts=recovery_attempts,
        )
        recovery_succeeded: bool | None = None
        try:
            recovery_succeeded = _recover_locked(config, recovery_attempts, mode)
            return recovery_succeeded
        finally:
            event(
                "recovery-lock-released",
                True,
                "本进程已结束本轮联网恢复并释放互斥锁",
                mode=mode,
                recovery_process_id=process_id,
                recovery_completed=recovery_succeeded is not None,
                recovery_succeeded=recovery_succeeded,
            )


def _recover_locked(config: AppConfig, recovery_attempts: int, mode: str) -> bool:
    login_wait_seconds = 300 if mode in {"Morning", "Wake"} else 60 if mode == "Manual" else 30
    if do_login(config, wait_seconds=login_wait_seconds):
        _ensure_uu(config)
        return True
    active_config = _active_recovery_config(config, mode)
    if active_config is None:
        return False
    config = active_config
    stage = read_status().get("stage")
    if stage in {
        "wifi-not-visible",
        "ethernet-unavailable",
        "ruijie-awaiting-field-validation",
        "ruijie-ethernet-link-unavailable",
        "ruijie-submission-backoff",
        "ruijie-ui-safety-check-failed",
        "authentication-paused",
        "portal-allowlist-blocked",
    }:
        event(
            "recovery-paused",
            False,
            "当前所选网络尚未就绪或认证已暂停，已跳过网卡重启和凭据提交",
            reason=stage,
        )
        return False
    if (
        config.connection_mode == CONNECTION_MODE_WIRELESS
        and recovery_attempts >= config.recovery_attempts_before_wifi_restart + 1
    ):
        event(
            "wlan-restart-threshold",
            True,
            "累计恢复失败次数已超过阈值，重启 WLAN 并主动重连",
            recovery_attempts=recovery_attempts,
            threshold=config.recovery_attempts_before_wifi_restart,
        )
        _restart_wlan(config.wlan_interface, config.portal.ssid)
        if do_login(config, wait_seconds=60):
            _ensure_uu(config)
            return True
        active_config = _active_recovery_config(config, mode)
        if active_config is None:
            return False
        config = active_config
        stage = read_status().get("stage")
        if stage in {
            "wifi-not-visible",
            "ethernet-unavailable",
            "authentication-paused",
            "portal-allowlist-blocked",
        }:
            return False
    event("primary-recovery-failed", False, "程序联网流程本轮未能恢复联网")
    write_status("primary-recovery-failed", False, "程序联网流程本轮未恢复联网，后台将按策略重试")
    active_config = _active_recovery_config(config, mode)
    if active_config is None:
        return False
    return False


def _record_wake_success(config: AppConfig, already_online: bool) -> None:
    status = read_status()
    confirmed_at = (
        datetime.now().astimezone().isoformat(timespec="milliseconds")
        if already_online
        else status.get("probe_succeeded_at")
        or datetime.now().astimezone().isoformat(timespec="milliseconds")
    )
    if already_online:
        recovery_stage = None
        recovery_source = (
            "dorm-ethernet-already-online"
            if config.connection_mode == CONNECTION_MODE_DORM_ETHERNET
            else "workstation-ruijie-already-online"
            if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
            else "wireless-already-online"
        )
    else:
        recovery_stage = status.get("stage")
        recovery_source = _recovery_source(recovery_stage)
    save_morning_online_baseline(
        {
            "confirmed_at": confirmed_at,
            "source": recovery_source,
            "login_submitted_at": None if already_online else status.get("login_submitted_at"),
            "probe_succeeded_at": confirmed_at,
        }
    )
    append_connectivity_event(
        "morning-online-confirmed" if already_online else "reconnected",
        source=recovery_source,
        cause="already-online" if already_online else "wake-recovery",
        recovery_stage=recovery_stage,
        confirmed_at=confirmed_at,
    )


def _process_wake_request(config: AppConfig, request: dict) -> bool:
    request_id = str(request.get("id") or "")
    if not request_id or not mark_wake_request_running(request_id):
        return False
    event(
        "wake-request-received",
        True,
        "后台监测已接收唤醒后的联网请求，并成为本轮唯一自动认证执行者",
        wake_request_id=request_id,
        wake_request_source=request.get("source"),
    )
    write_status("wake-recovery-started", None, "已唤醒，后台监测正在统一处理联网确认")
    already_online = _online(config)
    ok = already_online or bool(_recover(config, 0, "Wake"))
    if ok:
        _record_wake_success(config, already_online)
        _ensure_uu(config)
        message = "唤醒后已在线，未重复提交登录" if already_online else "唤醒后认证及真实联网探测成功"
        write_status("wake-recovery-succeeded", True, message)
    else:
        message = "唤醒后的统一联网流程未通过真实联网探测，后台监测将按策略继续重试"
        write_status("wake-recovery-failed", False, message)
    complete_wake_request(request_id, ok, message)
    event(
        "wake-request-completed",
        ok,
        message,
        wake_request_id=request_id,
        wake_request_source=request.get("source"),
    )
    return ok


def run_wake_coordinator(config: AppConfig) -> bool:
    prune()
    if not config.wake_enabled:
        event(
            "wake-coordinator-skipped",
            True,
            "每日唤醒已关闭，忽略残留唤醒任务触发",
            wake_enabled=False,
        )
        write_status("wake-disabled", True, "每日唤醒已按配置关闭")
        _start_monitor_task("wake-disabled-passive")
        return True
    request = create_wake_request("wake-task")
    arm_monitor(config, "wake-coordinator")
    write_status(
        "wake-requested",
        None,
        "电脑已唤醒，正在把联网确认请求交给后台监测",
        wake_request_id=request["id"],
    )
    _start_monitor_task("wake-coordinator")
    signaled = signal_wake_monitor()
    event(
        "wake-request-created",
        True,
        "唤醒协调器已投递请求；认证仅由后台监测执行",
        wake_request_id=request["id"],
        monitor_signaled=signaled,
    )
    with keep_system_awake():
        completed = wait_for_wake_result(
            request["id"], MORNING_RECOVERY_HANDOFF_WAIT_SECONDS
        )
    if completed is None:
        event(
            "wake-coordinator-timeout",
            False,
            "等待后台监测完成唤醒联网请求超时；请求仍保留供后台继续处理",
            wake_request_id=request["id"],
        )
        return False
    return bool(completed.get("success"))


def run_morning(config: AppConfig) -> bool:
    """Compatibility entrypoint for tasks installed by releases before 1.24.15."""
    event(
        "legacy-morning-entry",
        True,
        "旧 MorningLogin 任务已转交唤醒协调器，不再直接执行认证",
    )
    return run_wake_coordinator(config)


def monitor(config: AppConfig, once: bool = False) -> None:
    with acquire_monitor_lock() as acquired:
        if not acquired:
            event(
                "monitor-already-running",
                True,
                "已有一个后台联网监测实例，本进程正常退出",
            )
            return
        with SystemAwakeLease("monitor") as awake:
            _monitor_locked(config, once, awake)


def _monitor_locked(config: AppConfig, once: bool, awake: SystemAwakeLease) -> None:
    prune()
    state = (
        {
            "armed": bool(config.auto_connect_on_startup),
            "policy": "active" if config.auto_connect_on_startup else "passive",
            "source": "once",
            "armed_at": None,
        }
        if once
        else load_monitor_state(config)
    )
    event(
        "monitor-started",
        True,
        "后台联网监测任务已启动",
        wake_enabled=config.wake_enabled,
        hibernate_enabled=config.hibernate_enabled,
        monitor_policy=state.get("policy"),
        monitor_started_by=state.get("source"),
    )
    write_status(
        "monitor-started",
        None,
        "断网监测已启动",
        wake_enabled=config.wake_enabled,
        hibernate_enabled=config.hibernate_enabled,
        monitor_policy=state.get("policy"),
        monitor_started_by=state.get("source"),
    )
    failures = 0
    recovery_attempts = 0
    next_wifi_recovery_at = 0.0
    passive_wait_logged = False
    logged_suppression_until = ""
    previous_workstation_route = None
    while True:
        if not once:
            config = load_config()
            state = load_monitor_state(config)
        if not once and not _in_monitor_window(config):
            write_status(
                "monitor-outside-window",
                True,
                f"当前不在 {config.monitor_window_start}–{config.monitor_window_end} 监测窗口",
                wake_enabled=config.wake_enabled,
                hibernate_enabled=config.hibernate_enabled,
                monitor_policy=state.get("policy"),
            )
            return
        suppressed_until = str(state.get("monitor_suppressed_until") or "")
        suppression_remaining = suppression_remaining_seconds(state)
        # Hold through authentication, online probes and all intervening waits,
        # but only for a wake session, never for passive/startup monitoring.
        awake.set_required(
            not once
            and config.wake_enabled
            and bool(state.get("armed"))
            and bool(state.get(
                "wake_keep_awake",
                state.get("source") in {"wake-coordinator", "wake-request"},
            ))
            and suppression_remaining == 0
        )
        if suppression_remaining > 0:
            if suppressed_until != logged_suppression_until:
                event(
                    "monitor-paused-after-manual-logout",
                    True,
                    "手动注销后的 5 分钟暂停期内，不执行联网探测或自动恢复",
                    monitor_suppressed_until=suppressed_until,
                    remaining_seconds=suppression_remaining,
                    monitor_suppression_source=state.get("monitor_suppression_source"),
                )
                logged_suppression_until = suppressed_until
            write_status(
                "monitor-paused-after-manual-logout",
                True,
                "网络已手动注销，5 分钟暂停期内不进行联网监测",
                monitor_suppressed_until=suppressed_until,
                remaining_seconds=suppression_remaining,
                monitor_policy="manual-logout-pause",
            )
            if once:
                return
            wait_for_monitor_signal(
                min(
                    suppression_remaining,
                    max(1, config.passive_probe_interval_seconds),
                )
            )
            continue
        if suppressed_until:
            if not once:
                state = clear_monitor_suppression(config, "manual-logout-pause-expired")
            event(
                "monitor-resumed-after-manual-logout",
                True,
                "手动注销后的 5 分钟暂停期已结束，恢复联网监测",
                monitor_suppressed_until=suppressed_until,
            )
            logged_suppression_until = ""
        if not once and not prepare_workstation_startup(config, state, _online_detail):
            failures = 0
            recovery_attempts = 0
            wait_for_monitor_signal(5)
            continue
        if not once and config.wake_enabled:
            wake_request = open_wake_request()
            if wake_request is None:
                wake_request = create_fallback_request_if_due(config.wake_time)
                if wake_request is not None:
                    event(
                        "wake-request-fallback-created",
                        True,
                        "唤醒任务未在宽限期内投递请求，后台监测已创建一次兜底请求",
                        wake_request_id=wake_request.get("id"),
                    )
            if wake_request is not None:
                if not bool(state.get("armed")) or not state.get("wake_keep_awake"):
                    state = arm_monitor(config, "wake-request")
                awake.set_required(True)
                wake_ok = _process_wake_request(config, wake_request)
                failures = 0
                recovery_attempts = 0
                next_wifi_recovery_at = 0.0
                passive_wait_logged = False
                if not wake_ok:
                    wait_for_monitor_signal(config.recovery_retry_seconds)
                    continue
        if not bool(state.get("armed")):
            online, probe_source = _online_detail(config)
            if online:
                confirmed_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
                if once:
                    state.update(
                        {
                            "armed": True,
                            "policy": "active",
                            "armed_at": confirmed_at,
                            "source": "first-campus-online",
                        }
                    )
                else:
                    state = arm_monitor(config, "first-campus-online")
                append_connectivity_event(
                    "first-campus-online-confirmed",
                    source=EVENT_SOURCE,
                    confirmed_at=confirmed_at,
                    monitor_policy="active",
                )
                event(
                    "monitor-armed",
                    True,
                    "首次校园网真实联网探测成功，已进入主动监测",
                    confirmed_at=confirmed_at,
                    monitor_armed_at=state.get("armed_at"),
                    monitor_started_by="first-campus-online",
                )
                write_status(
                    "monitor-active",
                    True,
                    "校园网首次联网已确认，正在主动监测",
                    confirmed_at=confirmed_at,
                    monitor_policy="active",
                    monitor_armed_at=state.get("armed_at"),
                    monitor_started_by="first-campus-online",
                )
                _ensure_uu(config)
                failures = 0
                recovery_attempts = 0
                passive_wait_logged = False
            else:
                passive_observation = getattr(config, "_workstation_observation", None) if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE else None
                if passive_observation is not None:
                    _record_workstation_observation(config, passive_observation, 1, 0, policy="passive")
                    if once:
                        return
                    wait_for_monitor_signal(config.passive_probe_interval_seconds)
                    continue
                passive_wifi_connection_requested = False
                if (
                    config.connection_mode == CONNECTION_MODE_WIRELESS
                    and probe_source == "wlan-unavailable"
                ):
                    enabled = _ensure_target_wlan_enabled(config)
                    if enabled.success and enabled.changed:
                        requested, visible = _request_target_wlan_connection(config)
                        passive_wifi_connection_requested = requested
                        event(
                            "monitor-passive-wlan-recovery",
                            requested,
                            (
                                "被动监测发现 Wi-Fi 关闭，已开启并请求连接目标校园网络"
                                if requested
                                else "被动监测已开启 Wi-Fi，但尚未请求到目标校园网络"
                            ),
                            visibility=(
                                "visible"
                                if visible
                                else "not-visible"
                                if visible is False
                                else "scan-unavailable"
                            ),
                        )
                if not passive_wait_logged:
                    event(
                        "monitor-passive-waiting",
                        True,
                        (
                            "被动阶段已开启并连接校园 Wi-Fi，暂不自动提交门户凭据"
                            if passive_wifi_connection_requested
                            else "正在被动等待校园网首次联网，不主动连接或认证"
                        ),
                        probe_source=probe_source,
                        wake_enabled=config.wake_enabled,
                        hibernate_enabled=config.hibernate_enabled,
                        monitor_policy=(
                            "passive-wifi-enable-only"
                            if passive_wifi_connection_requested
                            else "passive"
                        ),
                    )
                    passive_wait_logged = True
                if passive_wifi_connection_requested:
                    write_status(
                        "wlan-connecting",
                        None,
                        "已开启 Wi-Fi，正在连接 NJMU_WLAN",
                        probe_source=probe_source,
                        monitor_policy="passive-wifi-enable-only",
                    )
                else:
                    write_status(
                        "monitor-passive-waiting",
                        None,
                        (
                            "正在等待宿舍有线网首次联网；可在界面点击登录按钮"
                            if config.connection_mode == CONNECTION_MODE_DORM_ETHERNET
                            else "正在等待工位有线首次联网；可在界面点击登录认证完成现场校验"
                            if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                            else "正在等待 NJMU_WLAN 首次联网；可在界面点击登录按钮"
                        ),
                        probe_source=probe_source,
                        wake_enabled=config.wake_enabled,
                        hibernate_enabled=config.hibernate_enabled,
                        monitor_policy="passive",
                        retry_after_seconds=config.passive_probe_interval_seconds,
                    )
                if once:
                    return
                wait_for_monitor_signal(config.passive_probe_interval_seconds)
                continue
        sleep_seconds = config.monitor_interval_seconds
        online, probe_source, probe_attempts = _monitor_probe(config)
        observation = getattr(config, "_workstation_observation", None) if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE else None
        workstation_fields = observation.fields if observation is not None else {}
        if observation is not None:
            route_mode = observation.fields["route_mode"]
            previous_route = previous_workstation_route
            if previous_route is not None and previous_route != route_mode:
                event("network-route-changed", True, "工位默认出口路由发生变化",
                      previous_route_mode=previous_route, route_mode=route_mode,
                      connection_mode=config.connection_mode)
            previous_workstation_route = route_mode
            if (observation.available or not observation.fields["confirmed_failure"]
                    or not observation.recovery_allowed):
                failures = _record_workstation_observation(config, observation, probe_attempts, failures)
                if observation.available:
                    recovery_attempts = 0
                    next_wifi_recovery_at = 0.0
                if once:
                    return
                wait_for_monitor_signal(sleep_seconds)
                continue
        if online:
            if failures:
                append_connectivity_event("reconnected", source=EVENT_SOURCE, cause="offline-detected")
            else:
                append_connectivity_event(
                    "online-confirmed",
                    source=EVENT_SOURCE,
                    probe_attempts=probe_attempts,
                )
            failures = 0
            recovery_attempts = 0
            next_wifi_recovery_at = 0.0
            event(
                "monitor",
                True,
                "联网探测成功",
                probe_attempts=probe_attempts,
                probe_source=probe_source,
                monitor_policy="active",
                monitor_armed_at=state.get("armed_at"),
            )
            write_status(
                "online",
                True,
                "双目标联网探测确认在线",
                probe_source=probe_source,
                wake_enabled=config.wake_enabled,
                hibernate_enabled=config.hibernate_enabled,
                monitor_policy="active",
                monitor_armed_at=state.get("armed_at"),
                monitor_started_by=state.get("source"),
            )
        else:
            previous_failures = failures
            failures += probe_attempts
            failure_messages = {
                "wlan-unavailable": "WLAN 信息检测失败",
                "ssid-mismatch": "当前 WLAN 不是目标校园网络",
                "ethernet-unavailable": "宿舍有线网卡、网线或默认路由尚未就绪",
                "workstation-ethernet-unavailable": "工位有线尚未取得可验证的网络信息",
                "microsoft-connect-test": "Microsoft Connect Test 联网探测失败",
                "all-connectivity-probes-failed": "Microsoft 与 Android 联网探测均失败",
                "workstation-access-failed": "两组工位联网探测连续失败，原生认证会话需要恢复",
            }
            failure_message = failure_messages.get(probe_source, "联网探测失败")
            paused_for_auth = config.auth_paused and probe_source in {
                "microsoft-connect-test",
                "all-connectivity-probes-failed",
                "workstation-access-failed",
            }
            portal_allowlist_paused = (
                paused_for_auth
                and config.auth_pause_reason == PORTAL_ALLOWLIST_PAUSE_REASON
            )
            waiting_for_ssid_rescan = (
                probe_source in {"wlan-unavailable", "ssid-mismatch"}
                and time.monotonic() < next_wifi_recovery_at
            )
            waiting_for_ethernet = probe_source == "ethernet-unavailable"
            waiting_for_unvalidated_ruijie = (
                probe_source == "workstation-ethernet-unavailable"
                and not (config.ruijie_auto_enabled or config.ruijie_native_auto_enabled)
            )
            recovery_policy = (
                "portal-allowlist-paused"
                if portal_allowlist_paused
                else "authentication-paused"
                if paused_for_auth
                else "wait-for-ethernet"
                if waiting_for_ethernet
                else "ruijie-awaiting-field-validation"
                if waiting_for_unvalidated_ruijie
                else "ssid-rescan-backoff"
                if waiting_for_ssid_rescan
                else "immediate"
                if _should_recover(probe_source, failures)
                else "confirm-twice"
            )
            if previous_failures == 0:
                append_connectivity_event(
                    "offline-detected",
                    source=probe_source,
                    consecutive_failures=failures,
                    probe_attempts=probe_attempts,
                    recovery_policy=recovery_policy,
                    **workstation_fields,
                )
            event(
                "monitor",
                False,
                failure_message,
                consecutive_failures=failures,
                failure_source=probe_source,
                probe_attempts=probe_attempts,
                recovery_policy=recovery_policy,
                **workstation_fields,
            )
            if paused_for_auth:
                if portal_allowlist_paused:
                    write_status(
                        "portal-allowlist-blocked",
                        False,
                        "认证页面未通过官方门户允许列表校验，自动登录保持暂停且不会重复打开页面",
                        reason=PORTAL_ALLOWLIST_PAUSE_REASON,
                        automatic_submission_paused=True,
                        monitor_policy="active",
                    )
                else:
                    write_status(
                        "authentication-paused",
                        False,
                        "账号、密码或运营商需要重新确认，自动登录已暂停",
                        reason=config.auth_pause_reason or "authentication-rejected",
                    )
            elif waiting_for_ethernet:
                write_status(
                    "ethernet-unavailable",
                    False,
                    "正在等待宿舍有线网卡、网线和 DHCP 就绪；不会改用工位锐捷连接",
                    monitor_policy="active",
                    retry_after_seconds=sleep_seconds,
                )
            elif waiting_for_unvalidated_ruijie:
                write_status(
                    "ruijie-awaiting-field-validation",
                    False,
                    "工位锐捷自动填写尚未通过现场验证；后台不会操作官方客户端",
                    automatic_submission_paused=True,
                    monitor_policy="active",
                )
            elif waiting_for_ssid_rescan:
                remaining_seconds = max(1, int(next_wifi_recovery_at - time.monotonic()))
                write_status(
                    "wifi-not-visible",
                    False,
                    "当前区域搜不到校园 Wi-Fi，正在低频等待下一次扫描",
                    retry_after_seconds=remaining_seconds,
                )
            elif _should_recover(probe_source, failures):
                pending_wake_request = open_wake_request() if not once else None
                if pending_wake_request is not None:
                    wake_ok = _process_wake_request(config, pending_wake_request)
                    failures = 0
                    recovery_attempts = 0
                    next_wifi_recovery_at = 0.0
                    if not wake_ok:
                        wait_for_monitor_signal(config.recovery_retry_seconds)
                    continue
                priority_delay = (
                    wake_priority_delay_seconds(config.wake_time)
                    if not once and config.wake_enabled
                    else 0
                )
                if priority_delay > 0:
                    event(
                        "monitor-recovery-deferred-for-wake",
                        True,
                        "已发现断网，但处于每日唤醒优先窗口，等待 Wake 请求后由本监测进程统一认证",
                        failure_source=probe_source,
                        defer_seconds=priority_delay,
                    )
                    write_status(
                        "monitor-waiting-for-wake-request",
                        None,
                        "已发现断网，正在等待每日唤醒请求，期间不会提前认证",
                        retry_after_seconds=priority_delay,
                        monitor_policy="wake-priority",
                    )
                    wait_for_monitor_signal(priority_delay)
                    continue
                recovery_attempts += 1
                if _recover(config, recovery_attempts, "Monitor"):
                    recovery_status = read_status()
                    recovery_stage = recovery_status.get("stage")
                    recovery_source = _recovery_source(recovery_stage)
                    confirmed_at = recovery_status.get("probe_succeeded_at") or datetime.now().astimezone().isoformat(timespec="milliseconds")
                    append_connectivity_event(
                        "reconnected",
                        source=recovery_source,
                        cause=probe_source,
                        recovery_stage=recovery_stage,
                        confirmed_at=confirmed_at,
                    )
                    event(
                        "monitor-recovery",
                        True,
                        "断网恢复后真实联网探测成功",
                        source=recovery_source,
                        recovery_stage=recovery_stage,
                        confirmed_at=confirmed_at,
                    )
                    failures = 0
                    recovery_attempts = 0
                    next_wifi_recovery_at = 0.0
                    write_status(
                        "recovered",
                        True,
                        "断网后已通过真实联网探测恢复",
                        source=recovery_source,
                        recovery_stage=recovery_stage,
                        confirmed_at=confirmed_at,
                        monitor_policy="active",
                        monitor_armed_at=state.get("armed_at"),
                    )
                else:
                    recovery_stage = read_status().get("stage")
                    if recovery_stage == "wifi-not-visible":
                        next_wifi_recovery_at = time.monotonic() + config.ssid_not_visible_retry_seconds
                        recovery_attempts = 0
                        event(
                            "ssid-rescan-backoff",
                            False,
                            "校园 Wi-Fi 不可见，降低连接恢复频率且不重启网卡",
                            retry_seconds=config.ssid_not_visible_retry_seconds,
                        )
                        write_status(
                            "wifi-not-visible",
                            False,
                            "当前区域搜不到校园 Wi-Fi，稍后低频重试",
                            retry_after_seconds=config.ssid_not_visible_retry_seconds,
                            monitor_policy="active",
                        )
                        sleep_seconds = config.ssid_not_visible_retry_seconds
                    elif recovery_stage == "portal-allowlist-blocked":
                        recovery_attempts = 0
                        write_status(
                            "portal-allowlist-blocked",
                            False,
                            "认证页面未通过官方门户允许列表校验，后台认证已暂停且不会重复打开页面",
                            reason=PORTAL_ALLOWLIST_PAUSE_REASON,
                            automatic_submission_paused=True,
                            monitor_policy="active",
                        )
                    elif recovery_stage == "authentication-paused":
                        recovery_attempts = 0
                        write_status(
                            "authentication-paused",
                            False,
                            "账号、密码或运营商错误，自动登录已暂停；请在主界面重新输入凭据",
                            monitor_policy="active",
                        )
                    else:
                        sleep_seconds = config.recovery_retry_seconds
                        write_status(
                            "recovery-waiting",
                            False,
                            "程序联网流程未恢复联网，后台将继续重试",
                            consecutive_failures=failures,
                            monitor_policy="active",
                            retry_after_seconds=sleep_seconds,
                        )
        if once:
            return
        wait_for_monitor_signal(sleep_seconds)


def run_hibernate() -> bool:
    prune()
    config = load_config()
    if not config.hibernate_enabled:
        event(
            "hibernate-skipped",
            True,
            "每日定时休眠已关闭，忽略残留休眠任务触发",
            hibernate_enabled=False,
        )
        write_status("hibernate-disabled", True, "每日定时休眠已按配置关闭")
        return True
    write_status("hibernate-started", None, "准备进入休眠")
    try:
        stopped = subprocess.run(
            ["schtasks.exe", "/End", "/TN", MONITOR_TASK_NAME],
            capture_output=True,
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        event(
            "monitor-stop-before-hibernate",
            stopped.returncode == 0,
            (
                "休眠前已结束联网监测任务，避免恢复流程跨休眠延续"
                if stopped.returncode == 0
                else "休眠前未发现可结束的联网监测实例，继续执行休眠"
            ),
            task_returncode=stopped.returncode,
        )
    except (OSError, subprocess.SubprocessError) as error:
        event(
            "monitor-stop-before-hibernate",
            False,
            "休眠前无法结束监测任务，仍继续执行计划休眠",
            error_type=type(error).__name__,
        )
    requested_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    append_connectivity_event(
        "hibernate-requested",
        source=EVENT_SOURCE,
        requested_at=requested_at,
        scheduled_time=config.sleep_time,
        wake_enabled=config.wake_enabled,
        hibernate_enabled=config.hibernate_enabled,
    )
    event(
        "hibernate",
        True,
        "执行计划休眠；系统恢复后将由监测任务恢复触发器重新启动",
        requested_at=requested_at,
        scheduled_time=config.sleep_time,
        wake_enabled=config.wake_enabled,
        hibernate_enabled=config.hibernate_enabled,
    )
    try:
        subprocess.run(["shutdown.exe", "/h"], check=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        return True
    except (OSError, subprocess.SubprocessError) as error:
        event("hibernate", False, type(error).__name__)
        write_status("hibernate-failed", False, "无法执行休眠")
        return False
