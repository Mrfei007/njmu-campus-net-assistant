"""Separate workstation link, effective access, source-bound access and health."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import subprocess

from .config import AppConfig
from .ethernet import EthernetInfo, detect_ethernet_interface, detect_linked_physical_ethernet, inspect_workstation_routes
from .keepalive_status import read_health
from .probe import ProbeResult, detailed_connectivity_probe


@dataclass
class Observation:
    state: str
    source: str
    message: str
    available: bool
    fields: dict[str, object]
    recovery_allowed: bool = False


_EXIT_REASON_MESSAGES = {
    "exception": "异常退出",
    "keepalive-send-failed": "保活发送失败后退出",
    "first-keepalive-send-failed": "首帧保活发送失败",
    "link-down": "链路断开后退出",
    "authentication-failed": "认证失败",
    "authentication-unsuccessful": "认证未成功",
    "adapter-open-failed": "网卡打开失败",
    "invalid-input": "启动参数无效",
    "invalid-echo-frame": "保活帧无效",
    "loop-end": "等待被中断",
}


def _native_verified(config: AppConfig) -> bool:
    try:
        from .native_backend_state import primary_status
        return bool(config.ruijie_native_auto_enabled and primary_status()["valid"])
    except Exception:
        return False


def _backend_label(health: dict[str, object]) -> str:
    return "锐捷驱动后备" if str(health.get("native_backend") or "") == "rawether" else "Npcap"


def _keepalive_suffix(config: AppConfig, health: dict[str, object]) -> str:
    """Explain the bridge's own state without conflating it with connectivity."""
    state = str(health.get("state") or "unknown")
    reason = str(health.get("reason") or "")
    basis = str(health.get("verdict_basis") or "")
    backend = _backend_label(health)
    # 版本衔接问题（桥/程序版本不一致、旧目录进程残留）优先给出可执行提示。
    try:
        from .component_compat import first_hint
        hint = first_hint(dict(health))
    except Exception:
        hint = ""
    if hint and state in {"unknown", "exited", "inactive", "stale", "stopped"}:
        return hint
    if state == "running":
        return f"后台保活最近一次发送调用成功（{backend}）"
    if state == "send-failed":
        return f"后台保活发送失败（{backend}）"
    if state == "retrying":
        return f"后台保活发送异常，正在有限重试（{backend}）"
    if state == "exited":
        cause = _EXIT_REASON_MESSAGES.get(str(health.get("exit_reason") or ""))
        if cause:
            return f"后台保活进程已退出（{cause}，{backend}）"
        if basis == "absent":
            return f"后台保活会话已不存在（进程已退出且没有活动会话，{backend}）"
        try:
            sends = int(health.get("successful_sends") or 0)
        except (TypeError, ValueError):
            sends = 0
        if sends > 0:
            return f"后台保活进程已退出（未记录退出原因，此前已成功发送 {sends} 次，{backend}）"
        return f"后台保活进程已退出（没有退出原因记录，{backend}）"
    if state == "stopped":
        requested = str(health.get("exit_reason") or "") == "stop-requested"
        return (
            f"后台保活会话已结束（按请求停止，{backend}）" if requested
            else f"后台保活会话已结束（{backend}）"
        )
    if state == "stale":
        return f"后台保活发送记录已过期，状态待确认（{backend}）"
    if state == "inactive":
        return "尚未建立原生保活会话"
    # Unknown: explain whether verification is the missing prerequisite.
    if not getattr(config, "ruijie_native_auto_enabled", False):
        return "原生认证尚未完成检查验证，本程序后台自动认证未启用"
    try:
        from .native_backend_state import primary_status
        status = primary_status()
    except Exception:
        status = {"valid": False, "reason": "state-unavailable"}
    if not status["valid"]:
        if status.get("reason") in {"app-version-changed", "bridge-changed"}:
            return "程序或 NpcapBridge 已更新，请重新验证原生认证"
        return "原生认证验证状态不可用，请重新验证"
    if reason in {"no-valid-send-record", "no-send-record"}:
        return "本程序原生保活尚无有效记录"
    if reason == "authentication-in-progress":
        return "原生保活正在认证"
    if reason == "process-unverified":
        return "原生保活记录存在，但进程状态无法核验"
    if reason == "session-record-mismatch":
        return "保活记录与运行中的会话不一致"
    ambiguous = {
        "session-owner-missing": "桥接进程在运行但未持有保活会话（状态异常，暂不重建）",
        "pid-mismatch": "状态记录与当前进程不一致（可能属于其它会话），暂不重建",
        "mutex-held-elsewhere": "另一个保活会话正持有会话锁，本次不重建",
        "unsupported-bridge-schema": "桥接状态记录版本不受支持（组件版本不匹配）",
        "missing-created-at": "桥接状态记录不完整（缺少进程创建时间），组件版本可能不匹配",
        "unexpected-image": "状态记录来自非本程序的进程，已忽略",
        "invalid-clock": "系统时间异常，保活状态无法判定",
    }
    if reason in ambiguous:
        return ambiguous[reason]
    return "后台保活状态未知"


def observe(config: AppConfig, network: EthernetInfo | None) -> Observation:
    health = read_health()
    reason = "ok"
    if network is None:
        try:
            detect_linked_physical_ethernet()
            detect_ethernet_interface(require_preferred=False)
            reason = "network-selection-unverified"
        except RuntimeError as error:
            reason = str(error)
        except (OSError, ValueError, subprocess.SubprocessError):
            reason = "network-info-unavailable"
    try:
        route = inspect_workstation_routes(network)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        route = {"route_mode": "unknown", "tunnel_detected": False, "path_verified_direct": False}
    args = (config.portal.check_url, config.portal.success_text, config.portal.secondary_check_url)
    with ThreadPoolExecutor(max_workers=2) as executor:
        effective_job = executor.submit(detailed_connectivity_probe, None, *args)
        bound_job = executor.submit(detailed_connectivity_probe, network.ip, *args) if network else None
        effective = effective_job.result()
        bound = bound_job.result() if bound_job else ProbeResult(False, "not-attempted", reason)
    fields: dict[str, object] = {
        "connection_mode": config.connection_mode, "ethernet_info_reason": reason,
        "ethernet_ready": network is not None,
        "ethernet_interface": network.interface if network else None,
        **route, "effective_probe": effective.public_dict(), "ethernet_bound_probe": bound.public_dict(),
        "keepalive": health, "connectivity_scope": "effective-or-source-bound-access",
        "authentication_state": "unverified", "confirmed_failure": False,
    }
    if network is None:
        messages = {
            "physical-ethernet-link-not-found": "工位有线未连接，等待网线连接",
            "ambiguous-physical-ethernet-links": "有多块工位有线网卡，认证目标尚不明确",
            "ambiguous-physical-ethernet-routes": "有多块工位有线网卡，认证目标尚不明确",
            "physical-ethernet-default-route-not-found": "工位有线正在等待有效地址或网关",
            "ethernet-network-details-incomplete": "工位有线网络信息不完整，等待地址、网关或 DNS",
            "session-ethernet-not-found": "原认证会话对应的有线网卡未就绪",
        }
        message = messages.get(reason, "工位有线信息暂未确认，监测结果未知")
        return Observation("network-unknown", "workstation-network-unverified", message, False, fields)
    if effective.success:
        message = "工位有线已连接；检测到 TUN 路由；当前联网探测成功" if route["tunnel_detected"] else "工位有线已连接；当前联网探测成功"
        if not bound.success:
            message += "；有线绑定探测异常"
        state, source, available = "online", effective.source, True
    elif bound.success:
        state, source, available = "exit-degraded", "effective-exit-failed", True
        message = "工位有线绑定探测成功；当前默认出口访问异常，等待复查代理、DNS 或路由"
    else:
        state, source, available = "access-failed", "workstation-access-failed", False
        message = "工位有线已连接；两组联网探测失败，原因待确认"
    health_state = health["state"]
    message += "；" + _keepalive_suffix(config, health)
    # A TUN or unknown route must never cause an authentication reset merely
    # because HTTP probes fail. A matching bridge's terminated/failed session
    # is evidence for recovery, whereas a stale record is not.
    matched = health.get("adapter_description") == network.description
    failed_session = matched and health_state in {"send-failed", "exited", "stopped"}
    native_ready = _native_verified(config)
    initial_session = (native_ready and route["route_mode"] == "ethernet-default"
                       and health.get("reason") in {"no-send-record", "no-valid-send-record", "no-native-session"})
    # 直连以太网（无 TUN/无备用出口）时，连续两次双目标探测失败即足以判定
    # 认证会话已失效；否则保活"发送成功"会让监测停在 diagnosis-wait 永不恢复。
    direct_ethernet_failure = (native_ready and route["route_mode"] == "ethernet-default"
                               and not route["tunnel_detected"])
    allowed = state == "access-failed" and (failed_session or initial_session
                                            or direct_ethernet_failure)
    fields["recovery_evidence"] = (
        "native-session-ended-or-send-failed" if failed_session
        else "initial-native-session-required" if initial_session
        else "direct-ethernet-double-probe-failure" if direct_ethernet_failure
        else "insufficient-authentication-evidence")
    return Observation(state, source, message, available, fields, allowed)
