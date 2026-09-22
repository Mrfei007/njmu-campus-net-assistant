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
    suffix = {
        "running": "后台保活最近一次发送调用成功",
        "send-failed": "后台保活发送失败",
        "retrying": "后台保活发送异常，正在有限重试",
        "exited": "后台保活进程已退出",
        "stopped": "后台保活会话已结束",
        "stale": "后台保活发送记录已过期，状态待确认",
        "inactive": "尚未建立原生保活会话",
    }.get(str(health_state), "后台保活状态未知")
    message += "；" + suffix
    # A TUN or unknown route must never cause an authentication reset merely
    # because HTTP probes fail. A matching bridge's terminated/failed session
    # is evidence for recovery, whereas a stale record is not.
    matched = health.get("adapter_description") == network.description
    failed_session = matched and health_state in {"send-failed", "exited", "stopped"}
    initial_session = (config.ruijie_native_auto_enabled and route["route_mode"] == "ethernet-default"
                       and health.get("reason") in {"no-send-record", "no-valid-send-record", "no-native-session"})
    official_session = (not config.ruijie_native_auto_enabled and config.ruijie_auto_enabled
                        and route["route_mode"] == "ethernet-default")
    allowed = state == "access-failed" and (failed_session or initial_session or official_session)
    fields["recovery_evidence"] = "native-session-ended-or-send-failed" if failed_session else "initial-native-session-required" if initial_session else "validated-official-client-and-default-ethernet-probe-failure" if official_session else "insufficient-authentication-evidence"
    return Observation(state, source, message, available, fields, allowed)
