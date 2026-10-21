from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timedelta
from pathlib import Path


from .product import INTERNAL_NAME


APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / INTERNAL_NAME
CONFIG_PATH = APP_DIR / "config.json"
NORMAL_MONITOR_INTERVAL_SECONDS = 120
CONNECTION_MODE_WIRELESS = "wireless"
CONNECTION_MODE_DORM_ETHERNET = "dorm_ethernet"
CONNECTION_MODE_WORKSTATION_RUIJIE = "workstation_ruijie"
CONNECTION_MODES = {
    CONNECTION_MODE_WIRELESS,
    CONNECTION_MODE_DORM_ETHERNET,
    CONNECTION_MODE_WORKSTATION_RUIJIE,
}


@dataclass
class PortalConfig:
    school: str = "NJMU"
    ssid: str = "NJMU_WLAN"
    portal_host: str = "wlan.njmu.edu.cn"
    check_url: str = "http://www.msftconnecttest.com/connecttest.txt"
    success_text: str = "Microsoft Connect Test"
    secondary_check_url: str = "http://connectivitycheck.gstatic.cn/generate_204"
    success_page_url: str = "https://captiveportal-login.njmu.edu.cn/auth/index.html/u"
    operator: str = "电信"


@dataclass
class AppConfig:
    mode: str = "monitor"
    connection_mode: str = CONNECTION_MODE_WIRELESS
    wlan_interface: str = "auto"
    portal: PortalConfig = field(default_factory=PortalConfig)
    monitor_interval_seconds: int = NORMAL_MONITOR_INTERVAL_SECONDS
    passive_probe_interval_seconds: int = 30
    recovery_retry_seconds: int = 60
    recovery_attempts_before_wifi_restart: int = 2
    wake_enabled: bool = False
    auto_connect_on_startup: bool = False
    hibernate_enabled: bool = False
    wake_time: str = "08:55"
    sleep_time: str = "00:30"
    monitor_start_time: str = "09:10"
    monitor_window_start: str = "09:00"
    monitor_window_end: str = "00:30"
    ssid_not_visible_retry_seconds: int = 300
    auth_paused: bool = False
    auth_pause_reason: str = ""
    auth_paused_at: str = ""
    portal_allowlist_manual_retry_available: bool = True
    login_submission_timestamps: list[str] = field(default_factory=list)
    start_uu: bool = False
    uu_path: str = ""
    keep_login_page_open: bool = True
    wireless_http_experimental: bool = True
    dorm_protocol_observer_enabled: bool = False
    ruijie_path: str = ""
    native_backend: str = "auto"      # "auto" | "npcap" | "rawether"
    ruijie_native_auto_enabled: bool = False
    keepalive_watchdog_enabled: bool = True
    rawether_fallback_enabled: bool = False
    ruijie_submission_timestamps: list[str] = field(default_factory=list)

    def public_dict(self) -> dict:
        return asdict(self)


def normalize_time(value: str) -> str:
    return datetime.strptime(value.strip(), "%H:%M").strftime("%H:%M")


def add_minutes(value: str, minutes: int) -> str:
    parsed = datetime.strptime(normalize_time(value), "%H:%M")
    return (parsed + timedelta(minutes=minutes)).strftime("%H:%M")


def apply_schedule(config: AppConfig) -> AppConfig:
    if config.connection_mode not in CONNECTION_MODES:
        config.connection_mode = CONNECTION_MODE_WIRELESS
    config.wake_time = normalize_time(config.wake_time)
    config.sleep_time = normalize_time(config.sleep_time)
    # Wake 任务会向 Monitor 投递晨间恢复请求；唤醒后 15 分钟的
    # Monitor 日历触发用于协调任务未能完成衔接时再次启动监测。
    config.monitor_start_time = add_minutes(config.wake_time, 15)
    config.monitor_window_start = config.wake_time
    config.monitor_window_end = config.sleep_time
    # 当前策略允许两轮普通恢复；累计失败超过 2 次时重启 WLAN 后主动重连。
    config.recovery_attempts_before_wifi_restart = 2
    # 正常在线监测固定为每 2 分钟一次。被动探测、恢复重试和
    # 校园 Wi-Fi 不可见时的降频仍使用各自独立的间隔。
    config.wireless_http_experimental = True
    config.dorm_protocol_observer_enabled = False
    config.monitor_interval_seconds = NORMAL_MONITOR_INTERVAL_SECONDS
    config.ssid_not_visible_retry_seconds = 300
    config.passive_probe_interval_seconds = max(10, int(config.passive_probe_interval_seconds))
    config.recovery_retry_seconds = max(30, int(config.recovery_retry_seconds))
    if not isinstance(config.login_submission_timestamps, list):
        config.login_submission_timestamps = []
    else:
        config.login_submission_timestamps = [
            str(value) for value in config.login_submission_timestamps if isinstance(value, str)
        ][-10:]
    if not isinstance(config.ruijie_submission_timestamps, list):
        config.ruijie_submission_timestamps = []
    else:
        config.ruijie_submission_timestamps = [
            str(value) for value in config.ruijie_submission_timestamps if isinstance(value, str)
        ][-10:]
    return config


def minutes_between(start: str, end: str) -> int:
    start_hour, start_minute = (int(part) for part in normalize_time(start).split(":"))
    end_hour, end_minute = (int(part) for part in normalize_time(end).split(":"))
    start_value = start_hour * 60 + start_minute
    end_value = end_hour * 60 + end_minute
    if end_value <= start_value:
        end_value += 24 * 60
    return end_value - start_value


def load_config(*, read_only: bool = False) -> AppConfig:
    if not CONFIG_PATH.exists():
        return apply_schedule(AppConfig())
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    portal = PortalConfig(**raw.get("portal", {}))
    allowed_fields = {item.name for item in fields(AppConfig)} - {"portal"}
    values = {k: v for k, v in raw.items() if k in allowed_fields}
    # 1.5.8 renamed the official-client fallback switch to the Rawether driver
    # fallback.  Read the old key once so an upgrade keeps the user's choice.
    if "rawether_fallback_enabled" not in raw and "ruijie_background_client_fallback" in raw:
        values["rawether_fallback_enabled"] = bool(raw.get("ruijie_background_client_fallback"))
    # Preserve the old startup preference once; thereafter the switches are independent.
    if "auto_connect_on_startup" not in raw:
        values["auto_connect_on_startup"] = bool(raw.get("wake_enabled", False))
    config = apply_schedule(AppConfig(portal=portal, **values))
    required_fields = {
        "connection_mode",
        "wake_enabled",
        "auto_connect_on_startup",
        "hibernate_enabled",
        "passive_probe_interval_seconds",
        "recovery_retry_seconds",
        "wireless_http_experimental",
        "dorm_protocol_observer_enabled",
    }
    required_portal_fields = {"secondary_check_url"}
    if not read_only and (
        not required_fields.issubset(raw)
        or not required_portal_fields.issubset(raw.get("portal", {}))
        or raw.get("wireless_http_experimental") is not True
        or raw.get("dorm_protocol_observer_enabled") is True
        or raw.get("monitor_interval_seconds") != config.monitor_interval_seconds
    ):
        save_config(config)
    return config


def save_config(config: AppConfig) -> None:
    apply_schedule(config)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config.public_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
