"""Read-only environment checks for the two native authentication backends."""
from __future__ import annotations

from pathlib import Path

from . import native_wired
from .ethernet import detect_linked_physical_ethernet
from .native_backend_state import file_sha256
from .npcap_backend import bridge_available, npcap_detected
from .rawether import (
    BRIDGE_PATH,
    DLL_NAME,
    DRIVER_NAME,
    NPCAP_BRIDGE_PATH,
    SYSTEM32,
)
from .ruijie import resolve_installation
from .ruijie_profiles import supported_client_hashes


def _rows(entries: list[tuple[str, str, bool | None]]) -> list[dict]:
    return [{"label": label, "value": value, "ok": ok} for label, value, ok in entries]


def npcap_environment() -> dict:
    """Check only what the primary Npcap path needs (no Ruijie client)."""
    bridge_found = NPCAP_BRIDGE_PATH.is_file()
    bridge_ready = bool(bridge_found and bridge_available())
    installed = npcap_detected()
    profile_ready = bool(supported_client_hashes())
    try:
        link = detect_linked_physical_ethernet()
        adapter = link.description
        link_ready = True
    except (RuntimeError, OSError):
        adapter = "未检测到唯一已连接的物理有线网卡"
        link_ready = False
    success = bool(installed and bridge_found and bridge_ready and link_ready and profile_ready)
    if not installed:
        message = "未安装 Npcap 驱动，无法使用原生认证"
    elif not bridge_found:
        message = "缺少 native\\bin\\NpcapBridge.exe"
    elif not bridge_ready:
        message = "NpcapBridge.exe 自检失败（请确认 Npcap 安装完整）"
    elif not link_ready:
        message = "未检测到唯一已连接的物理有线网卡"
    elif not profile_ready:
        message = "缺少内置锐捷协议兼容模板"
    else:
        message = "Npcap 环境检查通过"
    return {
        "success": success,
        "message": message,
        "adapter": adapter,
        "npcap_installed": installed,
        "bridge_found": bool(bridge_found),
        "bridge_ready": bridge_ready,
        "link_ready": link_ready,
        "profile_ready": profile_ready,
        "rows": _rows([
            ("Npcap 驱动", "已安装" if installed else "未安装", installed),
            ("NpcapBridge", "自检通过" if bridge_ready else "缺失或自检失败", bridge_ready),
            ("物理有线网卡", adapter, link_ready),
            ("锐捷协议模板", "已就绪" if profile_ready else "缺失", profile_ready),
        ]),
    }


def rawether_environment(configured_path: str | Path) -> dict:
    """Read-only check for the optional Rawether fallback (never authenticates)."""
    try:
        installation = resolve_installation(configured_path)
        client_path = str(installation.launcher)
        worker_sha256 = installation.worker_sha256
        client_ok = True
        client_error = ""
    except Exception as error:  # RuijieSafetyError / OSError
        installation = None
        client_path = str(configured_path or "")
        worker_sha256 = ""
        client_ok = False
        client_error = str(error)
    report = native_wired.environment_report(configured_path)
    raw = report.get("rawether") or {}
    dll_path = (installation.worker.parent / DLL_NAME) if installation is not None else None
    driver_path = SYSTEM32 / "drivers" / DRIVER_NAME
    dll_sha = file_sha256(dll_path) if dll_path is not None else ""
    driver_sha = file_sha256(driver_path)
    link_ready = bool(report.get("link_ready"))
    compatibility_ready = bool(report.get("compatibility_profile_ready"))
    restore_pending = bool(report.get("restore_pending"))
    client_running = report.get("ruijie_running")
    bridge_sha = file_sha256(BRIDGE_PATH)
    bridge_ready = bool(bridge_sha)
    components_ready = bool(
        raw.get("dll_hash_matches") and raw.get("driver_hash_matches")
        and raw.get("driver_installed") and bridge_ready
    )
    success = bool(client_ok and components_ready and link_ready
                   and compatibility_ready and not restore_pending)
    if not client_ok:
        message = f"锐捷客户端不可用：{client_error or '路径或文件校验失败'}"
    elif not raw.get("dll_hash_matches"):
        message = "W64N55.dll 缺失或哈希与已核验版本不一致"
    elif not raw.get("driver_installed") or not raw.get("driver_hash_matches"):
        message = "PCASp50 驱动缺失或哈希与已核验版本不一致"
    elif not bridge_ready:
        message = "RawetherBridge.exe 缺失"
    elif not link_ready:
        message = "未检测到唯一已连接的物理有线网卡"
    elif not compatibility_ready:
        message = "锐捷客户端版本未纳入兼容资料"
    elif restore_pending:
        message = "存在未完成的旧版网络设置恢复任务，请先完成恢复"
    else:
        message = "锐捷驱动后备连接检查通过"
    record = {
        "client_path": client_path,
        "worker_sha256": worker_sha256,
        "w64n55_sha256": dll_sha,
        "pcasp50_sha256": driver_sha,
        "rawether_bridge_sha256": bridge_sha,
        "restore_pending": restore_pending,
        "link_ok": link_ready,
        "client_running": bool(client_running) if client_running is not None else None,
    }
    return {
        "success": success,
        "message": message,
        "adapter": report.get("adapter", ""),
        "client_path": client_path,
        "worker_sha256": worker_sha256,
        "w64n55_sha256": dll_sha,
        "pcasp50_sha256": driver_sha,
        "rawether_bridge_sha256": bridge_sha,
        "link_ok": link_ready,
        "restore_pending": restore_pending,
        "client_running": client_running,
        "record": record,
        "rows": _rows([
            ("锐捷客户端", ("已核验" if client_ok else "不可用"), client_ok),
            ("客户端版本", worker_sha256[:12] + ("…" if worker_sha256 else "未读取"),
             bool(compatibility_ready)),
            ("W64N55.dll", "哈希匹配" if raw.get("dll_hash_matches") else "缺失或哈希不匹配",
             bool(raw.get("dll_hash_matches"))),
            ("PCASp50 驱动", (
                "运行中" if raw.get("driver_state") == "running"
                else "已安装" if raw.get("driver_installed") else "未安装"
            ), bool(raw.get("driver_installed") and raw.get("driver_hash_matches"))),
            ("RawetherBridge", "自检通过" if bridge_ready else "缺失", bridge_ready),
            ("物理有线网卡", str(report.get("adapter") or ""), link_ready),
            ("锐捷客户端进程", (
                "正在运行（建议先退出，避免会话冲突）"
                if client_running else "未运行"
            ), None if client_running else True),
        ]),
    }
