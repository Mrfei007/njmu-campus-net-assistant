"""版本衔接：桥接组件与主程序的契约一致性检查。

升级过程中最容易出问题的不是功能，而是"新旧组件混用"：
  * 主程序 1.6 期望状态文件 schema v2，但机器上跑的还是 1.5.x 的桥；
  * 旧安装目录里的桥进程没退出，仍在写状态文件、仍持有会话互斥体；
  * 桥比主程序还新（用户只换了程序，没换整包）。
这些情况不该表现为"状态未知"了事，而要给出可执行的提示。
"""
from __future__ import annotations

from pathlib import Path

from .keepalive_status import EXPECTED_BRIDGE_SCHEMA


def expected_bridge_dir() -> Path | None:
    """本程序自带桥接器所在目录（不存在则返回 None，跳过目录校验）。"""
    try:
        from .native_backend_state import NPCAP_BRIDGE_PATH
    except Exception:
        return None
    directory = Path(NPCAP_BRIDGE_PATH).parent
    return directory if directory.is_dir() else None


def bridge_from_other_install(image_path: str) -> bool:
    """状态记录里的桥进程是否来自其它安装目录（旧版本残留）。"""
    if not image_path:
        return False
    expected = expected_bridge_dir()
    if expected is None:
        return False
    try:
        return Path(image_path).parent.resolve() != expected.resolve()
    except OSError:
        return False


def issues(health: dict) -> list[dict[str, str]]:
    """返回此记录的衔接问题（空列表 = 组件一致）。"""
    found: list[dict[str, str]] = []
    try:
        schema = int(health.get("bridge_schema") or 0)
    except (TypeError, ValueError):
        schema = 0
    if schema and schema < EXPECTED_BRIDGE_SCHEMA:
        found.append({
            "code": "bridge-outdated",
            "message": "桥接组件仍是旧版本（状态记录 schema v1），请重新安装完整程序包后再验证",
        })
    elif schema > EXPECTED_BRIDGE_SCHEMA:
        found.append({
            "code": "app-outdated",
            "message": "桥接组件比本程序更新，请更新主程序",
        })
    if bridge_from_other_install(str(health.get("image_path") or "")):
        found.append({
            "code": "bridge-from-other-install",
            "message": "状态记录来自其它安装目录的桥接进程（旧版本可能仍在运行），请先退出旧版本程序",
        })
    return found


def first_hint(health: dict) -> str:
    """给界面/日志用的一句提示；没有衔接问题时返回空串。"""
    found = issues(health)
    return found[0]["message"] if found else ""