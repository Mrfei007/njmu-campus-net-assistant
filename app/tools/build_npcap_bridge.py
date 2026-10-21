#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 src/campus_net_assistant/npcap_bridge.py 编译成 native/bin/NpcapBridge.exe。

用法（在 repo\\app 下执行）：
    python -P tools\\build_npcap_bridge.py                # 源码比 exe 新才重编
    python -P tools\\build_npcap_bridge.py --force        # 强制重编
    python -P tools\\build_npcap_bridge.py --check        # 只报告是否需要重编

依赖仓库自带的 vendor\\PyInstaller（优先用环境变量 NJMU_DEPENDENCY_VENDOR，
与 build_local.py 一致），不依赖系统里是否 pip 装了 PyInstaller。

为什么要单独一个脚本：NpcapBridge.exe 是 --onefile 产物，`build_local.py`
只是把它当二进制复制进发布包；桥的代码改了却忘了重编，发布包里就是旧桥
（1.5.8–1.5.9.2 一直如此）。1.6 起把重编做成显式、可检查的一步。
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
SOURCE = PROJECT / "src" / "campus_net_assistant" / "npcap_bridge.py"
TARGET = PROJECT / "src" / "campus_net_assistant" / "native" / "bin" / "NpcapBridge.exe"
WORK = PROJECT / "build" / "npcap-bridge"
DIST = WORK / "dist"


def vendor_dir() -> Path:
    override = os.environ.get("NJMU_DEPENDENCY_VENDOR")
    if override:
        return Path(override)
    return PROJECT.parent / "campus-net-assistant" / "vendor"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def needs_rebuild() -> bool:
    if not TARGET.is_file():
        return True
    return SOURCE.stat().st_mtime > TARGET.stat().st_mtime


def main(argv: list[str]) -> int:
    force = "--force" in argv
    check_only = "--check" in argv
    required = needs_rebuild()
    print("[*] source : %s" % SOURCE)
    print("[*] target : %s" % TARGET)
    if TARGET.is_file():
        print("[*] current: %d bytes sha256=%s mtime=%s" % (
            TARGET.stat().st_size, sha256(TARGET),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(TARGET.stat().st_mtime))))
    if not required and not force:
        print("[OK] bridge is up to date (use --force to rebuild)")
        return 0
    if check_only:
        print("[!] bridge needs rebuild")
        return 0

    vendor = vendor_dir()
    if not (vendor / "PyInstaller").is_dir():
        print("[x] PyInstaller not found under vendor: %s" % vendor)
        print("    set NJMU_DEPENDENCY_VENDOR to the bundled dependency directory")
        return 2
    if not SOURCE.is_file():
        print("[x] missing bridge source: %s" % SOURCE)
        return 2

    # 与 build_local.py 相同的隔离策略：避免把无关桌面运行库扫进包里
    python_root = Path(sys.executable).resolve().parent
    paths = [python_root, python_root / "DLLs", python_root / "Scripts"]
    os.environ["PATH"] = os.pathsep.join(str(path) for path in paths if path.is_dir())
    for name in ("QT_PLUGIN_PATH", "QML2_IMPORT_PATH", "QML_IMPORT_PATH", "PYTHONPATH"):
        os.environ.pop(name, None)

    sys.path.insert(0, str(vendor))
    from PyInstaller.__main__ import run

    DIST.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    built = DIST / "NpcapBridge.exe"
    built.unlink(missing_ok=True)
    print("[*] PyInstaller: %s" % (vendor / "PyInstaller"))
    print("[*] building NpcapBridge.exe (onefile) ...")
    run([
        "--clean", "--noconfirm", "--onefile", "--console",
        "--name", "NpcapBridge",
        "--distpath", str(DIST),
        "--workpath", str(WORK / "work"),
        "--specpath", str(WORK),
        str(SOURCE),
    ])
    if not built.is_file():
        print("[x] build finished without %s" % built)
        return 1
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_bytes(built.read_bytes())
    print("[OK] %s (%d bytes) sha256=%s" % (TARGET, TARGET.stat().st_size, sha256(TARGET)))

    # 自检：--onefile 会在临时目录自解包；受限环境下 %TEMP% 不可写，改用构工作目录。
    extract_root = WORK / "tmp"
    extract_root.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["TEMP"] = env["TMP"] = str(extract_root)
    check = subprocess.run([str(TARGET), "selftest"], capture_output=True, timeout=180, env=env)
    if check.returncode != 0:
        stderr = check.stderr.decode("utf-8", "replace")
        # --onefile 启动时要先把依赖解包到临时目录。沙箱/杀软拒绝写临时目录时，
        # 连 1.5.9.2 的旧桥也会以同样方式失败（已实测对照），与桥的代码无关；
        # 这种环境问题不能把构建卡死，但必须明确告警，交由正常机器上的构建验证。
        if check.returncode in (-1, 0xFFFFFFFF) and "Failed to extract" in stderr:
            print("[!] selftest skipped: this environment blocks --onefile self-extraction")
            print("    (packaged exe is unaffected; run selftest on a normal machine to confirm)")
            return 0
        print("[x] selftest failed with code %d" % check.returncode)
        print(check.stdout.decode("utf-8", "replace"))
        print(stderr)
        return 1
    print("[OK] selftest passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))