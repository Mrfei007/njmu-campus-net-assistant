from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
# 依赖目录默认在 app/../campus-net-assistant/vendor；单源仓库里依赖不进版本库，
# 因此允许用 NJMU_DEPENDENCY_VENDOR 指向仓库外的只读依赖目录。
_VENDOR_OVERRIDE = os.environ.get("NJMU_DEPENDENCY_VENDOR")
DEPENDENCY_VENDOR = Path(_VENDOR_OVERRIDE) if _VENDOR_OVERRIDE else ROOT.parent / "campus-net-assistant" / "vendor"
PRODUCT_NAME = "NJMU校园网自动化连接程序"
VERSION_SOURCE = ROOT / "src" / "campus_net_assistant" / "version.py"
VERSION = str(runpy.run_path(str(VERSION_SOURCE))["VERSION"])
if not re.fullmatch(r"\d+\.\d+(?:\.\d+){0,2}", VERSION):
    # 允许 a.b / a.b.c / a.b.c.d；Windows 版本资源由 render_version_info() 补齐到 4 段。
    raise SystemExit(f"无效的产品版本号：{VERSION!r}")
BUILD_ID = datetime.now().strftime("%Y%m%d-%H%M%S")
DIST_ROOT = ROOT / "dist-builds" / BUILD_ID
BUILD_ROOT = ROOT / "build" / BUILD_ID
WORK_ROOT = BUILD_ROOT / "pyinstaller"
SPEC_ROOT = BUILD_ROOT / "spec"
METADATA_ROOT = BUILD_ROOT / "metadata"
RELEASE_ROOT = ROOT / "release"
SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
BRIDGE_SOURCE = ROOT / "src" / "campus_net_assistant" / "native" / "RawetherBridge.cs"
BRIDGE_BINARY = BUILD_ROOT / "native" / "RawetherBridge.exe"
NPCAP_BRIDGE_BINARY = ROOT / "src" / "campus_net_assistant" / "native" / "bin" / "NpcapBridge.exe"
# Npcap's installer is redistributed inside the portable package so the first
# workstation setup can use the "select installer…" flow without a second
# download.  It is not a driver binary; Npcap is installed by its own signed
# installer.  NJMU_NPCAP_INSTALLER allows a release build to point at a copy
# outside the repository while the checked-in default keeps builds repeatable.
NPCAP_INSTALLER = ROOT / "tools" / "npcap-1.89.exe"
NPCAP_INSTALLER_SIZE = 1_325_224
NPCAP_INSTALLER_SHA256 = "8aed85e900d783d1308506e919587d3e540451947af8a82f2d04f819e44305cc"
VERSION_INFO_TEMPLATE = ROOT / "version_info.txt"
GENERATED_VERSION_INFO = METADATA_ROOT / "version_info.txt"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_version_info() -> Path:
    parts = [int(part) for part in VERSION.split(".")]
    numeric = tuple((parts + [0, 0, 0, 0])[:4])
    rendered = VERSION_INFO_TEMPLATE.read_text(encoding="utf-8")
    rendered = rendered.replace("@@VERSION_COMMA@@", ", ".join(str(part) for part in numeric))
    rendered = rendered.replace("@@FILE_VERSION@@", ".".join(str(part) for part in numeric))
    rendered = rendered.replace("@@VERSION@@", VERSION)
    METADATA_ROOT.mkdir(parents=True, exist_ok=True)
    GENERATED_VERSION_INFO.write_text(rendered, encoding="utf-8")
    return GENERATED_VERSION_INFO


def render_usage_guide() -> str:
    return (ROOT / "使用说明.txt").read_text(encoding="utf-8").replace("{{VERSION}}", VERSION)


def build_rawether_bridge() -> None:
    compiler = SYSTEM_ROOT / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        raise RuntimeError("缺少 Windows x64 C# 编译器，无法构建 Rawether 隔离桥接器")
    BRIDGE_BINARY.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [str(compiler), "/nologo", "/platform:x64", "/optimize+", "/target:exe", "/reference:System.ServiceProcess.dll",
         f"/out:{BRIDGE_BINARY}", str(BRIDGE_SOURCE)],
        check=False,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    )
    if completed.returncode:
        raise RuntimeError(f"Rawether 隔离桥接器构建失败：{completed.returncode}")


def isolate_build_environment() -> None:
    """Keep unrelated desktop/runtime DLL folders out of PyInstaller discovery."""
    python_root = Path(sys.executable).resolve().parent
    candidates = [
        python_root,
        python_root / "DLLs",
        python_root / "Scripts",
        DEPENDENCY_VENDOR / "PySide6",
        DEPENDENCY_VENDOR / "shiboken6",
        SYSTEM_ROOT / "System32",
        SYSTEM_ROOT,
    ]
    os.environ["PATH"] = os.pathsep.join(str(path) for path in candidates if path.is_dir())
    for name in (
        "QT_PLUGIN_PATH",
        "QML2_IMPORT_PATH",
        "QML_IMPORT_PATH",
        "PYTHONPATH",
    ):
        os.environ.pop(name, None)


def validate_windows_runtime(package_dir: Path) -> None:
    """Require the system UCRT and reject mismatched packaged runtime files."""
    internal = package_dir / "_internal"
    system32 = SYSTEM_ROOT / "System32"
    system_ucrt = system32 / "ucrtbase.dll"
    if not system_ucrt.is_file():
        raise RuntimeError(f"本机缺少 Windows UCRT 运行库：{system_ucrt}")

    packaged_ucrt = internal / "ucrtbase.dll"
    runtime_files = ([packaged_ucrt] if packaged_ucrt.is_file() else []) + sorted(
        internal.glob("api-ms-win-crt-*.dll")
    )
    for packaged in runtime_files:
        system_file = system32 / packaged.name
        if not system_file.is_file():
            raise RuntimeError(f"无法核对本机 Windows 运行库：{system_file}")
        if file_sha256(packaged) != file_sha256(system_file):
            raise RuntimeError(f"发布目录混入非本机 Windows 运行库：{packaged.name}")

    unrelated_runtime_files = {
        "icudt78.dll",
        "icuuc.dll",
        "libcrypto-3-x64.dll",
        "libssl-3-x64.dll",
    }
    found = sorted(path.name for path in internal.iterdir() if path.name.lower() in unrelated_runtime_files)
    if found:
        raise RuntimeError(f"发布目录混入无关桌面运行库：{', '.join(found)}")


def validate_packaged_gui(package_dir: Path) -> None:
    """Exercise the same Qt imports and platform plugin needed by double-click GUI startup."""
    executable = package_dir / f"{PRODUCT_NAME}.exe"
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    completed = subprocess.run(
        [str(executable), "--gui-smoke-check"],
        cwd=package_dir,
        env=environment,
        check=False,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"打包后的 GUI 启动检查失败，退出码：{completed.returncode}")


def validate_packaged_bridge(package_dir: Path) -> str:
    bridge = package_dir / "_internal" / "campus_net_assistant" / "native" / "bin" / BRIDGE_BINARY.name
    if not bridge.is_file():
        raise RuntimeError("发布目录缺少 Rawether 隔离桥接器")
    completed = subprocess.run(
        [str(bridge), "selftest"], capture_output=True, check=False, timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    )
    if completed.returncode:
        raise RuntimeError(f"打包后的 Rawether 桥接器自检失败：{completed.returncode}")
    return file_sha256(bridge)


def stage_npcap_installer(package_dir: Path) -> dict[str, object]:
    """Copy the signed Npcap installer to <package>/tools for first-run setup."""
    override = os.environ.get("NJMU_NPCAP_INSTALLER", "").strip()
    source = Path(override) if override else NPCAP_INSTALLER
    if not source.is_file():
        raise RuntimeError(
            f"缺少 Npcap 安装包：{source}；可设置 NJMU_NPCAP_INSTALLER 指向 npcap-*.exe"
        )
    if source.suffix.lower() != ".exe" or source.stat().st_size != NPCAP_INSTALLER_SIZE:
        raise RuntimeError(f"Npcap 安装包大小不符：{source}")
    source_sha = file_sha256(source)
    if source_sha != NPCAP_INSTALLER_SHA256:
        raise RuntimeError(f"Npcap 安装包 SHA-256 不符：{source} ({source_sha})")
    destination = package_dir / "tools" / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    copied_sha = file_sha256(destination)
    if copied_sha != NPCAP_INSTALLER_SHA256:
        raise RuntimeError(f"Npcap 安装包复制后校验失败：{destination}")
    return {
        "name": source.name,
        "size_bytes": source.stat().st_size,
        "sha256": copied_sha,
    }


def remove_previous_package() -> None:
    """Remove only the known build output, retrying transient AV file locks."""
    target = (DIST_ROOT / PRODUCT_NAME).resolve()
    if target.parent != DIST_ROOT.resolve():
        raise RuntimeError(f"拒绝清理意外的构建路径：{target}")
    if not target.exists():
        return
    last_error: OSError | None = None
    for attempt in range(12):
        try:
            shutil.rmtree(target)
            return
        except OSError as error:
            last_error = error
            time.sleep(0.25 + attempt * 0.15)
    raise RuntimeError(f"旧构建目录仍被占用：{target}") from last_error

if not (DEPENDENCY_VENDOR / "PyInstaller").is_dir():
    raise SystemExit(f"缺少本地构建依赖：{DEPENDENCY_VENDOR}")

build_rawether_bridge()
generated_version_info = render_version_info()
SPEC_ROOT.mkdir(parents=True, exist_ok=True)
isolate_build_environment()
sys.path.insert(0, str(DEPENDENCY_VENDOR))
from PyInstaller.__main__ import run


remove_previous_package()
run(
    [
        "--clean",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--name",
        PRODUCT_NAME,
        "--distpath",
        str(DIST_ROOT),
        "--workpath",
        str(WORK_ROOT),
        "--specpath",
        str(SPEC_ROOT),
        "--version-file",
        str(generated_version_info),
        "--hidden-import",
        "campus_net_assistant.dorm_observer",
        "--hidden-import",
        "campus_net_assistant.dorm_script_survey",
        "--hidden-import",
        "campus_net_assistant.dorm_inline_survey",
        "--hidden-import",
        "campus_net_assistant.dorm_protocol",
        "--hidden-import",
        "campus_net_assistant.dorm_preflight",
        "--hidden-import",
        "campus_net_assistant.dorm_crypto",
        "--paths",
        str(ROOT / "src"),
        "--paths",
        str(DEPENDENCY_VENDOR),
        "--add-binary",
        f"{BRIDGE_BINARY};campus_net_assistant/native/bin",
        *(["--add-binary",
           f"{NPCAP_BRIDGE_BINARY};campus_net_assistant/native/bin"]
          if NPCAP_BRIDGE_BINARY.is_file() else []),
        str(ROOT / "entrypoint.py"),
    ]
)

package_dir = DIST_ROOT / PRODUCT_NAME
(package_dir / "使用说明.txt").write_text(render_usage_guide(), encoding="utf-8")
# Keep the signed installer next to the app so the Npcap setup dialog can find
# <program>/tools/npcap-*.exe without internet access.
npcap_installer = stage_npcap_installer(package_dir)
# Authentication instructions are consolidated into the usage guide.
manifest = {
    "product": PRODUCT_NAME,
    "version": VERSION,
    "platform": "Windows x64",
    "package_type": "PyInstaller onedir",
    "built_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    "npcap_installer": npcap_installer,
}
(package_dir / "版本信息.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
validate_windows_runtime(package_dir)
validate_packaged_gui(package_dir)
manifest["rawether_bridge_sha256"] = validate_packaged_bridge(package_dir)
manifest["gui_smoke_check"] = "passed"
manifest["rawether_bridge_selftest"] = "passed"
(package_dir / "版本信息.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
zip_path = RELEASE_ROOT / f"{PRODUCT_NAME}-{VERSION}-Windows-x64.zip"
if zip_path.exists():
    zip_path.unlink()
archive_root = f"{PRODUCT_NAME}-{VERSION}"
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(package_dir.rglob("*")):
        if path.is_file():
            archive.write(path, Path(archive_root) / path.relative_to(package_dir))

digest = file_sha256(zip_path)
(zip_path.with_suffix(zip_path.suffix + ".sha256.txt")).write_text(
    f"{digest}  {zip_path.name}\n",
    encoding="utf-8",
)
print(zip_path)
print(digest)
