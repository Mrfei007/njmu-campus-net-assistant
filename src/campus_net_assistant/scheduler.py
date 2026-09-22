from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime, timedelta
from pathlib import Path

from .config import APP_DIR, AppConfig, apply_schedule, load_config
from .logging_redacted import event
from .monitor_state import arm as arm_monitor
from .monitor_state import disarm as disarm_monitor
from .product import TASK_PREFIX


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


class ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", getattr(wintypes, "HKEY", wintypes.HANDLE)),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _elevated_command(argument: str) -> tuple[str, str, str]:
    if getattr(sys, "frozen", False):
        executable = sys.executable
        return executable, argument, str(Path(executable).resolve().parent)
    entrypoint = Path(__file__).resolve().parents[2] / "entrypoint.py"
    executable = sys.executable
    return executable, f'"{entrypoint}" {argument}', str(entrypoint.parent)


def _run_elevated(argument: str, timeout_ms: int) -> int:
    executable, arguments, working_directory = _elevated_command(argument)
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = arguments
    info.lpDirectory = working_directory
    info.nShow = 0
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        raise PermissionError("管理员授权被取消或无法启动")
    try:
        wait_result = ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, timeout_ms)
        if wait_result == 0x00000102:  # WAIT_TIMEOUT
            raise TimeoutError("管理员进程在规定时间内未完成")
        exit_code = wintypes.DWORD()
        if not ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise RuntimeError("无法取得管理员进程退出状态")
        return int(exit_code.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(info.hProcess)


def _sid() -> str:
    if os.name != "nt":
        return "S-1-5-18"
    command = "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        creationflags=CREATE_NO_WINDOW,
    )
    sid = result.stdout.strip()
    if not sid.startswith("S-"):
        raise RuntimeError("无法取得当前 Windows 用户 SID")
    return sid


def _task_command(mode: str) -> tuple[str, str, str]:
    if getattr(sys, "frozen", False):
        return sys.executable, f'--background {mode}', str(Path(sys.executable).resolve().parent)
    entrypoint = Path(__file__).resolve().parents[2] / "entrypoint.py"
    return sys.executable, f'"{entrypoint}" --background {mode}', str(entrypoint.parent)


def _xml(
    task_name: str,
    mode: str,
    start_time: str | None,
    execution_limit: str,
    wake: bool = False,
    restart_on_failure: bool = False,
    logon_trigger: bool = False,
    resume_trigger: bool = False,
) -> str:
    namespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", namespace)
    tag = lambda name: f"{{{namespace}}}{name}"
    task = ET.Element(tag("Task"), {"version": "1.3"})
    ET.SubElement(task, tag("RegistrationInfo"))
    task.find(tag("RegistrationInfo")).append(ET.Element(tag("URI")))
    task.find(tag("RegistrationInfo")).find(tag("URI")).text = "\\" + task_name
    user_sid = _sid()
    principals = ET.SubElement(task, tag("Principals"))
    principal = ET.SubElement(principals, tag("Principal"), {"id": "Author"})
    ET.SubElement(principal, tag("UserId")).text = user_sid
    ET.SubElement(principal, tag("LogonType")).text = "InteractiveToken"
    ET.SubElement(principal, tag("RunLevel")).text = "HighestAvailable"
    settings = ET.SubElement(task, tag("Settings"))
    ET.SubElement(settings, tag("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, tag("StopIfGoingOnBatteries")).text = "false"
    ET.SubElement(settings, tag("ExecutionTimeLimit")).text = execution_limit
    ET.SubElement(settings, tag("MultipleInstancesPolicy")).text = "IgnoreNew"
    ET.SubElement(settings, tag("StartWhenAvailable")).text = "true"
    if restart_on_failure:
        restart = ET.SubElement(settings, tag("RestartOnFailure"))
        ET.SubElement(restart, tag("Interval")).text = "PT1M"
        ET.SubElement(restart, tag("Count")).text = "3"
    if wake:
        ET.SubElement(settings, tag("WakeToRun")).text = "true"
    ET.SubElement(settings, tag("UseUnifiedSchedulingEngine")).text = "true"
    triggers = ET.SubElement(task, tag("Triggers"))
    if start_time:
        trigger = ET.SubElement(triggers, tag("CalendarTrigger"))
        now = datetime.now().astimezone()
        hour, minute = (int(part) for part in start_time.split(":", 1))
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        boundary = candidate.isoformat(timespec="seconds")
        ET.SubElement(trigger, tag("StartBoundary")).text = boundary
        daily = ET.SubElement(trigger, tag("ScheduleByDay"))
        ET.SubElement(daily, tag("DaysInterval")).text = "1"
    if logon_trigger:
        logon = ET.SubElement(triggers, tag("LogonTrigger"))
        ET.SubElement(logon, tag("Enabled")).text = "true"
        ET.SubElement(logon, tag("UserId")).text = user_sid
    if resume_trigger:
        resume = ET.SubElement(triggers, tag("EventTrigger"))
        ET.SubElement(resume, tag("Enabled")).text = "true"
        ET.SubElement(resume, tag("Subscription")).text = (
            "<QueryList><Query Id='0' Path='System'><Select Path='System'>"
            "*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] "
            "and EventID=1]]</Select></Query></QueryList>"
        )
    command, arguments, working_directory = _task_command(mode)
    actions = ET.SubElement(task, tag("Actions"), {"Context": "Author"})
    action = ET.SubElement(actions, tag("Exec"))
    ET.SubElement(action, tag("Command")).text = command
    ET.SubElement(action, tag("Arguments")).text = arguments
    ET.SubElement(action, tag("WorkingDirectory")).text = working_directory
    # schtasks 读取的是 UTF-16 文件；让 XML 声明与实际字节编码保持一致。
    xml_bytes = ET.tostring(task, encoding="utf-16", xml_declaration=True)
    return xml_bytes.decode("utf-16")


def _register(task_name: str, xml_text: str) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-16", suffix=".xml", delete=False, dir=APP_DIR) as handle:
        handle.write(xml_text)
        xml_path = handle.name
    try:
        result = subprocess.run(
            ["schtasks.exe", "/Create", "/TN", task_name, "/XML", xml_path, "/F"],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "无详细错误").strip()
            raise RuntimeError(f"计划任务 {task_name} 创建失败：{detail}")
    finally:
        try:
            Path(xml_path).unlink()
        except OSError:
            pass


def _delete_task(task_name: str) -> bool:
    subprocess.run(
        ["schtasks.exe", "/End", "/TN", task_name],
        capture_output=True,
        timeout=20,
        creationflags=CREATE_NO_WINDOW,
    )
    result = subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", task_name, "/F"],
        capture_output=True,
        timeout=20,
        creationflags=CREATE_NO_WINDOW,
    )
    return result.returncode == 0


def _stop_orphaned_monitor_processes() -> int:
    """Stop monitor children left behind by an older task/executable instance."""
    if os.name != "nt":
        return 0
    executable_names = {
        Path(sys.executable).name,
        "NJMU校园网自动化连接程序.exe",
        "南医校园网自动登录辅助程序.exe",
        "NJMUCampusNetAssistant.exe",
    }
    names = ",".join(f"'{name.replace("'", "''")}'" for name in sorted(executable_names))
    command = (
        f"$names=@({names}); $stopped=0; "
        "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $names -contains $_.Name -and "
        "$_.CommandLine -match '(?i)--background\\s+monitor(?:\\s|$)' } | "
        "ForEach-Object { "
        "$result=Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue; "
        "if($result.ReturnValue -eq 0){$stopped++} }; "
        "$stopped"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        if completed.returncode != 0:
            return 0
        return int((completed.stdout or "0").strip().splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return 0


def install(config: AppConfig) -> dict:
    if os.name != "nt":
        raise RuntimeError("计划任务安装仅支持 Windows")
    if not is_admin():
        raise PermissionError("安装每日唤醒、休眠和监测任务需要管理员权限")
    apply_schedule(config)
    monitor_name = f"{TASK_PREFIX}Monitor"
    _delete_task(monitor_name)
    stopped_orphan_monitors = _stop_orphaned_monitor_processes()
    specs: list[tuple[str, str, str | None, str, bool, bool, bool, bool]] = []
    if config.wake_enabled:
        specs.append(
            (
                f"{TASK_PREFIX}Wake",
                "wake",
                config.wake_time,
                "PT25M",
                True,
                False,
                False,
                False,
            )
        )
    if config.hibernate_enabled:
        specs.append(
            (
                f"{TASK_PREFIX}Hibernate",
                "hibernate",
                config.sleep_time,
                "PT5M",
                False,
                False,
                False,
                False,
            )
        )
    specs.append(
        (
            monitor_name,
            "monitor",
            config.monitor_start_time if config.wake_enabled else None,
            "PT0S",
            False,
            True,
            True,
            not config.wake_enabled,
        )
    )
    for name, mode, start, limit, wake, restart_on_failure, logon, resume in specs:
        _register(
            name,
            _xml(
                name,
                mode,
                start,
                limit,
                wake,
                restart_on_failure,
                logon_trigger=logon,
                resume_trigger=resume,
            ),
        )
    configured_names = {item[0] for item in specs}
    removed_tasks = []
    for optional_name in (
        f"{TASK_PREFIX}Wake",
        f"{TASK_PREFIX}MorningLogin",
        f"{TASK_PREFIX}Hibernate",
    ):
        if optional_name not in configured_names and _delete_task(optional_name):
            removed_tasks.append(optional_name)
    if config.auto_connect_on_startup:
        arm_monitor(config, "configuration-auto-connect-enabled")
    else:
        disarm_monitor(config, "configuration-passive")
    started = subprocess.run(
        ["schtasks.exe", "/Run", "/TN", monitor_name],
        capture_output=True,
        timeout=20,
        creationflags=CREATE_NO_WINDOW,
    )
    installed = [item[0] for item in specs]
    event(
        "scheduler-install",
        True,
        "已按功能开关更新计划任务，并启动唯一后台监测任务",
        wake_enabled=config.wake_enabled,
        hibernate_enabled=config.hibernate_enabled,
        auto_connect_on_startup=config.auto_connect_on_startup,
        monitor_policy="active" if config.auto_connect_on_startup else "passive",
        installed_tasks=installed,
        removed_tasks=removed_tasks,
        stopped_orphan_monitors=stopped_orphan_monitors,
        monitor_start_returncode=started.returncode,
    )
    return {
        "installed": installed,
        "removed": removed_tasks,
        "stopped_orphan_monitors": stopped_orphan_monitors,
        "monitor_started": started.returncode == 0,
    }


def install_with_elevation(config: AppConfig) -> dict | None:
    """Run the same executable elevated when the GUI was opened normally."""
    if is_admin():
        return install(config)
    if os.name != "nt":
        raise PermissionError("计划任务安装需要管理员权限")
    if _run_elevated("--install-tasks", 120000) != 0:
        raise RuntimeError("管理员进程未能完成计划任务安装")
    return {"elevated": True}


def remove_all_tasks() -> dict:
    """Stop and delete every task owned by the formal application."""
    if os.name != "nt":
        raise RuntimeError("计划任务清理仅支持 Windows")
    if not is_admin():
        raise PermissionError("清理自动化任务需要管理员权限")
    removed = []
    for mode in ("Wake", "MorningLogin", "Hibernate", "Monitor"):
        name = f"{TASK_PREFIX}{mode}"
        if _delete_task(name):
            removed.append(name)
    stopped_orphan_monitors = _stop_orphaned_monitor_processes()
    disarm_monitor(load_config(), "automation-stopped")
    event(
        "scheduler-remove",
        True,
        "已停止后台监测并清理全部自动化计划任务",
        removed_tasks=removed,
        stopped_orphan_monitors=stopped_orphan_monitors,
    )
    return {
        "removed": removed,
        "stopped_orphan_monitors": stopped_orphan_monitors,
    }


def remove_all_tasks_with_elevation() -> dict:
    if is_admin():
        return remove_all_tasks()
    if os.name != "nt":
        raise PermissionError("清理自动化任务需要管理员权限")
    if _run_elevated("--remove-tasks", 120000) != 0:
        raise RuntimeError("管理员进程未能完成自动化任务清理")
    return {"elevated": True}


def logout_network_with_elevation(config: AppConfig) -> bool:
    """Run manual network logout elevated without elevating the whole GUI."""
    if is_admin():
        from .controller import logout_network

        return logout_network(config)
    if os.name != "nt":
        raise PermissionError("校园网络注销需要管理员权限")
    return _run_elevated("--manual-logout", 300000) == 0


def reauthenticate_with_elevation(config: AppConfig) -> bool:
    """Backward-compatible name for the manual network logout action."""
    return logout_network_with_elevation(config)


def validate_login_with_elevation(config: AppConfig) -> bool:
    """Run one offline credential validation elevated without elevating the GUI."""
    if is_admin():
        from .controller import validate_login

        return validate_login(config)
    if os.name != "nt":
        raise PermissionError("校园网登录认证需要管理员权限")
    return _run_elevated("--manual-login-validate", 300000) == 0


def installed_task_names() -> list[str]:
    names: list[str] = []
    for mode in ("Wake", "MorningLogin", "Hibernate", "Monitor"):
        name = f"{TASK_PREFIX}{mode}"
        result = subprocess.run(["schtasks.exe", "/Query", "/TN", name], capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        if result.returncode == 0:
            names.append(name)
    return names
