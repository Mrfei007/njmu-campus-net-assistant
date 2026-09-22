"""Bounded boot preparation; driver loading is separate from authentication."""
from __future__ import annotations

import os
import subprocess
import time

from . import rawether
from .config import CONNECTION_MODE_WORKSTATION_RUIJIE
from .ethernet import get_linked_physical_ethernet
from .logging_redacted import event
from .monitor_state import save
from .recovery_lock import acquire_recovery_lock
from .status import write as write_status

PREPARE_SECONDS = 120


def _driver_configuration_verified() -> bool:
    """Only the installed, demand-start kernel driver at the pinned path."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\PCASp50") as key:
            kind = winreg.QueryValueEx(key, "Type")[0]
            start = winreg.QueryValueEx(key, "Start")[0]
            path = winreg.QueryValueEx(key, "ImagePath")[0]
        path = os.path.expandvars(path).replace("/", "\\").casefold()
        expected = str(rawether.SYSTEM32 / "drivers" / rawether.DRIVER_NAME).casefold()
        return kind == 1 and start == 3 and path in {
            expected, "\\??\\" + expected,
            r"system32\drivers\pcasp50.sys", r"\systemroot\system32\drivers\pcasp50.sys",
        }
    except (OSError, TypeError, AttributeError):
        return False


def _start_verified_driver(config) -> str:
    report = rawether.inspect(config.ruijie_path)
    if not report.get("reuse_candidate") or not report.get("bridge_ready"):
        return "components-unverified"
    if not _driver_configuration_verified():
        return "driver-config-unverified"
    if rawether._service_state("PCASp50") == "running":
        return "running"
    if rawether._service_state("PCASp50") != "stopped":
        return "driver-not-stopped"
    # Fixed service and absolute OS tool path; never install/configure/stop it.
    try:
        completed = subprocess.run(
            [str(rawether.SYSTEM32 / "sc.exe"), "start", "PCASp50"],
            capture_output=True, timeout=10, creationflags=rawether.CREATE_NO_WINDOW,
        )
        if completed.returncode == 5:
            return "access-denied"
        deadline = time.monotonic() + 10
        while True:
            state = rawether._service_state("PCASp50")
            if state == "running":
                return "running"
            if state != "start-pending" or time.monotonic() >= deadline:
                return f"start-failed-{completed.returncode}-{state}"
            time.sleep(0.5)
    except (OSError, subprocess.SubprocessError):
        return "driver-start-error"


def prepare(config, state: dict, online_check) -> bool:
    """One monitor tick. False means wait five seconds without counting failures.

    Persistent state prevents monitor restarts from extending the deadline or
    repeatedly loading the driver. The caller holds the monitor mutex.
    """
    if (config.connection_mode != CONNECTION_MODE_WORKSTATION_RUIJIE
            or not config.ruijie_native_auto_enabled or not state.get("armed")
            or state.get("boot_prepare_done")
            or (state.get("source") not in {"new-boot", "configuration-auto-connect-enabled"}
                and "boot_prepare_started" not in state)):
        return True
    if "boot_prepare_started" not in state:
        state["boot_prepare_started"] = time.time()
        save(state)
        event("boot-prepare-started", True, "立即检查驱动，独立等待开机网络就绪", timeout_seconds=PREPARE_SECONDS)
    driver = rawether._service_state("PCASp50")
    if driver == "stopped" and not state.get("boot_driver_start_attempted"):
        with acquire_recovery_lock() as acquired:
            if not acquired:
                return False
            # Starting the verified driver is independent of link, DHCP or Internet.
            # Persist before invoking the OS so restarting Monitor never repeats it.
            state["boot_driver_start_attempted"] = True
            save(state)
            result = _start_verified_driver(config)
            state["boot_driver_start_result"] = result
            save(state)
            event("boot-driver-start", result == "running", "开机驱动准备结果", reason=result)
            driver = rawether._service_state("PCASp50")
    link = get_linked_physical_ethernet()
    service = rawether._service_state("RJSuService")
    ready = link is not None and driver == "running" and service == "running"
    # Internet is an early exit, never a prerequisite for authentication.
    online = bool(not ready and link is not None and online_check(config)[0])
    elapsed = max(0, time.time() - float(state["boot_prepare_started"]))
    if online or ready:
        state["boot_prepare_done"] = True
        save(state)
        event("boot-prepare-ready", True, "开机准备完成", already_online=online,
              driver_state=driver, elapsed_seconds=round(elapsed, 1))
        return True
    if elapsed < PREPARE_SECONDS:
        write_status("boot-preparing", None, "已检查驱动，正在等待开机网卡与锐捷服务就绪",
                     driver_state=driver, service_state=service,
                     remaining_seconds=max(0, round(PREPARE_SECONDS - elapsed)))
        return False
    if (link is None or service != "running" or driver in {"start-pending", "unreadable"}):
        write_status("boot-dependency-wait", None,
                     "开机准备已超时，网卡或锐捷服务尚未就绪，继续等待",
                     driver_state=driver, service_state=service)
        return False
    state["boot_prepare_done"] = True
    save(state)
    event("boot-prepare-ended", True, "开机准备窗口结束，转入常规监测",
          driver_state=rawether._service_state("PCASp50"))
    return True
