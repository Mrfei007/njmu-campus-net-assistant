"""Constrained diagnostics for the verified PCAUSA Rawether components.

No function in this module starts or stops a service. Adapter access is isolated
in a short-lived helper process. Each progressively active diagnostic requires
separate UI confirmation. Credentials and the challenge-bound private extension
cross only an anonymous pipe and are never included in returned diagnostics.
The DLL and driver hashes are pinned to the supplied NJMU 4.99 client.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import ipaddress
import locale
import os
import re
import struct
import subprocess
import time
from ctypes import wintypes
from pathlib import Path


DLL_NAME = "W64N55.dll"
BRIDGE_NAME = "RawetherBridge.exe"
DLL_SHA256 = "6c04b7710dfaaf16fa1cecb4a3fe82190bc98ac17ca037620091a18ad740cc02"
DRIVER_SERVICE = "PCASp50"
DRIVER_NAME = "PCASp50.sys"
DRIVER_SHA256 = "2a368b0dd607b822dfd5f731eff959726003db6c9d32b255ad0ce2c5712ad17a"
EXPECTED_EXPORTS = (
    "W32N_OpenProtocolDriver",
    "W32N_CloseProtocolDriver",
    "W32N_OpenAdapterA",
    "W32N_CloseAdapter",
    "W32N_PacketRead",
    "W32N_PacketReadEx",
    "W32N_CancelPacketRead",
    "W32N_SetBPFProgram",
    "W32N_MakeNdisRequest",
    "W32N_PacketSend",
    "W32N_SendSinglePacket",
    "W32N_QueryEthCurrentAddress",
    "MacEnum_OpenEnumeration",
    "MacEnum_OpenEnumerationEx",
    "MacEnum_GetFirstAdapterInfoHandle",
    "MacEnum_GetNextAdapterInfoHandle",
    "MacEnum_QueryAdapterFriendlyName_A",
    "MacEnum_QueryAdapterNdisName_A",
    "MacEnum_CloseAdapterInfoHandle",
    "MacEnum_CloseEnumeration",
)
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
BRIDGE_PATH = Path(__file__).resolve().parent / "native" / "bin" / BRIDGE_NAME
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


# ---------------------------------------------------------------- Npcap 后端

NPCAP_BRIDGE_NAME = "NpcapBridge.exe"
NPCAP_BRIDGE_PATH = Path(__file__).resolve().parent / "native" / "bin" / NPCAP_BRIDGE_NAME


def native_backend() -> str:
    """返回当前生效的原始帧后端："npcap" 或 "rawether"。"""
    mode = "auto"
    try:
        from .config import load_config
        mode = str(getattr(load_config(read_only=True), "native_backend", "auto") or "auto")
        mode = mode.casefold()
    except Exception:
        mode = "auto"
    if mode in {"npcap", "rawether"}:
        return mode
    return "npcap" if NPCAP_BRIDGE_PATH.is_file() else "rawether"


def npcap_bridge_ready() -> bool:
    if not NPCAP_BRIDGE_PATH.is_file():
        return False
    try:
        completed = subprocess.run(
            [str(NPCAP_BRIDGE_PATH), "selftest"], capture_output=True, timeout=12,
            creationflags=CREATE_NO_WINDOW, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _log_stop_request(success: bool, reason: str) -> None:
    try:
        from .logging_redacted import keepalive_stop_requested
        keepalive_stop_requested(success, reason, "rawether")
    except Exception:
        pass


def _active_keepalive_backend() -> str:
    """Best-effort backend of the bridge session currently writing telemetry."""
    try:
        from .keepalive_status import read_health
        health = read_health()
        if health.get("state") in {"running", "send-failed", "retrying", "stale"}:
            backend = str(health.get("native_backend") or "")
            if backend in {"npcap", "rawether"}:
                return backend
    except Exception:
        pass
    return ""


def stop_private_session(reason: str = "") -> bool:
    """Ask the active (or any installed) persistent bridge session to close."""
    active = _active_keepalive_backend()
    candidates: list[str] = []
    if active:
        candidates.append(active)
    for backend in ("npcap", "rawether"):
        if backend not in candidates:
            candidates.append(backend)
    tried = False
    stopped_any = False
    for backend in candidates:
        if backend == "npcap":
            if not NPCAP_BRIDGE_PATH.is_file():
                continue
            from .npcap_backend import stop_session
            tried = True
            if stop_session(reason):
                stopped_any = True
                if active:
                    return True
        elif BRIDGE_PATH.is_file():
            tried = True
            try:
                completed = subprocess.run(
                    [str(BRIDGE_PATH), "stop-private-session"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    creationflags=CREATE_NO_WINDOW,
                    check=False,
                )
                success = completed.returncode == 0
            except (OSError, subprocess.SubprocessError):
                success = False
            _log_stop_request(success, reason)
            if success:
                stopped_any = True
                if active:
                    return True
    if not tried:
        _log_stop_request(True, reason or "bridge-missing")
        return True
    return stopped_any


def send_logoff_adapter(configured_path: str | Path, friendly_name: str) -> dict[str, object]:
    """Stop this app's keepalive and send exactly one fixed EAPOL-Logoff."""
    active = _active_keepalive_backend()
    if active == "npcap" and not NPCAP_BRIDGE_PATH.is_file():
        active = ""
    if active == "rawether" and not BRIDGE_PATH.is_file():
        active = ""
    backend = active or ("npcap" if NPCAP_BRIDGE_PATH.is_file() else "rawether")
    if backend == "npcap":
        from .npcap_backend import logoff
        return logoff(configured_path, friendly_name)
    result: dict[str, object] = {
        "logoff_test": True,
        "success": False,
        "target_adapter": friendly_name,
        "session_stopped": False,
        "adapter_opened": False,
        "adapter_closed": False,
        "address_query_status": -1,
        "send_status": -1,
        "frames_sent": 0,
    }
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行，未发送注销报文"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL，未发送注销报文"
        return result
    result["session_stopped"] = stop_private_session("manual-logout")
    if not result["session_stopped"]:
        result["message"] = "后台保活未能安全停止，未发送注销报文"
        return result
    try:
        completed = subprocess.run(
            [str(BRIDGE_PATH), "send-logoff", str(dll), _encode_local_name(friendly_name)],
            capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "EAPOL 注销辅助进程超时并已结束"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动受限的 EAPOL 注销"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    values: dict[str, str] = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {
                "OPENED", "CLOSED", "ADDRESS_QUERY", "SEND_STATUS", "FRAMES_SENT", "RESULT",
            }:
                values[key] = value
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            address_query_status=int(values.get("ADDRESS_QUERY", "-1")),
            send_status=int(values.get("SEND_STATUS", "-1")),
            frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 1)),
            bridge_exit_code=int(completed.returncode),
        )
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的注销结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    result["success"] = bool(
        before == after
        and completed.returncode == 0
        and result["adapter_opened"]
        and result["adapter_closed"]
        and result["address_query_status"] == 0
        and result["send_status"] == 0
        and result["frames_sent"] == 1
        and values.get("RESULT") == "LOGOFF_FINISHED"
    )
    if result["success"]:
        result["message"] = "已停止本程序保活并发送 1 个标准 EAPOL-Logoff"
    elif before != after:
        result["message"] = "注销前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 76:
        result["message"] = "目标网卡已打开，但固定 EAPOL-Logoff 发送失败"
    else:
        result["message"] = f"EAPOL 注销未完成（桥接器退出码 {completed.returncode}）"
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_amd64_pe(path: Path) -> bool:
    with path.open("rb") as handle:
        head = handle.read(4096)
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
    if pe_offset + 6 > len(head):
        return False
    return head[pe_offset:pe_offset + 4] == b"PE\0\0" and struct.unpack_from("<H", head, pe_offset + 4)[0] == 0x8664


class _SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("service_type", wintypes.DWORD),
        ("current_state", wintypes.DWORD),
        ("controls_accepted", wintypes.DWORD),
        ("win32_exit_code", wintypes.DWORD),
        ("service_specific_exit_code", wintypes.DWORD),
        ("check_point", wintypes.DWORD),
        ("wait_hint", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("service_flags", wintypes.DWORD),
    ]


def _service_state(name: str) -> str:
    if os.name != "nt":
        return "unsupported"
    advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi.OpenSCManagerW.restype = wintypes.HANDLE
    advapi.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi.OpenServiceW.restype = wintypes.HANDLE
    advapi.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    advapi.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    manager = advapi.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
    if not manager:
        return "unreadable"
    service = None
    try:
        service = advapi.OpenServiceW(manager, name, 0x0004)  # SERVICE_QUERY_STATUS
        if not service:
            return "missing" if ctypes.get_last_error() == 1060 else "unreadable"
        status = _SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        if not advapi.QueryServiceStatusEx(
            service, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)
        ):
            return "unreadable"
        return {1: "stopped", 2: "start-pending", 3: "stop-pending", 4: "running"}.get(
            int(status.current_state), "other"
        )
    finally:
        if service:
            advapi.CloseServiceHandle(service)
        advapi.CloseServiceHandle(manager)


def _candidate_dll(configured_path: str | Path) -> Path | None:
    raw = str(configured_path).strip().strip('"')
    if not raw:
        return None
    selected = Path(raw).expanduser()
    try:
        selected = selected.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    folder = selected if selected.is_dir() else selected.parent
    candidate = folder / DLL_NAME
    return candidate if candidate.is_file() else None


def _exports_present(path: Path) -> tuple[bool, list[str]]:
    if os.name != "nt":
        return False, list(EXPECTED_EXPORTS)
    library = ctypes.WinDLL(str(path))
    missing = [name for name in EXPECTED_EXPORTS if not hasattr(library, name)]
    del library
    return not missing, missing


def inspect(configured_path: str | Path = "") -> dict[str, object]:
    """Return redacted, read-only evidence about possible Rawether reuse."""
    report: dict[str, object] = {
        "mode": "read-only",
        "dll_name": DLL_NAME,
        "dll_found": False,
        "dll_hash_matches": False,
        "dll_architecture_matches": False,
        "exports_ready": False,
        "missing_exports": list(EXPECTED_EXPORTS),
        "driver_service": DRIVER_SERVICE,
        "driver_installed": False,
        "driver_hash_matches": False,
        "driver_state": _service_state(DRIVER_SERVICE),
        "reuse_candidate": False,
        "bridge_found": BRIDGE_PATH.is_file(),
        "bridge_ready": False,
    }
    if report["bridge_found"]:
        try:
            completed = subprocess.run(
                [str(BRIDGE_PATH), "selftest"], capture_output=True, timeout=10,
                creationflags=CREATE_NO_WINDOW, check=False,
            )
            report["bridge_ready"] = completed.returncode == 0
            report["bridge_sha256"] = _sha256(BRIDGE_PATH)
        except (OSError, subprocess.SubprocessError):
            pass
    dll = _candidate_dll(configured_path)
    if dll is not None:
        report["dll_found"] = True
        try:
            report["dll_hash_matches"] = _sha256(dll) == DLL_SHA256
            report["dll_architecture_matches"] = _is_amd64_pe(dll)
            if report["dll_hash_matches"] and report["dll_architecture_matches"]:
                report["exports_ready"], report["missing_exports"] = _exports_present(dll)
        except OSError:
            pass
    driver = SYSTEM32 / "drivers" / DRIVER_NAME
    if report["driver_state"] not in ("missing", "unsupported") and driver.is_file():
        report["driver_installed"] = True
        try:
            report["driver_hash_matches"] = _sha256(driver) == DRIVER_SHA256
        except OSError:
            pass
    report["reuse_candidate"] = all(
        report[key]
        for key in ("dll_found", "dll_hash_matches", "dll_architecture_matches", "exports_ready",
                    "driver_installed", "driver_hash_matches")
    )
    if report["reuse_candidate"] and report["bridge_ready"]:
        report["message"] = "已找到并核验 Rawether DLL、原始帧接口、PCASp50 驱动和隔离桥接器；尚未启动驱动或打开网卡"
    elif report["reuse_candidate"]:
        report["message"] = "Rawether 组件已核验，但隔离桥接器缺失或未通过兼容版本自检"
    elif not report["dll_found"]:
        report["message"] = "请先在主窗口选择当前机器上的官方锐捷客户端，才能定位 Rawether DLL"
    elif not report["dll_hash_matches"]:
        report["message"] = "Rawether DLL 与已核验的南医大 4.99 版本不一致，已拒绝加载"
    elif not report["driver_installed"]:
        report["message"] = "未找到 PCASp50 原始帧驱动"
    elif not report["driver_hash_matches"]:
        report["message"] = "PCASp50 驱动与安装包中的已核验版本不一致"
    else:
        report["message"] = "Rawether 组件不完整，尚不能进入适配器打开测试"
    return report


def _decode_local_name(value: str) -> str:
    if len(value) > 1024 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value):
        raise ValueError("invalid base64")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > 520:
        raise ValueError("adapter name too long")
    encodings = ("mbcs", locale.getpreferredencoding(False), "gb18030", "utf-8")
    for encoding in encodings:
        try:
            text = raw.decode(encoding)
            break
        except (LookupError, UnicodeDecodeError):
            continue
    else:
        text = raw.decode("utf-8", "replace")
    text = "".join(character for character in text if character >= " " and character != "\x7f").strip()
    return text[:260]


def _encode_local_name(value: str) -> str:
    for encoding in ("mbcs", locale.getpreferredencoding(False), "gb18030", "utf-8"):
        try:
            return base64.b64encode(value.encode(encoding)).decode("ascii")
        except (LookupError, UnicodeEncodeError):
            continue
    raise ValueError("adapter name cannot be encoded")


def _protocol_label(value: int, labels: dict[int, str]) -> str:
    if value < 0:
        return "NONE"
    return labels.get(value, f"OTHER_{value}")


def enumerate_adapters(configured_path: str | Path) -> dict[str, object]:
    """Enumerate adapter metadata without opening a packet adapter or sending frames."""
    readiness = inspect(configured_path)
    result: dict[str, object] = {
        "adapter_enumeration": True,
        "success": False,
        "adapters": [],
        "adapter_count": 0,
        "adapter_opened": False,
        "frames_read": 0,
        "frames_sent": 0,
    }
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；本步骤不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    try:
        completed = subprocess.run(
            [str(BRIDGE_PATH), "enumerate", str(dll)], capture_output=True, timeout=20,
            creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "Rawether 只读枚举超时；辅助进程已结束，未打开网卡或发送报文"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except OSError:
        result["message"] = "无法启动 Rawether 隔离桥接器"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    adapters: list[dict[str, object]] = []
    try:
        output = completed.stdout.decode("ascii", "strict")
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) != 5 or fields[0] != "ADAPTER":
                continue
            friendly_status, ndis_status = int(fields[1]), int(fields[2])
            ndis_bytes = base64.b64decode(fields[4], validate=True)
            friendly = _decode_local_name(fields[3]) if friendly_status == 0 else ""
            if friendly and ndis_status == 0:
                adapters.append({
                    "friendly_name": friendly,
                    "ndis_name_sha256": hashlib.sha256(ndis_bytes).hexdigest(),
                })
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的适配器信息"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    after = _service_state(DRIVER_SERVICE)
    result.update(
        adapters=adapters,
        adapter_count=len(adapters),
        bridge_exit_code=int(completed.returncode),
        driver_state_after=after,
    )
    if before != after:
        result["message"] = "枚举前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 0 and adapters:
        result["success"] = True
        result["message"] = "Rawether 已只读枚举到网卡；未打开网卡、读取或发送报文"
    elif completed.returncode == 69:
        result["message"] = "Rawether 没有枚举到可用网卡"
    elif completed.returncode == 66:
        result["message"] = "Rawether 协议发现会话无法打开，可能正被其他进程独占"
    else:
        result["message"] = f"Rawether 只读枚举未完成（桥接器退出码 {completed.returncode}）"
    return result


def open_close_adapter(configured_path: str | Path, friendly_name: str) -> dict[str, object]:
    """Open and immediately close one uniquely named adapter without reading or sending."""
    result: dict[str, object] = {
        "adapter_open_close": True,
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "frames_read": 0,
        "frames_sent": 0,
    }
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；本步骤不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    try:
        encoded_name = _encode_local_name(friendly_name)
        completed = subprocess.run(
            [str(BRIDGE_PATH), "open-close", str(dll), encoded_name],
            capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "打开并关闭网卡的辅助进程超时；进程已结束且没有读取或发送报文"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动 Rawether 网卡访问验证"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    try:
        lines = completed.stdout.decode("ascii", "strict").splitlines()
    except UnicodeError:
        lines = []
    result["adapter_opened"] = "OPENED\t1" in lines
    result["adapter_closed"] = "CLOSED\t1" in lines
    result["bridge_exit_code"] = int(completed.returncode)
    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    if before != after:
        result["message"] = "验证前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 0 and result["adapter_opened"] and result["adapter_closed"]:
        result["success"] = True
        result["message"] = "已准确打开并关闭目标有线网卡；没有读取或发送报文"
    elif completed.returncode == 71:
        result["message"] = "Rawether 中没有唯一匹配当前有线网卡的条目"
    elif completed.returncode == 72:
        result["message"] = "Rawether 找到了目标有线网卡，但无法打开网卡句柄"
    else:
        result["message"] = f"网卡访问验证未完成（桥接器退出码 {completed.returncode}）"
    return result


def receive_one_adapter(configured_path: str | Path, friendly_name: str) -> dict[str, object]:
    """Passively receive at most one frame, never sending or retaining packet bytes."""
    result: dict[str, object] = {
        "adapter_receive_one": True,
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "read_started": False,
        "eapol_filter_set": False,
        "ndis_packet_filter_set": False,
        "receive_slots": 0,
        "reads_posted": 0,
        "read_completed": False,
        "frame_received": False,
        "frame_class": "NONE",
        "frame_length": 0,
        "eapol_packet_type": "NONE",
        "eap_code": "NONE",
        "eap_identifier": -1,
        "eap_method": "NONE",
        "frames_read": 0,
        "frames_sent": 0,
    }
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；本步骤不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    try:
        encoded_name = _encode_local_name(friendly_name)
        completed = subprocess.run(
            [str(BRIDGE_PATH), "receive-one", str(dll), encoded_name, "60000"],
            capture_output=True, timeout=70, creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "被动读取辅助进程超时并已结束；没有发送报文"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动 Rawether 被动读取验证"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    values: dict[str, str] = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {
                "OPENED", "CLOSED", "NDIS_FILTER_SET", "FILTER_SET", "RECEIVE_SLOTS",
                "READ_POSTED", "READ_STARTED", "READ_COMPLETED", "FRAME_LENGTH",
                "FRAME_CLASS", "EAPOL_TYPE", "EAP_CODE", "EAP_IDENTIFIER", "EAP_TYPE",
                "FRAMES_READ", "FRAMES_SENT",
            }:
                values[key] = value
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            ndis_packet_filter_set=values.get("NDIS_FILTER_SET") == "1",
            eapol_filter_set=values.get("FILTER_SET") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            read_started=values.get("READ_STARTED") == "1",
            read_completed=values.get("READ_COMPLETED") == "1",
            frame_length=max(0, min(int(values.get("FRAME_LENGTH", "0")), 2048)),
            frame_class=values.get("FRAME_CLASS", "NONE")
            if values.get("FRAME_CLASS") in {"NONE", "EAPOL", "OTHER"} else "NONE",
            eapol_packet_type=_protocol_label(int(values.get("EAPOL_TYPE", "-1")), {
                0: "EAP_PACKET", 1: "START", 2: "LOGOFF", 3: "KEY", 4: "ASF_ALERT", 0xBF: "VENDOR_BF",
            }),
            eap_code=_protocol_label(int(values.get("EAP_CODE", "-1")), {
                1: "REQUEST", 2: "RESPONSE", 3: "SUCCESS", 4: "FAILURE",
            }),
            eap_identifier=max(-1, min(int(values.get("EAP_IDENTIFIER", "-1")), 255)),
            eap_method=_protocol_label(int(values.get("EAP_TYPE", "-1")), {
                1: "IDENTITY", 4: "MD5_CHALLENGE",
            }),
            frames_read=1 if values.get("FRAMES_READ") == "1" else 0,
            frames_sent=0,
        )
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的被动读取结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    result["frame_received"] = result["frames_read"] == 1
    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    if before != after:
        result["message"] = "读取前后驱动状态发生变化，结果已作废"
    elif int(completed.returncode) == 0 and result["adapter_opened"] and \
            result["adapter_closed"] and result["ndis_packet_filter_set"] and \
            result["eapol_filter_set"] and result["read_started"] and result["reads_posted"] > 0:
        result["success"] = True
        if result["frame_received"]:
            kind = "EAPOL" if result["frame_class"] == "EAPOL" else "非 EAPOL"
            result["message"] = f"被动读取成功，收到 1 个{kind}帧；没有发送报文"
        else:
            result["message"] = "EAPOL 被动读取接口已正常启动，等待 60 秒未收到报文；没有发送报文"
    elif int(completed.returncode) == 73:
        result["message"] = "目标网卡已打开，但 Rawether 被动读取请求无法启动"
    elif int(completed.returncode) == 74:
        result["message"] = "目标网卡已打开，但无法安装仅接收 EAPOL 的过滤规则"
    elif int(completed.returncode) == 75:
        result["message"] = "目标网卡已打开，但无法为临时句柄启用被动报文投递"
    else:
        result["message"] = f"被动读取验证未完成（桥接器退出码 {completed.returncode}）"
    result["bridge_exit_code"] = int(completed.returncode)
    return result


def send_start_adapter(configured_path: str | Path, friendly_name: str) -> dict[str, object]:
    """Send exactly one standard EAPOL-Start and wait for Request/Identity."""
    result: dict[str, object] = {
        "active_start_test": True,
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "ndis_packet_filter_set": False,
        "eapol_filter_set": False,
        "receive_slots": 0,
        "reads_posted": 0,
        "read_started": False,
        "identity_request_received": False,
        "frame_length": 0,
        "eap_identifier": -1,
        "frames_read": 0,
        "frames_sent": 0,
        "address_query_status": -1,
        "send_status": -1,
    }
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；主动测试不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    try:
        completed = subprocess.run(
            [str(BRIDGE_PATH), "send-start", str(dll), _encode_local_name(friendly_name), "8000"],
            capture_output=True, timeout=18, creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "EAPOL-Start 辅助进程超时并已结束"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动受限的 EAPOL-Start 测试"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    values: dict[str, str] = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {
                "OPENED", "CLOSED", "NDIS_FILTER_SET", "FILTER_SET", "RECEIVE_SLOTS",
                "READ_POSTED", "READ_STARTED", "FRAME_LENGTH", "FRAME_CLASS", "EAPOL_TYPE",
                "EAP_CODE", "EAP_IDENTIFIER", "EAP_TYPE", "ADDRESS_QUERY", "SEND_STATUS",
                "FRAMES_READ", "FRAMES_SENT",
            }:
                values[key] = value
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            ndis_packet_filter_set=values.get("NDIS_FILTER_SET") == "1",
            eapol_filter_set=values.get("FILTER_SET") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            read_started=values.get("READ_STARTED") == "1",
            frame_length=max(0, min(int(values.get("FRAME_LENGTH", "0")), 2048)),
            eap_identifier=max(-1, min(int(values.get("EAP_IDENTIFIER", "-1")), 255)),
            frames_read=1 if values.get("FRAMES_READ") == "1" else 0,
            frames_sent=1 if values.get("FRAMES_SENT") == "1" else 0,
            address_query_status=int(values.get("ADDRESS_QUERY", "-1")),
            send_status=int(values.get("SEND_STATUS", "-1")),
        )
        result["identity_request_received"] = (
            values.get("FRAME_CLASS") == "EAPOL" and values.get("EAPOL_TYPE") == "0" and
            values.get("EAP_CODE") == "1" and values.get("EAP_TYPE") == "1" and
            result["frames_read"] == 1
        )
        address_ok = values.get("ADDRESS_QUERY") == "0"
        send_ok = values.get("SEND_STATUS") == "0" and result["frames_sent"] == 1
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的主动测试结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    result["bridge_exit_code"] = int(completed.returncode)
    if before != after:
        result["message"] = "测试前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 0 and result["adapter_opened"] and result["adapter_closed"] and \
            result["ndis_packet_filter_set"] and result["eapol_filter_set"] and \
            result["read_started"] and address_ok and send_ok:
        result["success"] = result["identity_request_received"]
        result["message"] = (
            "已发送 1 个标准 EAPOL-Start，并收到 Request/Identity"
            if result["success"] else
            "已发送 1 个标准 EAPOL-Start，但 8 秒内未收到 Request/Identity"
        )
    elif completed.returncode == 76:
        result["message"] = "目标网卡已打开，但固定 EAPOL-Start 发送失败"
    else:
        result["message"] = f"EAPOL-Start 测试未完成（桥接器退出码 {completed.returncode}）"
    return result


def send_identity_probe_adapter(
    configured_path: str | Path, friendly_name: str, username: str
) -> dict[str, object]:
    """Send Start and one bare Identity response, then wait for MD5 Challenge."""
    result: dict[str, object] = {
        "identity_probe_test": True,
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "ndis_packet_filter_set": False,
        "eapol_filter_set": False,
        "receive_slots": 0,
        "reads_posted": 0,
        "read_started": False,
        "identity_request_received": False,
        "identity_response_sent": False,
        "md5_challenge_received": False,
        "identity_identifier": -1,
        "md5_identifier": -1,
        "frame_length": 0,
        "frames_read": 0,
        "frames_sent": 0,
        "address_query_status": -1,
        "start_send_status": -1,
        "identity_send_status": -1,
    }
    try:
        identity = username.encode("utf-8")
    except UnicodeError:
        result["message"] = "校园网账号无法编码，未发送任何报文"
        return result
    if not identity or len(identity) > 128 or b"\0" in identity:
        result["message"] = "校园网账号长度不适合 Identity 探测，未发送任何报文"
        return result
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；Identity 测试不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    try:
        completed = subprocess.run(
            [str(BRIDGE_PATH), "send-identity", str(dll), _encode_local_name(friendly_name), "10000"],
            input=base64.b64encode(identity) + b"\n",
            capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "Identity 探测辅助进程超时并已结束"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动受限的 Identity 探测"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    values: dict[str, str] = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {
                "OPENED", "CLOSED", "NDIS_FILTER_SET", "FILTER_SET", "RECEIVE_SLOTS",
                "READ_POSTED", "READ_STARTED", "FRAME_LENGTH", "ADDRESS_QUERY", "SEND_STATUS",
                "IDENTITY_RECEIVED", "IDENTITY_IDENTIFIER", "IDENTITY_SEND_STATUS",
                "MD5_RECEIVED", "MD5_IDENTIFIER", "FRAMES_READ", "FRAMES_SENT",
            }:
                values[key] = value
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            ndis_packet_filter_set=values.get("NDIS_FILTER_SET") == "1",
            eapol_filter_set=values.get("FILTER_SET") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            read_started=values.get("READ_STARTED") == "1",
            frame_length=max(0, min(int(values.get("FRAME_LENGTH", "0")), 2048)),
            frames_read=max(0, min(int(values.get("FRAMES_READ", "0")), 2)),
            frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 2)),
            address_query_status=int(values.get("ADDRESS_QUERY", "-1")),
            start_send_status=int(values.get("SEND_STATUS", "-1")),
            identity_send_status=int(values.get("IDENTITY_SEND_STATUS", "-1")),
            identity_identifier=max(-1, min(int(values.get("IDENTITY_IDENTIFIER", "-1")), 255)),
            md5_identifier=max(-1, min(int(values.get("MD5_IDENTIFIER", "-1")), 255)),
        )
        result["identity_request_received"] = values.get("IDENTITY_RECEIVED") == "1"
        result["identity_response_sent"] = (
            result["identity_send_status"] == 0 and result["frames_sent"] == 2
        )
        result["md5_challenge_received"] = values.get("MD5_RECEIVED") == "1"
        setup_ok = (
            values.get("ADDRESS_QUERY") == "0" and values.get("SEND_STATUS") == "0" and
            result["frames_sent"] >= 1
        )
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的 Identity 探测结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    result["bridge_exit_code"] = int(completed.returncode)
    if before != after:
        result["message"] = "测试前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 0 and result["adapter_opened"] and result["adapter_closed"] and \
            result["ndis_packet_filter_set"] and result["eapol_filter_set"] and \
            result["read_started"] and setup_ok:
        result["success"] = result["md5_challenge_received"]
        if result["success"]:
            result["message"] = "已发送 Start 和一次 Identity 响应，并收到 Request/MD5-Challenge"
        elif result["identity_response_sent"]:
            result["message"] = "已发送一次 Identity 响应，但 10 秒内未收到 MD5 Challenge"
        else:
            result["message"] = "已发送 Start，但未收到可用于回复的 Request/Identity"
    elif completed.returncode == 76:
        result["message"] = "Start 或 Identity 响应的底层发送失败"
    elif completed.returncode == 77:
        result["message"] = "辅助进程拒绝了 Identity 输入，未执行完整探测"
    else:
        result["message"] = f"Identity 探测未完成（桥接器退出码 {completed.returncode}）"
    return result


def send_md5_probe_adapter(
    configured_path: str | Path, friendly_name: str, username: str, password: str
) -> dict[str, object]:
    """Try one standard EAP-MD5 response without any Ruijie private extension."""
    result: dict[str, object] = {
        "md5_probe_test": True,
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "receive_slots": 0,
        "reads_posted": 0,
        "identity_request_received": False,
        "identity_response_sent": False,
        "md5_challenge_received": False,
        "md5_response_sent": False,
        "eap_result_received": False,
        "eap_result": "NONE",
        "identity_identifier": -1,
        "md5_identifier": -1,
        "result_identifier": -1,
        "frame_length": 0,
        "frames_read": 0,
        "frames_sent": 0,
        "start_send_status": -1,
        "identity_send_status": -1,
        "md5_send_status": -1,
    }
    try:
        identity = username.encode("utf-8")
        secret = password.encode("utf-8")
    except UnicodeError:
        result["message"] = "校园网凭据无法编码，未发送任何报文"
        return result
    if not identity or len(identity) > 128 or b"\0" in identity or \
            not secret or len(secret) > 512 or b"\0" in secret:
        result["message"] = "校园网凭据长度不适合 MD5 探测，未发送任何报文"
        return result
    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；MD5 测试不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result
    pipe_input = base64.b64encode(identity) + b"\n" + base64.b64encode(secret) + b"\n"
    try:
        completed = subprocess.run(
            [str(BRIDGE_PATH), "send-md5", str(dll), _encode_local_name(friendly_name), "12000"],
            input=pipe_input, capture_output=True, timeout=22,
            creationflags=CREATE_NO_WINDOW, check=False,
        )
    except subprocess.TimeoutExpired:
        result["message"] = "标准 MD5 探测辅助进程超时并已结束"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, ValueError):
        result["message"] = "无法启动受限的标准 MD5 探测"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    finally:
        pipe_input = b""
        secret = b""

    values: dict[str, str] = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {
                "OPENED", "CLOSED", "NDIS_FILTER_SET", "FILTER_SET", "RECEIVE_SLOTS",
                "READ_POSTED", "READ_STARTED", "FRAME_LENGTH", "ADDRESS_QUERY", "SEND_STATUS",
                "IDENTITY_RECEIVED", "IDENTITY_IDENTIFIER", "IDENTITY_SEND_STATUS",
                "MD5_RECEIVED", "MD5_IDENTIFIER", "MD5_SEND_STATUS", "RESULT_RECEIVED",
                "RESULT_CODE", "RESULT_IDENTIFIER", "FRAMES_READ", "FRAMES_SENT",
            }:
                values[key] = value
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            ndis_packet_filter_set=values.get("NDIS_FILTER_SET") == "1",
            eapol_filter_set=values.get("FILTER_SET") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            read_started=values.get("READ_STARTED") == "1",
            frame_length=max(0, min(int(values.get("FRAME_LENGTH", "0")), 2048)),
            frames_read=max(0, min(int(values.get("FRAMES_READ", "0")), 3)),
            frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 3)),
            address_query_status=int(values.get("ADDRESS_QUERY", "-1")),
            start_send_status=int(values.get("SEND_STATUS", "-1")),
            identity_send_status=int(values.get("IDENTITY_SEND_STATUS", "-1")),
            md5_send_status=int(values.get("MD5_SEND_STATUS", "-1")),
            identity_identifier=max(-1, min(int(values.get("IDENTITY_IDENTIFIER", "-1")), 255)),
            md5_identifier=max(-1, min(int(values.get("MD5_IDENTIFIER", "-1")), 255)),
            result_identifier=max(-1, min(int(values.get("RESULT_IDENTIFIER", "-1")), 255)),
        )
        result["identity_request_received"] = values.get("IDENTITY_RECEIVED") == "1"
        result["identity_response_sent"] = result["identity_send_status"] == 0 and result["frames_sent"] >= 2
        result["md5_challenge_received"] = values.get("MD5_RECEIVED") == "1"
        result["md5_response_sent"] = result["md5_send_status"] == 0 and result["frames_sent"] == 3
        result["eap_result_received"] = values.get("RESULT_RECEIVED") == "1"
        result["eap_result"] = {"3": "SUCCESS", "4": "FAILURE"}.get(
            values.get("RESULT_CODE", ""), "NONE"
        )
        setup_ok = (
            values.get("ADDRESS_QUERY") == "0" and values.get("SEND_STATUS") == "0" and
            result["frames_sent"] >= 1
        )
    except (UnicodeError, ValueError):
        result["message"] = "Rawether 桥接器返回了无法校验的标准 MD5 探测结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    result["bridge_exit_code"] = int(completed.returncode)
    if before != after:
        result["message"] = "测试前后驱动状态发生变化，结果已作废"
    elif completed.returncode == 0 and result["adapter_opened"] and result["adapter_closed"] and \
            result["ndis_packet_filter_set"] and result["eapol_filter_set"] and \
            result["read_started"] and setup_ok:
        result["success"] = result["eap_result"] == "SUCCESS"
        if result["success"]:
            result["message"] = "标准 EAP-MD5 响应已收到 Success；本测试未发送锐捷私有扩展或保活"
        elif result["eap_result"] == "FAILURE":
            result["message"] = "标准 EAP-MD5 响应收到 Failure；服务器可能要求锐捷私有扩展"
        elif result["md5_response_sent"]:
            result["message"] = "已发送一次标准 EAP-MD5 响应，但 12 秒内未收到 Success/Failure"
        elif result["identity_response_sent"]:
            result["message"] = "已发送 Identity 响应，但未收到可用于回复的 MD5 Challenge"
        else:
            result["message"] = "已发送 Start，但未收到可用于回复的 Request/Identity"
    elif completed.returncode == 76:
        result["message"] = "Start、Identity 或 MD5 响应的底层发送失败"
    elif completed.returncode == 77:
        result["message"] = "辅助进程拒绝了凭据输入，未执行完整探测"
    else:
        result["message"] = f"标准 MD5 探测未完成（桥接器退出码 {completed.returncode}）"
    return result


def _adapter_ipv4_configuration(interface_name: str) -> dict[str, object]:
    """Read the selected adapter's current addressing without changing it."""
    if not interface_name or any(ord(character) < 32 for character in interface_name):
        raise RuntimeError("目标有线网卡名称无效")
    address_result = subprocess.run(
        [str(SYSTEM32 / "netsh.exe"), "interface", "ipv4", "show", "addresses",
         f"name={interface_name}"],
        capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW, check=False,
    )
    dns_result = subprocess.run(
        [str(SYSTEM32 / "netsh.exe"), "interface", "ipv4", "show", "dnsservers",
         f"name={interface_name}"],
        capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW, check=False,
    )
    if address_result.returncode or dns_result.returncode:
        raise RuntimeError("无法读取目标有线网卡的 IPv4 参数")
    def decode(value: bytes) -> str:
        for encoding in (locale.getpreferredencoding(False), "gb18030", "utf-8"):
            try:
                return value.decode(encoding)
            except (LookupError, UnicodeError):
                continue
        raise UnicodeError
    try:
        address_text = decode(address_result.stdout)
        dns_text = decode(dns_result.stdout)
        ip_match = next((re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                         for line in address_text.splitlines()
                         if re.search(r"(?i)IP\s*(?:Address|地址)", line)), None)
        mask_match = next((re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
                           for line in address_text.splitlines()
                           if re.search(r"(?i)Subnet\s*Prefix|子网.*前缀", line)), [])
        gateway_match = next((re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                              for line in address_text.splitlines()
                              if re.search(r"(?i)Default\s*Gateway|默认网关", line)), None)
        dns_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", dns_text)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"
        mask = mask_match[-1] if mask_match else "0.0.0.0"
        gateway = gateway_match.group(1) if gateway_match else "0.0.0.0"
        dns = dns_match.group(1) if dns_match else "0.0.0.0"
        for value in (ip, gateway, dns):
            ipaddress.IPv4Address(value)
        ipaddress.IPv4Address(mask)
        dhcp_line = next((line for line in address_text.splitlines() if "DHCP" in line.upper()), "")
        dhcp = bool(re.search(r"(?i)\bYes\b|启用|是", dhcp_line))
    except (UnicodeError, ValueError, TypeError, AttributeError):
        raise RuntimeError("目标有线网卡返回了无效的 IPv4 参数") from None
    return {
        "ip": ip,
        "mask": mask,
        "gateway": gateway,
        "dns": dns,
        "dhcp": dhcp,
    }


def send_private_md5_probe_adapter(
    configured_path: str | Path, friendly_name: str, username: str, password: str,
    interface_name: str = "", *, persistent_session: bool = False,
    backend: str | None = None,
) -> dict[str, object]:
    """Authenticate once; optionally leave a constrained keepalive bridge running.

    ``backend`` selects the raw-frame backend explicitly ("npcap" or
    "rawether").  Without it the legacy configured default is used.
    """
    selected = backend or native_backend()
    if selected == "npcap":
        from .npcap_backend import login
        result = login(configured_path, friendly_name, username, password,
                       interface_name, persistent_session=persistent_session)
        result.setdefault("native_backend", "npcap")
        return result
    result: dict[str, object] = {
        "private_md5_probe_test": True,
        "native_backend": "rawether",
        "success": False,
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
        "receive_slots": 0,
        "reads_posted": 0,
        "identity_request_received": False,
        "identity_response_sent": False,
        "md5_challenge_received": False,
        "md5_response_sent": False,
        "private_extension_sent": False,
        "echo_frames_prepared": False,
        "echo_frames_sent": 0,
        "connectivity_probe_attempted": False,
        "connectivity_succeeded": False,
        "persistent_session_requested": bool(persistent_session),
        "session_started": False,
        "v4_branch": -1,
        "eap_result": "NONE",
        "md5_identifier": -1,
        "result_identifier": -1,
        "frame_length": 0,
        "frames_read": 0,
        "frames_sent": 0,
    }
    try:
        identity = username.encode("utf-8")
        secret = password.encode("utf-8")
    except UnicodeError:
        result["message"] = "校园网凭据无法编码，未发送任何报文"
        return result
    if not identity or len(identity) > 128 or b"\0" in identity or \
            not secret or len(secret) > 512 or b"\0" in secret:
        result["message"] = "校园网凭据长度不适合锐捷认证，未发送任何报文"
        return result

    readiness = inspect(configured_path)
    if not readiness.get("reuse_candidate") or not readiness.get("bridge_ready"):
        result["message"] = readiness.get("message", "Rawether 接入条件尚未就绪")
        return result
    before = _service_state(DRIVER_SERVICE)
    result["driver_state_before"] = before
    if before != "running":
        result["message"] = "PCASp50 驱动当前未运行；锐捷认证测试不会代替官方组件启动驱动"
        return result
    dll = _candidate_dll(configured_path)
    if dll is None or _sha256(dll) != DLL_SHA256:
        result["message"] = "无法定位已核验的 Rawether DLL"
        return result

    try:
        from .config import APP_DIR, load_config
        from .probe import connectivity_probe
        from .ruijie import resolve_installation
        from .ruijie_protocol import (
            PROFILE_PATH_NAME, echo_frame, echo_key, load_profile, prepare_extension, v4_check_type,
        )
        from .ruijie_profiles import builtin_profile_for_client
        installation = resolve_installation(configured_path)
        profile_path = APP_DIR / PROFILE_PATH_NAME
        profile = builtin_profile_for_client(str(getattr(installation, "worker_sha256", "")))
        if profile is None:
            if not profile_path.is_file():
                result["message"] = "当前锐捷客户端版本尚未纳入支持列表，未发送任何报文"
                return result
            profile = load_profile(profile_path.read_text(encoding="utf-8"))
        network = _adapter_ipv4_configuration(interface_name)
        settings = load_config()
    except (OSError, RuntimeError) as error:
        result["message"] = str(error)
        return result

    process = None
    keep_process = False
    output_lines: list[str] = []
    pipe_input = base64.b64encode(identity) + b"\n" + base64.b64encode(secret) + b"\n"
    try:
        if persistent_session:
            stop_private_session("new-native-session")
            time.sleep(3)
        process = subprocess.Popen(
            [str(BRIDGE_PATH), "run-private-session" if persistent_session else "send-private-md5",
             str(dll), _encode_local_name(friendly_name), "15000"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        if process.stdin is None or process.stdout is None:
            raise OSError
        process.stdin.write(pipe_input)
        process.stdin.flush()
        private_request_seen = False
        while True:
            raw_line = process.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("ascii", "strict").rstrip("\r\n")
            fields = line.split("\t")
            if len(fields) == 3 and fields[0] == "PRIVATE_REQUEST":
                challenge = base64.b64decode(fields[1], validate=True)
                mac = base64.b64decode(fields[2], validate=True)
                extension = prepare_extension(
                    profile, challenge, installation.worker, identity, secret, mac,
                    str(network["ip"]), str(network["mask"]), str(network["gateway"]),
                    str(network["dns"]), bool(network["dhcp"]),
                )
                result["v4_branch"] = v4_check_type(challenge)
                process.stdin.write(base64.b64encode(extension) + b"\n")
                process.stdin.flush()
                private_request_seen = True
                challenge = mac = extension = b""
            elif len(fields) == 2 and fields[0] == "PRIVATE_SUCCESS_FRAME":
                success_frame = base64.b64decode(fields[1], validate=True)
                key = echo_key(success_frame)
                first_echo = echo_frame(
                    profile, success_frame[:6], success_frame[6:12], key, 0x102B
                )
                process.stdin.write(base64.b64encode(first_echo) + b"\n")
                if not persistent_session:
                    second_echo = echo_frame(
                        profile, success_frame[:6], success_frame[6:12], key, 0x102C
                    )
                    process.stdin.write(base64.b64encode(second_echo) + b"\n")
                else:
                    second_echo = b""
                process.stdin.flush()
                result["echo_frames_prepared"] = True
                result["eap_result"] = "SUCCESS"
                success_frame = first_echo = second_echo = b""
                key = 0
            elif len(fields) == 3 and fields[0] == "ECHO_SEND_STATUS":
                output_lines.append(line)
                if fields[1] == "1" and fields[2] == "0":
                    result["connectivity_probe_attempted"] = True
                    try:
                        current_network = _adapter_ipv4_configuration(interface_name)
                        current_ip = str(current_network["ip"])
                        if current_ip != "0.0.0.0":
                            online, source = connectivity_probe(
                                current_ip,
                                settings.portal.check_url,
                                settings.portal.success_text,
                                settings.portal.secondary_check_url,
                            )
                            result["connectivity_succeeded"] = bool(online)
                            result["connectivity_source"] = source if online else ""
                    except (OSError, RuntimeError, ValueError):
                        pass
            elif len(fields) == 2 and fields[0] == "SESSION_READY" and persistent_session:
                output_lines.append(line)
                result["session_process_id"] = max(0, int(fields[1]))
                deadline = time.monotonic() + 30
                while not result["connectivity_succeeded"] and time.monotonic() < deadline:
                    result["connectivity_probe_attempted"] = True
                    try:
                        current_network = _adapter_ipv4_configuration(interface_name)
                        current_ip = str(current_network["ip"])
                        if current_ip != "0.0.0.0":
                            online, source = connectivity_probe(
                                current_ip,
                                settings.portal.check_url,
                                settings.portal.success_text,
                                settings.portal.secondary_check_url,
                            )
                            result["connectivity_succeeded"] = bool(online)
                            result["connectivity_source"] = source if online else ""
                    except (OSError, RuntimeError, ValueError):
                        pass
                    if not result["connectivity_succeeded"]:
                        time.sleep(3)
                if result["connectivity_succeeded"]:
                    result["session_started"] = True
                    result["echo_frames_sent"] = max(1, int(result["echo_frames_sent"]))
                    keep_process = True
                    break
                stop_private_session("verification-failed")
                break
            else:
                output_lines.append(line)
        if not keep_process:
            process.wait(timeout=8)
        if not private_request_seen and process.returncode == 0:
            result["message"] = "本轮没有收到可用于生成锐捷扩展的 MD5 Challenge"
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            process.wait(timeout=3)
        result["message"] = "锐捷扩展认证辅助进程超时并已结束"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        result["message"] = str(error) if str(error) else "无法完成锐捷扩展认证测试"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result
    finally:
        pipe_input = identity = secret = b""
        if process is not None:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()

    values: dict[str, str] = {}
    echo_statuses: dict[str, str] = {}
    for line in output_lines:
        fields = line.split("\t")
        if len(fields) == 3 and fields[0] == "ECHO_SEND_STATUS" and fields[1] in {"1", "2"}:
            echo_statuses[fields[1]] = fields[2]
            continue
        key, separator, value = line.partition("\t")
        if separator and key in {
            "OPENED", "CLOSED", "NDIS_FILTER_SET", "FILTER_SET", "RECEIVE_SLOTS",
            "READ_POSTED", "READ_STARTED", "FRAME_LENGTH", "ADDRESS_QUERY", "SEND_STATUS",
            "IDENTITY_RECEIVED", "IDENTITY_SEND_STATUS", "MD5_RECEIVED", "MD5_IDENTIFIER",
            "MD5_SEND_STATUS", "PRIVATE_EXTENSION_ACCEPTED", "RESULT_RECEIVED", "RESULT_CODE",
            "RESULT_IDENTIFIER", "ECHO_FRAMES_SENT", "FRAMES_READ", "FRAMES_SENT",
        }:
            values[key] = value
    try:
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            frame_length=max(0, min(int(values.get("FRAME_LENGTH", "0")), 2048)),
            frames_read=max(0, min(int(values.get("FRAMES_READ", "0")), 3)),
            frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 5)),
            echo_frames_sent=(
                1 if keep_process else
                max(0, min(int(values.get("ECHO_FRAMES_SENT", "0")), 2))
            ),
            md5_identifier=max(-1, min(int(values.get("MD5_IDENTIFIER", "-1")), 255)),
            result_identifier=max(-1, min(int(values.get("RESULT_IDENTIFIER", "-1")), 255)),
        )
        result["identity_request_received"] = values.get("IDENTITY_RECEIVED") == "1"
        result["identity_response_sent"] = values.get("IDENTITY_SEND_STATUS") == "0"
        result["md5_challenge_received"] = values.get("MD5_RECEIVED") == "1"
        result["private_extension_sent"] = values.get("PRIVATE_EXTENSION_ACCEPTED") == "1" and \
            values.get("MD5_SEND_STATUS") == "0"
        result["md5_response_sent"] = result["private_extension_sent"]
        result["eap_result"] = {"3": "SUCCESS", "4": "FAILURE"}.get(
            values.get("RESULT_CODE", ""), "NONE"
        )
        result["first_echo_sent"] = echo_statuses.get("1") == "0"
        result["second_echo_sent"] = echo_statuses.get("2") == "0"
    except ValueError:
        result["message"] = "Rawether 桥接器返回了无法校验的锐捷认证结果"
        result["driver_state_after"] = _service_state(DRIVER_SERVICE)
        return result

    after = _service_state(DRIVER_SERVICE)
    result["driver_state_after"] = after
    result["bridge_exit_code"] = None if keep_process else int(process.returncode)
    if before != after:
        result["message"] = "测试前后驱动状态发生变化，结果已作废"
    elif keep_process and result["session_started"] and result["connectivity_succeeded"]:
        result["success"] = True
        result["message"] = "锐捷认证成功，后台持续保活已启动，真实联网验证成功"
    elif process.returncode == 0 and result["adapter_opened"] and result["adapter_closed"]:
        result["success"] = result["eap_result"] == "SUCCESS"
        if result["success"] and result["echo_frames_sent"] >= 2 and result["connectivity_succeeded"]:
            result["message"] = "锐捷认证成功，两个保活均已发送，真实联网验证成功"
        elif result["success"] and result["echo_frames_sent"] >= 1:
            result["message"] = "锐捷认证成功并已发送保活，但真实联网验证尚未成功"
        elif result["success"]:
            result["message"] = "锐捷私有扩展认证成功，但本轮没有完成保活发送"
        elif result["eap_result"] == "FAILURE":
            result["message"] = "锐捷私有扩展响应已发送，但服务器返回 Failure"
        elif result["private_extension_sent"]:
            result["message"] = "锐捷私有扩展响应已发送，但 15 秒内未收到 Success/Failure"
        elif result["identity_response_sent"]:
            result["message"] = "已发送 Identity 响应，但未完成锐捷私有扩展响应"
        else:
            result["message"] = "已发送 Start，但未收到可用于回复的 Request/Identity"
    elif process.returncode == 76:
        result["message"] = "Start、Identity 或锐捷扩展响应的底层发送失败"
    elif process.returncode == 77:
        result["message"] = "辅助进程拒绝了认证输入，未执行完整测试"
    else:
        result["message"] = f"锐捷扩展认证未完成（桥接器退出码 {process.returncode}）"
    return result
