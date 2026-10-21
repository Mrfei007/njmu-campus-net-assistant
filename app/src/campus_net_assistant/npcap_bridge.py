#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NpcapBridge —— 与 RawetherBridge 同协议的 Npcap 版桥接器（控制台程序）。

设计目标：**对 Python 主程序完全透明**。rawether.py 通过 stdin/stdout 的
行协议驱动它，因此主程序那套解析、限频、状态机、界面都不需要改，
只是把"原始帧收发"从 PCAUSA Rawether 换成 Npcap。

支持的模式（与 C# 版同参数形状）
--------------------------------
  selftest                                  自检，成功退出码 0
  send-private-md5  <path> <adapter_b64> <timeout_ms>
  run-private-session <path> <adapter_b64> <timeout_ms>
  send-logoff       <path> <adapter_b64>
  stop-private-session

stdout 行协议（与 C# 版一致）
-----------------------------
  OPENED / CLOSED / NDIS_FILTER_SET / FILTER_SET
  RECEIVE_SLOTS / READ_POSTED / READ_STARTED
  ADDRESS_QUERY / SEND_STATUS
  IDENTITY_RECEIVED / IDENTITY_SEND_STATUS
  MD5_RECEIVED / MD5_IDENTIFIER / MD5_SEND_STATUS
  PRIVATE_EXTENSION_ACCEPTED
  PRIVATE_REQUEST\t<b64 challenge>\t<b64 mac>
  PRIVATE_SUCCESS_FRAME\t<b64 success frame>
  RESULT_RECEIVED / RESULT_CODE / RESULT_IDENTIFIER / FRAME_LENGTH
  ECHO_SEND_STATUS\t<1|2>\t<status>
  ECHO_FRAMES_SENT / FRAMES_READ / FRAMES_SENT
  SESSION_READY\t<pid>

退出码（沿用 C# 版语义）
------------------------
  0  正常；63 自检失败；64 参数错误；73/74/75 读取/过滤失败；
  76 发送失败；78 会话已存在；79/80 停止事件异常。

安全边界
--------
* 只操作自己打开的 Npcap 句柄，不改网卡配置、不安装/卸载驱动、不碰锐捷文件。
* 不记录报文内容、账号、密码、密钥；遥测只写状态与计数。
"""

from __future__ import annotations

import base64
import ctypes
import json
import locale
import os
import sys
import threading
import time
import traceback
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

APP_INTERNAL_NAME = "NJMUCampusNetAssistant"
SESSION_MUTEX_NAME = r"Local\NJMUCampusNetAssistant-RuijieSession"
SESSION_STOP_EVENT_NAME = r"Local\NJMUCampusNetAssistant-RuijieSessionStop"
KEEPALIVE_SECONDS = 30
EAPOL_ETHERTYPE = 0x888E
PAE_GROUP = bytes.fromhex("0180c2000003")
SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
WPCAP_CANDIDATES = [
    SYSTEM_ROOT / "System32" / "Npcap" / "wpcap.dll",
    SYSTEM_ROOT / "System32" / "wpcap.dll",
    Path(r"C:\Program Files\Npcap\wpcap.dll"),
]
TELEMETRY_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / APP_INTERNAL_NAME
STATE_PATH = TELEMETRY_DIR / "native-keepalive-state.json"
DIAG_DIR = TELEMETRY_DIR / "diagnostics"


# ---------------------------------------------------------------- 网卡链路状态

class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", ctypes.c_uint),
]

_IPHLPAPI = ctypes.WinDLL("iphlpapi", use_last_error=True)
_IPHLPAPI.GetAdaptersAddresses.argtypes = [
    wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(wintypes.ULONG),
]
_IPHLPAPI.GetAdaptersAddresses.restype = wintypes.ULONG

AF_UNSPEC = 0
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
ERROR_BUFFER_OVERFLOW = 111
IF_OPER_STATUS_UP = 1


def adapter_oper_status(description: str):
    """返回该网卡的 IF_OPER_STATUS；找不到返回 None。"""
    if not description:
        return None
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = wintypes.ULONG(16384)
    buffer = ctypes.create_string_buffer(size.value)
    result = _IPHLPAPI.GetAdaptersAddresses(AF_UNSPEC, flags, None, buffer,
                                            ctypes.byref(size))
    if result == ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(size.value)
        result = _IPHLPAPI.GetAdaptersAddresses(AF_UNSPEC, flags, None, buffer,
                                                ctypes.byref(size))
    if result != 0:
        return None
    wanted = description.casefold()
    node = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
    while node:
        item = node.contents
        friendly = item.FriendlyName or ""
        native = item.Description or ""
        if wanted and (wanted in friendly.casefold() or wanted in native.casefold()):
            return int(item.OperStatus)
        node = item.Next
    return None


def adapter_link_up(description: str):
    """True=链路 up，False=链路已断（网线拔出/网卡禁用），None=取不到。"""
    status = adapter_oper_status(description)
    if status is None:
        return None
    return status == IF_OPER_STATUS_UP


def out(line: str) -> None:
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def read_line() -> str:
    try:
        value = sys.stdin.readline()
    except Exception:
        return ""
    return value.strip()


# ---------------------------------------------------------------- Win32 同步对象

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
kernel32.ReleaseMutex.restype = wintypes.BOOL

EVENT_MODIFY_STATE = 0x0002
WAIT_OBJECT_0 = 0x00000000
ERROR_ALREADY_EXISTS = 183
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102

# 状态文件契约：1.5.x 为 1，1.6 起为 2（新增真实创建时间、心跳序号、桥哈希）。
BRIDGE_SCHEMA_VERSION = 2
EXIT_SESSION_ALREADY_ACTIVE = 78
EXIT_SESSION_MUTEX_UNAVAILABLE = 80

kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
kernel32.GetProcessTimes.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL


def process_created_at() -> str:
    """真实进程创建时间（UTC ISO）；空串表示查询失败。

    与"开始保活"时刻不同：后者取在网卡打开完成之后，比真实创建时间晚 1~3 秒。
    读取端用本字段做 PID 复用校验，两者混用会误判活进程为"已退出"。
    """
    try:
        values = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(kernel32.GetCurrentProcess(),
                                       *(ctypes.byref(value) for value in values)):
            return ""
        ticks = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
        seconds = ticks / 10_000_000 - 11644473600
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    except (OSError, AttributeError, ValueError, OverflowError):
        return ""


def process_image_path() -> str:
    """当前进程的可执行文件完整路径；空串表示查询失败。"""
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(kernel32.GetCurrentProcess(), 0,
                                                   buffer, ctypes.byref(size)):
            return ""
        return buffer.value
    except (OSError, AttributeError):
        return ""


def self_sha256() -> str:
    """桥自身文件哈希；用于远程确认"这台机器跑的是哪个桥"。"""
    try:
        path = process_image_path()
        if not path or not os.path.isfile(path):
            return ""
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ImportError):
        return ""


# ---------------------------------------------------------------- Npcap 绑定

class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [
    ("next", ctypes.POINTER(pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", wintypes.LONG), ("tv_usec", wintypes.LONG)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class Pcap:
    def __init__(self):
        self.dll = None
        self.handle = None

    def load(self) -> bool:
        for path in WPCAP_CANDIDATES:
            if not path.is_file():
                continue
            directory = str(path.parent)
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(directory)
                except Exception:
                    pass
            os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")
            try:
                self.dll = ctypes.WinDLL(str(path))
            except OSError:
                continue
            return self._bind()
        return False

    def _bind(self) -> bool:
        dll = self.dll
        try:
            dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p]
            dll.pcap_findalldevs.restype = ctypes.c_int
            dll.pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
            dll.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_char_p]
            dll.pcap_open_live.restype = ctypes.c_void_p
            dll.pcap_close.argtypes = [ctypes.c_void_p]
            dll.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program),
                                         ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
            dll.pcap_compile.restype = ctypes.c_int
            dll.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program)]
            dll.pcap_setfilter.restype = ctypes.c_int
            dll.pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]
            dll.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
            dll.pcap_sendpacket.restype = ctypes.c_int
            dll.pcap_next_ex.argtypes = [ctypes.c_void_p,
                                         ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                                         ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
            dll.pcap_next_ex.restype = ctypes.c_int
            dll.pcap_geterr.argtypes = [ctypes.c_void_p]
            dll.pcap_geterr.restype = ctypes.c_char_p
            return True
        except Exception:
            return False

    def list_devices(self):
        errbuf = ctypes.create_string_buffer(256)
        head = ctypes.POINTER(pcap_if)()
        if self.dll.pcap_findalldevs(ctypes.byref(head), errbuf) != 0:
            return []
        devices = []
        try:
            node = head
            while node:
                item = node.contents
                name = item.name.decode("utf-8", "replace") if item.name else ""
                description = item.description.decode("utf-8", "replace") if item.description else ""
                devices.append((name, description))
                node = item.next
        finally:
            self.dll.pcap_freealldevs(head)
        return devices

    def open(self, device_name: str) -> bool:
        errbuf = ctypes.create_string_buffer(256)
        self.handle = self.dll.pcap_open_live(device_name.encode("utf-8"), 65535, 1, 1000, errbuf)
        return bool(self.handle)

    def set_eapol_filter(self) -> bool:
        program = bpf_program()
        if self.dll.pcap_compile(self.handle, ctypes.byref(program),
                                 b"ether proto 0x888e", 1, 0xFFFFFFFF) != 0:
            return False
        try:
            return self.dll.pcap_setfilter(self.handle, ctypes.byref(program)) == 0
        finally:
            self.dll.pcap_freecode(ctypes.byref(program))

    def send(self, frame: bytes) -> int:
        if not self.handle:
            return 6
        buffer = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        return int(self.dll.pcap_sendpacket(self.handle, buffer, len(frame)))

    def next_frame(self, timeout_ms: int = 1000):
        header = ctypes.POINTER(pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        deadline = time.monotonic() + max(1, timeout_ms) / 1000.0
        while time.monotonic() < deadline:
            result = self.dll.pcap_next_ex(self.handle, ctypes.byref(header), ctypes.byref(data))
            if result == 1:
                return ctypes.string_at(data, int(header.contents.caplen))
            if result == 0:
                continue
            return None
        return None

    def close(self) -> None:
        if self.handle:
            self.dll.pcap_close(self.handle)
            self.handle = None


# ---------------------------------------------------------------- 以太帧工具

def eapol_offset(frame: bytes) -> int:
    if len(frame) < 14:
        return -1
    ethertype = (frame[12] << 8) | frame[13]
    if ethertype in (0x8100, 0x88A8) and len(frame) >= 18:
        ethertype = (frame[16] << 8) | frame[17]
        return 18 if ethertype == EAPOL_ETHERTYPE else -1
    return 14 if ethertype == EAPOL_ETHERTYPE else -1


def eapol_type(frame: bytes) -> int:
    offset = eapol_offset(frame)
    return frame[offset + 1] if offset >= 0 and len(frame) > offset + 1 else -1


def is_identity_request(frame: bytes) -> bool:
    offset = eapol_offset(frame)
    if offset < 0 or len(frame) < offset + 9:
        return False
    body = (frame[offset + 2] << 8) | frame[offset + 3]
    return (frame[offset + 1] == 0 and body >= 5
            and frame[offset + 4] == 1 and frame[offset + 8] == 1)


def is_md5_request(frame: bytes) -> bool:
    offset = eapol_offset(frame)
    if offset < 0 or len(frame) < offset + 26:
        return False
    body = (frame[offset + 2] << 8) | frame[offset + 3]
    eap_length = (frame[offset + 6] << 8) | frame[offset + 7]
    return (frame[offset + 1] == 0 and body >= 22 and 22 <= eap_length <= body
            and frame[offset + 4] == 1 and frame[offset + 8] == 4 and frame[offset + 9] == 16)


def request_identifier(frame: bytes) -> int:
    offset = eapol_offset(frame)
    return frame[offset + 5] if offset >= 0 and len(frame) > offset + 5 else -1


def eap_result_code(frame: bytes) -> int:
    offset = eapol_offset(frame)
    if offset < 0 or len(frame) < offset + 8:
        return -1
    body = (frame[offset + 2] << 8) | frame[offset + 3]
    eap_length = (frame[offset + 6] << 8) | frame[offset + 7]
    if frame[offset + 1] != 0 or body < 4 or not 4 <= eap_length <= body:
        return -1
    return frame[offset + 4]


def build_start(source: bytes) -> bytes:
    return PAE_GROUP + source + b"\x88\x8e\x01\x01\x00\x00"


def build_logoff(source: bytes) -> bytes:
    return PAE_GROUP + source + b"\x88\x8e\x01\x02\x00\x00"


def build_identity_response(source: bytes, destination: bytes, identifier: int,
                            identity: bytes) -> bytes:
    eap_length = 5 + len(identity)
    eap = bytes([2, identifier]) + eap_length.to_bytes(2, "big") + b"\x01" + identity
    return destination + source + b"\x88\x8e\x01\x00" + len(eap).to_bytes(2, "big") + eap


def build_md5_response(source: bytes, destination: bytes, identifier: int,
                       identity: bytes, digest: bytes, extension: bytes) -> bytes:
    eap_length = 6 + len(digest) + len(identity)
    eap = (bytes([2, identifier]) + eap_length.to_bytes(2, "big")
           + b"\x04\x10" + digest + identity)
    return (destination + source + b"\x88\x8e\x01\x00"
            + len(eap).to_bytes(2, "big") + eap + extension)


def reverse_complement(value: int) -> int:
    reversed_bits = int(f"{value:08b}"[::-1], 2)
    return reversed_bits ^ 0xFF


def increment_encoded_uint32(frame: bytearray, offset: int) -> None:
    value = 0
    for index in range(4):
        value = (value << 8) | reverse_complement(frame[offset + index])
    value = (value + 1) & 0xFFFFFFFF
    for index in range(3, -1, -1):
        frame[offset + index] = reverse_complement(value & 0xFF)
        value >>= 8


# ---------------------------------------------------------------- 遥测

class Telemetry:
    def __init__(self, adapter: str):
        self.active = False
        self.adapter = adapter
        self.session = str(uuid.uuid4())
        self.state = "authenticating"
        self.sends = 0
        self.last_status = 0
        self.last_success = ""
        self.last_failure = ""
        self.last_failure_status = 0
        self.send_duration = 0
        self.attempt = 0
        self.retry_recoveries = 0
        self.driver_state = "npcap"
        self.service_state = "not-applicable"
        self.link_state = "unknown"
        self.exit_reason = ""
        self.exit_code = -1
        self.exited_at = ""
        self.pruned_day = ""
        self.started = datetime.now(timezone.utc).isoformat()
        # 1.6：真实创建时间与桥自身哈希；查询失败时退回 started 并把状态标为不完整。
        self.created_at = process_created_at() or self.started
        self.image_path = process_image_path()
        self.bridge_sha = self_sha256()
        self.heartbeat_seq = 0

    def enable(self) -> None:
        self.active = True

    def _link_state(self) -> str:
        state = adapter_link_up(self.adapter)
        if state is True:
            return "up"
        if state is False:
            return "down"
        return "unknown"

    def _snapshot_failure(self) -> None:
        self.link_state = self._link_state()

    def record(self, state: str, status: int, successful_sends: int) -> None:
        if not self.active:
            return
        self.state = state
        self.last_status = status
        if successful_sends > self.sends and status == 0:
            self.last_success = datetime.now(timezone.utc).isoformat()
        self.sends = successful_sends
        self._save_state()

    def record_attempt(self, state: str, status: int, attempt: int, elapsed: int,
                       successful_sends: int) -> None:
        if not self.active:
            return
        self.attempt = attempt
        self.send_duration = elapsed
        if state in ("retrying", "send-failed"):
            self.last_failure = datetime.now(timezone.utc).isoformat()
            self.last_failure_status = status
            self._snapshot_failure()
        if state == "running" and attempt > 1:
            self.retry_recoveries += 1
        self.record(state, status, successful_sends + (1 if state == "running" else 0))
        if state != "running" or attempt > 1:
            self._append_diagnostic()

    def record_exception(self, text: str) -> None:
        """Persist an unhandled bridge exception; traceback contains no secrets."""
        self.exit_reason = "exception"
        self.exit_code = 1
        self.exited_at = datetime.now(timezone.utc).isoformat()
        self._append_diagnostic({
            "record_type": "bridge-exception",
            "traceback": text[-4000:],
        })

    def finalize(self, reason: str, code: int) -> None:
        """Write the real exit cause before the process disappears."""
        self.exit_reason = reason or "loop-end"
        self.exit_code = int(code)
        self.exited_at = datetime.now(timezone.utc).isoformat()
        if self.active:
            self.state = "stopped" if self.exit_reason in {"stop-requested", "completed"} else "exited"
            self._save_state()
            self._append_diagnostic({"record_type": "bridge-exit"})
        else:
            # Authentication failed before telemetry was enabled; still leave a
            # diagnostic trail so the app can explain why no keepalive exists.
            self._append_diagnostic({"record_type": "bridge-exit"})

    def _body(self) -> str:
        payload = {
            "schema_version": BRIDGE_SCHEMA_VERSION,
            "session_id": self.session,
            "process_id": os.getpid(),
            # v2：真实创建时间；process_started_at 保留为"开始保活"时刻以兼容旧读取端。
            "process_created_at": self.created_at,
            "keepalive_started_at": self.started,
            "process_started_at": self.started,
            "heartbeat_seq": self.heartbeat_seq,
            "bridge_sha256": self.bridge_sha,
            "image_path": self.image_path,
            "adapter_description": self.adapter,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "state": self.state,
            "successful_sends": self.sends,
            "last_send_status": self.last_status,
            "last_success_at": self.last_success,
            "last_failure_at": self.last_failure,
            "last_failure_status": self.last_failure_status,
            "send_duration_ms": self.send_duration,
            "send_attempt": self.attempt,
            "retry_recoveries": self.retry_recoveries,
            "failure_driver_state": self.driver_state,
            "failure_service_state": self.service_state,
            "failure_link_state": self.link_state,
            "native_backend": "npcap",
            "exit_reason": self.exit_reason,
            "exit_code": self.exit_code,
            "exited_at": self.exited_at,
        }
        return json.dumps(payload, ensure_ascii=False)

    def _save_state(self) -> None:
        temporary = None
        # 每次落盘心跳序号 +1：即使本机时钟乱跳，只要序号在涨就说明会话活着。
        self.heartbeat_seq += 1
        try:
            TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
            temporary = str(STATE_PATH) + "." + self.session + ".tmp"
            Path(temporary).write_text(self._body(), encoding="utf-8")
            os.replace(temporary, STATE_PATH)
            temporary = None
        except Exception:
            pass
        finally:
            if temporary:
                try:
                    os.remove(temporary)
                except Exception:
                    pass

    def _append_diagnostic(self, extra: dict | None = None) -> None:
        try:
            DIAG_DIR.mkdir(parents=True, exist_ok=True)
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if self.pruned_day != today:
                self.pruned_day = today
                limit = time.time() - 7 * 86400
                for path in DIAG_DIR.glob("native-keepalive-????-??-??.jsonl"):
                    try:
                        if path.stat().st_mtime < limit:
                            path.unlink()
                    except Exception:
                        pass
            payload = json.loads(self._body())
            if extra:
                payload.update(extra)
            path = DIAG_DIR / ("native-keepalive-" + today + ".jsonl")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            pass


# ---------------------------------------------------------------- 设备解析

def decode_local_name(value: str) -> str:
    for encoding in ("mbcs", locale.getpreferredencoding(False), "gb18030", "utf-8"):
        try:
            return base64.b64decode(value, validate=True).decode(encoding)
        except Exception:
            continue
    return ""


def open_by_description(pcap: Pcap, description: str):
    devices = pcap.list_devices()
    if not devices:
        return None
    wanted = description.casefold()
    for name, text in devices:
        lowered = text.casefold()
        if wanted and (wanted in lowered or lowered in wanted):
            return name, text
    for name, text in devices:
        lowered = text.casefold()
        if "ethernet" in lowered or "i219" in lowered:
            return name, text
    return None


def local_mac(description: str) -> bytes:
    import subprocess
    try:
        completed = subprocess.run(["getmac", "/v", "/fo", "csv", "/nh"],
                                   capture_output=True, timeout=15,
                                   creationflags=0x08000000, check=False).stdout
    except Exception:
        return b""
    for encoding in ("utf-8", "gb18030", "mbcs"):
        try:
            text = completed.decode(encoding)
            break
        except Exception:
            continue
    else:
        return b""
    wanted = description.casefold()
    fallback = b""
    for line in text.splitlines():
        cells = [cell.strip().strip('"') for cell in line.split('","')]
        if len(cells) < 3:
            continue
        adapter = cells[1].strip('"')
        address = cells[2].strip('"').replace("-", "").replace(":", "")
        if len(address) != 12:
            continue
        try:
            value = bytes.fromhex(address)
        except ValueError:
            continue
        if wanted and (wanted in adapter.casefold() or adapter.casefold() in wanted):
            return value
        if not fallback and ("ethernet" in adapter.casefold() or "i219" in adapter.casefold()):
            fallback = value
    return fallback


# ---------------------------------------------------------------- 会话

class Session:
    def __init__(self, mode: str, timeout_ms: int, description: str):
        self.mode = mode
        self.persistent = mode == "run-private-session"
        self.timeout = max(5.0, timeout_ms / 1000.0)
        self.description = description
        self.stop_event = None
        self.mutex = None
        self.mutex_owned = False
        self.takeover_from = ""
        self.telemetry = None
        self.pcap = None
        self.source = b""
        self.exit_reason = ""
        self.exit_code = -1

    def set_exit(self, reason: str, code: int | None = None) -> None:
        """Remember why this bridge process is about to end."""
        if reason:
            self.exit_reason = reason
        if code is not None:
            self.exit_code = int(code)

    # -- 生命周期对象 -------------------------------------------------
    def create_stop_event(self) -> bool:
        handle = kernel32.CreateEventW(None, False, False, SESSION_STOP_EVENT_NAME)
        if not handle:
            return False
        self.stop_event = handle
        return True

    def acquire_session_mutex(self) -> bool:
        """真正持有会话互斥体，并在对象已存在时区分两种情况。

        1.5.x 用 bInitialOwner=False 创建却把 mutex_owned 置 True，等于"创建但不持有"：
        读取端的"会话是否在跑"因此恒为假，误判无法降级为 unknown。1.6 起改为
        CreateMutexW(..., True, ...) 请求所有权，并在已存在时：
          * WaitForSingleObject(0) 超时 → 另一个会话正持有 → 本实例退出（78）；
          * 立即获得（含 WAIT_ABANDONED）→ 前任已死，接管并记录 takeover_from。
        """
        handle = kernel32.CreateMutexW(None, True, SESSION_MUTEX_NAME)
        if not handle:
            return False
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            status = kernel32.WaitForSingleObject(handle, 0)
            if status == WAIT_TIMEOUT:
                kernel32.CloseHandle(handle)
                self.set_exit("session-already-active", EXIT_SESSION_ALREADY_ACTIVE)
                return False
            if status not in {WAIT_OBJECT_0, WAIT_ABANDONED}:
                kernel32.CloseHandle(handle)
                self.set_exit("session-mutex-unavailable", EXIT_SESSION_MUTEX_UNAVAILABLE)
                return False
            self.takeover_from = self._previous_session_pid()
        self.mutex = handle
        self.mutex_owned = True
        return True

    @staticmethod
    def _previous_session_pid() -> str:
        """读取旧状态文件里的 pid，仅用于诊断"接管了谁"。"""
        try:
            raw = json.loads(STATE_PATH.read_text(encoding="utf-8-sig"))
            return str(int(raw.get("process_id") or 0))
        except (OSError, ValueError, TypeError):
            return ""

    def stopped(self) -> bool:
        if not self.stop_event:
            return False
        return kernel32.WaitForSingleObject(self.stop_event, 0) == WAIT_OBJECT_0

    def sleep_unless_stopped(self, milliseconds: int) -> bool:
        deadline = time.monotonic() + milliseconds / 1000.0
        while time.monotonic() < deadline:
            if self.stopped():
                return True
            remaining = int((deadline - time.monotonic()) * 1000)
            time.sleep(max(0.01, min(remaining, 200) / 1000.0))
        return self.stopped()

    def cleanup(self) -> None:
        if self.pcap is not None:
            self.pcap.close()
            out("CLOSED\t1")
        if self.mutex_owned and self.mutex:
            kernel32.ReleaseMutex(self.mutex)
            self.mutex_owned = False
        for handle_name in ("mutex", "stop_event"):
            handle = getattr(self, handle_name)
            if handle:
                kernel32.CloseHandle(handle)
                setattr(self, handle_name, None)

    # -- 打开网卡 -----------------------------------------------------
    def open_adapter(self, description: str) -> bool:
        pcap = Pcap()
        if not pcap.load():
            out("ERROR\twpcap-load\t0")
            return False
        match = open_by_description(pcap, description)
        if match is None:
            out("ERROR\tno-adapter\t0")
            return False
        if not pcap.open(match[0]):
            out("ERROR\topen-adapter\t0")
            return False
        self.pcap = pcap
        out("OPENED\t1")
        # Npcap 不需要 NDIS OID；这两个字段保持 1 让上层诊断不至于误判
        out("NDIS_FILTER_SET\t1")
        if not pcap.set_eapol_filter():
            out("FILTER_SET\t0")
            return False
        out("FILTER_SET\t1")
        out("RECEIVE_SLOTS\t1")
        out("READ_POSTED\t1")
        out("READ_STARTED\t1")
        self.source = local_mac(match[1])
        out("ADDRESS_QUERY\t%d" % (0 if len(self.source) == 6 else 87))
        self.link_description = match[1]
        self.telemetry = Telemetry(match[1])
        return len(self.source) == 6

    # -- 链路状态 -----------------------------------------------------
    def link_state(self):
        return adapter_link_up(getattr(self, "link_description", self.description))

    def wait_keepalive_window(self, milliseconds: int) -> str:
        """等待一个保活周期，期间持续盯链路。返回 "ready" / "stopped" / "link-down"。"""
        deadline = time.monotonic() + milliseconds / 1000.0
        while time.monotonic() < deadline:
            if self.stopped():
                return "stopped"
            if self.link_state() is False:
                # 连续两次确认，避免链路抖动导致误停
                time.sleep(0.4)
                if self.link_state() is False:
                    return "link-down"
            remaining = deadline - time.monotonic()
            time.sleep(max(0.05, min(2.0, remaining)))
        return "stopped" if self.stopped() else "ready"

    # -- 认证 ---------------------------------------------------------
    def authenticate(self, identity: bytes, password: bytes) -> tuple:
        """返回 (success_frame, result_code, md5_identifier, frames_read, frames_sent)。"""
        sent = 0
        if self.pcap.send(build_start(self.source)) != 0:
            out("SEND_STATUS\t31")
            return None, -1, -1, 0, 0
        sent += 1
        out("SEND_STATUS\t0")

        deadline = time.monotonic() + self.timeout
        stage = "identity"
        md5_identifier = -1
        reads = 0
        last_start = time.monotonic()
        retries = 0
        server = PAE_GROUP
        while time.monotonic() < deadline:
            if stage == "identity" and retries < 3 and time.monotonic() - last_start >= 5.0:
                retries += 1
                self.pcap.send(build_start(self.source))
                sent += 1
                last_start = time.monotonic()
            frame = self.pcap.next_frame(1000)
            if frame is None:
                continue
            reads += 1
            if stage in ("identity", "md5") and is_identity_request(frame):
                server = frame[6:12]
                identifier = request_identifier(frame)
                out("IDENTITY_RECEIVED\t1")
                out("IDENTITY_IDENTIFIER\t%d" % identifier)
                status = 0 if self.pcap.send(
                    build_identity_response(self.source, server, identifier, identity)) == 0 else 31
                if status == 0:
                    sent += 1
                out("IDENTITY_SEND_STATUS\t%d" % status)
                if status != 0:
                    return None, -1, -1, reads, sent
                stage = "md5"
            elif stage == "md5" and is_md5_request(frame):
                server = frame[6:12]
                md5_identifier = request_identifier(frame)
                offset = eapol_offset(frame)
                challenge = frame[offset + 10:offset + 26]
                out("MD5_RECEIVED\t1")
                out("MD5_IDENTIFIER\t%d" % md5_identifier)
                out("PRIVATE_REQUEST\t%s\t%s"
                    % (base64.b64encode(challenge).decode("ascii"),
                       base64.b64encode(self.source).decode("ascii")))
                extension_b64 = read_line()
                try:
                    extension = base64.b64decode(extension_b64, validate=True)
                except Exception:
                    extension = b""
                accepted = 0x80 <= len(extension) <= 0x800
                out("PRIVATE_EXTENSION_ACCEPTED\t%d" % (1 if accepted else 0))
                if not accepted:
                    out("MD5_SEND_STATUS\t87")
                    return None, -1, md5_identifier, reads, sent
                digest = md5((bytes([md5_identifier & 0xFF]) + password + challenge))
                status = 0 if self.pcap.send(
                    build_md5_response(self.source, server, md5_identifier,
                                       identity, digest, extension)) == 0 else 31
                if status == 0:
                    sent += 1
                out("MD5_SEND_STATUS\t%d" % status)
                if status != 0:
                    return None, -1, md5_identifier, reads, sent
                stage = "result"
            elif stage == "result" and eapol_type(frame) == 0:
                code = eap_result_code(frame)
                if code in (3, 4):
                    out("RESULT_RECEIVED\t1")
                    out("RESULT_CODE\t%d" % code)
                    out("RESULT_IDENTIFIER\t%d" % request_identifier(frame))
                    out("FRAME_LENGTH\t%d" % len(frame))
                    return frame, code, md5_identifier, reads, sent
        out("RESULT_RECEIVED\t0")
        out("RESULT_CODE\t-1")
        out("FRAME_LENGTH\t0")
        return None, -1, md5_identifier, reads, sent

    def send_echo_once(self, frame: bytearray) -> int:
        # 1149/1167 之类都在表示"设备/链路已不可用"，不能当成发送成功。
        if self.link_state() is False:
            return 1167
        status = self.pcap.send(bytes(frame))
        return 31 if status != 0 else 0

    def retry_echo(self, frame: bytearray, successful_sends: int) -> int:
        for attempt in range(1, 4):
            if self.stopped():
                self.telemetry.record_attempt("stopped", 995, attempt, 0, successful_sends)
                return 995
            started = time.monotonic()
            status = self.send_echo_once(frame)
            elapsed = int((time.monotonic() - started) * 1000)
            if status == 0:
                self.telemetry.record_attempt("running", status, attempt, elapsed, successful_sends)
                return 0
            retry = status == 31 and attempt < 3
            self.telemetry.record_attempt("retrying" if retry else "send-failed",
                                          status, attempt, elapsed, successful_sends)
            if not retry:
                return status
            if self.sleep_unless_stopped(1000 if attempt == 1 else 3000):
                self.telemetry.record_attempt("stopped", 995, attempt, elapsed, successful_sends)
                return 995
        return 31

    def run(self) -> int:
        identity_b64 = read_line()
        password_b64 = read_line()
        try:
            identity = base64.b64decode(identity_b64, validate=True)
            password = base64.b64decode(password_b64, validate=True)
        except Exception:
            self.set_exit("invalid-input")
            return 77
        if not identity or not password or len(identity) > 128 or len(password) > 512:
            self.set_exit("invalid-input")
            return 77

        description = self.description
        if not self.open_adapter(description):
            self.set_exit("adapter-open-failed")
            return 72

        success_frame, code, md5_identifier, reads, sent = self.authenticate(identity, password)
        out("FRAMES_READ\t%d" % min(reads, 3))
        out("FRAMES_SENT\t%d" % sent)

        if success_frame is None or code != 3:
            self.telemetry.record("send-failed" if success_frame is None else "authenticating",
                                  -1 if success_frame is None else 0, 0)
            self.set_exit("authentication-failed" if success_frame is None else "authentication-unsuccessful")
            return 0 if code == 4 else 76

        # 保活
        self.telemetry.enable()
        out("PRIVATE_SUCCESS_FRAME\t%s" % base64.b64encode(success_frame).decode("ascii"))
        echo_b64 = read_line()
        try:
            first_echo = bytearray(base64.b64decode(echo_b64, validate=True))
        except Exception:
            self.set_exit("invalid-echo-frame")
            return 87
        if self.persistent:
            second_echo = None
        else:
            second_b64 = read_line()
            try:
                second_echo = bytearray(base64.b64decode(second_b64, validate=True))
            except Exception:
                second_echo = None

        status = self.retry_echo(first_echo, 0)
        sent += 1 if status == 0 else 0
        out("ECHO_SEND_STATUS\t1\t%d" % status)
        if status != 0:
            out("ECHO_FRAMES_SENT\t0")
            self.set_exit(_exit_reason_for_status(status))
            return 76
        out("ECHO_FRAMES_SENT\t1")

        if self.persistent:
            out("SESSION_READY\t%d" % os.getpid())
            echo_sent = 1
            sequence = 0x102C
            while True:
                window = self.wait_keepalive_window(KEEPALIVE_SECONDS * 1000)
                if window == "stopped":
                    self.set_exit("stop-requested")
                    break
                if window == "link-down":
                    # 链路已断：不再发"看起来成功"的保活，记录失败并退出会话，
                    # 让主程序据此判定需要重新认证。
                    out("LINK_DOWN\t1")
                    self.telemetry.record_attempt("send-failed", 1167, 1, 0, echo_sent)
                    self.set_exit("link-down")
                    break
                candidate = bytearray(first_echo)
                increment_encoded_uint32(candidate, 24)
                increment_encoded_uint32(candidate, 34)
                status = self.retry_echo(candidate, echo_sent)
                if status != 0:
                    if status == 1167:
                        out("LINK_DOWN\t1")
                    self.set_exit(_exit_reason_for_status(status))
                    break
                first_echo = candidate
                echo_sent += 1
                sequence = (sequence + 1) & 0xFFFFFFFF
                self.telemetry.record("running", 0, echo_sent)
            out("ECHO_FRAMES_SENT\t%d" % echo_sent)
            return 0

        # 非持久：等 30 秒再发第二个保活
        if second_echo is not None:
            window = self.wait_keepalive_window(KEEPALIVE_SECONDS * 1000)
            if window == "stopped":
                out("ECHO_SEND_STATUS\t2\t995")
                self.set_exit("stop-requested")
                return 0
            status = 1167 if window == "link-down" else self.send_echo_once(second_echo)
            out("ECHO_SEND_STATUS\t2\t%d" % status)
            if status == 0:
                sent += 1
                out("FRAMES_SENT\t%d" % sent)
            self.telemetry.record("running" if status == 0 else "send-failed", status, 2)
            self.set_exit(_exit_reason_for_status(status))
        else:
            self.set_exit("completed")
        return 0


def _exit_reason_for_status(status: int) -> str:
    if status == 995:
        return "stop-requested"
    if status == 1167:
        return "link-down"
    return "keepalive-send-failed"


def md5(data: bytes) -> bytes:
    import hashlib
    return hashlib.md5(data).digest()


# ---------------------------------------------------------------- 模式入口

def mode_selftest() -> int:
    pcap = Pcap()
    if not pcap.load():
        out("SELFTEST\t0")
        return 63
    devices = pcap.list_devices()
    out("SELFTEST\t%d" % (1 if devices else 0))
    return 0 if devices else 63


def mode_stop_private_session() -> int:
    handle = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, SESSION_STOP_EVENT_NAME)
    if not handle:
        return 0
    try:
        if not kernel32.SetEvent(handle):
            return 79
    finally:
        kernel32.CloseHandle(handle)
    mutex = kernel32.CreateMutexW(None, False, SESSION_MUTEX_NAME)
    if not mutex:
        return 80
    try:
        result = kernel32.WaitForSingleObject(mutex, 5000)
        if result == WAIT_OBJECT_0:
            kernel32.ReleaseMutex(mutex)
            return 0
        return 80
    finally:
        kernel32.CloseHandle(mutex)


def mode_send_logoff() -> int:
    # argv: [exe, "send-logoff", <path placeholder>, <adapter_b64>]
    if len(sys.argv) < 4:
        return 64
    description = decode_local_name(sys.argv[3])
    pcap = Pcap()
    if not pcap.load():
        return 66
    match = open_by_description(pcap, description)
    if match is None:
        return 69
    if not pcap.open(match[0]):
        return 72
    out("OPENED\t1")
    try:
        source = local_mac(match[1])
        if len(source) != 6:
            out("ADDRESS_QUERY\t87")
            return 76
        out("ADDRESS_QUERY\t0")
        status = pcap.send(build_logoff(source))
        out("SEND_STATUS\t%d" % status)
        out("FRAMES_SENT\t%d" % (1 if status == 0 else 0))
        out("RESULT\t%s" % ("LOGOFF_FINISHED" if status == 0 else "LOGOFF_FAILED"))
        return 0 if status == 0 else 76
    finally:
        pcap.close()
        out("CLOSED\t1")


def main() -> int:
    if len(sys.argv) < 2:
        return 64
    mode = sys.argv[1]
    if mode == "selftest":
        return mode_selftest()
    if mode == "stop-private-session":
        return mode_stop_private_session()
    if mode == "send-logoff":
        return mode_send_logoff()
    if mode not in ("send-private-md5", "run-private-session"):
        return 64
    # argv: [exe, mode, <path placeholder>, <adapter_b64>, <timeout_ms>]
    if len(sys.argv) < 5:
        return 64
    try:
        timeout_ms = int(sys.argv[4])
    except ValueError:
        return 64
    description = decode_local_name(sys.argv[3])

    session = Session(mode, timeout_ms, description)
    if session.persistent:
        if not session.acquire_session_mutex():
            if session.exit_reason == "session-already-active":
                out("SESSION_ALREADY_RUNNING\t1")
                return EXIT_SESSION_ALREADY_ACTIVE
            out("SESSION_MUTEX_UNAVAILABLE\t1")
            return EXIT_SESSION_MUTEX_UNAVAILABLE
        if session.takeover_from:
            # 前任桥异常退出但互斥体残留：本实例已接管，记录接管对象便于排查。
            out("SESSION_TAKEOVER\t%s" % session.takeover_from)
    if not session.create_stop_event():
        return 79
    code = 70
    try:
        code = session.run()
        if not session.exit_reason:
            session.exit_reason = "loop-end"
        return code
    except Exception:
        code = 1
        session.set_exit("exception", 1)
        if session.telemetry is not None:
            session.telemetry.record_exception(traceback.format_exc())
        raise
    finally:
        try:
            if session.telemetry is not None:
                session.telemetry.finalize(session.exit_reason or "loop-end", code)
        except Exception:
            pass
        session.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
