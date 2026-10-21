from __future__ import annotations

import ctypes
import json
import locale
import os
import re
import subprocess
import time
import uuid
from ctypes import wintypes
from dataclasses import dataclass


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
AUTO_INTERFACE_NAMES = {"", "auto", "自动"}
_AUTO_INTERFACE_CACHE: dict[str, str] = {}


@dataclass
class WlanInfo:
    interface: str
    ssid: str
    ip: str
    gateway: str = ""
    ifindex: int = 0
    dns_servers: tuple[str, ...] = ()


@dataclass(frozen=True)
class WlanEnableResult:
    success: bool
    changed: bool
    reason: str
    interface: str = ""
    adapter_enabled: bool = False
    software_radio_enabled: bool = False
    hardware_radio_blocked: bool = False


@dataclass(frozen=True)
class _AdapterEnableResult:
    success: bool
    changed: bool
    reason: str
    interface: str = ""
    interface_guid: str = ""


@dataclass(frozen=True)
class _RadioEnableResult:
    success: bool
    changed: bool
    reason: str
    hardware_radio_blocked: bool = False


_DOT11_RADIO_STATE_UNKNOWN = 0
_DOT11_RADIO_STATE_ON = 1
_DOT11_RADIO_STATE_OFF = 2
_WLAN_INTF_OPCODE_RADIO_STATE = 4
_WLAN_MAX_PHY_INDEX = 64


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_text(cls, value: str) -> "_GUID":
        return cls.from_buffer_copy(uuid.UUID(value.strip().strip("{}")).bytes_le)


class _WLAN_PHY_RADIO_STATE(ctypes.Structure):
    _fields_ = [
        ("dwPhyIndex", wintypes.DWORD),
        ("dot11SoftwareRadioState", ctypes.c_int),
        ("dot11HardwareRadioState", ctypes.c_int),
    ]


class _WLAN_RADIO_STATE(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfPhys", wintypes.DWORD),
        ("PhyRadioState", _WLAN_PHY_RADIO_STATE * _WLAN_MAX_PHY_INDEX),
    ]


def _decode_netsh_output(raw: bytes | str) -> str:
    """Decode redirected ``netsh`` output across Windows locale settings.

    ``mbcs`` is not always the encoding used by a redirected console process,
    especially when the UTF-8 system-locale option is enabled.  Keep every
    successful decoding candidate and prefer the one containing recognizable
    WLAN field labels rather than accepting mojibake that happens to decode.
    """
    if isinstance(raw, str):
        return raw
    encodings = [
        locale.getpreferredencoding(False),
        "utf-8-sig",
        "gb18030",
        "cp950",
        "mbcs",
    ]
    candidates: list[str] = []
    for encoding in encodings:
        if not encoding or encoding.casefold() in {
            item.casefold() for item in encodings[: encodings.index(encoding)] if item
        }:
            continue
        try:
            candidates.append(raw.decode(encoding))
        except (LookupError, UnicodeDecodeError):
            continue
    if not candidates:
        return raw.decode(errors="replace")

    def score(output: str) -> tuple[int, int]:
        interface_labels = len(
            re.findall(
                r"^\s*(?:Interface\s+name|接口名称|接口名|Name|名称)\s*[:：]",
                output,
                re.MULTILINE | re.IGNORECASE,
            )
        )
        ssid_labels = len(
            re.findall(r"^\s*SSID\s*[:：]", output, re.MULTILINE | re.IGNORECASE)
        )
        return interface_labels * 10 + ssid_labels * 3, -output.count("\ufffd")

    return max(candidates, key=score)


def _interface_blocks(output: str) -> list[tuple[str, str]]:
    """Parse English or Chinese ``netsh wlan show interfaces`` output."""
    name_matches = list(
        re.finditer(
            r"^\s*(?:Interface\s+name|接口名称|接口名|Name|名称)\s*[:：]\s*(.+?)\s*$",
            output,
            re.MULTILINE | re.IGNORECASE,
        )
    )
    blocks: list[tuple[str, str]] = []
    for index, match in enumerate(name_matches):
        end = name_matches[index + 1].start() if index + 1 < len(name_matches) else len(output)
        block = output[match.end() : end]
        ssid_match = re.search(r"^\s*SSID\s*[:：]\s*(.+?)\s*$", block, re.MULTILINE | re.IGNORECASE)
        blocks.append((match.group(1).strip(), ssid_match.group(1).strip() if ssid_match else ""))
    return blocks


def _single_interface_fallback(output: str, interfaces: list[str]) -> list[tuple[str, str]]:
    """Safely associate one reported SSID with the only wireless adapter.

    Some localized Windows builds use an interface-name label that ``netsh``
    does not document consistently.  Falling back is unambiguous only when
    PowerShell reports one wireless adapter and ``netsh`` reports one SSID.
    """
    interface_names = [name.strip() for name in interfaces if name.strip()]
    ssids = [
        match.group(1).strip()
        for match in re.finditer(
            r"^\s*SSID\s*[:：]\s*(.+?)\s*$",
            output,
            re.MULTILINE | re.IGNORECASE,
        )
        if match.group(1).strip()
    ]
    if len(interface_names) == 1 and len(ssids) == 1:
        return [(interface_names[0], ssids[0])]
    return []


def _netsh_interfaces() -> list[tuple[str, str]]:
    if os.name != "nt":
        return []
    try:
        raw = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        output = _decode_netsh_output(raw)
        blocks = _interface_blocks(output)
        if blocks:
            return blocks
        return _single_interface_fallback(output, _powershell_wireless_interfaces())
    except (OSError, subprocess.SubprocessError):
        return []


def _powershell_wireless_interfaces() -> list[str]:
    command = (
        "$items=Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Status -ne 'Not Present' -and ("
        "$_.InterfaceDescription -match 'Wireless|Wi-Fi|WLAN|802\\.11|无线' "
        "-or $_.Name -match 'Wi-Fi|WLAN|无线') } | "
        "Sort-Object @{Expression={if($_.Status -eq 'Up'){0}else{1}}},ifIndex | "
        "Select-Object -ExpandProperty Name; $items | ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-Command", command],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        ).strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, str):
            return [data]
        return [str(item) for item in data if str(item).strip()]
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return []


def _wireless_interface_names(blocks: list[tuple[str, str]] | None = None) -> list[str]:
    names: list[str] = []
    for name, _ssid in blocks if blocks is not None else _netsh_interfaces():
        if name and name.casefold() not in {item.casefold() for item in names}:
            names.append(name)
    for name in _powershell_wireless_interfaces():
        if name and name.casefold() not in {item.casefold() for item in names}:
            names.append(name)
    return names


def _profile_exists_on_interface(interface: str, ssid: str) -> bool:
    try:
        completed = subprocess.run(
            [
                "netsh",
                "wlan",
                "show",
                "profile",
                f"name={ssid}",
                f"interface={interface}",
            ],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=12,
            creationflags=CREATE_NO_WINDOW,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _ssid_visible_on_interface(interface: str, ssid: str) -> tuple[bool | None, str]:
    try:
        completed = subprocess.run(
            [
                "netsh",
                "wlan",
                "show",
                "networks",
                "mode=bssid",
                f"interface={interface}",
            ],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        if completed.returncode != 0:
            return None, f"netsh-exit-{completed.returncode}"
        visible_ssids = {
            match.group(1).strip()
            for match in re.finditer(
                r"^\s*SSID\s+\d+\s*[:：]\s*(.*)$",
                completed.stdout,
                re.MULTILINE | re.IGNORECASE,
            )
        }
        return ssid in visible_ssids, "visible" if ssid in visible_ssids else "not-visible"
    except (OSError, subprocess.SubprocessError) as error:
        return None, type(error).__name__


def resolve_wlan_interface(interface: str = "auto", target_ssid: str = "") -> str:
    if interface.strip().lower() not in AUTO_INTERFACE_NAMES:
        return interface.strip()
    blocks = _netsh_interfaces()
    if target_ssid:
        for name, ssid in blocks:
            if ssid == target_ssid:
                _AUTO_INTERFACE_CACHE[target_ssid] = name
                return name
    candidates = _wireless_interface_names(blocks)
    cached = _AUTO_INTERFACE_CACHE.get(target_ssid, "")
    if cached and any(cached.casefold() == name.casefold() for name in candidates):
        return cached
    if target_ssid:
        profile_candidates = [
            name for name in candidates if _profile_exists_on_interface(name, target_ssid)
        ]
        for name in profile_candidates:
            visible, _reason = _ssid_visible_on_interface(name, target_ssid)
            if visible:
                _AUTO_INTERFACE_CACHE[target_ssid] = name
                return name
        if profile_candidates:
            _AUTO_INTERFACE_CACHE[target_ssid] = profile_candidates[0]
            return profile_candidates[0]
        for name in candidates:
            visible, _reason = _ssid_visible_on_interface(name, target_ssid)
            if visible:
                _AUTO_INTERFACE_CACHE[target_ssid] = name
                return name
    return candidates[0] if candidates else ""


def _enable_wlan_adapter(interface: str, target_ssid: str) -> _AdapterEnableResult:
    resolved = resolve_wlan_interface(interface, target_ssid)
    if not resolved:
        return _AdapterEnableResult(False, False, "wireless-interface-not-found")
    safe_interface = resolved.replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f"$adapter=Get-NetAdapter -Name '{safe_interface}' -ErrorAction Stop | Select-Object -First 1; "
        "$changed=$false; "
        "if([string]$adapter.Status -eq 'Disabled'){"
        "$adapter | Enable-NetAdapter -Confirm:$false -ErrorAction Stop; $changed=$true}; "
        f"$adapter=Get-NetAdapter -Name '{safe_interface}' -ErrorAction Stop | Select-Object -First 1; "
        "[pscustomobject]@{"
        "Interface=[string]$adapter.Name;"
        "InterfaceGuid=[string]$adapter.InterfaceGuid;"
        "Status=[string]$adapter.Status;"
        "Changed=[bool]$changed"
        "} | ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-Command", command],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        ).strip()
        data = json.loads(raw) if raw else {}
        interface_name = str(data.get("Interface") or resolved).strip()
        interface_guid = str(data.get("InterfaceGuid") or "").strip()
        changed = bool(data.get("Changed"))
        if not interface_guid:
            return _AdapterEnableResult(
                False,
                changed,
                "wireless-interface-guid-unavailable",
                interface_name,
            )
        return _AdapterEnableResult(
            True,
            changed,
            "adapter-enabled" if changed else "adapter-already-enabled",
            interface_name,
            interface_guid,
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
        return _AdapterEnableResult(
            False,
            False,
            f"adapter-enable-{type(error).__name__}",
            resolved,
        )


def _load_wlan_api():
    wlan_api = ctypes.WinDLL("wlanapi.dll")
    wlan_api.WlanOpenHandle.argtypes = [
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE),
    ]
    wlan_api.WlanOpenHandle.restype = wintypes.DWORD
    wlan_api.WlanQueryInterface.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    wlan_api.WlanQueryInterface.restype = wintypes.DWORD
    wlan_api.WlanSetInterface.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    wlan_api.WlanSetInterface.restype = wintypes.DWORD
    wlan_api.WlanFreeMemory.argtypes = [wintypes.LPVOID]
    wlan_api.WlanFreeMemory.restype = None
    wlan_api.WlanCloseHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    wlan_api.WlanCloseHandle.restype = wintypes.DWORD
    return wlan_api


def _query_radio_states(
    wlan_api, handle, interface_guid: _GUID
) -> tuple[int, list[tuple[int, int, int]]]:
    data_size = wintypes.DWORD()
    data_pointer = ctypes.c_void_p()
    opcode_type = wintypes.DWORD()
    result = int(
        wlan_api.WlanQueryInterface(
            handle,
            ctypes.byref(interface_guid),
            _WLAN_INTF_OPCODE_RADIO_STATE,
            None,
            ctypes.byref(data_size),
            ctypes.byref(data_pointer),
            ctypes.byref(opcode_type),
        )
    )
    if result != 0 or not data_pointer.value:
        return result, []
    try:
        radio_state = ctypes.cast(
            data_pointer, ctypes.POINTER(_WLAN_RADIO_STATE)
        ).contents
        count = min(int(radio_state.dwNumberOfPhys), _WLAN_MAX_PHY_INDEX)
        return 0, [
            (
                int(radio_state.PhyRadioState[index].dwPhyIndex),
                int(radio_state.PhyRadioState[index].dot11SoftwareRadioState),
                int(radio_state.PhyRadioState[index].dot11HardwareRadioState),
            )
            for index in range(count)
        ]
    finally:
        wlan_api.WlanFreeMemory(data_pointer)


def _set_wlan_software_radio(interface_guid: str) -> _RadioEnableResult:
    if os.name != "nt":
        return _RadioEnableResult(False, False, "unsupported-platform")
    try:
        guid = _GUID.from_text(interface_guid)
        wlan_api = _load_wlan_api()
    except (AttributeError, OSError, ValueError) as error:
        return _RadioEnableResult(False, False, f"wlan-api-{type(error).__name__}")

    negotiated_version = wintypes.DWORD()
    handle = wintypes.HANDLE()
    result = int(
        wlan_api.WlanOpenHandle(
            2,
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(handle),
        )
    )
    if result != 0:
        return _RadioEnableResult(False, False, f"wlan-open-error-{result}")
    try:
        result, states = _query_radio_states(wlan_api, handle, guid)
        if result != 0:
            return _RadioEnableResult(False, False, f"wlan-query-error-{result}")
        if not states:
            return _RadioEnableResult(False, False, "radio-state-unavailable")

        changed = any(
            software_state != _DOT11_RADIO_STATE_ON
            for _phy_index, software_state, _hardware_state in states
        )
        for phy_index, software_state, _hardware_state in states:
            if software_state == _DOT11_RADIO_STATE_ON:
                continue
            requested = _WLAN_PHY_RADIO_STATE(
                phy_index,
                _DOT11_RADIO_STATE_ON,
                _DOT11_RADIO_STATE_UNKNOWN,
            )
            result = int(
                wlan_api.WlanSetInterface(
                    handle,
                    ctypes.byref(guid),
                    _WLAN_INTF_OPCODE_RADIO_STATE,
                    ctypes.sizeof(requested),
                    ctypes.byref(requested),
                    None,
                )
            )
            if result != 0:
                return _RadioEnableResult(False, changed, f"wlan-set-error-{result}")

        if changed:
            time.sleep(2)
        result, verified_states = _query_radio_states(wlan_api, handle, guid)
        if result != 0:
            return _RadioEnableResult(False, changed, f"wlan-verify-error-{result}")
        if not verified_states:
            return _RadioEnableResult(False, changed, "radio-state-unavailable")
        hardware_blocked = any(
            hardware_state == _DOT11_RADIO_STATE_OFF
            for _phy_index, _software_state, hardware_state in verified_states
        )
        software_enabled = all(
            software_state == _DOT11_RADIO_STATE_ON
            for _phy_index, software_state, _hardware_state in verified_states
        )
        if hardware_blocked:
            return _RadioEnableResult(False, changed, "hardware-radio-off", True)
        if not software_enabled:
            return _RadioEnableResult(False, changed, "software-radio-remains-off")
        return _RadioEnableResult(
            True,
            changed,
            "software-radio-enabled" if changed else "software-radio-already-enabled",
        )
    finally:
        wlan_api.WlanCloseHandle(handle, None)


def ensure_wlan_enabled(interface: str, target_ssid: str) -> WlanEnableResult:
    """Enable the selected adapter and its software radio without cycling it off."""
    if os.name != "nt":
        return WlanEnableResult(False, False, "unsupported-platform")
    adapter = _enable_wlan_adapter(interface, target_ssid)
    if not adapter.success:
        return WlanEnableResult(
            False,
            adapter.changed,
            adapter.reason,
            adapter.interface,
            adapter_enabled=adapter.changed,
        )
    if adapter.changed:
        time.sleep(2)
    radio = _set_wlan_software_radio(adapter.interface_guid)
    return WlanEnableResult(
        radio.success,
        adapter.changed or radio.changed,
        radio.reason,
        adapter.interface,
        adapter_enabled=adapter.changed,
        software_radio_enabled=radio.changed,
        hardware_radio_blocked=radio.hardware_radio_blocked,
    )


def connect_wlan(interface: str, ssid: str) -> tuple[bool, str]:
    """Ask Windows WLAN AutoConfig to connect using an existing saved profile."""
    if os.name != "nt":
        return False, "unsupported-platform"
    resolved = resolve_wlan_interface(interface, ssid)
    if not resolved:
        return False, "wireless-interface-not-found"
    try:
        completed = subprocess.run(
            [
                "netsh",
                "wlan",
                "connect",
                f"name={ssid}",
                f"ssid={ssid}",
                f"interface={resolved}",
            ],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        if completed.returncode == 0:
            return True, "connection-requested"
        return False, f"netsh-exit-{completed.returncode}"
    except (OSError, subprocess.SubprocessError) as error:
        return False, type(error).__name__


def ssid_visible(interface: str, ssid: str) -> tuple[bool | None, str]:
    """Return whether the target SSID is visible without changing adapter state."""
    if os.name != "nt":
        return None, "unsupported-platform"
    resolved = resolve_wlan_interface(interface, ssid)
    if not resolved:
        return None, "wireless-interface-not-found"
    return _ssid_visible_on_interface(resolved, ssid)


def get_wlan(interface: str = "auto", target_ssid: str = "") -> WlanInfo | None:
    if os.name != "nt":
        return None
    resolved = resolve_wlan_interface(interface, target_ssid)
    if not resolved:
        return None
    try:
        safe_interface = resolved.replace("'", "''")
        powershell = (
            "$ErrorActionPreference='Stop'; "
            f"$configuration=Get-NetIPConfiguration -InterfaceAlias '{safe_interface}' -ErrorAction Stop; "
            "$ipv4=@($configuration.IPv4Address | "
            "Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254*' } | "
            "Select-Object -First 1 -ExpandProperty IPAddress)[0]; "
            "$gateway=@($configuration.IPv4DefaultGateway | "
            "Where-Object { $_.NextHop } | "
            "Select-Object -First 1 -ExpandProperty NextHop)[0]; "
            "$dns=@($configuration.DNSServer | "
            "ForEach-Object { $_.ServerAddresses } | "
            "Where-Object { $_ }); "
            "[pscustomobject]@{"
            "InterfaceIndex=[int]$configuration.InterfaceIndex;"
            "IPAddress=[string]$ipv4;"
            "Gateway=[string]$gateway;"
            "DNSServers=$dns"
            "} | ConvertTo-Json -Depth 3 -Compress"
        )
        raw = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-Command", powershell],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        ).strip()
        data = json.loads(raw) if raw else {}
        ip = str(data.get("IPAddress") or "").strip()
        if not ip:
            return None
        gateway = str(data.get("Gateway") or "").strip()
        dns_data = data.get("DNSServers") or []
        if isinstance(dns_data, str):
            dns_data = [dns_data]
        dns_servers = tuple(str(item).strip() for item in dns_data if str(item).strip())
        ifindex = int(data.get("InterfaceIndex") or 0)
        blocks = _netsh_interfaces()
        ssid = next((current for name, current in blocks if name.casefold() == resolved.casefold()), "")
        return WlanInfo(resolved, ssid, ip, gateway, ifindex, dns_servers)
    except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
        return None
