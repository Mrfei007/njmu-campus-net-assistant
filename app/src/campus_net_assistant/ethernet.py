from __future__ import annotations

import locale
import os
import re
import subprocess
from dataclasses import dataclass


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


@dataclass(frozen=True)
class EthernetInfo:
    interface: str
    description: str
    ip: str
    gateway: str
    ifindex: int
    dns_servers: tuple[str, ...] = ()
    route_metric: int = 0


@dataclass(frozen=True)
class LinkedEthernetInfo:
    interface: str
    description: str
    ifindex: int


@dataclass(frozen=True)
class _DefaultRoute:
    gateway: str
    interface_ip: str
    metric: int


def _decode_output(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw
    encodings = (
        "utf-8-sig",
        locale.getpreferredencoding(False),
        "gb18030",
        "cp950",
        "mbcs",
    )
    candidates: list[str] = []
    tried: set[str] = set()
    for encoding in encodings:
        if not encoding or encoding.casefold() in tried:
            continue
        tried.add(encoding.casefold())
        try:
            candidates.append(raw.decode(encoding))
        except (LookupError, UnicodeDecodeError):
            continue
    if not candidates:
        return raw.decode(errors="replace")

    def score(output: str) -> tuple[int, int]:
        markers = sum(
            output.casefold().count(marker.casefold())
            for marker in ("interface", "configuration", "connected", "接口", "配置", "已连接")
        )
        return markers, -output.count("\ufffd")

    return max(candidates, key=score)


def _run_text(arguments: list[str], timeout: int = 15) -> str:
    raw = subprocess.check_output(
        arguments,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    return _decode_output(raw)


def _interface_descriptions(route_output: str) -> dict[int, str]:
    descriptions: dict[int, str] = {}
    for line in route_output.splitlines():
        match = re.match(r"^\s*(\d+)\.{3}.*?\.{6}(.+?)\s*$", line)
        if match:
            descriptions[int(match.group(1))] = match.group(2).strip()
    return descriptions


def _connected_interfaces(netsh_output: str) -> dict[int, str]:
    connected: dict[int, str] = {}
    for line in netsh_output.splitlines():
        match = re.match(r"^\s*(\d+)\s+\d+\s+\d+\s+(\S+)\s+(.+?)\s*$", line)
        if not match:
            continue
        if match.group(2).strip().casefold() in {"connected", "已连接"}:
            connected[int(match.group(1))] = match.group(3).strip()
    return connected


def _interface_blocks(output: str) -> list[tuple[str, str]]:
    headers = list(
        re.finditer(
            r'^\s*(?:Configuration\s+for\s+interface|.*接口)\s+["“]([^"”]+)["”].*$',
            output,
            re.MULTILINE | re.IGNORECASE,
        )
    )
    blocks: list[tuple[str, str]] = []
    for index, match in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(output)
        blocks.append((match.group(1).strip(), output[match.end() : end]))
    return blocks


def _interface_addresses(address_output: str) -> dict[str, str]:
    addresses: dict[str, str] = {}
    for name, block in _interface_blocks(address_output):
        for line in block.splitlines():
            if not re.search(r"(?i)IP(?:v4)?\s*(?:Address)?|IP\s*地址", line):
                continue
            if re.search(r"(?i)subnet|prefix|子网|前缀", line):
                continue
            match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            if match and not match.group(1).startswith("169.254."):
                addresses.setdefault(name, match.group(1))
                break
    return addresses


def _dns_servers(dns_output: str) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for name, block in _interface_blocks(dns_output):
        addresses: list[str] = []
        for match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", block):
            address = match.group(1)
            if address not in addresses:
                addresses.append(address)
        result[name] = tuple(addresses)
    return result


def _default_routes(route_output: str) -> list[_DefaultRoute]:
    routes: list[_DefaultRoute] = []
    pattern = re.compile(
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$"
    )
    for line in route_output.splitlines():
        match = pattern.match(line)
        if match:
            routes.append(_DefaultRoute(match.group(1), match.group(2), int(match.group(3))))
    return routes


def _is_physical_ethernet(description: str) -> bool:
    lowered = description.casefold()
    excluded = (
        "wireless",
        "wi-fi",
        "wifi",
        "802.11",
        "virtual",
        "vmware",
        "hyper-v",
        "vpn",
        "loopback",
        "bluetooth",
        "sangfor",
    )
    if any(marker in lowered for marker in excluded):
        return False
    return any(
        marker in lowered
        for marker in ("ethernet", "gbe", "gigabit", "realtek", "有线")
    )


def detect_ethernet_interface(*, require_preferred: bool = True, preferred_description: str = "") -> EthernetInfo:
    """Select physical Ethernet, with strict system-route checks for portals.

    The default deliberately refuses ambiguous routing. The portal flow binds every
    probe to the selected interface, so silently choosing a VPN or VM adapter
    would produce misleading success/failure results. Workstation monitoring
    can select its unique/session-bound physical adapter under a TUN route.
    """
    if os.name != "nt":
        raise RuntimeError("unsupported-platform")
    route_output = _run_text(["route.exe", "print", "-4"])
    interface_output = _run_text(["netsh.exe", "interface", "ipv4", "show", "interfaces"])
    address_output = _run_text(["netsh.exe", "interface", "ipv4", "show", "addresses"])
    dns_output = _run_text(["netsh.exe", "interface", "ipv4", "show", "dnsservers"])

    descriptions = _interface_descriptions(route_output)
    connected = _connected_interfaces(interface_output)
    addresses = _interface_addresses(address_output)
    dns_by_name = _dns_servers(dns_output)
    routes = _default_routes(route_output)
    if not routes:
        raise RuntimeError("no-ipv4-default-route")

    candidates: list[EthernetInfo] = []
    for index, name in connected.items():
        description = descriptions.get(index, "")
        ip = addresses.get(name, "")
        matching_routes = [route for route in routes if route.interface_ip == ip]
        if not ip or not matching_routes or not _is_physical_ethernet(description):
            continue
        preferred = min(matching_routes, key=lambda route: route.metric)
        candidates.append(
            EthernetInfo(
                interface=name,
                description=description,
                ip=ip,
                gateway=preferred.gateway,
                ifindex=index,
                dns_servers=dns_by_name.get(name, ()),
                route_metric=preferred.metric,
            )
        )
    if not candidates:
        raise RuntimeError("physical-ethernet-default-route-not-found")

    if not require_preferred:
        matching = [item for item in candidates if item.description == preferred_description]
        if preferred_description:
            if len(matching) != 1:
                raise RuntimeError("session-ethernet-not-found")
            candidates = matching
        elif len(candidates) != 1:
            raise RuntimeError("ambiguous-physical-ethernet-routes")
    best_metric = min(item.route_metric for item in candidates)
    best = [item for item in candidates if item.route_metric == best_metric]
    if len(best) != 1:
        raise RuntimeError("ambiguous-physical-ethernet-routes")

    system_best_metric = min(route.metric for route in routes)
    system_best_ips = [route.interface_ip for route in routes if route.metric == system_best_metric]
    selected = best[0]
    if require_preferred and (selected.route_metric != system_best_metric or system_best_ips != [selected.ip]):
        raise RuntimeError("ethernet-is-not-unique-preferred-default-route")
    if not selected.gateway or not selected.dns_servers:
        raise RuntimeError("ethernet-network-details-incomplete")
    return selected


def get_ethernet(*, require_preferred: bool = True, preferred_description: str = "") -> EthernetInfo | None:
    try:
        return detect_ethernet_interface(require_preferred=require_preferred, preferred_description=preferred_description)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError):
        return None


def detect_linked_physical_ethernet() -> LinkedEthernetInfo:
    """Return one linked physical Ethernet adapter even before DHCP is available.

    Workstation 802.1X happens before the adapter necessarily has an IPv4
    address/default route, so the stricter portal detector above cannot be used
    as its precondition.
    """
    if os.name != "nt":
        raise RuntimeError("unsupported-platform")
    route_output = _run_text(["route.exe", "print", "-4"])
    interface_output = _run_text(["netsh.exe", "interface", "ipv4", "show", "interfaces"])
    descriptions = _interface_descriptions(route_output)
    connected = _connected_interfaces(interface_output)
    candidates = [
        LinkedEthernetInfo(name, descriptions.get(index, ""), index)
        for index, name in connected.items()
        if _is_physical_ethernet(descriptions.get(index, ""))
    ]
    if not candidates:
        raise RuntimeError("physical-ethernet-link-not-found")
    if len(candidates) != 1:
        raise RuntimeError("ambiguous-physical-ethernet-links")
    return candidates[0]


def get_linked_physical_ethernet() -> LinkedEthernetInfo | None:
    try:
        return detect_linked_physical_ethernet()
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError):
        return None


def inspect_workstation_routes(network: EthernetInfo | None) -> dict[str, object]:
    """Describe competing routes; never treat a route preference as link loss.

    Also detect split default routes used by VPN/TUN software. Unknown competing
    interfaces remain 'alternate-route', rather than being called a proven TUN.
    """
    output = _run_text(["route.exe", "print", "-4"])
    descriptions = _interface_descriptions(output)
    connected = _connected_interfaces(_run_text(["netsh.exe", "interface", "ipv4", "show", "interfaces"]))
    addresses = _interface_addresses(_run_text(["netsh.exe", "interface", "ipv4", "show", "addresses"]))
    active_ips = {addresses.get(name): descriptions.get(index, "") for index, name in connected.items()}
    pattern = re.compile(r"^\s*(0\.0\.0\.0|128\.0\.0\.0)\s+(0\.0\.0\.0|128\.0\.0\.0)\s+(\d+(?:\.\d+){3})\s+(\d+(?:\.\d+){3})\s+(\d+)\s*$")
    defaults = []
    split = []
    for line in output.splitlines():
        match = pattern.match(line)
        if not match or match[4] not in active_ips:
            continue
        item = (match[4], int(match[5]))
        if match[2] == "0.0.0.0" and match[1] == "0.0.0.0":
            defaults.append(item)
        elif match[2] == "128.0.0.0":
            split.append(item)
    selected_ips = {ip for ip, _ in split}
    if defaults:
        best = min(metric for _, metric in defaults)
        selected_ips.update(ip for ip, metric in defaults if metric == best)
    competing = {ip for ip in selected_ips if network is None or ip != network.ip}
    tunnel_markers = ("tunnel", "tun", "vpn", "wireguard", "wintun", "tap", "sing-box", "mihomo", "clash", "sangfor")
    tunnel = any(any(marker in active_ips[ip].casefold() for marker in tunnel_markers) for ip in competing)
    mode = "tunnel" if tunnel else "alternate-route" if competing else "ethernet-default" if network and selected_ips == {network.ip} else "unknown"
    return {"route_mode": mode, "tunnel_detected": tunnel, "path_verified_direct": False}
