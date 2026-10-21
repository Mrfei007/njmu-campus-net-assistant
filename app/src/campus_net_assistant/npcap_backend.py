#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Npcap 后端的 Python 侧编排（与 rawether.py 里的 Rawether 路径等价）。

它不直接收发帧：帧收发在独立子进程 NpcapBridge.exe 里完成，
这里只负责——和现有 rawether.py 一样——读 stdout 行协议、
收到挑战后算 576 字节私有扩展、收到 Success 后算保活帧、
并把结果整理成 controller 认识的 dict。
"""

from __future__ import annotations

import base64
import hashlib
import locale
import os
import subprocess
import sys
import time
from pathlib import Path

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
FIXED_FINGERPRINT = b"0" * 32
TIMEOUT_MS = 15000

_MODULE_DIR = Path(__file__).resolve().parent
NPCAP_EXE = _MODULE_DIR / "native" / "bin" / "NpcapBridge.exe"
NPCAP_SCRIPT = _MODULE_DIR.parent.parent.parent / "product" / "npcap_bridge.py"


def npcap_detected() -> bool:
    """Whether Npcap's wpcap.dll is installed (native or WinPcap-compat mode)."""
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return ((system_root / "System32" / "Npcap" / "wpcap.dll").is_file()
            or (system_root / "System32" / "wpcap.dll").is_file())



def bridge_command(mode: str, *arguments: str) -> list:
    """优先用打包好的 NpcapBridge.exe；开发期回退到 python 跑 npcap_bridge.py。"""
    if NPCAP_EXE.is_file():
        return [str(NPCAP_EXE), mode, *arguments]
    candidates = [NPCAP_SCRIPT, _MODULE_DIR / "npcap_bridge.py"]
    for candidate in candidates:
        if candidate.is_file():
            return [sys.executable, "-B", str(candidate), mode, *arguments]
    raise RuntimeError("找不到 NpcapBridge（exe 或 py）")


def bridge_available() -> bool:
    try:
        command = bridge_command("selftest")
    except RuntimeError:
        return False
    try:
        completed = subprocess.run(command, capture_output=True, timeout=12,
                                   creationflags=CREATE_NO_WINDOW, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _encode_local_name(value: str) -> str:
    for encoding in ("mbcs", locale.getpreferredencoding(False), "gb18030", "utf-8"):
        try:
            return base64.b64encode(value.encode(encoding)).decode("ascii")
        except Exception:
            continue
    raise ValueError("adapter name cannot be encoded")


def _log_stop_request(success: bool, reason: str) -> None:
    try:
        from .logging_redacted import keepalive_stop_requested
        keepalive_stop_requested(success, reason, "npcap")
    except Exception:
        pass


def stop_session(reason: str = "") -> bool:
    try:
        command = bridge_command("stop-private-session")
    except RuntimeError:
        _log_stop_request(True, reason or "bridge-missing")
        return True
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=8, creationflags=CREATE_NO_WINDOW, check=False)
        success = completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        success = False
    _log_stop_request(success, reason)
    return success


# ---------------------------------------------------------------- 私有扩展

def _build_extension(profile, challenge: bytes, username: bytes, password: bytes,
                     mac: bytes, network: dict) -> bytes:
    from . import ruijie_protocol as protocol
    extension = protocol.network_header(
        str(network["ip"]), str(network["mask"]), str(network["gateway"]),
        str(network["dns"]), bool(network["dhcp"])) + profile.extension[0x17:]
    extension = protocol.set_property(extension, 0x2D, mac)
    extension = protocol.set_property(extension, 0x18, bytes([int(network["dhcp"])]))
    extension = protocol.set_property(extension, 0x17, FIXED_FINGERPRINT)
    extension = protocol.set_property(
        extension, 0x2F,
        protocol.public_password_property_reference(username, password, challenge))
    return protocol.set_property(
        extension, 0x4D, protocol.public_v4_reference(challenge))


def _site_profile():
    from . import ruijie_profiles as profiles
    hashes = tuple(profiles.supported_client_hashes())
    if not hashes:
        raise RuntimeError("内置站点模板为空")
    profile = profiles.builtin_profile_for_client(hashes[0])
    if profile is None:
        raise RuntimeError("内置站点模板缺失")
    return profile


def inspect(configured_path: str | Path = "") -> dict:
    """给界面/环境检查用的只读报告。"""
    report = {
        "mode": "npcap",
        "bridge_found": NPCAP_EXE.is_file(),
        "bridge_ready": False,
        "site_profile_available": False,
        "reuse_candidate": False,
        "message": "",
    }
    try:
        report["site_profile_available"] = _site_profile() is not None
    except Exception:
        report["site_profile_available"] = False
    report["bridge_ready"] = bridge_available()
    report["reuse_candidate"] = bool(report["bridge_found"] and report["bridge_ready"]
                                     and report["site_profile_available"])
    if report["reuse_candidate"]:
        report["message"] = "已就绪：Npcap 原始帧桥 + 内置站点模板（不依赖锐捷组件）"
    elif not report["bridge_found"]:
        report["message"] = "缺少 native\\bin\\NpcapBridge.exe"
    elif not report["bridge_ready"]:
        report["message"] = "NpcapBridge 自检失败（Npcap 是否已安装？）"
    else:
        report["message"] = "缺少内置站点模板"
    return report


# ---------------------------------------------------------------- 主流程

def login(configured_path, friendly_name: str, username: str, password: str,
          interface_name: str = "", *, persistent_session: bool = False) -> dict:
    from . import ruijie_protocol as protocol
    from . import rawether

    result: dict = {
        "private_md5_probe_test": True,
        "native_backend": "npcap",
        "success": False,
        "backend": "npcap",
        "target_adapter": friendly_name,
        "adapter_opened": False,
        "adapter_closed": False,
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
        "eap_result": "NONE",
        "frames_read": 0,
        "frames_sent": 0,
        "v4_branch": -1,
    }
    if not username or not password:
        result["message"] = "校园网账号或密码为空"
        return result
    try:
        identity = username.encode("utf-8")
        secret = password.encode("utf-8")
    except UnicodeError:
        result["message"] = "校园网凭据无法编码"
        return result

    try:
        profile = _site_profile()
        network = rawether._adapter_ipv4_configuration(interface_name)
        modified = profile
    except Exception as error:
        result["message"] = f"准备站点模板或网络参数失败（{type(error).__name__}）"
        return result

    mode = "run-private-session" if persistent_session else "send-private-md5"
    try:
        command = bridge_command(mode, "npcap", _encode_local_name(friendly_name),
                                 str(TIMEOUT_MS))
    except RuntimeError as error:
        result["message"] = str(error)
        return result

    if persistent_session:
        stop_session("new-native-session")
        time.sleep(2)

    process = None
    keep_process = False
    output_lines: list = []
    pipe_input = base64.b64encode(identity) + b"\n" + base64.b64encode(secret) + b"\n"
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        if process.stdin is None or process.stdout is None:
            raise OSError
        process.stdin.write(pipe_input)
        process.stdin.flush()
        while True:
            raw = process.stdout.readline()
            if not raw:
                break
            line = raw.decode("ascii", "strict").rstrip("\r\n")
            fields = line.split("\t")
            if len(fields) == 3 and fields[0] == "PRIVATE_REQUEST":
                challenge = base64.b64decode(fields[1], validate=True)
                mac = base64.b64decode(fields[2], validate=True)
                result["md5_challenge_received"] = True
                result["v4_branch"] = protocol.v4_check_type(challenge)
                extension = _build_extension(profile, challenge, identity, secret, mac, network)
                process.stdin.write(base64.b64encode(extension) + b"\n")
                process.stdin.flush()
                challenge = mac = extension = b""
            elif len(fields) == 2 and fields[0] == "PRIVATE_SUCCESS_FRAME":
                success_frame = base64.b64decode(fields[1], validate=True)
                key = protocol.echo_key(success_frame)
                first_echo = protocol.echo_frame(profile, success_frame[:6],
                                                 success_frame[6:12], key, 0x102B)
                process.stdin.write(base64.b64encode(first_echo) + b"\n")
                if persistent_session:
                    second_echo = b""
                else:
                    second_echo = protocol.echo_frame(profile, success_frame[:6],
                                                      success_frame[6:12], key, 0x102C)
                    process.stdin.write(base64.b64encode(second_echo) + b"\n")
                process.stdin.flush()
                result["echo_frames_prepared"] = True
                result["private_extension_sent"] = True
                result["md5_response_sent"] = True
                result["eap_result"] = "SUCCESS"
                success_frame = first_echo = second_echo = b""
                key = 0
            elif len(fields) == 3 and fields[0] == "ECHO_SEND_STATUS":
                output_lines.append(line)
                if fields[1] == "1" and fields[2] == "0":
                    result["connectivity_probe_attempted"] = True
                    try:
                        current = rawether._adapter_ipv4_configuration(interface_name)
                        current_ip = str(current["ip"])
                        if current_ip != "0.0.0.0":
                            from .config import load_config
                            from .probe import connectivity_probe
                            settings = load_config(read_only=True)
                            online, source = connectivity_probe(
                                current_ip, settings.portal.check_url,
                                settings.portal.success_text,
                                settings.portal.secondary_check_url)
                            result["connectivity_succeeded"] = bool(online)
                            result["connectivity_source"] = source if online else ""
                    except Exception:
                        pass
            elif len(fields) == 2 and fields[0] == "SESSION_READY" and persistent_session:
                output_lines.append(line)
                result["session_process_id"] = max(0, int(fields[1]))
                deadline = time.monotonic() + 30
                while not result["connectivity_succeeded"] and time.monotonic() < deadline:
                    result["connectivity_probe_attempted"] = True
                    try:
                        current = rawether._adapter_ipv4_configuration(interface_name)
                        current_ip = str(current["ip"])
                        if current_ip != "0.0.0.0":
                            from .config import load_config
                            from .probe import connectivity_probe
                            settings = load_config(read_only=True)
                            online, source = connectivity_probe(
                                current_ip, settings.portal.check_url,
                                settings.portal.success_text,
                                settings.portal.secondary_check_url)
                            result["connectivity_succeeded"] = bool(online)
                            result["connectivity_source"] = source if online else ""
                    except Exception:
                        pass
                    if not result["connectivity_succeeded"]:
                        time.sleep(3)
                if result["connectivity_succeeded"]:
                    result["session_started"] = True
                    result["echo_frames_sent"] = max(1, int(result["echo_frames_sent"]))
                    keep_process = True
                    break
                stop_session("verification-failed")
                break
            else:
                output_lines.append(line)

        if not keep_process:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            process.wait(timeout=3)
        result["message"] = "Npcap 认证辅助进程超时并已结束"
        return result
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        result["message"] = str(error) or "Npcap 认证未完成"
        return result
    finally:
        pipe_input = identity = secret = b""
        if process is not None:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()

    values: dict = {}
    echo_statuses: dict = {}
    for line in output_lines:
        fields = line.split("\t")
        if len(fields) == 3 and fields[0] == "ECHO_SEND_STATUS" and fields[1] in {"1", "2"}:
            echo_statuses[fields[1]] = fields[2]
            continue
        key, separator, value = line.partition("\t")
        if separator and key in {
            "OPENED", "CLOSED", "FILTER_SET", "RECEIVE_SLOTS", "READ_POSTED", "READ_STARTED",
            "ADDRESS_QUERY", "SEND_STATUS", "IDENTITY_RECEIVED", "IDENTITY_SEND_STATUS",
            "MD5_RECEIVED", "MD5_IDENTIFIER", "MD5_SEND_STATUS", "PRIVATE_EXTENSION_ACCEPTED",
            "RESULT_RECEIVED", "RESULT_CODE", "RESULT_IDENTIFIER", "ECHO_FRAMES_SENT",
            "FRAMES_READ", "FRAMES_SENT",
        }:
            values[key] = value
    try:
        result.update(
            adapter_opened=values.get("OPENED") == "1",
            adapter_closed=values.get("CLOSED") == "1",
            receive_slots=max(0, min(int(values.get("RECEIVE_SLOTS", "0")), 32)),
            reads_posted=max(0, min(int(values.get("READ_POSTED", "0")), 32)),
            frames_read=max(0, min(int(values.get("FRAMES_READ", "0")), 4)),
            frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 5)),
            echo_frames_sent=(1 if keep_process else
                              max(0, min(int(values.get("ECHO_FRAMES_SENT", "0")), 2))),
            md5_identifier=max(-1, min(int(values.get("MD5_IDENTIFIER", "-1")), 255)),
            result_identifier=max(-1, min(int(values.get("RESULT_IDENTIFIER", "-1")), 255)),
        )
        result["identity_request_received"] = values.get("IDENTITY_RECEIVED") == "1"
        result["identity_response_sent"] = values.get("IDENTITY_SEND_STATUS") == "0"
        result["md5_challenge_received"] = (values.get("MD5_RECEIVED") == "1"
                                            or result["md5_challenge_received"])
        result["private_extension_sent"] = (
            values.get("PRIVATE_EXTENSION_ACCEPTED") == "1"
            and values.get("MD5_SEND_STATUS") == "0")
        result["md5_response_sent"] = result["private_extension_sent"]
        result["eap_result"] = {"3": "SUCCESS", "4": "FAILURE"}.get(
            values.get("RESULT_CODE", ""), result["eap_result"])
    except ValueError:
        result["message"] = "Npcap 桥接器返回了无法校验的结果"
        return result

    result["success"] = result["eap_result"] == "SUCCESS"
    result["bridge_exit_code"] = None if keep_process else (
        int(process.returncode) if process is not None else -1)
    if keep_process and result["session_started"] and result["connectivity_succeeded"]:
        result["message"] = "Npcap 认证成功，后台保活已启动，真实联网验证成功"
    elif result["success"] and result["echo_frames_sent"] >= 2 and result["connectivity_succeeded"]:
        result["message"] = "Npcap 认证成功，两个保活均已发送，真实联网验证成功"
    elif result["success"] and result["echo_frames_sent"] >= 1:
        result["message"] = "Npcap 认证成功并已发送保活，但真实联网验证尚未成功"
    elif result["success"]:
        result["message"] = "Npcap 私有扩展认证成功，但本轮没有完成保活发送"
    elif result["eap_result"] == "FAILURE":
        result["message"] = "Npcap 私有扩展响应已发送，但服务器返回 Failure"
    else:
        result["message"] = "Npcap 认证未完成（未收到 Success）"
    return result


def logoff(configured_path, friendly_name: str) -> dict:
    result: dict = {
        "logoff_test": True,
        "success": False,
        "backend": "npcap",
        "target_adapter": friendly_name,
        "session_stopped": False,
        "adapter_opened": False,
        "adapter_closed": False,
        "frames_sent": 0,
    }
    session_stopped = stop_session("manual-logout")
    result["session_stopped"] = session_stopped
    if not session_stopped:
        result["message"] = "后台保活未能安全停止，未发送注销报文"
        return result
    try:
        command = bridge_command("send-logoff", "npcap", _encode_local_name(friendly_name))
    except RuntimeError as error:
        result["message"] = str(error)
        return result
    try:
        completed = subprocess.run(command, capture_output=True, timeout=15,
                                   creationflags=CREATE_NO_WINDOW, check=False)
    except (OSError, subprocess.SubprocessError):
        result["message"] = "无法启动 Npcap 注销辅助进程"
        return result
    values: dict = {}
    try:
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("\t")
            if separator and key in {"OPENED", "CLOSED", "SEND_STATUS", "FRAMES_SENT", "RESULT"}:
                values[key] = value
    except (UnicodeError, ValueError):
        result["message"] = "Npcap 注销结果无法校验"
        return result
    result.update(
        adapter_opened=values.get("OPENED") == "1",
        adapter_closed=values.get("CLOSED") == "1",
        frames_sent=max(0, min(int(values.get("FRAMES_SENT", "0")), 1)),
        send_status=int(values.get("SEND_STATUS", "-1")),
        bridge_exit_code=int(completed.returncode),
    )
    result["success"] = bool(result["adapter_opened"] and result["adapter_closed"]
                             and result["frames_sent"] == 1
                             and values.get("RESULT") == "LOGOFF_FINISHED")
    result["message"] = ("已停止保活并发送 1 个标准 EAPOL-Logoff" if result["success"]
                         else "Npcap 注销未完成")
    return result
