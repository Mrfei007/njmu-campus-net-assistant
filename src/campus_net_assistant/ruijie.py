from __future__ import annotations

import ctypes
import hashlib
import os
import re
import subprocess
import time
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


RUIJIE_WINDOW_TITLE = re.compile(r"^南京医科大学认证客户端 V4\.99\.20131213$")
RUIJIE_WORKER_NAME = "8021x.exe"
RUIJIE_LAUNCHER_NAME = "RuijieSupplicant.exe"
# 工位客户端截图的基准客户区约为 370 x 510。输入位置全部按客户区比例
# 计算，因此 Windows DPI 只要保持整体布局比例，就不应因绝对像素变大而误判。
EXPECTED_CLIENT_ASPECT_MIN = 0.62
EXPECTED_CLIENT_ASPECT_MAX = 0.82
# 现场 1.10 日志在高 DPI 工位上取得的逻辑客户区为 214 x 312，比例与
# 已核对皮肤一致。最低值只用于排除退化/异常窗口，不能再充当版本判断。
EXPECTED_CLIENT_WIDTH_MIN = 180
EXPECTED_CLIENT_HEIGHT_MIN = 260
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


class RuijieSafetyError(RuntimeError):
    def __init__(self, reason: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.reason = reason
        self.details = details


@dataclass(frozen=True)
class RuijieInstallation:
    launcher: Path
    worker: Path
    worker_sha256: str


@dataclass(frozen=True)
class RuijieWindow:
    hwnd: int
    pid: int
    title: str
    process_path: Path
    visible: bool
    client_width: int
    client_height: int


@dataclass(frozen=True)
class RuijieSubmission:
    submitted_at: str
    process_id: int
    window_title: str
    worker_sha256: str


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_installation(configured_path: str | Path) -> RuijieInstallation:
    raw = str(configured_path).strip().strip('"')
    if not raw:
        raise RuijieSafetyError("client-path-missing", "尚未选择官方锐捷客户端")
    selected = Path(raw).expanduser()
    try:
        selected = selected.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuijieSafetyError("client-path-invalid", "所选锐捷客户端路径不存在") from error
    if not selected.is_file() or selected.suffix.casefold() != ".exe":
        raise RuijieSafetyError("client-path-invalid", "所选路径不是锐捷客户端可执行文件")
    if selected.name.casefold() not in {
        RUIJIE_LAUNCHER_NAME.casefold(),
        RUIJIE_WORKER_NAME.casefold(),
    }:
        raise RuijieSafetyError(
            "client-path-untrusted",
            f"只允许选择 {RUIJIE_LAUNCHER_NAME} 或 {RUIJIE_WORKER_NAME}",
        )
    folder = selected.parent
    worker = folder / RUIJIE_WORKER_NAME
    launcher = folder / RUIJIE_LAUNCHER_NAME
    if not worker.is_file():
        raise RuijieSafetyError("client-files-incomplete", "客户端目录缺少 8021x.exe")
    if not launcher.is_file():
        launcher = worker
    return RuijieInstallation(
        launcher=launcher.resolve(),
        worker=worker.resolve(),
        worker_sha256=_file_sha256(worker),
    )


def _process_path(pid: int) -> Path | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return Path(buffer.value).resolve()
    finally:
        kernel32.CloseHandle(handle)


def _window_snapshot(hwnd: int) -> RuijieWindow | None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetClientRect.restype = wintypes.BOOL
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return None
    title_buffer = ctypes.create_unicode_buffer(length + 1)
    if not user32.GetWindowTextW(hwnd, title_buffer, length + 1):
        return None
    title = title_buffer.value
    if not RUIJIE_WINDOW_TITLE.fullmatch(title):
        return None
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    process_path = _process_path(int(pid.value))
    if process_path is None:
        return None
    rect = wintypes.RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(rect)):
        return None
    return RuijieWindow(
        hwnd=int(hwnd),
        pid=int(pid.value),
        title=title,
        process_path=process_path,
        visible=bool(user32.IsWindowVisible(hwnd)),
        client_width=max(0, rect.right - rect.left),
        client_height=max(0, rect.bottom - rect.top),
    )


def _all_official_windows() -> list[RuijieWindow]:
    if os.name != "nt":
        return []
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    windows: list[RuijieWindow] = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        snapshot = _window_snapshot(hwnd)
        if snapshot is not None:
            windows.append(snapshot)
        return True

    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.EnumWindows(callback, 0)
    return windows


def _matches_installation(window: RuijieWindow, installation: RuijieInstallation) -> bool:
    try:
        return window.process_path.samefile(installation.worker)
    except OSError:
        return window.process_path == installation.worker


def _layout_is_expected(window: RuijieWindow) -> bool:
    if window.client_width < EXPECTED_CLIENT_WIDTH_MIN:
        return False
    if window.client_height < EXPECTED_CLIENT_HEIGHT_MIN:
        return False
    if window.client_height <= 0:
        return False
    aspect = window.client_width / window.client_height
    return EXPECTED_CLIENT_ASPECT_MIN <= aspect <= EXPECTED_CLIENT_ASPECT_MAX


def select_official_window(
    windows: list[RuijieWindow],
    installation: RuijieInstallation,
    *,
    require_visible: bool,
) -> RuijieWindow:
    candidates = [item for item in windows if _matches_installation(item, installation)]
    if require_visible:
        candidates = [item for item in candidates if item.visible]
    if not candidates:
        raise RuijieSafetyError("client-window-not-found", "未找到匹配的官方锐捷认证窗口")
    if len(candidates) != 1:
        raise RuijieSafetyError("client-window-ambiguous", "检测到多个锐捷认证窗口，已停止自动填写")
    selected = candidates[0]
    if not _layout_is_expected(selected):
        aspect = (
            round(selected.client_width / selected.client_height, 4)
            if selected.client_height > 0
            else 0
        )
        raise RuijieSafetyError(
            "client-layout-unrecognized",
            (
                "锐捷客户端布局比例与工位已核对版本不一致"
                f"（客户区 {selected.client_width}×{selected.client_height}）"
            ),
            client_width=selected.client_width,
            client_height=selected.client_height,
            client_aspect=aspect,
        )
    return selected


def probe_official_client(configured_path: str | Path) -> dict[str, object]:
    installation = resolve_installation(configured_path)
    matching = [
        item for item in _all_official_windows() if _matches_installation(item, installation)
    ]
    visible = [item for item in matching if item.visible]
    layout_matches = bool(visible) and len(visible) == 1 and _layout_is_expected(visible[0])
    return {
        "installation_valid": True,
        "launcher": str(installation.launcher),
        "worker": str(installation.worker),
        "worker_sha256": installation.worker_sha256,
        "matching_window_count": len(matching),
        "visible_window_count": len(visible),
        "layout_matches": layout_matches,
        "window_title": visible[0].title if len(visible) == 1 else "",
        "client_width": visible[0].client_width if len(visible) == 1 else 0,
        "client_height": visible[0].client_height if len(visible) == 1 else 0,
    }


def _wait_for_window(installation: RuijieInstallation, timeout_seconds: int) -> RuijieWindow:
    deadline = time.monotonic() + max(1, timeout_seconds)
    last_error: RuijieSafetyError | None = None
    while time.monotonic() < deadline:
        try:
            return select_official_window(
                _all_official_windows(),
                installation,
                require_visible=True,
            )
        except RuijieSafetyError as error:
            last_error = error
        time.sleep(0.5)
    if last_error is not None:
        raise last_error
    raise RuijieSafetyError("client-window-timeout", "等待锐捷客户端窗口超时")


def _show_or_launch(installation: RuijieInstallation) -> RuijieWindow:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    hidden = [
        item
        for item in _all_official_windows()
        if _matches_installation(item, installation) and not item.visible
    ]
    if len(hidden) > 1:
        raise RuijieSafetyError("client-window-ambiguous", "检测到多个隐藏的锐捷窗口")
    if hidden:
        user32.ShowWindow(hidden[0].hwnd, 9)  # SW_RESTORE
    else:
        subprocess.Popen(
            [str(installation.launcher)],
            cwd=str(installation.launcher.parent),
            close_fds=True,
            creationflags=CREATE_NO_WINDOW,
        )
    return _wait_for_window(installation, 15)


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _anonymous_ = ("union",)
    _fields_ = [("type", wintypes.DWORD), ("union", _INPUTUNION)]


def _send_inputs(inputs: list[_INPUT]) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    array = (_INPUT * len(inputs))(*inputs)
    sent = user32.SendInput(len(inputs), array, ctypes.sizeof(_INPUT))
    if sent != len(inputs):
        raise RuijieSafetyError("input-injection-failed", "Windows 未能完成锐捷客户端输入")


def _keyboard_input(vk: int = 0, scan: int = 0, flags: int = 0) -> _INPUT:
    return _INPUT(type=1, ki=_KEYBDINPUT(vk, scan, flags, 0, None))


def _mouse_input(flags: int) -> _INPUT:
    return _INPUT(type=0, mi=_MOUSEINPUT(0, 0, 0, flags, 0, None))


def _select_all() -> None:
    _send_inputs(
        [
            _keyboard_input(vk=0x11),
            _keyboard_input(vk=0x41),
            _keyboard_input(vk=0x41, flags=0x0002),
            _keyboard_input(vk=0x11, flags=0x0002),
        ]
    )


def _key_press(vk: int) -> list[_INPUT]:
    return [
        _keyboard_input(vk=vk),
        _keyboard_input(vk=vk, flags=0x0002),
    ]


def _clear_text_field() -> None:
    """Clear remembered text even when the legacy control ignores Ctrl+A."""
    _select_all()
    # 先走标准全选删除；旧版锐捷编辑框若忽略 Ctrl+A，则转到末尾逐字
    # 退格，再从开头补删，保证记住的账号或密码不会与新值拼接。
    inputs: list[_INPUT] = []
    inputs.extend(_key_press(0x2E))  # VK_DELETE
    inputs.extend(_key_press(0x23))  # VK_END
    for _ in range(128):
        inputs.extend(_key_press(0x08))  # VK_BACK
    inputs.extend(_key_press(0x24))  # VK_HOME
    for _ in range(128):
        inputs.extend(_key_press(0x2E))  # VK_DELETE
    _send_inputs(inputs)
    time.sleep(0.05)


def _send_unicode_text(value: str) -> None:
    inputs: list[_INPUT] = []
    for character in value:
        codepoint = ord(character)
        if codepoint > 0xFFFF:
            raise RuijieSafetyError("credentials-unsupported-character", "账号或密码包含当前客户端不支持的字符")
        inputs.append(_keyboard_input(scan=codepoint, flags=0x0004))
        inputs.append(_keyboard_input(scan=codepoint, flags=0x0004 | 0x0002))
    if inputs:
        _send_inputs(inputs)


def _foreground_exact(window: RuijieWindow) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.BringWindowToTop.argtypes = [wintypes.HWND]
    user32.BringWindowToTop.restype = wintypes.BOOL
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.ShowWindow(window.hwnd, 9)
    user32.BringWindowToTop(window.hwnd)
    user32.SetForegroundWindow(window.hwnd)
    time.sleep(0.25)
    if int(user32.GetForegroundWindow() or 0) != window.hwnd:
        raise RuijieSafetyError("client-not-foreground", "无法将官方锐捷客户端置于前台，未填写账号密码")


def _click_client_position(window: RuijieWindow, x_ratio: float, y_ratio: float) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    user32.ClientToScreen.restype = wintypes.BOOL
    user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    user32.SetCursorPos.restype = wintypes.BOOL
    if int(user32.GetForegroundWindow() or 0) != window.hwnd:
        raise RuijieSafetyError("client-lost-foreground", "锐捷窗口失去前台焦点，已停止填写")
    point = wintypes.POINT(
        int(round(window.client_width * x_ratio)),
        int(round(window.client_height * y_ratio)),
    )
    if not user32.ClientToScreen(window.hwnd, ctypes.byref(point)):
        raise RuijieSafetyError("client-coordinate-failed", "无法定位锐捷客户端输入框")
    if not user32.SetCursorPos(point.x, point.y):
        raise RuijieSafetyError("client-coordinate-failed", "无法定位锐捷客户端输入框")
    _send_inputs([_mouse_input(0x0002), _mouse_input(0x0004)])
    time.sleep(0.15)


def authenticate_once(
    configured_path: str | Path,
    username: str,
    password: str,
    *,
    expected_worker_sha256: str = "",
) -> RuijieSubmission:
    if not username.strip() or not password:
        raise RuijieSafetyError("credentials-missing", "校园网账号或密码为空")
    installation = resolve_installation(configured_path)
    if expected_worker_sha256 and installation.worker_sha256.casefold() != expected_worker_sha256.casefold():
        raise RuijieSafetyError("client-version-changed", "锐捷客户端文件已变化，需要重新进行现场验证")
    window = _show_or_launch(installation)
    _foreground_exact(window)

    # 已核对的 4.99.20131213 南京医科大学皮肤采用固定比例布局。每次输入前都
    # 再确认前台窗口，且不使用剪贴板，防止密码落入剪贴板历史。
    _click_client_position(window, 0.59, 0.648)
    _clear_text_field()
    _send_unicode_text(username.strip())
    _click_client_position(window, 0.59, 0.706)
    _clear_text_field()
    _send_unicode_text(password)
    _click_client_position(window, 0.82, 0.948)
    submitted_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    return RuijieSubmission(
        submitted_at=submitted_at,
        process_id=window.pid,
        window_title=window.title,
        worker_sha256=installation.worker_sha256,
    )


def _safe_dialog_text(hwnd: int) -> str:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.EnumChildWindows.argtypes = [wintypes.HWND, callback_type, wintypes.LPARAM]
    user32.EnumChildWindows.restype = wintypes.BOOL
    values: list[str] = []

    @callback_type
    def callback(child: int, _lparam: int) -> bool:
        class_buffer = ctypes.create_unicode_buffer(128)
        user32.GetClassNameW(child, class_buffer, len(class_buffer))
        if class_buffer.value.casefold() == "edit":
            return True
        length = user32.GetWindowTextLengthW(child)
        if 0 < length <= 256:
            text_buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(child, text_buffer, length + 1)
            text = text_buffer.value.strip()
            if text:
                values.append(text)
        return True

    user32.EnumChildWindows(hwnd, callback, 0)
    return " ".join(values)[:512]


def _classify_authentication_dialog_text(text: str) -> str | None:
    compact = "".join(str(text).split())
    if not compact:
        return None
    if any(
        marker in compact
        for marker in ("账号或密码错误", "用户名或密码错误", "用户或密码错误")
    ):
        return "credentials-invalid"
    if any(
        marker in compact
        for marker in ("密码错误", "密码不正确", "密码有误", "口令错误", "密码验证失败")
    ):
        return "password-invalid"
    if any(
        marker in compact
        for marker in (
            "账号不存在",
            "用户不存在",
            "用户名不存在",
            "账号错误",
            "用户名错误",
            "账号无效",
            "用户无效",
        )
    ):
        return "account-invalid"
    if any(
        marker in compact
        for marker in (
            "认证失败",
            "验证失败",
            "登录失败",
            "认证错误",
            "不允许接入",
            "认证服务器无响应",
            "获取IP失败",
        )
    ):
        return "client-reported-failure"
    # 成功提示、普通信息窗口和无法识别的窗口都不是失败证据；调用方继续
    # 等待绑定有线网卡的真实联网探测结果。
    return None


def detect_authentication_dialog(process_id: int) -> tuple[str, str] | None:
    if os.name != "nt":
        return None
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    dialogs: list[tuple[str, str]] = []

    @callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if int(pid.value) != int(process_id) or not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title_buffer = ctypes.create_unicode_buffer(max(1, length + 1))
        user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer))
        title = title_buffer.value.strip()
        if RUIJIE_WINDOW_TITLE.fullmatch(title):
            return True
        text = f"{title} {_safe_dialog_text(hwnd)}".strip()
        if text:
            dialogs.append((title, text))
        return True

    user32.EnumWindows(callback, 0)
    if not dialogs:
        return None
    text = " ".join(item[1] for item in dialogs)
    reason = _classify_authentication_dialog_text(text)
    if reason is None:
        return None
    # 返回的消息仅来自非 Edit 控件；调用方仍不应将原文写入日志。
    return reason, (dialogs[0][0] or "锐捷客户端提示认证未成功")
