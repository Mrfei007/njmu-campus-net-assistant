from __future__ import annotations

import argparse
import getpass
import sys

from .config import (
    CONNECTION_MODE_DORM_ETHERNET,
    CONNECTION_MODE_WORKSTATION_RUIJIE,
    CONNECTION_MODE_WIRELESS,
    load_config,
    save_config,
)
from .controller import do_login, is_admin, logout_network, monitor, run_hibernate, run_morning, run_wake_coordinator, validate_login
from .credentials import save as save_credentials
from .logging_redacted import event
from .product import PRODUCT_NAME
from .scheduler import install as install_tasks
from .scheduler import remove_all_tasks


def configure() -> None:
    config = load_config()
    mode = input("运行模式 [monitor/full/manual]（默认 monitor）：").strip() or "monitor"
    if mode not in {"monitor", "full", "manual"}:
        raise SystemExit("运行模式必须是 monitor、full 或 manual")
    config.mode = mode
    current_connection = {
        CONNECTION_MODE_WIRELESS: "1",
        CONNECTION_MODE_DORM_ETHERNET: "2",
        CONNECTION_MODE_WORKSTATION_RUIJIE: "3",
    }.get(config.connection_mode, "1")
    connection_choice = input(
        f"连接方式 [1 全校无线网 / 2 宿舍有线网 / 3 工位有线网（锐捷认证）]（默认 {current_connection}）："
    ).strip() or current_connection
    connection_modes = {
        "1": CONNECTION_MODE_WIRELESS,
        "2": CONNECTION_MODE_DORM_ETHERNET,
        "3": CONNECTION_MODE_WORKSTATION_RUIJIE,
    }
    if connection_choice not in connection_modes:
        raise SystemExit("连接方式必须是 1（全校无线网）、2（宿舍有线网）或 3（工位有线网）")
    config.connection_mode = connection_modes[connection_choice]
    if config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE:
        config.ruijie_path = input("官方锐捷客户端路径：").strip() or config.ruijie_path
    config.portal.operator = input(f"运营商（默认 {config.portal.operator}）：").strip() or config.portal.operator
    username = input("校园网账号：").strip()
    password = getpass.getpass("校园网密码：")
    config.auth_paused = False
    config.auth_pause_reason = ""
    config.auth_paused_at = ""
    save_credentials(username, password)
    save_config(config)
    print("配置已保存；密码只写入 Windows Credential Manager。")
    if mode == "full":
        print(install_tasks(config))


def _background(mode: str, once: bool = False) -> int:
    config = load_config()
    if mode == "wake":
        return 0 if run_wake_coordinator(config) else 1
    if mode == "morning":
        return 0 if run_morning(config) else 1
    if mode == "monitor":
        monitor(config, once=once)
        return 0
    if mode == "hibernate":
        return 0 if run_hibernate() else 1
    raise SystemExit(f"未知后台模式：{mode}")


def main() -> None:
    parser = argparse.ArgumentParser(prog=PRODUCT_NAME)
    parser.add_argument("command", nargs="?", choices=["configure", "status", "login", "monitor"])
    parser.add_argument("--background", choices=["wake", "morning", "monitor", "hibernate"])
    parser.add_argument("--install-tasks", action="store_true")
    parser.add_argument("--remove-tasks", action="store_true")
    parser.add_argument("--manual-logout", action="store_true")
    parser.add_argument("--manual-reauthenticate", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--manual-login-validate", action="store_true")
    parser.add_argument("--gui-smoke-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--workstation-monitor-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--diagnostic-output", help=argparse.SUPPRESS)
    parser.add_argument("--native-wired-test", action="store_true")
    parser.add_argument("--native-wired-restore", action="store_true")
    parser.add_argument("--native-wired-check", action="store_true")
    parser.add_argument("--once", action="store_true", help="monitor 只执行一次")
    args = parser.parse_args()

    if args.workstation_monitor_check:
        import json
        from .controller import _monitor_probe
        config = load_config(read_only=True)
        if config.connection_mode != CONNECTION_MODE_WORKSTATION_RUIJIE:
            raise SystemExit("只读工位监测检查需要工位连接模式")
        online, source, attempts = _monitor_probe(config, record=False)
        observation = config._workstation_observation
        report = json.dumps({"success": online, "message": observation.message,
                          "probe_source": source, "probe_attempts": attempts,
                          "recovery_allowed": observation.recovery_allowed,
                          **observation.fields}, ensure_ascii=False, indent=2)
        if args.diagnostic_output:
            from pathlib import Path
            Path(args.diagnostic_output).write_text(report, encoding="utf-8")
        if sys.stdout is not None:
            print(report)
        return

    if args.native_wired_check or args.native_wired_test or args.native_wired_restore:
        import json
        from .native_wired import environment_report, run_restore, run_trial
        if args.native_wired_check:
            print(json.dumps(environment_report(), ensure_ascii=False, indent=2))
            return
        if not is_admin():
            raise SystemExit("原生认证测试及恢复需要管理员权限，请从程序界面启动")
        result = run_restore() if args.native_wired_restore else run_trial(load_config())
        raise SystemExit(0 if result["success"] else 1)

    if args.gui_smoke_check:
        from .gui import smoke_check_gui_runtime

        raise SystemExit(0 if smoke_check_gui_runtime() else 1)

    if args.manual_logout or args.manual_reauthenticate:
        config = load_config()
        try:
            ok = logout_network(config)
        except Exception as error:
            event("manual-network-logout-elevated", False, f"{type(error).__name__}: {error}")
            raise SystemExit(1) from error
        event(
            "manual-network-logout-elevated",
            ok,
            "提权后的网络注销流程已完成" if ok else "提权后的网络注销流程未成功",
        )
        raise SystemExit(0 if ok else 1)
    if args.manual_login_validate:
        config = load_config()
        try:
            ok = validate_login(config)
        except Exception as error:
            event("manual-login-validation-elevated", False, f"{type(error).__name__}: {error}")
            raise SystemExit(1) from error
        event(
            "manual-login-validation-elevated",
            ok,
            "提权后的登录认证已完成" if ok else "提权后的登录认证未成功",
        )
        raise SystemExit(0 if ok else 1)
    if args.install_tasks:
        config = load_config()
        try:
            install_tasks(config)
        except Exception as error:
            event("scheduler-install", False, f"{type(error).__name__}: {error}")
            raise SystemExit(1) from error
        raise SystemExit(0)
    if args.remove_tasks:
        try:
            remove_all_tasks()
        except Exception as error:
            event("scheduler-remove", False, f"{type(error).__name__}: {error}")
            raise SystemExit(1) from error
        raise SystemExit(0)
    if args.background:
        raise SystemExit(_background(args.background, once=args.once))
    if args.command is None:
        from .gui import run_gui

        run_gui()
        return

    config = load_config()
    if args.command == "configure":
        configure()
    elif args.command == "status":
        from .scheduler import installed_task_names
        from .status import read as read_status
        print(config.public_dict())
        print({"administrator": is_admin()})
        print({"installed_tasks": installed_task_names(), "status": read_status()})
    elif args.command == "login":
        raise SystemExit(0 if do_login(config) else 1)
    else:
        monitor(config, once=args.once)


if __name__ == "__main__":
    main()
