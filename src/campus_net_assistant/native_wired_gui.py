from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog, QLabel, QMessageBox, QPushButton, QTextEdit, QVBoxLayout,
)

from .config import load_config
from .native_wired import REPORT_PATH, NativeWiredError, environment_report
from .ruijie import RuijieSafetyError
from .ruijie_protocol import RuijieProtocolError


class NativeWorker(QObject):
    finished = Signal(dict)

    def __init__(self, action: str, paths: list[str] | None = None) -> None:
        super().__init__()
        self.action = action
        self.paths = paths or []

    @Slot()
    def run(self) -> None:
        try:
            config = load_config()
            if self.action == "check":
                result = environment_report(config.ruijie_path)
            elif self.action == "import":
                from .native_wired import import_ruijie_captures
                result = import_ruijie_captures([Path(value) for value in self.paths], config.ruijie_path)
            elif self.action == "enumerate":
                from .rawether import enumerate_adapters
                result = enumerate_adapters(config.ruijie_path)
            elif self.action == "open-close":
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import open_close_adapter
                link = detect_linked_physical_ethernet()
                result = open_close_adapter(config.ruijie_path, link.description)
            elif self.action == "receive-one":
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import receive_one_adapter
                link = detect_linked_physical_ethernet()
                result = receive_one_adapter(config.ruijie_path, link.description)
            elif self.action == "send-start":
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import send_start_adapter
                link = detect_linked_physical_ethernet()
                result = send_start_adapter(config.ruijie_path, link.description)
            elif self.action == "send-identity":
                from .credentials import load_username
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import send_identity_probe_adapter
                link = detect_linked_physical_ethernet()
                result = send_identity_probe_adapter(
                    config.ruijie_path, link.description, load_username()
                )
            elif self.action == "send-md5":
                from .credentials import load
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import send_md5_probe_adapter
                link = detect_linked_physical_ethernet()
                username, password = load()
                try:
                    result = send_md5_probe_adapter(
                        config.ruijie_path, link.description, username, password
                    )
                finally:
                    password = ""
            elif self.action == "send-private-md5":
                from .credentials import load
                from .ethernet import detect_linked_physical_ethernet
                from .rawether import send_private_md5_probe_adapter
                link = detect_linked_physical_ethernet()
                username, password = load()
                try:
                    result = send_private_md5_probe_adapter(
                        config.ruijie_path, link.description, username, password, link.interface,
                        persistent_session=True,
                    )
                    if result.get("success") and result.get("session_started"):
                        config.ruijie_native_auto_enabled = True
                        from .config import save_config
                        save_config(config)
                finally:
                    password = ""
            else:
                from .scheduler import _run_elevated, is_admin
                from .native_wired import run_restore
                if is_admin():
                    result = run_restore()
                else:
                    REPORT_PATH.unlink(missing_ok=True)
                    code = _run_elevated("--native-wired-restore", 300000)
                    result = json.loads(REPORT_PATH.read_text(encoding="utf-8")) if REPORT_PATH.exists() else {
                        "success": False, "message": f"管理员操作未完成（退出码 {code}）"
                    }
            self.finished.emit(result)
        except (NativeWiredError, RuijieProtocolError, RuijieSafetyError, RuntimeError) as error:
            self.finished.emit({"success": False, "message": str(error)})
        except Exception as error:
            self.finished.emit({"success": False, "message": f"操作未完成（{type(error).__name__}）"})


class NativeWiredDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("工位有线网 · 原生锐捷认证")
        self.resize(640, 430)
        self.thread = None
        self.worker = None
        layout = QVBoxLayout(self)
        intro = QLabel(
            "本页用于检查并启用面向南医学生的工位原生锐捷认证。\n\n"
            "请先安装学校提供的锐捷客户端并在主界面选择其程序路径；兼容资料已内置，学生无需抓包。"
            "“重新检查接入条件”不会发送认证报文，也不会读取账号密码。"
            "首次启用时，请先在官方锐捷客户端注销并保持网线连接，再点击“验证并启用原生锐捷认证”。"
            "认证成功后，程序会进行真实联网验证并在后台每 30 秒保活；失败时日常登录仍会回退到官方客户端。"
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.check_button = QPushButton("重新检查接入条件")
        self.md5_button = QPushButton("验证并启用原生锐捷认证")
        self.restore_button = QPushButton("恢复原有有线设置")
        self.restore_button.setVisible(False)
        layout.addWidget(self.check_button)
        layout.addWidget(self.md5_button)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        layout.addWidget(self.restore_button)
        self.check_button.clicked.connect(lambda: self.start("check"))
        self.md5_button.clicked.connect(self.confirm_md5_probe)
        self.restore_button.clicked.connect(lambda: self.start("restore"))
        self.start("check")

    @Slot()
    def confirm_md5_probe(self) -> None:
        answer = QMessageBox.question(
            self,
            "确认发送密码挑战响应",
            "此测试必须在官方锐捷已经注销、网线仍连接时运行。\n\n"
            "程序将从 Windows 凭据管理器读取账号和密码，依次发送 Start、Identity 响应和一次"
            "带 576 字节锐捷私有扩展的 EAP-MD5 挑战响应，然后等待 Success 或 Failure。"
            "私有扩展会根据本轮 Challenge 在内存中即时生成；收到 Success 后立即发送一次保活，"
            "并执行真实联网验证。验证成功后，受限桥接器会每 30 秒继续保活。账号、密码、Challenge、MAC、"
            "Success 私有内容、保活密钥和摘要均不会显示或写入日志。\n\n"
            "认证成功后会自动启用工位模式的原生认证；失败时正式登录仍可回退到官方锐捷客户端。"
            "是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.start("send-private-md5")

    def start(self, action: str, paths: list[str] | None = None) -> None:
        if self.thread is not None:
            return
        for button in (self.check_button, self.md5_button, self.restore_button):
            button.setEnabled(False)
        self.result_text.setPlainText({
            "check": "正在检查…",
            "import": "正在读取并脱敏抓包…",
            "send-private-md5": "正在进行一次锐捷扩展认证；成功后启动后台保活并验证真实联网，约需 30 秒…",
            "restore": "正在恢复，请等待完成后再关闭窗口…",
        }.get(action, "正在执行…"))
        self.thread = QThread(self)
        self.worker = NativeWorker(action, paths)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.show_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(dict)
    def show_result(self, result: dict) -> None:
        if result.get("private_md5_probe_test"):
            self.result_text.setPlainText(
                f"{result.get('message', '锐捷扩展认证结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"探测前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"探测后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'后台保活中' if result.get('session_started') else '已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                f"接收缓冲区：{result.get('reads_posted', 0)}/{result.get('receive_slots', 0)}\n"
                f"收到 Identity：{'是' if result.get('identity_request_received') else '否'}\n"
                f"账号响应发送：{'成功' if result.get('identity_response_sent') else '未发送或失败'}\n"
                f"收到 MD5 Challenge：{'是' if result.get('md5_challenge_received') else '否'}\n"
                f"MD5 Identifier：{result.get('md5_identifier', -1)}\n"
                f"V4 校验分支：{result.get('v4_branch', -1)}\n"
                f"锐捷私有扩展发送：{'成功' if result.get('private_extension_sent') else '未发送或失败'}\n"
                f"认证结果：{result.get('eap_result', 'NONE')}\n"
                f"保活生成：{'成功' if result.get('echo_frames_prepared') else '未生成'}\n"
                f"后台持续保活：{'已启动（每 30 秒）' if result.get('session_started') else '未启动'}\n"
                f"真实联网验证：{'成功' if result.get('connectivity_succeeded') else '未成功'}\n"
                f"结果 Identifier：{result.get('result_identifier', -1)}\n"
                f"最后报文长度：{result.get('frame_length', 0)} 字节\n"
                f"匹配报文：{result.get('frames_read', 0)}\n"
                f"发送报文：{result.get('frames_sent', 0)}\n"
                "账号/密码/Challenge/MAC/Success 私有内容/保活密钥/摘要显示或记录：否"
            )
        elif result.get("md5_probe_test"):
            self.result_text.setPlainText(
                f"{result.get('message', '标准 MD5 探测结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"探测前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"探测后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                f"接收缓冲区：{result.get('reads_posted', 0)}/{result.get('receive_slots', 0)}\n"
                f"收到 Identity：{'是' if result.get('identity_request_received') else '否'}\n"
                f"账号响应发送：{'成功' if result.get('identity_response_sent') else '未发送或失败'}\n"
                f"收到 MD5 Challenge：{'是' if result.get('md5_challenge_received') else '否'}\n"
                f"MD5 Identifier：{result.get('md5_identifier', -1)}\n"
                f"标准 MD5 响应发送：{'成功' if result.get('md5_response_sent') else '未发送或失败'}\n"
                f"认证结果：{result.get('eap_result', 'NONE')}\n"
                f"结果 Identifier：{result.get('result_identifier', -1)}\n"
                f"最后报文长度：{result.get('frame_length', 0)} 字节\n"
                f"匹配报文：{result.get('frames_read', 0)}\n"
                f"发送报文：{result.get('frames_sent', 0)}\n"
                "账号/密码/Challenge/MD5 内容显示或记录：否"
            )
        elif result.get("identity_probe_test"):
            self.result_text.setPlainText(
                f"{result.get('message', 'Identity 探测结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"探测前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"探测后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                f"接收缓冲区：{result.get('reads_posted', 0)}/{result.get('receive_slots', 0)}\n"
                f"Start 发送：{'成功' if result.get('start_send_status') == 0 and result.get('frames_sent', 0) >= 1 else '失败'}\n"
                f"收到 Identity：{'是' if result.get('identity_request_received') else '否'}\n"
                f"Identity Identifier：{result.get('identity_identifier', -1)}\n"
                f"账号响应发送：{'成功' if result.get('identity_response_sent') else '未发送或失败'}\n"
                f"收到 MD5 Challenge：{'是' if result.get('md5_challenge_received') else '否'}\n"
                f"MD5 Identifier：{result.get('md5_identifier', -1)}\n"
                f"最后报文长度：{result.get('frame_length', 0)} 字节\n"
                f"匹配报文：{result.get('frames_read', 0)}\n"
                f"发送报文：{result.get('frames_sent', 0)}\n"
                "密码读取/发送：否"
            )
        elif result.get("active_start_test"):
            self.result_text.setPlainText(
                f"{result.get('message', '主动探测结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"探测前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"探测后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                f"临时句柄报文投递：{'已启用' if result.get('ndis_packet_filter_set') else '未启用'}\n"
                f"EAPOL 过滤规则：{'已设置' if result.get('eapol_filter_set') else '未设置'}\n"
                f"接收缓冲区：{result.get('reads_posted', 0)}/{result.get('receive_slots', 0)}\n"
                f"网卡地址读取：{'成功' if result.get('address_query_status') == 0 else '失败'}\n"
                f"Start 发送：{'成功' if result.get('send_status') == 0 and result.get('frames_sent') == 1 else '失败'}\n"
                f"收到 Identity：{'是' if result.get('identity_request_received') else '否'}\n"
                f"EAP Identifier：{result.get('eap_identifier', -1)}\n"
                f"报文长度：{result.get('frame_length', 0)} 字节\n"
                f"读取报文：{result.get('frames_read', 0)}\n"
                f"发送报文：{result.get('frames_sent', 0)}"
            )
        elif result.get("adapter_receive_one"):
            frame_class = {
                "EAPOL": "EAPOL",
                "OTHER": "其他以太网帧",
                "NONE": "未收到",
            }.get(result.get("frame_class"), "未确认")
            self.result_text.setPlainText(
                f"{result.get('message', '被动读取验证结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"读取前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"读取后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                f"临时句柄报文投递：{'已启用' if result.get('ndis_packet_filter_set') else '未启用'}\n"
                f"EAPOL 过滤规则：{'已设置' if result.get('eapol_filter_set') else '未设置'}\n"
                f"接收缓冲区：{result.get('reads_posted', 0)}/{result.get('receive_slots', 0)}\n"
                f"读取请求：{'已启动' if result.get('read_started') else '未启动'}\n"
                f"报文类型：{frame_class}\n"
                f"EAPOL 类型：{result.get('eapol_packet_type', 'NONE')}\n"
                f"EAP：{result.get('eap_code', 'NONE')} / {result.get('eap_method', 'NONE')}\n"
                f"报文长度：{result.get('frame_length', 0)} 字节\n"
                f"读取报文：{result.get('frames_read', 0)}\n发送报文：0"
            )
        elif result.get("adapter_open_close"):
            self.result_text.setPlainText(
                f"{result.get('message', '网卡访问验证结束')}\n\n"
                f"目标网卡：{result.get('target_adapter', '未确定')}\n"
                f"验证前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"验证后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                f"网卡句柄：{'已打开并关闭' if result.get('adapter_opened') and result.get('adapter_closed') else '未完成'}\n"
                "读取报文：0\n发送报文：0"
            )
        elif result.get("adapter_enumeration"):
            names = [str(item.get("friendly_name", "")) for item in result.get("adapters", [])]
            listed = "\n".join(f"• {name}" for name in names) if names else "• 未枚举到网卡"
            self.result_text.setPlainText(
                f"{result.get('message', '只读枚举结束')}\n\n"
                f"枚举到的网卡：{result.get('adapter_count', 0)} 个\n{listed}\n\n"
                f"枚举前驱动状态：{result.get('driver_state_before', '未读取')}\n"
                f"枚举后驱动状态：{result.get('driver_state_after', '未读取')}\n"
                "网卡句柄：未打开\n读取报文：0\n发送报文：0"
            )
        elif "profile_ready" in result:
            self.restore_button.setVisible(bool(result.get("restore_pending")))
            ruijie = result.get("ruijie_running")
            raw = result.get("rawether", {})
            state = {"stopped": "已安装，当前未启动", "running": "已安装，当前运行中",
                     "missing": "未安装", "unreadable": "无法读取"}.get(raw.get("driver_state"), "状态未知")
            self.result_text.setPlainText(
                f"实测协议：EAP-MD5 + 锐捷私有扩展\n"
                f"有线链路：{result.get('adapter')}\n"
                f"Rawether DLL：{'已核验' if raw.get('dll_hash_matches') else '未通过核验'}\n"
                f"原始帧接口：{'完整' if raw.get('exports_ready') else '不完整'}\n"
                f"隔离桥接器：{'已就绪' if raw.get('bridge_ready') else '未就绪'}\n"
                f"PCASp50 驱动：{state}，文件{'已核验' if raw.get('driver_hash_matches') else '未通过核验'}\n"
                f"南医工位兼容资料：{'已就绪' if result.get('compatibility_profile_ready') else '未就绪'}"
                f"（{result.get('capture_profile_message', '尚未检查')}）\n"
                f"只读接入结论：{raw.get('message', '检查未完成')}\n"
                f"锐捷客户端进程：{'无法读取' if ruijie is None else '正在运行' if ruijie else '未运行'}\n"
                f"设置恢复：{'有待恢复的设置，请先点击恢复按钮' if result.get('restore_pending') else '无待恢复设置'}"
            )
        elif result.get("capture_profile_ready"):
            self.result_text.setPlainText(
                f"{result.get('message', '兼容资料已生成')}\n\n"
                f"已采用抓包数：{result.get('capture_profile_count', 0)}\n"
                "下一步请先在官方锐捷客户端注销并保持网线连接，再点击“验证并启用原生锐捷认证”。"
            )
        else:
            flag = lambda key: "成功" if result.get(key) else "未确认"
            self.result_text.setPlainText(
                f"{result.get('message', '操作结束')}\n\n"
                f"Windows 认证：{flag('authentication_succeeded')}\n"
                f"有线实际联网：{flag('connectivity_succeeded')}\n"
                f"原设置恢复：{flag('settings_restored')}\n\n"
                f"结果文件：{REPORT_PATH}"
            )

    @Slot()
    def thread_finished(self) -> None:
        self.thread = self.worker = None
        for button in (self.check_button, self.md5_button, self.restore_button):
            button.setEnabled(True)

    def reject(self) -> None:
        if self.thread is None:
            super().reject()

    def closeEvent(self, event) -> None:
        if self.thread is not None:
            event.ignore()
        else:
            super().closeEvent(event)
