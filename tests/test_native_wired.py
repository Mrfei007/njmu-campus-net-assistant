from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import sys
import shutil
import struct
import unittest
import uuid
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from campus_net_assistant import native_wired as native
from campus_net_assistant import rawether
from campus_net_assistant.config import AppConfig


def workspace_temp(testcase: unittest.TestCase) -> Path:
    root = ROOT / ".test-temp"
    root.mkdir(exist_ok=True)
    folder = root / uuid.uuid4().hex
    folder.mkdir()
    testcase.addCleanup(shutil.rmtree, folder, True)
    return folder


def protocol_test_tlv_extension() -> bytes:
    output = bytearray(576)
    cursor = 0x46
    for item_type, length in ((0x17, 34), (0x18, 6), (0x2D, 8), (0x2F, 18), (0x4D, 130)):
        output[cursor:cursor + 2] = b"\x1a" + bytes([length + 6])
        base = cursor + 2
        output[base:base + 4] = b"\x00\x00\x13\x11"
        output[base + 4] = item_type
        output[base + 5] = length
        cursor = base + 4 + length
    return bytes(output)


def protocol_test_fake_pe(code: bytes) -> bytes:
    data = bytearray(0x200 + len(code))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    section = 0x80 + 24 + 0xF0
    struct.pack_into("<II", data, section + 16, len(code), 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200:] = code
    return bytes(data)


class NativeWiredTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = workspace_temp(self)
        for key, value in {
            "APP_DIR": self.folder,
            "PROFILE_PATH": self.folder / "profile.xml",
            "REPORT_PATH": self.folder / "result.json",
            "STATE_PATH": self.folder / "restore.json",
            "RUIJIE_PROFILE_PATH": self.folder / "ruijie-native-profile.json",
        }.items():
            self.stack.enter_context(patch.object(native, key, value))
        self.trust = native.TrustSettings("radius.example.edu", ("12" * 20,))

    def test_legacy_peap_parser_remains_strict_for_restore_compatibility(self):
        text = native.profile_xml(self.trust)
        self.assertEqual(native.parse_profile(text), self.trust)
        self.assertIn("<UseWinLogonCredentials>false", text)
        self.assertNotIn("<Password>", text)
        with self.assertRaises(native.NativeWiredError):
            native.parse_profile(text.replace('>0</AuthorId>', '>29115</AuthorId>'))

    def test_legacy_credential_xml_escapes_values(self):
        tree = ET.fromstring(native.credentials_xml("person<&", 'p<&"'))
        ns = "{http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1}"
        self.assertEqual(tree.findtext(f".//{ns}Username"), "person<&")
        self.assertEqual(tree.findtext(f".//{ns}Password"), 'p<&"')

    def test_confirmed_protocol_retires_peap_trial_without_side_effects(self):
        with patch("campus_net_assistant.credentials.load") as load, \
             patch.object(native, "_lan") as lan, patch.object(native, "_ps") as powershell, \
             patch.object(native, "acquire_recovery_lock") as lock:
            report = native.run_trial(AppConfig())
        self.assertFalse(report["success"])
        self.assertFalse(report["request_dispatched"])
        self.assertIn("EAP", report["message"])
        load.assert_not_called()
        lan.assert_not_called()
        powershell.assert_not_called()
        lock.assert_not_called()

    def test_environment_exposes_protocol_and_read_only_rawether_result(self):
        raw = {"mode": "read-only", "reuse_candidate": True, "message": "ready"}
        with patch.object(native, "inspect_rawether", return_value=raw) as inspect, \
             patch.object(native, "detect_linked_physical_ethernet", side_effect=RuntimeError), \
             patch.object(native, "_service_running", return_value=False), \
             patch.object(native, "_ps", return_value="False"):
            report = native.environment_report("C:/official/RuijieSupplicant.exe")
        inspect.assert_called_once_with("C:/official/RuijieSupplicant.exe")
        self.assertTrue(report["protocol_confirmed"])
        self.assertTrue(report["peap_trial_retired"])
        self.assertIs(report["rawether"], raw)

    def test_environment_uses_builtin_profile_for_supported_school_client(self):
        supported_hash = "b84d7d794a94eb3679caf826b8fddfec76cdc028a1c0e95ae7fcf61e37927bfe"
        raw = {"mode": "read-only", "reuse_candidate": True, "message": "ready"}
        installation = SimpleNamespace(worker_sha256=supported_hash)
        with patch.object(native, "inspect_rawether", return_value=raw), \
             patch.object(native, "resolve_installation", return_value=installation), \
             patch.object(native, "detect_linked_physical_ethernet", side_effect=RuntimeError), \
             patch.object(native, "_service_running", return_value=False), \
             patch.object(native, "_ps", return_value="False"):
            report = native.environment_report("C:/official/RuijieSupplicant.exe")
        self.assertTrue(report["compatibility_profile_ready"])
        self.assertEqual(report["compatibility_profile_source"], "built-in")
        self.assertEqual(report["capture_profile_count"], 0)

    def test_dialog_exposes_only_production_native_actions(self):
        from PySide6.QtWidgets import QApplication, QMessageBox
        from campus_net_assistant.native_wired_gui import NativeWiredDialog
        app = QApplication.instance() or QApplication([])
        with patch.object(NativeWiredDialog, "start") as start:
            dialog = NativeWiredDialog()
        start.assert_called_once_with("check")
        self.assertEqual(dialog.check_button.text(), "重新检查接入条件")
        self.assertFalse(hasattr(dialog, "test_button"))
        self.assertFalse(hasattr(dialog, "import_button"))
        self.assertFalse(hasattr(dialog, "enumerate_button"))
        self.assertFalse(hasattr(dialog, "open_close_button"))
        self.assertFalse(hasattr(dialog, "receive_button"))
        self.assertFalse(hasattr(dialog, "start_button"))
        self.assertFalse(hasattr(dialog, "identity_button"))
        self.assertEqual(dialog.md5_button.text(), "验证并启用原生锐捷认证")
        self.assertFalse(dialog.restore_button.isVisible())
        with patch.object(dialog, "start") as md5_start, \
             patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            dialog.confirm_md5_probe()
        md5_start.assert_called_once_with("send-private-md5")
        dialog.show()
        app.processEvents()
        dialog.thread = object()
        dialog.reject()
        self.assertTrue(dialog.isVisible())
        dialog.thread = None
        dialog.reject()
        self.assertFalse(dialog.isVisible())

    def test_authentication_evidence_still_requires_fresh_matching_session(self):
        events = [
            {"event_id": 15503, "record_id": 10, "guid": "abc", "connection": "1", "time": "2026-09-05T00:00:02Z"},
            {"event_id": 15505, "record_id": 11, "guid": "abc", "connection": "1", "time": "2026-09-05T00:00:03Z"},
        ]
        self.assertTrue(native.authentication_evidence(events, "abc", 9, "2026-09-05T00:00:01Z")["authenticated"])
        self.assertIsNone(native.authentication_evidence(events[1:], "abc", 9, "2026-09-05T00:00:01Z"))


class RawetherInspectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = workspace_temp(self)

    def test_untrusted_dll_is_never_loaded(self):
        exe = self.folder / "RuijieSupplicant.exe"
        dll = self.folder / rawether.DLL_NAME
        exe.write_bytes(b"MZ")
        dll.write_bytes(b"MZ-untrusted")
        with patch.object(rawether, "_service_state", return_value="missing"), \
             patch.object(rawether, "_exports_present") as exports:
            report = rawether.inspect(exe)
        self.assertTrue(report["dll_found"])
        self.assertFalse(report["dll_hash_matches"])
        self.assertFalse(report["reuse_candidate"])
        exports.assert_not_called()

    def _ready_files(self):
        exe = self.folder / "RuijieSupplicant.exe"
        dll = self.folder / rawether.DLL_NAME
        driver_dir = self.folder / "drivers"
        driver_dir.mkdir()
        driver = driver_dir / rawether.DRIVER_NAME
        exe.write_bytes(b"launcher")
        dll.write_bytes(b"known-dll")
        driver.write_bytes(b"known-driver")
        return exe, dll, driver

    def test_ready_requires_every_pinned_component_and_export(self):
        exe, dll, driver = self._ready_files()
        hashes = {dll: rawether.DLL_SHA256, driver: rawether.DRIVER_SHA256}
        with patch.object(rawether, "SYSTEM32", self.folder), \
             patch.object(rawether, "_service_state", return_value="stopped"), \
             patch.object(rawether, "_sha256", side_effect=lambda path: hashes.get(path, "bridge-hash")), \
             patch.object(rawether, "_is_amd64_pe", return_value=True), \
             patch.object(rawether, "_exports_present", return_value=(True, [])):
            report = rawether.inspect(exe)
        self.assertTrue(report["reuse_candidate"])
        self.assertEqual(report["mode"], "read-only")
        self.assertEqual(report["driver_state"], "stopped")

    def test_missing_export_blocks_next_stage(self):
        exe, dll, driver = self._ready_files()
        hashes = {dll: rawether.DLL_SHA256, driver: rawether.DRIVER_SHA256}
        with patch.object(rawether, "SYSTEM32", self.folder), \
             patch.object(rawether, "_service_state", return_value="stopped"), \
             patch.object(rawether, "_sha256", side_effect=lambda path: hashes.get(path, "bridge-hash")), \
             patch.object(rawether, "_is_amd64_pe", return_value=True), \
             patch.object(rawether, "_exports_present", return_value=(False, ["W32N_PacketSend"])):
            report = rawether.inspect(exe)
        self.assertFalse(report["reuse_candidate"])
        self.assertEqual(report["missing_exports"], ["W32N_PacketSend"])

    def test_enumeration_returns_only_friendly_name_and_hash(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        friendly = base64.b64encode("Intel(R) Ethernet Connection (24) I219-V".encode()).decode()
        ndis = base64.b64encode(b"\\Device\\{private-guid}").decode()
        completed = subprocess.CompletedProcess(
            [], 0, stdout=f"ADAPTER\t0\t0\t{friendly}\t{ndis}\nRESULT\t1\n".encode(), stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.enumerate_adapters(self.folder / "RuijieSupplicant.exe")
        self.assertTrue(report["success"])
        self.assertEqual(report["adapter_count"], 1)
        self.assertEqual(report["adapters"][0]["friendly_name"], "Intel(R) Ethernet Connection (24) I219-V")
        self.assertEqual(len(report["adapters"][0]["ndis_name_sha256"]), 64)
        self.assertNotIn("private-guid", repr(report))
        self.assertIn("enumerate", run.call_args.args[0])
        self.assertFalse(report["adapter_opened"])
        self.assertEqual(report["frames_sent"], 0)

    def test_enumeration_never_starts_a_stopped_driver(self):
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", return_value="stopped"), \
             patch.object(rawether.subprocess, "run") as run:
            report = rawether.enumerate_adapters(self.folder / "RuijieSupplicant.exe")
        self.assertFalse(report["success"])
        self.assertIn("不会", report["message"])
        run.assert_not_called()

    def test_open_close_never_reads_or_sends(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = subprocess.CompletedProcess(
            [], 0, stdout=b"OPENED\t1\nCLOSED\t1\nRESULT\tOPENED_CLOSED\n", stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.open_close_adapter(
                self.folder / "RuijieSupplicant.exe",
                "Intel(R) Ethernet Connection (24) I219-V",
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["adapter_opened"])
        self.assertTrue(report["adapter_closed"])
        self.assertEqual(report["frames_read"], 0)
        self.assertEqual(report["frames_sent"], 0)
        self.assertEqual(run.call_args.args[0][1], "open-close")
        self.assertNotIn("Intel(R)", run.call_args.args[0][-1])

    def test_receive_one_reports_only_redacted_metadata_and_never_sends(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = subprocess.CompletedProcess(
            [], 0, stdout=(
                b"OPENED\t1\nNDIS_FILTER_SET\t1\nFILTER_SET\t1\nRECEIVE_SLOTS\t15\n"
                b"READ_POSTED\t15\nREAD_STARTED\t1\nREAD_COMPLETED\t1\n"
                b"FRAME_LENGTH\t96\nFRAME_CLASS\tEAPOL\nEAPOL_TYPE\t0\n"
                b"EAP_CODE\t1\nEAP_IDENTIFIER\t2\nEAP_TYPE\t4\nFRAMES_READ\t1\n"
                b"FRAMES_SENT\t0\nCLOSED\t1\nRESULT\tRECEIVE_FINISHED\n"
            ), stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.receive_one_adapter(
                self.folder / "RuijieSupplicant.exe",
                "Intel(R) Ethernet Connection (24) I219-V",
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["frame_received"])
        self.assertTrue(report["ndis_packet_filter_set"])
        self.assertTrue(report["eapol_filter_set"])
        self.assertEqual(report["receive_slots"], 15)
        self.assertEqual(report["reads_posted"], 15)
        self.assertEqual(report["frame_class"], "EAPOL")
        self.assertEqual(report["frame_length"], 96)
        self.assertEqual(report["eapol_packet_type"], "EAP_PACKET")
        self.assertEqual(report["eap_code"], "REQUEST")
        self.assertEqual(report["eap_identifier"], 2)
        self.assertEqual(report["eap_method"], "MD5_CHALLENGE")
        self.assertEqual(report["frames_read"], 1)
        self.assertEqual(report["frames_sent"], 0)
        self.assertEqual(run.call_args.args[0][1], "receive-one")
        self.assertEqual(run.call_args.args[0][-1], "60000")
        self.assertNotIn("Intel(R)", run.call_args.args[0][3])

    def test_send_start_reports_only_identity_metadata(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = subprocess.CompletedProcess(
            [], 0, stdout=(
                b"OPENED\t1\nNDIS_FILTER_SET\t1\nFILTER_SET\t1\nRECEIVE_SLOTS\t15\n"
                b"READ_POSTED\t15\nREAD_STARTED\t1\nADDRESS_QUERY\t0\nSEND_STATUS\t0\n"
                b"FRAME_LENGTH\t64\nFRAME_CLASS\tEAPOL\nEAPOL_TYPE\t0\nEAP_CODE\t1\n"
                b"EAP_IDENTIFIER\t7\nEAP_TYPE\t1\nFRAMES_READ\t1\nFRAMES_SENT\t1\n"
                b"CLOSED\t1\nRESULT\tSTART_FINISHED\n"
            ), stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.send_start_adapter(
                self.folder / "RuijieSupplicant.exe",
                "Intel(R) Ethernet Connection (24) I219-V",
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["identity_request_received"])
        self.assertEqual(report["frames_read"], 1)
        self.assertEqual(report["frames_sent"], 1)
        self.assertEqual(report["eap_identifier"], 7)
        self.assertEqual(run.call_args.args[0][1], "send-start")
        self.assertNotIn("Intel(R)", run.call_args.args[0][3])

    def test_identity_probe_passes_username_only_through_stdin_and_reports_challenge(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = subprocess.CompletedProcess(
            [], 0, stdout=(
                b"OPENED\t1\nNDIS_FILTER_SET\t1\nFILTER_SET\t1\nRECEIVE_SLOTS\t15\n"
                b"READ_POSTED\t15\nREAD_STARTED\t1\nADDRESS_QUERY\t0\nSEND_STATUS\t0\n"
                b"IDENTITY_RECEIVED\t1\nIDENTITY_IDENTIFIER\t1\nIDENTITY_SEND_STATUS\t0\n"
                b"MD5_RECEIVED\t1\nMD5_IDENTIFIER\t2\nFRAME_LENGTH\t60\n"
                b"FRAMES_READ\t2\nFRAMES_SENT\t2\nCLOSED\t1\nRESULT\tIDENTITY_FINISHED\n"
            ), stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.send_identity_probe_adapter(
                self.folder / "RuijieSupplicant.exe",
                "Intel(R) Ethernet Connection (24) I219-V",
                "test-account",
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["identity_request_received"])
        self.assertTrue(report["identity_response_sent"])
        self.assertTrue(report["md5_challenge_received"])
        self.assertEqual(report["identity_identifier"], 1)
        self.assertEqual(report["md5_identifier"], 2)
        self.assertEqual(report["frames_read"], 2)
        self.assertEqual(report["frames_sent"], 2)
        self.assertEqual(run.call_args.args[0][1], "send-identity")
        self.assertNotIn("test-account", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["input"], base64.b64encode(b"test-account") + b"\n")

    def test_identity_probe_rejects_empty_username_without_opening_driver(self):
        with patch.object(rawether, "inspect") as inspect:
            report = rawether.send_identity_probe_adapter("C:/official/client.exe", "Ethernet", "")
        self.assertFalse(report["success"])
        self.assertEqual(report["frames_sent"], 0)
        inspect.assert_not_called()

    def test_md5_probe_passes_credentials_only_through_stdin_and_reports_success(self):
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = subprocess.CompletedProcess(
            [], 0, stdout=(
                b"OPENED\t1\nNDIS_FILTER_SET\t1\nFILTER_SET\t1\nRECEIVE_SLOTS\t15\n"
                b"READ_POSTED\t15\nREAD_STARTED\t1\nADDRESS_QUERY\t0\nSEND_STATUS\t0\n"
                b"IDENTITY_RECEIVED\t1\nIDENTITY_IDENTIFIER\t1\nIDENTITY_SEND_STATUS\t0\n"
                b"MD5_RECEIVED\t1\nMD5_IDENTIFIER\t2\nMD5_SEND_STATUS\t0\n"
                b"RESULT_RECEIVED\t1\nRESULT_CODE\t3\nRESULT_IDENTIFIER\t2\n"
                b"FRAME_LENGTH\t195\nFRAMES_READ\t3\nFRAMES_SENT\t3\n"
                b"CLOSED\t1\nRESULT\tMD5_FINISHED\n"
            ), stderr=b""
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.send_md5_probe_adapter(
                self.folder / "RuijieSupplicant.exe",
                "Intel(R) Ethernet Connection (24) I219-V",
                "test-account", "test-secret",
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["md5_response_sent"])
        self.assertEqual(report["eap_result"], "SUCCESS")
        self.assertEqual(report["result_identifier"], 2)
        self.assertEqual(report["frames_read"], 3)
        self.assertEqual(report["frames_sent"], 3)
        self.assertEqual(run.call_args.args[0][1], "send-md5")
        self.assertNotIn("test-account", run.call_args.args[0])
        self.assertNotIn("test-secret", run.call_args.args[0])
        self.assertEqual(
            run.call_args.kwargs["input"],
            base64.b64encode(b"test-account") + b"\n" +
            base64.b64encode(b"test-secret") + b"\n",
        )

    def test_md5_probe_rejects_empty_password_without_opening_driver(self):
        with patch.object(rawether, "inspect") as inspect:
            report = rawether.send_md5_probe_adapter(
                "C:/official/client.exe", "Ethernet", "account", ""
            )
        self.assertFalse(report["success"])
        self.assertEqual(report["frames_sent"], 0)
        inspect.assert_not_called()

    def test_private_md5_probe_builds_extension_only_after_challenge(self):
        from campus_net_assistant import config as config_module
        from campus_net_assistant import probe as probe_module
        from campus_net_assistant import ruijie as ruijie_module
        from campus_net_assistant import ruijie_protocol as protocol

        class KeptBytesIO(io.BytesIO):
            def close(self):
                pass

        challenge = bytes([1]) + bytes(15)
        mac = bytes.fromhex("001122334455")
        server = bytes.fromhex("66778899aabb")
        success_body = bytearray(177)
        success_body[0] = 3
        success_body[139:143] = b"\x12\x34\x56\x78"
        success_frame = mac + server + b"\x88\x8e\x01\x00\x00\xb1" + bytes(success_body)
        client = self.folder / "8021x.exe"
        client.write_bytes(protocol_test_fake_pe(bytes(range(64))))
        profile = protocol.CompatibilityProfile(
            protocol_test_tlv_extension(), bytes(27), ("a" * 64,),
            hashlib.sha256(client.read_bytes()).hexdigest(),
        )
        (self.folder / protocol.PROFILE_PATH_NAME).write_text(
            protocol.profile_json(profile), encoding="utf-8"
        )
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        stdout = io.BytesIO(
            b"OPENED\t1\nRECEIVE_SLOTS\t15\nREAD_POSTED\t15\nREAD_STARTED\t1\n"
            b"IDENTITY_RECEIVED\t1\nIDENTITY_SEND_STATUS\t0\nMD5_RECEIVED\t1\nMD5_IDENTIFIER\t2\n" +
            b"PRIVATE_REQUEST\t" + base64.b64encode(challenge) + b"\t" + base64.b64encode(mac) + b"\n" +
            b"PRIVATE_EXTENSION_ACCEPTED\t1\nMD5_SEND_STATUS\t0\nRESULT_RECEIVED\t1\n"
            b"RESULT_CODE\t3\nRESULT_IDENTIFIER\t2\n" +
            b"PRIVATE_SUCCESS_FRAME\t" + base64.b64encode(success_frame) + b"\n" +
            b"ECHO_SEND_STATUS\t1\t0\nECHO_SEND_STATUS\t2\t0\nFRAME_LENGTH\t195\n"
            b"ECHO_FRAMES_SENT\t2\nFRAMES_READ\t3\nFRAMES_SENT\t5\n"
            b"CLOSED\t1\nRESULT\tPRIVATE_MD5_FINISHED\n"
        )
        fake_process = SimpleNamespace(
            stdin=KeptBytesIO(), stdout=stdout, returncode=0,
            wait=lambda timeout=None: 0, poll=lambda: 0, kill=lambda: None,
        )
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether, "_adapter_ipv4_configuration", return_value={
                 "ip": "10.1.2.3", "mask": "255.255.255.0", "gateway": "10.1.2.1",
                 "dns": "1.1.1.1", "dhcp": True,
             }), patch.object(config_module, "APP_DIR", self.folder), \
             patch.object(config_module, "load_config", return_value=SimpleNamespace(portal=SimpleNamespace(
                 check_url="http://primary", success_text="ok", secondary_check_url="http://secondary"
             ))), \
             patch.object(probe_module, "connectivity_probe", return_value=(True, "primary")), \
             patch.object(ruijie_module, "resolve_installation", return_value=SimpleNamespace(worker=client)), \
             patch.object(rawether.subprocess, "Popen", return_value=fake_process) as popen:
            report = rawether.send_private_md5_probe_adapter(
                self.folder / "RuijieSupplicant.exe", "Ethernet", "test-account", "test-secret", "Ethernet"
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["private_extension_sent"])
        self.assertEqual(report["echo_frames_sent"], 2)
        self.assertTrue(report["connectivity_succeeded"])
        self.assertEqual(report["v4_branch"], 1)
        self.assertNotIn("test-account", repr(report))
        self.assertNotIn("test-secret", repr(report))
        sent_lines = fake_process.stdin.getvalue().splitlines()
        self.assertEqual(len(sent_lines), 5)
        self.assertEqual(len(base64.b64decode(sent_lines[2], validate=True)), 576)
        self.assertEqual(len(base64.b64decode(sent_lines[3], validate=True)), 45)
        self.assertEqual(len(base64.b64decode(sent_lines[4], validate=True)), 45)
        self.assertEqual(popen.call_args.args[0][1], "send-private-md5")

    def test_bridge_allows_only_fixed_start_and_identity_send(self):
        source = (rawether.BRIDGE_PATH.parent.parent / "RawetherBridge.cs").read_text(encoding="utf-8")
        self.assertIn('"W32N_PacketReadEx"', source)
        self.assertIn('"W32N_CancelPacketRead"', source)
        self.assertIn('"W32N_SetBPFProgram"', source)
        self.assertIn('"W32N_MakeNdisRequest"', source)
        self.assertIn("const int ReceiveSlotCount = 15", source)
        self.assertIn('"W32N_SendSinglePacket"', source)
        self.assertIn("0x01,0x80,0xc2,0x00,0x00,0x03", source)
        self.assertIn("0x88,0x8e,0x01,0x01,0x00,0x00", source)
        self.assertIn('args[0] == "send-identity"', source)
        self.assertIn('args[0] == "send-md5"', source)
        self.assertIn('args[0] == "send-private-md5"', source)
        self.assertIn('args[0] == "send-logoff"', source)
        self.assertIn('args[0] == "run-private-session"', source)
        self.assertIn('args[0] == "stop-private-session"', source)
        self.assertIn("stoppedSession.WaitOne(5000)", source)
        self.assertIn("IncrementEncodedUInt32(candidate, 24)", source)
        self.assertIn("IncrementEncodedUInt32(candidate, 34)", source)
        self.assertIn("previous = candidate", source)
        self.assertIn("ref secondEcho", source)
        self.assertIn(
            "sendPrivateMd5 || runPrivateSession) &&\n                            friendlyStatus == 0",
            source,
        )
        self.assertIn("0x88,0x8e,0x01,0x02,0x00,0x00", source)
        self.assertIn("SendFixedLogoff", source)
        self.assertIn("PRIVATE_EXTENSION_ACCEPTED", source)
        self.assertIn("SendIdentityResponse", source)
        self.assertIn("SendMd5Response", source)
        self.assertIn("MD5.Create()", source)
        self.assertIn("Console.In.ReadLine()", source)
        self.assertNotIn("send-logoff-start", source)
        self.assertNotIn('"W32N_PacketSend"', source)

    def test_logoff_stops_keepalive_and_sends_only_one_fixed_frame(self):
        bridge = self.folder / "RawetherBridge.exe"
        bridge.write_bytes(b"bridge")
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        completed = SimpleNamespace(
            returncode=0,
            stdout=(
                b"OPENED\t1\nADDRESS_QUERY\t0\nSEND_STATUS\t0\nFRAMES_SENT\t1\n"
                b"CLOSED\t1\nRESULT\tLOGOFF_FINISHED\n"
            ),
        )
        with patch.object(rawether, "BRIDGE_PATH", bridge), \
             patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether, "stop_private_session", return_value=True) as stop, \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            report = rawether.send_logoff_adapter("client.exe", "Intel Ethernet")
        self.assertTrue(report["success"])
        self.assertEqual(report["frames_sent"], 1)
        stop.assert_called_once_with()
        self.assertEqual(run.call_args.args[0][1], "send-logoff")
        self.assertNotIn("credential", repr(run.call_args).casefold())

    def test_stop_private_session_waits_for_bridge_shutdown(self):
        bridge = self.folder / "RawetherBridge.exe"
        bridge.write_bytes(b"bridge")
        completed = SimpleNamespace(returncode=0)
        with patch.object(rawether, "BRIDGE_PATH", bridge), \
             patch.object(rawether.subprocess, "run", return_value=completed) as run:
            self.assertTrue(rawether.stop_private_session())
        self.assertEqual(run.call_args.args[0], [str(bridge), "stop-private-session"])
        self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_persistent_private_session_detaches_after_real_connectivity(self):
        self._assert_persistent_private_session([(True, "primary")])

    def test_persistent_private_session_waits_for_delayed_network(self):
        self._assert_persistent_private_session([
            (False, "dns-error"), (False, "dns-error"), (True, "primary"),
        ])

    def _assert_persistent_private_session(self, probe_results):
        from campus_net_assistant import config as config_module
        from campus_net_assistant import probe as probe_module
        from campus_net_assistant import ruijie as ruijie_module
        from campus_net_assistant import ruijie_protocol as protocol

        class KeptBytesIO(io.BytesIO):
            def close(self):
                pass

        challenge = bytes([1]) + bytes(15)
        mac = bytes.fromhex("001122334455")
        success_frame = mac + bytes.fromhex("66778899aabb") + b"\x88\x8e\x01\x00\x00\x04\x03\x02\x00\x04"
        stdout = io.BytesIO(
            b"OPENED\t1\nRECEIVE_SLOTS\t15\nREAD_POSTED\t15\nREAD_STARTED\t1\n"
            b"IDENTITY_SEND_STATUS\t0\n" +
            b"PRIVATE_REQUEST\t" + base64.b64encode(challenge) + b"\t" + base64.b64encode(mac) + b"\n" +
            b"PRIVATE_EXTENSION_ACCEPTED\t1\nMD5_SEND_STATUS\t0\n" +
            b"PRIVATE_SUCCESS_FRAME\t" + base64.b64encode(success_frame) + b"\n" +
            b"ECHO_SEND_STATUS\t1\t0\nIDENTITY_RECEIVED\t1\nMD5_RECEIVED\t1\n"
            b"MD5_IDENTIFIER\t2\nRESULT_CODE\t3\nRESULT_IDENTIFIER\t2\nFRAME_LENGTH\t195\n"
            b"ECHO_FRAMES_SENT\t1\nFRAMES_READ\t3\nFRAMES_SENT\t4\nSESSION_READY\t4321\n"
        )
        fake_process = SimpleNamespace(
            stdin=KeptBytesIO(), stdout=stdout, returncode=None,
            wait=lambda timeout=None: 0, poll=lambda: None, kill=lambda: None,
        )
        dll = self.folder / rawether.DLL_NAME
        dll.write_bytes(b"known-dll")
        (self.folder / protocol.PROFILE_PATH_NAME).write_text("{}", encoding="utf-8")
        with patch.object(rawether, "inspect", return_value={
                 "reuse_candidate": True, "bridge_ready": True, "message": "ready"
             }), patch.object(rawether, "_service_state", side_effect=["running", "running"]), \
             patch.object(rawether, "_candidate_dll", return_value=dll), \
             patch.object(rawether, "_sha256", return_value=rawether.DLL_SHA256), \
             patch.object(rawether, "_adapter_ipv4_configuration", return_value={
                 "ip": "10.1.2.3", "mask": "255.255.255.0", "gateway": "10.1.2.1",
                 "dns": "1.1.1.1", "dhcp": True,
             }), patch.object(rawether, "stop_private_session", return_value=True), \
             patch.object(rawether.time, "sleep"), patch.object(config_module, "APP_DIR", self.folder), \
             patch.object(config_module, "load_config", return_value=SimpleNamespace(portal=SimpleNamespace(
                 check_url="http://primary", success_text="ok", secondary_check_url="http://secondary"
             ))), patch.object(protocol, "load_profile", return_value=object()), \
             patch.object(protocol, "prepare_extension", return_value=bytes(576)), \
             patch.object(protocol, "v4_check_type", return_value=1), \
             patch.object(protocol, "echo_key", return_value=1), \
             patch.object(protocol, "echo_frame", return_value=bytes(45)), \
             patch.object(probe_module, "connectivity_probe", side_effect=probe_results) as probes, \
             patch.object(ruijie_module, "resolve_installation", return_value=SimpleNamespace(worker=self.folder / "8021x.exe")), \
             patch.object(rawether.subprocess, "Popen", return_value=fake_process) as popen:
            report = rawether.send_private_md5_probe_adapter(
                "client.exe", "Ethernet", "account", "secret", "Ethernet",
                persistent_session=True,
            )
        self.assertTrue(report["success"])
        self.assertTrue(report["session_started"])
        self.assertTrue(report["connectivity_succeeded"])
        self.assertEqual(report["session_process_id"], 4321)
        self.assertIsNone(report["bridge_exit_code"])
        self.assertEqual(popen.call_args.args[0][1], "run-private-session")
        self.assertEqual(len(fake_process.stdin.getvalue().splitlines()), 4)
        self.assertEqual(probes.call_count, len(probe_results))


if __name__ == "__main__":
    unittest.main()
