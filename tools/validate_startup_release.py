"""Check ZIP integrity, shipped code, docs and absence of local/private data."""
import base64
import hashlib
import json
import sys
import types
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root.parent / "campus-net-assistant" / "vendor"))
from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader


def nested_constants(value):
    if isinstance(value, types.CodeType):
        for item in value.co_consts:
            yield from nested_constants(item)
    elif isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from nested_constants(item)
    elif isinstance(value, dict):
        for item in value.keys():
            yield from nested_constants(item)
        for item in value.values():
            yield from nested_constants(item)
    else:
        yield value


def profile_property(extension: bytes, property_type: int) -> bytes:
    cursor = 0x46
    while cursor + 6 <= len(extension):
        base = cursor + 2 if extension[cursor] == 0x1A else cursor
        if base + 6 > len(extension) or extension[base:base + 4] != b"\0\0\x13\x11":
            break
        item_type = extension[base + 4]
        item_length = extension[base + 5]
        end = base + 4 + item_length
        if item_length < 2 or end > len(extension):
            break
        if item_type == property_type:
            return extension[base + 6:end]
        cursor = end
    raise AssertionError(f"packaged profile is missing property 0x{property_type:02x}")

version = "1.3.1"
product = "NJMU校园网自动化连接程序"
archive = root / "release" / f"{product}-{version}-Windows-x64.zip"
output = root / "output" / "startup-validation"
output.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    names = z.namelist()
    forbidden_names = {"w64n55.dll", "pcasp50.sys", "rjix.dll", "8021x.exe", "ruijiesupplicant.exe",
                       "config.json", "status.json", "monitor-state.json", "native-keepalive-state.json"}
    forbidden = [n for n in names if Path(n).name.casefold() in forbidden_names
                 or Path(n).suffix.casefold() in {".etl", ".pcap", ".pcapng", ".jsonl"}
                 or "/logs/" in n or "/edge-login-profile/" in n]
    assert not forbidden, forbidden
    manifest = json.loads(z.read(next(n for n in names if n.endswith("/版本信息.json"))))
    assert manifest["version"] == version
    assert manifest["gui_smoke_check"] == manifest["rawether_bridge_selftest"] == "passed"
    doc = next(n for n in names if n.endswith("/使用说明.txt"))
    assert z.read(doc) == (root / "使用说明.txt").read_bytes()
    assert not any(n.endswith("/工位原生认证说明.txt") for n in names)
    text = z.read(doc).decode("utf-8")
    assert all(s in text for s in (version, "120 秒", "30 秒", "默认关闭", "每次开机最多请求一次", "最多补发两次", "登录 Windows 后"))
    bridge_name = next(n for n in names if n.endswith("/native/bin/RawetherBridge.exe"))
    source_bridge = root / "src/campus_net_assistant/native/bin/RawetherBridge.exe"
    assert hashlib.sha256(z.read(bridge_name)).hexdigest() == hashlib.sha256(source_bridge.read_bytes()).hexdigest() == manifest["rawether_bridge_sha256"]
    package = next(p.parent for p in sorted((root / "dist-builds").glob("*/" + product + "/版本信息.json"), reverse=True)
                   if json.loads(p.read_text(encoding="utf-8"))["version"] == version)
    exe = package / f"{product}.exe"
    assert z.read(next(n for n in names if n.endswith("/" + exe.name))) == exe.read_bytes()
    reader = CArchiveReader(str(exe))
    pyz_path = output / "packaged-code.pyz"
    pyz_path.write_bytes(reader.extract(next(n for n in reader.toc if n.endswith(".pyz"))))
    pyz = ZlibArchiveReader(str(pyz_path))
    modules = ["startup", "controller", "config", "gui", "rawether", "ruijie_profiles", "workstation_monitor", "keepalive_status", "monitor_state", "scheduler"]
    assert all("campus_net_assistant." + n in pyz.toc for n in modules)
    assert version in pyz.extract("campus_net_assistant.product").co_consts
    assert 120 in pyz.extract("campus_net_assistant.startup").co_consts
    profile_constants = list(nested_constants(pyz.extract("campus_net_assistant.ruijie_profiles")))
    profile_candidates = []
    for value in profile_constants:
        if not isinstance(value, str) or len(value) < 700:
            continue
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError:
            continue
        if len(decoded) == 576:
            profile_candidates.append(decoded)
    assert len(profile_candidates) == 1
    packaged_profile = profile_candidates[0]
    assert not any(packaged_profile[:0x17])
    private_property_types = (0x17, 0x18, 0x2D, 0x2F, 0x36, 0x38, 0x4E, 0x4D, 0x54, 0x76)
    assert all(not any(profile_property(packaged_profile, item)) for item in private_property_types)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive.with_suffix(".zip.sha256.txt").read_text(encoding="utf-8").split()[0] == digest
    report = dict(version=version, zip_crc="passed", entries=len(names), forbidden_files=forbidden,
                  merged_instructions="passed", bridge_matches_source="passed", modules_present=modules,
                  native_profile_privacy="passed",
                  gui_smoke="passed", bridge_selftest="passed", zip_sha256=digest,
                  release_zip=str(archive), package_directory=str(package))
    (output / "release-validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
