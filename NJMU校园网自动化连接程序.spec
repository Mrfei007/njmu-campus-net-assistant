# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
project_dir = Path(SPECPATH)

a = Analysis([str(project_dir / 'entrypoint.py')], pathex=[str(project_dir / 'src'), str(project_dir.parent / 'campus-net-assistant/vendor')], binaries=[(str(project_dir / 'src/campus_net_assistant/native/bin/RawetherBridge.exe'), 'campus_net_assistant/native/bin')], datas=[], hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False, optimize=0)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='NJMU校园网自动化连接程序', debug=False, bootloader_ignore_signals=False, strip=False, upx=True, console=False, disable_windowed_traceback=False, argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None, version=str(project_dir / 'version_info.txt'))
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, upx_exclude=[], name='NJMU校园网自动化连接程序')
