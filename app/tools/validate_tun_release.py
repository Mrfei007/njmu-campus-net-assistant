from pathlib import Path
import hashlib,json,zipfile,sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root.parent/'campus-net-assistant'/'vendor'))
from PyInstaller.archive.readers import CArchiveReader,ZlibArchiveReader
version='1.24.17'
product='南医校园网自动登录辅助程序'
archive=root/'release'/f'{product}-{version}-Windows-x64.zip'
output=root/'output'/'tun-monitor-validation'
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None,'ZIP CRC validation failed'
 names=z.namelist()
 forbidden_names={'w64n55.dll','pcasp50.sys','rjix.dll','8021x.exe','ruijiesupplicant.exe','config.json','native-keepalive-state.json'}
 forbidden=[n for n in names if Path(n).name.casefold() in forbidden_names or Path(n).suffix.casefold() in {'.etl','.pcap','.pcapng'} or '/logs/' in n or '/edge-login-profile/' in n]
 assert not forbidden,forbidden
 manifest_name=next(n for n in names if n.endswith('/版本信息.json'))
 manifest=json.loads(z.read(manifest_name))
 assert manifest['version']==version
 assert manifest['gui_smoke_check']=='passed' and manifest['rawether_bridge_selftest']=='passed'
 bridge_name=next(n for n in names if n.endswith('/native/bin/RawetherBridge.exe'))
 packaged_bridge=hashlib.sha256(z.read(bridge_name)).hexdigest()
 source_bridge=hashlib.sha256((root/'src/campus_net_assistant/native/bin/RawetherBridge.exe').read_bytes()).hexdigest()
 assert packaged_bridge==source_bridge==manifest['rawether_bridge_sha256']
 package=root/'dist-builds'/max(p.name for p in (root/'dist-builds').iterdir() if p.is_dir())/product
 exe=package/f'{product}.exe'
 reader=CArchiveReader(str(exe))
 pyz_name=next(n for n in reader.toc if n.endswith('.pyz'))
 pyz_path=output/'packaged-code.pyz'
 pyz_path.write_bytes(reader.extract(pyz_name))
 pyz=ZlibArchiveReader(str(pyz_path))
 required=['campus_net_assistant.workstation_monitor','campus_net_assistant.keepalive_status','campus_net_assistant.probe','campus_net_assistant.controller']
 assert all(n in pyz.toc for n in required)
 assert version in pyz.extract('campus_net_assistant.product').co_consts
 digest=hashlib.sha256(archive.read_bytes()).hexdigest()
 assert (archive.with_suffix('.zip.sha256.txt')).read_text(encoding='utf-8').split()[0]==digest
 report={'version':version,'zip_crc':'passed','archive_entries':len(names),'forbidden_files':forbidden,'bridge_matches_source':'passed','required_modules_present':required,'packaged_version':'passed','gui_smoke':'passed','bridge_selftest':'passed','zip_sha256':digest,'package_directory':str(package),'release_zip':str(archive)}
 (output/'release-validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 print(json.dumps(report,ensure_ascii=False,indent=2))
