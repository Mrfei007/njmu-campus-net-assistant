"""Render isolated 1.5 widgets; no authentication or task installation."""
import os, sys, json
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / os.environ.get('UI_15_OUTPUT', 'output/ui-15')
OUT.mkdir(parents=True, exist_ok=True)
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['LOCALAPPDATA'] = str(OUT / 'isolated-runtime')
sys.path[:0] = [os.environ.get('UI_15_RUNTIME', str(ROOT/'src')), str(ROOT.parent/'campus-net-assistant/vendor')]
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QLineEdit
from PySide6.QtGui import QFontDatabase, QFont
from campus_net_assistant.config import AppConfig
from campus_net_assistant.gui import MainWindow
from campus_net_assistant.native_wired_gui import NativeWiredDialog
app=QApplication([])
fid=QFontDatabase.addApplicationFont(r'C:\Windows\Fonts\msyh.ttc')
app.setFont(QFont(QFontDatabase.applicationFontFamilies(fid)[0],10))
if os.environ.get('UI_15_RUNTIME'):
    import campus_net_assistant.gui as gui_module
    assert Path(gui_module.__file__).resolve().is_relative_to(Path(os.environ['UI_15_RUNTIME']).resolve()), gui_module.__file__
records=[]
for mode in ('workstation_ruijie','dorm_ethernet','wireless'):
    config=AppConfig(connection_mode=mode,ruijie_path=r'D:\ruijie\Ruijie Supplicant\RuijieSupplicant.exe',wake_enabled=True,wake_time='08:30',auto_connect_on_startup=True,start_uu=True,uu_path=r'D:\UU远程\GameViewer\GameViewer.exe')
    status=dict(stage='online',success=True,current_online=True,message='联网检测成功；当前显示为隔离验证示例',connection_mode=mode,monitor_policy='active',time='2026-10-17 08:30:00')
    with patch('campus_net_assistant.gui.load_config',return_value=config),patch('campus_net_assistant.gui.read_status',return_value=status),patch('campus_net_assistant.gui.installed_task_names',return_value=['NJMUCampusNetAssistant-Monitor','NJMUCampusNetAssistant-Wake']),patch('campus_net_assistant.gui.is_admin',return_value=False),patch('campus_net_assistant.gui.load_credentials',return_value=('demo','not-a-real-password')):
        w=MainWindow();w.timer.stop();w.show();app.processEvents()
        def snap(name):
            app.processEvents()
            assert w.grab().save(str(OUT/name))
            controls=[]
            for el in w.findChildren(QWidget):
                if el.isVisible() and isinstance(el,(QLabel,QPushButton,QLineEdit)):
                    pos=el.mapTo(w,el.rect().topLeft())
                    controls.append(dict(type=type(el).__name__,text='' if isinstance(el,QLineEdit) else el.text(),rect=[pos.x(),pos.y(),el.width(),el.height()]))
            records.append(dict(file=name,controls=controls))
        for index,label in enumerate(('connection','automation','maintenance')):
            w.tabs.setCurrentIndex(index);snap(f'{mode}-{label}.png')
            assert w.status_label.isHidden()
        w.tabs.setCurrentIndex(0)
        status.update(stage='offline',success=False,current_online=False,message='未联网（界面验证示例）')
        w.refresh();snap(f'{mode}-offline.png')
        w._set_credentials_editor_visible(True);snap(f'{mode}-credentials.png')
        w._set_credentials_editor_visible(False)
        w.resize(480,640);snap(f'{mode}-compact.png')
        if mode=='workstation_ruijie':
            dialog=NativeWiredDialog(w);dialog.show();app.processEvents()
            assert dialog.grab().save(str(OUT/'native-pending.png'))
            dialog._last_action='check'
            dialog.show_result(dict(profile_ready=False,link_ready=True,compatibility_profile_ready=True,rawether=dict(reuse_candidate=True,bridge_ready=True,dll_hash_matches=True,exports_ready=True),adapter='示例有线网卡'))
            dialog.thread_finished();app.processEvents()
            assert dialog.grab().save(str(OUT/'native-ready.png'))
            assert dialog.width() == 560 and dialog.height() == 560
            dialog.details_button.click();app.processEvents()
            assert dialog.result_text.isVisible()
            assert dialog.grab().save(str(OUT/'native-expanded.png'))
            dialog.resize(480,480);app.processEvents()
            assert dialog.width() == 480 and dialog.height() == 480
            for button in (dialog.cancel_button, dialog.md5_button):
                location=button.mapTo(dialog,button.rect().bottomRight())
                assert location.x() < dialog.width() and location.y() < dialog.height()
            assert dialog.content_scroll.verticalScrollBar().maximum() > 0
            assert dialog.grab().save(str(OUT/'native-compact.png'))
            dialog.reject()
        w.tray.hide();w._allow_close=True;w.close();app.processEvents()
(OUT/'controls.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf8')
print(f'{len(records)+4} screenshots generated; all data mocked; no network actions.')
