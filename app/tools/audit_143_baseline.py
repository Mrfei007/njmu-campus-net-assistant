"""Read-only semantic audit against the actual 1.4.3 executable archive."""
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))
from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader


def norm(value):
    if isinstance(value, types.CodeType):
        return (value.co_code, tuple(norm(x) for x in value.co_consts), value.co_names,
                value.co_varnames, value.co_argcount, value.co_kwonlyargcount, value.co_flags,
                value.co_exceptiontable)
    return value


def children(code):
    return {c.co_name: c for c in code.co_consts if isinstance(c, types.CodeType)}


def strings(code):
    for value in code.co_consts:
        if isinstance(value, str):
            yield value
        elif isinstance(value, types.CodeType):
            yield from strings(value)


def differences(a, b, prefix=""):
    result = []
    for name in sorted(a.keys() | b.keys()):
        path = prefix + name
        if name not in a or name not in b:
            result.append(path + " [added/removed]")
        elif norm(a[name]) != norm(b[name]):
            nested = differences(children(a[name]), children(b[name]), path + ".")
            result.extend(nested or [path])
    return result


out = ROOT / ".planning/ui-1.5"
baseline_exe = ROOT.parent / "njmu-campus-net-assistant-1.0/dist-builds/20260924-003517/NJMU校园网自动化连接程序/NJMU校园网自动化连接程序.exe"
archive = CArchiveReader(str(baseline_exe))
pyz_file = out / "baseline.pyz"
pyz_file.write_bytes(archive.extract(next(n for n in archive.toc if n.endswith(".pyz"))))
pyz = ZlibArchiveReader(str(pyz_file))
changed = {}
unchanged = []
for source in sorted((ROOT / "src/campus_net_assistant").glob("*.py")):
    name = "campus_net_assistant." + source.stem
    if name not in pyz.toc:
        changed[source.name] = ["not present in baseline archive"]
        continue
    before = pyz.extract(name)
    after = compile(source.read_text(encoding="utf-8-sig"), before.co_filename, "exec")
    if norm(before) == norm(after):
        unchanged.append(source.name)
    else:
        changed[source.name] = differences(children(before), children(after)) or ["module constants/statements"]

gui = pyz.extract("campus_net_assistant.gui")
main = children(gui)["MainWindow"]
methods = children(main)
current_gui = compile((ROOT / "src/campus_net_assistant/gui.py").read_text(encoding="utf-8"), gui.co_filename, "exec")
current_methods = children(children(current_gui)["MainWindow"])
key_methods = ["update_schedule_controls", "update_schedule_hint", "update_next_action", "configure_and_install"]
controller = pyz.extract("campus_net_assistant.controller")
current_controller = compile((ROOT / "src/campus_net_assistant/controller.py").read_text(encoding="utf-8"), controller.co_filename, "exec")
wake_functions = ["run_wake_coordinator", "_process_wake_request", "_monitor_locked", "run_morning"]
checks = {name: norm(methods[name]) == norm(current_methods[name]) for name in key_methods}
checks.update({name: norm(children(controller)[name]) == norm(children(current_controller)[name]) for name in wake_functions})
assert all(checks[name] for name in wake_functions), checks
assert all(name in unchanged for name in ("scheduler.py", "monitor_state.py", "startup.py", "wake_coordination.py"))
prior = ZlibArchiveReader(str(out / "pre-automation-fix.pyz"))
fix_changed_modules = []
for source in sorted((ROOT / "src/campus_net_assistant").glob("*.py")):
    name = "campus_net_assistant." + source.stem
    if name in prior.toc:
        old = prior.extract(name)
        new = compile(source.read_text(encoding="utf-8-sig"), old.co_filename, "exec")
        if norm(old) != norm(new):
            fix_changed_modules.append(source.name)
assert fix_changed_modules == ["ui_layout.py"], fix_changed_modules
report = dict(baseline_executable=str(baseline_exe), baseline_version_constants=list(strings(pyz.extract("campus_net_assistant.version"))),
              source_origin="existing 1.4.9 source, audited against packaged 1.4.3",
              baseline_automation_strings=[s for s in strings(methods["__init__"]) if any(x in s for x in ("开机", "唤醒", "休眠"))],
              baseline_next_action_strings=list(strings(methods["update_next_action"])),
              critical_behavior_unchanged=checks, unchanged_modules=unchanged, changed_modules=changed,
              this_fix_changed_runtime_modules=fix_changed_modules,
              reviewed_ui_differences={"update_next_action": "1.5 reads applied configuration; 1.4.3 reads editable controls. Both use the same wake-and-connect status phrase.",
                                       "configure_and_install": "1.5 forces wireless browserless priority and disables dorm observation; startup/wake settings remain separately saved."})
target = out / "automation-baseline-audit.json"
target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(report, ensure_ascii=False, indent=2))
