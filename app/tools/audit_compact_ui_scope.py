"""Verify that the compact UI revision changes no existing action implementation."""
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant/vendor"))
from PyInstaller.archive.readers import ZlibArchiveReader


def norm(value):
    if isinstance(value, types.CodeType):
        return (value.co_code, tuple(norm(x) for x in value.co_consts), value.co_names,
                value.co_varnames, value.co_argcount, value.co_kwonlyargcount,
                value.co_flags, value.co_exceptiontable)
    return value


def children(code):
    return {c.co_name: c for c in code.co_consts if isinstance(c, types.CodeType)}


archive = ZlibArchiveReader(str(ROOT / ".planning/ui-1.5/pre-compact-dialog.pyz"))
changed = []
unchanged = []
for source in sorted((ROOT / "src/campus_net_assistant").glob("*.py")):
    name = "campus_net_assistant." + source.stem
    if name not in archive.toc:
        continue
    before = archive.extract(name)
    after = compile(source.read_text(encoding="utf-8-sig"), before.co_filename, "exec")
    if norm(before) == norm(after):
        unchanged.append(source.name)
        continue
    changed.append(source.name)
    old, new = children(before), children(after)
    assert old.keys() == new.keys()
    if source.stem == "native_wired_gui":
        assert norm(old["NativeWorker"]) == norm(new["NativeWorker"])
        old, new = children(old["NativeWiredDialog"]), children(new["NativeWiredDialog"])
        assert old.keys() == new.keys()
        assert all(norm(old[n]) == norm(new[n]) for n in old if n != "__init__")
    elif source.stem == "ui_layout":
        assert all(norm(old[n]) == norm(new[n]) for n in old if n != "rebuild")
    else:
        raise AssertionError("Unexpected runtime change: " + source.name)
assert changed == ["native_wired_gui.py", "ui_layout.py"], changed
report = dict(changed_modules=changed, unchanged_modules=unchanged,
              only_changed_functions=["NativeWiredDialog.__init__", "ui_layout.rebuild"],
              existing_actions_and_workers_unchanged=True)
(ROOT / ".planning/ui-1.5/compact-dialog-scope.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"Scope verified: {len(unchanged)} unchanged modules; only dialog construction and layout changed.")
