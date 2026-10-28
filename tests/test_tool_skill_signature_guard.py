"""Guard kontrak skill (F19) — dua kelas drift yang membuat tools/ telat.

Latar: verify_findings crash di 11 program karena
email_sender_surface.audit() berubah di F18. Pelajarannya dua:
  1. RETURN SHAPE: semua skill mengembalikan (rows, meta) tuple —
     skill yang balikin list telanjang akan membuat pemanggil
     `rows, _ = mod.audit(...)` meledak. Dikunci sebagai kontrak.
  2. ARITY: pemanggilan mod.audit(...) di tools/ dicek terhadap
     signature audit() modul skill via inspect.signature.bind()
     (dummy None — bind hanya cek arity/nama, bukan tipe).

Statis via AST — nol eksekusi kode tools, nol jaringan.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))


def _iter_skill_modules():
    for p in sorted((ROOT / "skills").glob("*.py")):
        try:
            yield p.name, importlib.import_module(p.stem)
        except Exception:
            continue


def _audit_fn_nodes(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "audit":
            yield node


def _collect_audit_calls(source: str):
    """Yield (module_name_dari_alias, func_name, call_node) untuk semua
    panggilan <alias>.<func>(...) di satu file Python."""
    tree = ast.parse(source)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)):
            mod = aliases.get(node.func.value.id, node.func.value.id)
            yield mod, node.func.attr, node


class AuditReturnShapeContractTest(unittest.TestCase):
    """Kontrak: audit() skill selalu balikin (rows, meta) — 2-tuple."""

    def test_every_skill_audit_returns_rows_meta_tuple(self):
        bad = []
        for fname, mod in _iter_skill_modules():
            fn = getattr(mod, "audit", None)
            if fn is None:
                continue
            src = pathlib.Path(ROOT / "skills" / fname).read_text(
                encoding="utf-8-sig")  # tahan BOM
            tree = ast.parse(src)
            for node in _audit_fn_nodes(tree):
                rets = [n for n in ast.walk(node)
                        if isinstance(n, ast.Return)]
                if not rets:
                    bad.append(f"{fname}: audit() tanpa return")
                    continue
                for r in rets:
                    ok = (isinstance(r.value, ast.Tuple)
                          and len(r.value.elts) == 2)
                    if not ok:
                        bad.append(
                            f"{fname}:{r.lineno}: audit() return bukan "
                            "(rows, meta) 2-tuple")
        self.assertEqual(bad, [],
                         "kontrak return audit() dilanggar:\n"
                         + "\n".join(bad))


class ToolSkillSignatureGuardTest(unittest.TestCase):
    def test_every_tool_audit_call_matches_skill_signature(self):
        errors = []
        for tool_path in sorted((ROOT / "tools").glob("*.py")):
            src = tool_path.read_text(encoding="utf-8")
            for mod_name, func_name, call in _collect_audit_calls(src):
                if func_name != "audit":
                    continue
                try:
                    skill = importlib.import_module(mod_name)
                except Exception:
                    continue  # bukan modul skills (stdlib/modul tools)
                if not hasattr(skill, "audit"):
                    continue
                sig = inspect.signature(skill.audit)
                args = [ast.literal_eval(a) if isinstance(a, ast.Constant)
                        else None for a in call.args]
                kwargs = {kw.arg: None for kw in call.keywords
                          if kw.arg and kw.arg != "kwargs"}
                try:
                    sig.bind(*args, **kwargs)
                except TypeError as exc:
                    errors.append(
                        f"{tool_path.name}:{call.lineno} {mod_name}.audit() "
                        f"— {exc}")
        self.assertEqual(errors, [],
                         "pemanggil skill di tools/ tidak cocok dengan "
                         "signature audit() sekarang:\n" + "\n".join(errors))

    def test_guard_catches_wrong_arity_call(self):
        # bukti guard bekerja: pemanggilan tanpa argumen wajib harus
        # terdeteksi sebagai TypeError oleh bind()
        src = ("import rdap_whois as rd\n"
               "rd.audit()\n")
        caught = False
        for mod_name, func_name, call in _collect_audit_calls(src):
            skill = importlib.import_module(mod_name)
            sig = inspect.signature(getattr(skill, func_name))
            try:
                sig.bind(*[None] * len(call.args),
                         **{kw.arg: None for kw in call.keywords if kw.arg})
            except TypeError:
                caught = True
        self.assertTrue(caught, "arity salah harus tertangkap bind()")


if __name__ == "__main__":
    unittest.main(verbosity=1)
