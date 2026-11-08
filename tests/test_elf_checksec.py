"""Nol jaringan — test elf_checksec (enumerasi mitigasi ELF: NX/PIE/
RELRO/canary; fail-closed). ELF uji dibangun byte-per-byte dari
spesifikasi (tanpa compiler, tanpa jaringan)."""
from __future__ import annotations

import io
import contextlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import elf_checksec as ecs  # noqa: E402

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 4, 5, 6
DT_BIND_NOW, DT_FLAGS, DT_RPATH = 24, 30, 15
DT_GNU_HASH, DT_FLAGS_1 = 0x6FFFFEF5, 0x6FFFFFFB


def build_elf(*, is64: bool = True, little: bool = True, etype: int = 3,
              has_gnu_stack: bool = True, gnu_stack_x: bool = False,
              has_interp: bool = False, has_relro: bool = False,
              bind_now: bool = False, flags1_pie: bool = False,
              flags1_now: bool = False, canary_names: tuple = (),
              fortify_names: tuple = (), use_gnu_hash: bool = False,
              omit_hash: bool = False,
              no_dynamic: bool = False, has_rpath: bool = False,
              machine: int | None = None, extra_payload: bytes = b""
              ) -> bytes:
    """Bangun binary ELF minimal tapi sah (layout identitas vaddr)."""
    prefix = "<" if little else ">"
    ei_class = 2 if is64 else 1
    ei_data = 1 if little else 2
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    ehdr_size = 64 if is64 else 52
    phent = 56 if is64 else 32

    names = [n.encode() if isinstance(n, str) else n
             for n in (*canary_names, *fortify_names)]
    strtab = b"\x00"
    offs: list[int] = []
    for n in names:
        offs.append(len(strtab))
        strtab += n + b"\x00"
    symtab = b""
    for i, n in enumerate(names):
        if is64:
            symtab += struct.pack(prefix + "IBBHQQ", offs[i], 0x12, 0, 0,
                                  0x1000, 0)
        else:
            symtab += struct.pack(prefix + "IIIBBH", offs[i], 0x1000, 0,
                                  0x12, 0, 0)
    symcount = len(names) + 1  # + simbol nol

    hash_blob = b""
    if use_gnu_hash:
        if symcount > 1:
            bucket = [symcount - 1]
            chains = [0] * (symcount - 1)
            chains[-1] = 1
        else:
            bucket, chains = [0], []
        hash_blob = struct.pack(prefix + "IIII", 1, 1, 1, 0)
        hash_blob += b"\x00" * (8 if is64 else 4)  # bloom
        hash_blob += struct.pack(prefix + "I", *bucket)
        hash_blob += struct.pack(prefix + f"{len(chains)}I", *chains) \
            if chains else b""
    else:
        bucket = [1] if symcount > 1 else [0]
        chains = [1] * (symcount - 1)
        hash_blob = struct.pack(prefix + "II", 1, symcount)
        hash_blob += struct.pack(prefix + "I", *bucket)
        hash_blob += struct.pack(prefix + f"{len(chains)}I", *chains) \
            if chains else b""

    interp_data = b"/lib64/ld-linux-x86-64.so.2\x00"

    nph = 1 + int(has_interp) + int(has_gnu_stack) + int(has_relro) \
        + int(not no_dynamic)
    content_start = ehdr_size + nph * phent
    interp_off = content_start
    strtab_off = interp_off + (len(interp_data) if has_interp else 0)
    symtab_off = strtab_off + len(strtab)
    hash_off = symtab_off + len(symtab)
    dyn_off = hash_off + len(hash_blob)
    extra_off = dyn_off + (0 if no_dynamic else 0)
    total = extra_off + len(extra_payload)

    dyn_entries: list[tuple[int, int]] = []
    if not no_dynamic:
        dyn_entries = [(DT_STRTAB, strtab_off), (DT_SYMTAB, symtab_off)]
        if omit_hash:
            pass  # tanpa DT_HASH/DT_GNU_HASH -> dynsym tak terenumerate
        elif use_gnu_hash:
            dyn_entries.append((DT_GNU_HASH, hash_off))
        else:
            dyn_entries.append((DT_HASH, hash_off))
        if has_rpath:
            dyn_entries.append((DT_RPATH, strtab_off))
        if bind_now:
            dyn_entries.append((DT_FLAGS, 0x8))
            dyn_entries.append((DT_BIND_NOW, 0))
        if flags1_now or flags1_pie:
            f1 = (0x1 if flags1_now else 0) | (0x08000000
                                               if flags1_pie else 0)
            dyn_entries.append((DT_FLAGS_1, f1))
        dyn_entries.append((DT_NULL, 0))
    if is64:
        dyn_blob = b"".join(struct.pack(prefix + "QQ", t, v)
                            for t, v in dyn_entries)
    else:
        dyn_blob = b"".join(struct.pack(prefix + "II", t, v)
                            for t, v in dyn_entries)

    phdrs: list[bytes] = [(PT_LOAD, 0x5, 0, 0, total)]
    if has_interp:
        phdrs.append((PT_INTERP, 0x4, interp_off, interp_off,
                      len(interp_data)))
    if has_gnu_stack:
        phdrs.append((PT_GNU_STACK, 0x7 if gnu_stack_x else 0x6, 0, 0, 0))
    if has_relro:
        phdrs.append((PT_GNU_RELRO, 0x4, 0, 0, 0x100))
    if not no_dynamic:
        phdrs.append((PT_DYNAMIC, 0x6, dyn_off, dyn_off, len(dyn_blob)))

    ph_blob = b""
    for p_type, flags, off, vaddr, filesz in phdrs:
        if is64:
            ph_blob += struct.pack(prefix + "IIQQQQQQ", p_type, flags,
                                   off, vaddr, vaddr, filesz, filesz,
                                   0x1000)
        else:
            ph_blob += struct.pack(prefix + "IIIIIIII", p_type, off,
                                   vaddr, vaddr, filesz, filesz, flags,
                                   0x1000)

    ehdr = ident + struct.pack(
        prefix + (ecs.ELF64_HEADER if is64 else ecs.ELF32_HEADER),
        etype, machine if machine is not None else (0x3E if is64 else 3),
        1, 0x1000, ehdr_size, 0, 0, ehdr_size, phent, len(phdrs), 0, 0,
        0)
    blob = bytearray(ehdr + ph_blob)
    blob += interp_data if has_interp else b""
    blob += strtab + symtab + hash_blob
    if not no_dynamic:
        blob += dyn_blob
    blob += extra_payload
    return bytes(blob)


def _run_cli(argv: list[str]) -> tuple[int, dict | None, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = ecs.main(argv)
    out = None
    if "--out" in argv:
        dest = Path(argv[argv.index("--out") + 1])
        if dest.exists():
            out = json.loads(dest.read_text(encoding="utf-8"))
    else:
        try:
            out = json.loads(buf.getvalue())
        except json.JSONDecodeError:
            out = None
    return code, out, buf.getvalue()


FULL = dict(has_gnu_stack=True, gnu_stack_x=False, has_interp=True,
            has_relro=True, bind_now=True,
            canary_names=("__stack_chk_fail",))


class ElfChecksec(unittest.TestCase):
    def _write(self, blob: bytes) -> str:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            return fh.name

    def _one(self, **kw) -> dict:
        path = self._write(build_elf(**{**FULL, **kw}))
        code, out, _ = _run_cli([path])
        self.assertEqual(code, 0)
        assert out is not None
        self.assertEqual(out["summary"]["total"], 1)
        return out["files"][0]

    def test_full_mitigated_64(self) -> None:
        r = self._one(**FULL)
        self.assertEqual(r["verdict"], "MITIGATED")
        self.assertEqual(r["relro_level"], "full")
        self.assertEqual(r["mitigations"],
                         {"NX": True, "PIE": True, "RELRO_FULL": True,
                          "CANARY": True})
        self.assertEqual(r["elf_class"], 64)
        self.assertEqual(r["machine"], "x86-64")

    def test_nx_disabled_is_weak(self) -> None:
        r = self._one(gnu_stack_x=True)
        self.assertFalse(r["mitigations"]["NX"])
        self.assertEqual(r["verdict"], "WEAK")

    def test_gnu_stack_absent_is_weak_with_note(self) -> None:
        r = self._one(has_gnu_stack=False)
        self.assertFalse(r["mitigations"]["NX"])
        self.assertEqual(r["verdict"], "WEAK")
        self.assertTrue(any("GNU_STACK" in n for n in r["notes"]))

    def test_et_exec_no_pie(self) -> None:
        r = self._one(etype=2, has_interp=False)
        self.assertFalse(r["mitigations"]["PIE"])
        self.assertEqual(r["verdict"], "WEAK")

    def test_relro_partial_without_bind_now(self) -> None:
        r = self._one(bind_now=False)
        self.assertEqual(r["relro_level"], "partial")
        self.assertFalse(r["mitigations"]["RELRO_FULL"])
        self.assertEqual(r["verdict"], "PARTIAL")

    def test_relro_none(self) -> None:
        r = self._one(has_relro=False)
        self.assertEqual(r["relro_level"], "none")
        self.assertFalse(r["mitigations"]["RELRO_FULL"])
        self.assertEqual(r["verdict"], "PARTIAL")

    def test_relro_via_flags1_now(self) -> None:
        r = self._one(bind_now=False, flags1_now=True)
        self.assertEqual(r["relro_level"], "full")
        self.assertEqual(r["verdict"], "MITIGATED")

    def test_no_canary_symbol(self) -> None:
        r = self._one(canary_names=())
        self.assertFalse(r["mitigations"]["CANARY"])
        self.assertEqual(r["verdict"], "PARTIAL")

    def test_dso_inconclusive(self) -> None:
        # INCONCLUSIVE -> exit 2 (pola pe_mitigation_scan)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(build_elf(**{**FULL, "has_interp": False}))
            path = fh.name
        code, out, _ = _run_cli([path])
        self.assertEqual(code, 2)
        assert out is not None
        r = out["files"][0]
        self.assertEqual(r["verdict"], "INCONCLUSIVE")
        assert r["reason"] is not None
        self.assertIn("shared object", r["reason"])
        # fakta mitigasi tetap dilaporkan
        self.assertTrue(r["mitigations"]["NX"])
        self.assertTrue(r["mitigations"]["CANARY"])

    def test_pie_via_flags1_only(self) -> None:
        r = self._one(has_interp=False, flags1_pie=True)
        self.assertTrue(r["mitigations"]["PIE"])
        self.assertEqual(r["verdict"], "MITIGATED")

    def test_elf32_big_endian(self) -> None:
        r = self._one(is64=False, little=False, machine=0x08)
        self.assertEqual(r["elf_class"], 32)
        self.assertEqual(r["endian"], "be")
        self.assertEqual(r["machine"], "mips")
        self.assertEqual(r["verdict"], "MITIGATED")

    def test_gnu_hash_path(self) -> None:
        r = self._one(use_gnu_hash=True)
        self.assertTrue(r["mitigations"]["CANARY"])
        self.assertEqual(r["verdict"], "MITIGATED")

    def test_gnu_hash_empty_bucket(self) -> None:
        r = self._one(use_gnu_hash=True, canary_names=())
        self.assertFalse(r["mitigations"]["CANARY"])
        self.assertEqual(r["verdict"], "PARTIAL")

    def test_canary_unresolvable_inconclusive(self) -> None:
        # dynsym ada tapi tanpa tabel hash -> fail-closed (None),
        # BUKAN "canary absen"
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(build_elf(omit_hash=True))
            path = fh.name
        code, out, _ = _run_cli([path])
        self.assertEqual(code, 2)  # INCONCLUSIVE -> exit 2 (fail-closed)
        assert out is not None
        r = out["files"][0]
        self.assertIsNone(r["mitigations"]["CANARY"])
        self.assertEqual(r["verdict"], "INCONCLUSIVE")
        self.assertTrue(any("enumerate" in n for n in r["notes"]))

    def test_static_binary_byte_search(self) -> None:
        payload = b"JUNKJUNK" + b"__stack_chk_fail\x00" + b"JUNK"
        r = self._one(etype=2, has_interp=False, no_dynamic=True,
                      has_relro=False, extra_payload=payload)
        self.assertTrue(r["mitigations"]["CANARY"])
        self.assertFalse(r["mitigations"]["PIE"])
        self.assertEqual(r["verdict"], "WEAK")
        self.assertTrue(any("statis" in n for n in r["notes"]))

    def test_static_without_canary(self) -> None:
        r = self._one(etype=2, has_interp=False, no_dynamic=True,
                      has_relro=False, canary_names=(),
                      extra_payload=b"no symbols here at all")
        self.assertFalse(r["mitigations"]["CANARY"])
        self.assertTrue(any("pencarian byte" in n for n in r["notes"]))

    def test_fortify_and_rpath_notes(self) -> None:
        r = self._one(fortify_names=("__printf_chk",),
                      has_rpath=True)
        self.assertTrue(r["fortify_hint"])
        self.assertTrue(any("DT_RPATH" in n for n in r["notes"]))
        # fortify/rpath tidak memengaruhi verdict
        self.assertEqual(r["verdict"], "MITIGATED")

    def test_non_elf_and_truncated_exit_2(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"MZ\x90\x00 not elf at all")
            path = fh.name
        code, out, _ = _run_cli([path])
        self.assertEqual(code, 2)
        assert out is not None
        self.assertEqual(out["files"][0]["verdict"], "INCONCLUSIVE")
        self.assertIn("bukan file ELF", out["files"][0]["reason"])
        # header terpangkas
        short = self._write(build_elf()[:30])
        code, out, _ = _run_cli([short])
        self.assertEqual(code, 2)
        assert out is not None
        self.assertIn("terpangkas", out["files"][0]["reason"])

    def test_require_gate(self) -> None:
        path = self._write(build_elf(**{**FULL, "canary_names": ()}))
        code, out, err = _run_cli([path, "--require",
                                   "NX,PIE,RELRO_FULL,CANARY"])
        self.assertEqual(code, 1)
        code, _, _ = _run_cli([path, "--require", "NX,BOGUS"])
        self.assertEqual(code, 2)
        ok = self._write(build_elf(**FULL))
        code, _, _ = _run_cli([ok, "--require", "NX,PIE,RELRO_FULL,CANARY"])
        self.assertEqual(code, 0)

    def test_multiple_files_summary(self) -> None:
        a = self._write(build_elf(**FULL))
        b = self._write(build_elf(**{**FULL, "gnu_stack_x": True}))
        code, out, _ = _run_cli([a, b])
        self.assertEqual(code, 0)
        assert out is not None
        self.assertEqual(out["summary"],
                         {"total": 2, "mitigated": 1, "partial": 0,
                          "weak": 1, "inconclusive": 0})

    def test_deterministic(self) -> None:
        a = self._write(build_elf(**FULL))
        code1, out1, _ = _run_cli([a])
        code2, out2, _ = _run_cli([a])
        self.assertEqual(code1, code2)
        self.assertEqual(out1, out2)


if __name__ == "__main__":
    unittest.main()
