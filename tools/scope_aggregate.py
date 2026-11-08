"""[SAFETY: read-only] scope_aggregate — gabung ekspor kebijakan multi-program.

Pertanyaan yang dijawab: "daftar aset ter-konsolidasi lintas program apa
yang AMAN dikerjakan, dan aset mana yang KONFLIK sehingga wajib diklarifikasi
dulu?" Satu aset yang diizinkan program A tapi dilarang program B (atau
kontradiksi di dalam satu program) = jangan diuji sebelum jelas.

Konsep dari awarexone/Agentic-Bug-Hunter (MIT) — agregator scope lintas
platform bug bounty. Dibangun from scratch TANPA menyalin kode: versi ABH
menarik dump platform via jaringan (bbscope/bounty-targets-data); di sini
NOL jaringan — input adalah ekspor kebijakan JSON yang sudah dimiliki
operator (bentuk sama dengan tools/scope_gate.py), diproses murni lokal.

Read-only, NOL jaringan. Parser kanonik dipakai ulang dari scope_gate
(SATU parser untuk semua keputusan scope — tidak ada parser kedua yang
bisa menyimpang).

Yang dikerjakan:
  - dedup aset antar program (kunci kanonik dari komponen rule: wildcard/
    base/port/path, atau jaringan IP) + pencatatan klaim per program;
  - deteksi KONFLIK (temuan MEDIUM, perlu klarifikasi):
      * intra : KUNCI KANONIK SAMA in-scope DAN out-of-scope di program
                yang SAMA (kebijakan kontradiktif). Carve-out normal
                (wildcard in-scope + eksklusi subdomain di program yang
                sama) BUKAN konflik — itu struktur kebijakan yang wajar
                (deny-dinilai-dulu di gate), bukan kontradiksi.
      * cross : aset in-scope di program A tapi out-of-scope di program B
                (klaim bertabrakan antar program) — dideteksi SEMANTIK,
                bukan string sama persis: wildcard in-scope "*.target.com"
                kontra out-of-scope "staging.target.com" tetap kena
                (subdomain tertentang), CIDR beririsan juga kena.
    Himpunan yang dipertentangkan mengikuti semantik gate: out-of-scope
    eksak melarang host DAN subdomennya; wildcard (kedua sisi) tidak
    menutup apex; in-scope eksak hanya host itu. Port/path pembatas
    diabaikan saat deteksi (konflik dilaporkan lebih luas — aman, bukan
    lebih sempit). Kunci in-scope yang tertentang lintas program TIDAK
    dibuang dari daftar bersih (kebijakan programnya sendiri tetap sah);
    aset yang disengketakan tetap masuk daftar konflik dan dikeluarkan
    dari daftar bersih.
  - ringkasan per program (jumlah rule unik in/out) + catatan klaim ganda
    (aset sama in-scope di >= 2 program = info, bukan temuan).

Pemakaian:
  python tools/scope_aggregate.py --policy a.json --policy b.json --out agg.json
  python tools/scope_aggregate.py --policy a.json --policy b.json --list bersih.txt
Exit: 0 = konsolidasi bersih; 1 = ada konflik (kecuali --fail-on none);
2 = kebijakan/input tak bisa dinilai (fail-closed — konsolidasi parsial
tidak boleh diam-diam dipakai).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import scope_gate as sg  # noqa: E402  (parser kanonik dipakai ulang)

SCHEMA = "secai.scope-aggregate/1"
TOOL = "scope_aggregate"


def _rule_key(rule: sg.Rule) -> str:
    """Kunci kanonik aset dari komponen rule (bukan string mentah).

    "TARGET.com" dan "target.com" jatuh di kunci sama; "target.com" vs
    "target.com:8443" vs "target.com/api/" tetap berbeda (lingkup beda).
    """
    if rule["kind"] == "ip":
        return str(rule["network"])
    key = ("*." + rule["base"]) if rule["wild"] else rule["base"]
    if rule["port"] is not None:
        key += f":{rule['port']}"
    if rule["path"] is not None and rule["path"] != "/":
        key += rule["path"]
    return key


def _domain_conflict(in_rule: sg.Rule, out_rule: sg.Rule) -> bool:
    """True bila himpunan aset yang DIIZINKAN in_rule beririsan dengan
    himpunan yang DILARANG out_rule.

    Himpunan (mengikuti semantik gate):
      in eksak  H  -> {H}
      in wild  *.B  -> sub(B)          (apex TIDAK termasuk)
      out eksak  H -> {H} U sub(H)     (melarang itu melarang cabangnya)
      out wild  *.B -> sub(B)          (apex TIDAK termasuk)
    """
    if in_rule["wild"]:
        bi = in_rule["base"]
        if out_rule["wild"]:
            bo = out_rule["base"]
            return bi == bo or bi.endswith("." + bo) or bo.endswith("." + bi)
        ho = out_rule["base"]
        return ho == bi or ho.endswith("." + bi)
    hi = in_rule["base"]
    if out_rule["wild"]:
        return hi.endswith("." + out_rule["base"])
    return hi == out_rule["base"]


def _rules_conflict(in_rule: sg.Rule, out_rule: sg.Rule) -> bool:
    """Konflik in-scope vs out-of-scope untuk semua jenis rule."""
    if in_rule["kind"] == "ip" or out_rule["kind"] == "ip":
        if in_rule["kind"] != out_rule["kind"]:
            return False  # IPv4 vs IPv6 tidak pernah beririsan
        return in_rule["network"].overlaps(out_rule["network"])
    return _domain_conflict(in_rule, out_rule)


def _more_specific_key(a: sg.Rule, b: sg.Rule) -> str:
    """Kunci aset yang LEBIH SPESIFIK dari dua rule yang bertentangan —
    eksak di atas wildcard; IP tunggal di atas CIDR; CIDR sempit di atas
    lebar. Laporan konflik menunjuk aset konkret yang disengketakan."""
    if a["kind"] == "ip":
        if a["network"].prefixlen != b["network"].prefixlen:
            return _rule_key(a if a["network"].prefixlen > b["network"].prefixlen
                             else b)
        return _rule_key(a)
    if a["wild"] != b["wild"]:
        return _rule_key(b if a["wild"] else a)  # yang eksak menang
    return _rule_key(a)  # dua wildcard/eaksak sama — pilih deterministik


def _own_oos_denies(in_policy: sg.ParsedPolicy, probe_host: str) -> bool:
    """True bila kebijakan in-side SENDIRI sudah menolak probe_host.

    Digunakan utk membuang konflik cross palsu: bila program A juga
    meng-exclude aset yang disengketakan (carve-out yang SAMA antar
    program), A tidak benar-benar mengizinkannya — tidak ada
    pertentangan yang perlu diklarifikasi."""
    target = {"kind": "domain", "host": probe_host, "port": None,
              "path": "/", "scheme": "https"}
    for rule in in_policy.out_rules:
        if rule["kind"] == "domain" and sg._exclusion_matches(rule, target):
            return True
    return False


def consolidate(policies: list) -> dict:
    """Gabung kebijakan ter-parse jadi konsolidasi + konflik + ringkasan.

    policies: list[(ParsedPolicy, program_name)]. Semua harus valid —
    konsolidasi parsial tidak pernah dihasilkan (fail-closed di pemanggil).
    """
    assets: dict = {}

    def _record(rule: sg.Rule, program: str, side: str) -> None:
        key = _rule_key(rule)
        rec = assets.setdefault(key, {
            "asset": key,
            "kind": rule["kind"],
            "in_programs": [],
            "out_programs": [],
            "in_rules": [],
            "out_rules": [],
        })
        pool = rec["in_programs"] if side == "in" else rec["out_programs"]
        rpool = rec["in_rules"] if side == "in" else rec["out_rules"]
        if program not in pool:
            pool.append(program)
        rpool.append({"rule": rule["raw"], "program": program})

    for policy, program in policies:
        for rule in policy.in_rules:
            _record(rule, program, "in")
        for rule in policy.out_rules:
            _record(rule, program, "out")

    # --- deteksi konflik: setiap pasangan (in-rule, out-rule) ---------------
    seen: set = set()
    conflicts: list = []
    conflicted_keys: set = set()  # aset disengketakan — tidak layak daftar bersih
    for in_policy, in_program in policies:
        for in_rule in in_policy.in_rules:
            for out_policy, out_program in policies:
                for out_rule in out_policy.out_rules:
                    same_program = in_program == out_program
                    exact_key = _rule_key(in_rule) == _rule_key(out_rule)
                    if same_program:
                        # Carve-out (wildcard in-scope vs eksklusi
                        # subdomain-nya sendiri) = struktur kebijakan
                        # normal, bukan kontradiksi — gate menilai deny
                        # dulu memang dengan desain begitu. Hanya
                        # tabrakan kunci eksak yang membuat satu
                        # kebijakan melarang apa yang diizinkannya.
                        if not exact_key:
                            continue
                    elif not _rules_conflict(in_rule, out_rule):
                        continue
                    kind = "intra" if same_program else "cross"
                    sig = (in_program, out_program,
                           _rule_key(in_rule), _rule_key(out_rule), kind)
                    if sig in seen:
                        continue
                    disputed = _more_specific_key(in_rule, out_rule)
                    if kind == "cross" and in_rule["kind"] == "domain" \
                            and out_rule["kind"] == "domain":
                        # buang konflik palsu: kebijakan in-side sendiri
                        # sudah menolak aset yang disengketakan (carve-out
                        # sama antar program) -> tidak ada pertentangan.
                        # (Pasangan rule IP dilewati — klaim CIDR cukup
                        # dinilai dari irisan jaringan.)
                        key_rule = (in_rule
                                    if disputed == _rule_key(in_rule)
                                    else out_rule)
                        probe = (("x." if key_rule["wild"] else "")
                                 + key_rule["base"])
                        if _own_oos_denies(in_policy, probe):
                            continue
                    seen.add(sig)
                    conflicted_keys.add(disputed)
                    if kind == "intra":
                        conflicted_keys.add(_rule_key(in_rule))
                        reason = (
                            f"kebijakan {in_program!r} kontradiktif: "
                            f"{_rule_key(in_rule)} in-scope tapi "
                            f"{_rule_key(out_rule)} out-of-scope — "
                            f"perlu klarifikasi ke program")
                    else:
                        reason = (
                            f"{_rule_key(in_rule)} in-scope di program "
                            f"{in_program!r} tapi out-of-scope di program "
                            f"{out_program!r} ({_rule_key(out_rule)}) — "
                            f"perlu klarifikasi sebelum diuji")
                    conflicts.append({
                        "asset": disputed,
                        "kind": out_rule["kind"],
                        "conflict": kind,
                        "in_rule": in_rule["raw"],
                        "in_program": in_program,
                        "out_rule": out_rule["raw"],
                        "out_program": out_program,
                        "severity": "medium",
                        "reason": reason,
                    })
    conflicts.sort(key=lambda c: (c["conflict"], c["asset"],
                                  c["in_program"], c["out_program"]))

    for key, rec in assets.items():
        rec["in_programs"] = sorted(set(rec["in_programs"]))
        rec["out_programs"] = sorted(set(rec["out_programs"]))
        rec["conflict"] = key in conflicted_keys
        if len(rec["in_programs"]) > 1:
            rec["note"] = ("di-klaim in-scope oleh >= 2 program: "
                           + ", ".join(rec["in_programs"]))
        elif rec["conflict"]:
            rec["note"] = "konflik — wajib klarifikasi sebelum diuji"
        else:
            rec["note"] = None

    summary = {
        "programs": len(policies),
        "unique_assets": len(assets),
        "conflicts": len(conflicts),
        "multi_program_in_scope": sum(
            1 for r in assets.values() if len(r["in_programs"]) > 1),
        "clean_in_scope": sum(
            1 for r in assets.values()
            if r["in_programs"] and not r["conflict"]),
    }
    return {"assets": list(assets.values()), "conflicts": conflicts,
            "summary": summary}


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Konsolidasi ekspor kebijakan scope multi-program: "
                     "dedup, deteksi konflik, ringkasan per program. "
                     "NOL jaringan. Port konsep ABH (MIT)."))
    parser.add_argument("--policy", action="append", required=True,
                        metavar="FILE",
                        help="ekspor kebijakan JSON (boleh diulang)")
    parser.add_argument("--out", metavar="FILE",
                        help="tulis bukti JSON konsolidasi ke file")
    parser.add_argument("--list", metavar="FILE",
                        help="tulis daftar aset in-scope bersih "
                             "(tanpa konflik), satu per baris")
    parser.add_argument("--json", action="store_true",
                        help="cetak JSON ke stdout")
    parser.add_argument("--fail-on", choices=("any", "none"), default="any",
                        help="ambang exit 1: any = konflik -> exit 1 "
                             "(default), none = lapor saja")
    args = parser.parse_args(argv)

    # Parse SEMUA kebijakan dulu; satu saja gagal = gagal total (exit 2) —
    # konsolidasi dari pemahaman parsial tidak boleh dipakai.
    policies: list = []
    errors: list = []
    for path in args.policy:
        try:
            parsed = sg.parse_policy_file(path)
        except sg.PolicyError as exc:
            errors.append(str(exc))
            continue
        policies.append((parsed, parsed.program))
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        print(f"ERROR: {len(errors)} dari {len(args.policy)} kebijakan "
              f"gagal dinilai — fail-closed, konsolidasi dibatalkan",
              file=sys.stderr)
        return 2

    result = consolidate(policies)
    conflicts = result["conflicts"]
    exit_code = 1 if (conflicts and args.fail_on == "any") else 0

    evidence = {
        "schema": SCHEMA,
        "tool": TOOL,
        "policies": [
            {
                "program": program,
                "source": policy.path,
                "in_scope": len(policy.in_rules),
                "out_of_scope": len(policy.out_rules),
                "skipped_non_jaringan": sum(
                    1 for s in policy.skipped if s["reason"] == "non_network"),
                "skipped_unparseable": sum(
                    1 for s in policy.skipped if s["reason"] == "unparseable"),
            }
            for policy, program in policies
        ],
        "fail_on": args.fail_on,
        "assets": result["assets"],
        "conflicts": conflicts,
        "summary": result["summary"],
        "exit": exit_code,
    }

    if args.out:
        try:
            Path(args.out).write_text(
                json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: bukti tak bisa ditulis {args.out!r}: {exc}",
                  file=sys.stderr)
            return 2
    if args.list:
        clean = sorted(
            r["asset"] for r in result["assets"]
            if r["in_programs"] and not r["conflict"])
        try:
            Path(args.list).write_text(
                "".join(a + "\n" for a in clean), encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: daftar tak bisa ditulis {args.list!r}: {exc}",
                  file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(evidence, indent=2, ensure_ascii=False))
    else:
        for pol in evidence["policies"]:
            skipped = ""
            if pol["skipped_non_jaringan"] or pol["skipped_unparseable"]:
                skipped = (f", dilewati: {pol['skipped_non_jaringan']} "
                           f"non-jaringan + {pol['skipped_unparseable']} "
                           f"tak-terparse")
            print(f"[{pol['program']}] in={pol['in_scope']} "
                  f"out={pol['out_of_scope']}{skipped} ({pol['source']})")
        for c in conflicts:
            print(f"KONFLIK-{c['conflict'].upper()} (medium): {c['asset']} "
                  f"— {c['reason']}")
        s = result["summary"]
        print(f"Ringkasan: {s['programs']} program, {s['unique_assets']} "
              f"aset unik, {s['conflicts']} konflik, "
              f"{s['clean_in_scope']} aset in-scope bersih -> exit {exit_code}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
