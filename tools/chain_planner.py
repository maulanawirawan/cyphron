r"""[PLANNER: read-only] chain_planner — rencanakan rantai eksploitasi
A→B→C dari temuan findings.json cyphron: satu temuan rendah sering
menjadi submittable begitu digabung — tool ini menyusun kandidat
rantai secara deterministik dari tabel rantai terkurasi yang
MEMETAKAN setiap langkah ke tool cyphron yang benar-benar ada.

Port konsep dari awarexone/Agentic-Bug-Hunter 'chain-builder' agent
(dan /chain) — atribusi konsep, lisensi sumber MIT. Dibangun FROM
SCRATCH: tabel rantai ditulis ulang untuk ekosistem cyphron (langkah
B selalu menyebut tool cyphron pembawa buktinya, bukan alat live
pihak ketiga), semantik gabungan severity dinyatakan eksplisit per
baris tabel — tidak pernah ditebak. Skill sumber = agent LLM yang
menyusun rantai naratif; tool ini memilih sisi deterministik: tabel
data + pencocokan pola + aturan gabungan yang bisa diaudit.

Ranah tetangga eksplisit: merge_findings/cyphron merge = dedup
temuan; verify_gate = klaim status kerja; brocards_triage = logika
triase laporan; submission_gate (KOORDINATOR, satu program) = gerbang
pra-submission bug bounty; attack_coverage = cakupan deteksi ATT&CK.
Tool ini TIDAK mengeksekusi apa pun, TIDAK memprobe target — ia hanya
merencanakan; eksekusi probe = jalur gated proof tier (exploit_*).

Input -> mekanisme -> output:
  - Input   : --findings FILE (findings.json satu tool ATAU gabungan;
              array / {"findings": [...]}), --tools-dir PATH opsional
              (verifikasi jujur cakupan: langkah B yang tool-nya tak
              ada di repo ditandai tool-missing, bukan diam-diam
              direkomendasikan).
  - Mekanisme: klasifikasi tiap temuan ke kelas rantai (pencocokan
              nama tool + pola check + CWE — kelas tak dikenal masuk
              meta unmapped, tidak dibuang diam-diam), lalu lookup
              tabel rantai terkurasi CHAINS di bawah:
              tiap baris = A-side (kelas) -> langkah B (apa yang
              dicari, tool pembawa bukti, probe kind) -> aturan
              gabungan (severity kombinasi + kondisi uplift).
              B-side yang buktinya SUDAH ada di findings masuk =
              rantai "siap digabung" (kombinasi dihitung); yang belum
              = rantai "kandidat" + langkah bukti berikutnya.
  - Output  : chains per temuan (state ready/candidate, langkah,
              tool, severity gabungan, evidence-needed) + summary
              (unmapped, tool-missing) + notes; exit 1 bila ada
              rantai ready/candidate, 2 bila input rusak (fail-closed).

Tabel rantai: 12 pola (SSRF->metadata, redirect->OAuth, JWT->forge,
XSS->priv-esc, bucket->JS-secret->OAuth, takeover->OAuth, prompt-inj
->IDOR, traversal->RCE-sinyal, IDOR->method-mutation, GraphQL->
mutation-authz, CORS->token-theft, cache-poison->sessi). Semua
severity gabungan = DATA tabel (bukan vonis tool).

Stdlib json/argparse. Nol jaringan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "chain_planner/v1"
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ------------------------------------------------------- tabel rantai
# a_tools    : nama tool cyphron yang menghasilkan temuan A (sisi
#              kiri; boleh beberapa alias)
# a_checks   : pola awalan check-id temuan A (regex sederhana)
# a_cwes     : CWE yang memetakan ke kelas A
# b_step     : langkah berikutnya yang dicari
# b_tool     : tool cyphron pembawa bukti langkah B
# b_probe    : jenis bukti yang menaikkan verdict (probe kind)
# combined   : severity gabungan yang dinyatakan tabel
# uplift_note: kapan gabungan naik kelas
CHAINS: "list[dict]" = [
    dict(chain_id="ssrf-cloud-metadata",
         b_checks=(r"metadata|169\.254|100\.100\.100",),
         a_tools=("exploit_playbooks",), a_checks=(r"ssrf",),
         a_cwes=("CWE-918",),
         b_step="ssr ke metadata cloud (169.254.169.254 / 100.100.100.200) "
                "dari host yang sama",
         b_tool="exploit_playbooks (SsrfChainPlaybook)",
         b_probe="oob/request-response",
         combined="critical",
         uplift_note="metadata access = kredensial role instance -> "
                     "escalation akun cloud"),
    dict(chain_id="redirect-oauth-code-theft",
         b_checks=("oauth|redirect-uri",),
         a_tools=("open_redirect_surface", "redirect_chain"),
         a_checks=(r"redirect",), a_cwes=("CWE-601",),
         b_step="redirect_uri OAuth menerima varian domain -> code dicuri",
         b_tool="oauth_redirect_audit",
         b_probe="request-response",
         combined="critical",
         uplift_note="redirect terbuka + OAuth tanpa validasi ketat = "
                     "ATO via code theft"),
    dict(chain_id="jwt-weak-to-forge",
         b_checks=("forge|alg-confusion",),
         a_tools=("jwt_token_audit",), a_checks=(r"jwt",),
         a_cwes=("CWE-347", "CWE-327"),
         b_step="forge token (alg:none / HS256 dgn secret lemah / "
                "jwk inline) lalu akses endpoint admin",
         b_tool="exploit_playbooks (JwtAlgConfusionPlaybook)",
         b_probe="request-response",
         combined="critical",
         uplift_note="token ter-forge = auth bypass penuh, bukan cuma "
                     "info disclosure"),
    dict(chain_id="xss-stored-privesc",
         b_checks=("stored|priv-esc|privesc",),
         a_tools=("xss_reflect_check", "payload_lab"),
         a_checks=(r"xss",), a_cwes=("CWE-79",),
         b_step="payload tersimpan disinggung halaman admin (cek "
                "peran penampil) -> auto-POST eskalasi peran",
         b_tool="payload_lab",
         b_probe="request-response",
         combined="critical",
         uplift_note="XSS stored di konteks admin = priv-esc, bukan "
                     "self-XSS"),
    dict(chain_id="bucket-js-secret-oauth",
         b_checks=("js-bundle|client-secret|oauth-secret",),
         a_tools=("cloud_bucket_exposure", "cached_sensitive_files"),
         a_checks=(r"bucket|s3",), a_cwes=("CWE-200",),
         b_step="grepping bundle JS dari bucket -> kredensial OAuth "
                "client secret",
         b_tool="js_secret_scanner",
         b_probe="content",
         combined="high",
         uplift_note="bucket listing + secret di bundle = jalur ATO "
                     "OAuth tanpa interaksi korban"),
    dict(chain_id="takeover-oauth-redirect",
         b_checks=("redirect-uri",),
         a_tools=("takeover_fingerprint_checker", "takeover_cname_hygiene"),
         a_checks=(r"takeover",), a_cwes=("CWE-350",),
         b_step="subdomain mati diklaim -> daftarkan sebagai redirect_uri "
                "OAuth aplikasi korban",
         b_tool="oauth_redirect_audit",
         b_probe="request-response",
         combined="critical",
         uplift_note="takeover + OAuth = ATO penuh (code dikirim ke "
                     "penyerang)"),
    dict(chain_id="prompt-inj-to-idor",
         b_checks=("tool-call|chatbot-idor",),
         a_tools=("prompt_leak_probe",), a_checks=(r"prompt|llm",),
         a_cwes=("CWE-1427",),
         b_step="injeksi instruksi via chatbot LLM -> instruksi memanggil "
                "API internal atas nama user lain (IDOR)",
         b_tool="exploit_playbooks (IdorOrders/IdorMass)",
         b_probe="request-response",
         combined="high",
         uplift_note="prompt injection yang memicu akses data user lain "
                     "menjadi IDOR terverifikasi"),
    dict(chain_id="traversal-rce-signal",
         b_checks=("environ|rce",),
         a_tools=("payload_lab",), a_checks=(r"traversal|lfi",),
         a_cwes=("CWE-22",),
         b_step="baca /proc/self/environ atau file konfigurasi berisi "
                "kredensial -> sinyal RCE/kredensial",
         b_tool="repo_secret_scan",
         b_probe="request-response",
         combined="critical",
         uplift_note="traversal yang mencapai environ = eksekusi konteks "
                     "server terbaca"),
    dict(chain_id="idor-method-mutation",
         b_checks=("idor-mass|method-mutat|write|delete",),
         a_tools=("exploit_playbooks",), a_checks=(r"idor",),
         a_cwes=("CWE-639",),
         b_step="mutasi method pada path sama (GET->PUT/DELETE) — objek "
                "sama sering bocor lintas method",
         b_tool="exploit_playbooks (IdorMass)",
         b_probe="probe-pair",
         combined="high",
         uplift_note="IDOR baca + tulis = integritas, bukan cuma "
                     "kerahasiaan"),
    dict(chain_id="graphql-introspect-mutation",
         b_checks=("mutation",),
         a_tools=("graphql_depth_audit", "graphql_schema_map"),
         a_checks=(r"graphql",), a_cwes=("CWE-200",),
         b_step="introspection terbuka -> cari mutation sensitif tanpa "
                "authz terpisah",
         b_tool="graphql_depth_audit",
         b_probe="request-response",
         combined="high",
         uplift_note="skema terbuka + mutation tanpa authz = mass "
                     "assignment/priv-esc"),
    dict(chain_id="cors-cred-token-theft",
         b_checks=("credentialed",),
         a_tools=("cors_checker",), a_checks=(r"cors",),
         a_cwes=("CWE-942",),
         b_step="CORS credentialed + origin terpantul -> halaman penyerang "
                "membaca token sesi korban",
         b_tool="payload_lab",
         b_probe="request-response",
         combined="high",
         uplift_note="CORS reflektif ber-credential = pembacaan data "
                     "lintas-origin nyata"),
    dict(chain_id="crlf-cache-poison",
         b_checks=("poison",),
         a_tools=("crlf_inject", "host_header_poison"),
         a_checks=(r"crlf|host-header",), a_cwes=("CWE-93", "CWE-444"),
         b_step="header terinjeksi dikonsumsi cache -> web cache "
                "poisoning untuk semua pengunjung",
         b_tool="exploit_playbooks (CachePoisonPlaybook)",
         b_probe="differential",
         combined="high",
         uplift_note="injeksi satu-request menjadi amok cache-scope "
                     "luas"),
]

SEVERITY_LADDER = ("info", "low", "medium", "high", "critical")


def _load_findings(path: Path) -> "list[dict]":
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if "findings" not in data:
            raise ValueError("objek tanpa kunci 'findings' — bentuk "
                             "tidak dikenal (fail-closed)")
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError("findings.json bukan array / 'findings' bukan "
                         "array")
    return [f for f in data if isinstance(f, dict)]


def _classify(f: dict) -> "tuple[str, str] | None":
    """Kembalikan (chain_id, role) — role 'b' (bukti sisi-B; pola
    spesifik dicek dulu) atau 'a' (jangkar rantai), atau None. Satu
    temuan = satu peran."""
    tool = (f.get("tool") or "").lower()
    check = (f.get("check") or f.get("title") or "").lower()
    cwe = (f.get("cwe") or "").upper()
    for row in CHAINS:
        if any(re_search(p, check) for p in row.get("b_checks", ())):
            return row["chain_id"], "b"
    for row in CHAINS:
        if any(re_search(p, check) for p in row["a_checks"]):
            return row["chain_id"], "a"
    for row in CHAINS:
        if cwe and cwe in row["a_cwes"]:
            return row["chain_id"], "a"
    for row in CHAINS:
        if any(t and tool.startswith(t.lower()) for t in row["a_tools"]):
            return row["chain_id"], "a"
    return None


def re_search(pattern: str, text: str) -> bool:
    import re as _re
    return _re.search(pattern, text) is not None


def _combined(a_sev: str, declared: str, b_present: bool) -> str:
    """Severity gabungan = maks(severity A, nilai tabel) bila B hadir;
    bila B belum ada, kembalikan deklarasi tabel sebagai target."""
    if b_present:
        return declared if SEV_ORDER[declared] >= SEV_ORDER[a_sev] \
            else a_sev
    return declared


def plan(findings: "list[dict]", tools_dir: "Path | None") -> dict:
    by_chain: "dict[str, list[dict]]" = {}
    b_evidence: "dict[str, list[dict]]" = {}
    unmapped: "list[str]" = []
    for f in findings:
        cls = _classify(f)
        if cls is None:
            unmapped.append(f"{f.get('tool', '?')}:{f.get('check', '?')}")
            continue
        cid, role = cls
        (by_chain if role == "a" else b_evidence).setdefault(
            cid, []).append(f)

    present_tools = set()
    if tools_dir is not None and tools_dir.is_dir():
        present_tools = {p.stem for p in tools_dir.glob("*.py")}

    chains_out: "list[dict]" = []
    for row in CHAINS:
        a_hits = by_chain.get(row["chain_id"], [])
        if not a_hits:
            continue
        # apakah temuan sisi B sudah ada di input (pencocokan tool B)
        b_present = bool(b_evidence.get(row["chain_id"]))
        b_tool_stem = row["b_tool"].split(" (")[0].strip()
        tool_missing = (tools_dir is not None
                        and b_tool_stem not in present_tools)
        worst = max((f.get("severity") or "info") for f in a_hits)
        worst = worst if worst in SEV_ORDER else "info"
        chains_out.append({
            "chain_id": row["chain_id"],
            "state": "ready-to-combine" if b_present else "candidate",
            "a_findings": [
                {"tool": f.get("tool"), "check": f.get("check"),
                 "severity": f.get("severity"),
                 "title": (f.get("title") or "")[:120]}
                for f in a_hits[:10]
            ],
            "next_step": row["b_step"],
            "evidence_via": row["b_tool"],
            "probe_kind": row["b_probe"],
            "combined_severity": _combined(worst, row["combined"],
                                           b_present),
            "uplift_note": row["uplift_note"],
            "notes": (["tool pembawa bukti tidak ditemukan di "
                       "--tools-dir — verifikasi dulu sebelum "
                       "merekomendasikan"] if tool_missing else []),
        })

    order = {"ready-to-combine": 0, "candidate": 1}
    chains_out.sort(key=lambda c: (order[c["state"]],
                                   -SEV_ORDER.get(c["combined_severity"], 0),
                                   c["chain_id"]))
    return {
        "chains": chains_out,
        "unmapped": unmapped[:50],
        "b_evidence_total": sum(len(v) for v in b_evidence.values()),
        "stats": {
            "findings_in": len(findings),
            "classified": sum(len(v) for v in by_chain.values()),
            "unmapped": len(unmapped),
            "ready": sum(1 for c in chains_out
                         if c["state"] == "ready-to-combine"),
            "candidates": sum(1 for c in chains_out
                              if c["state"] == "candidate"),
        },
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", type=Path, required=True,
                    help="findings.json (array / {findings: [...]})")
    ap.add_argument("--tools-dir", type=Path, default=None,
                    help="opsional: verifikasi cakupan tool langkah B")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    if not args.findings.exists():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"file tidak ada: {args.findings}"}),
              file=sys.stderr)
        return 2
    try:
        findings = _load_findings(args.findings)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": SCHEMA,
                          "error": f"findings tidak terurai: {exc}"}),
              file=sys.stderr)
        return 2

    result = plan(findings, args.tools_dir)
    notes = [
        "rencana, bukan eksekusi: probe nyata = jalur gated proof tier "
        "(exploit_*) pada target ber-label exploit_allowed",
        "severity gabungan = deklarasi tabel yang diaudit, bukan vonis "
        "baru; verifikasi tiap langkah tetap wajib (verdict ladder)",
        "kelas tak dikenal dilaporkan di unmapped — tidak pernah "
        "dibuang diam-diam",
    ]
    if args.tools_dir is None:
        notes.append("--tools-dir tidak diberikan: cakupan tool langkah "
                     "B tidak diverifikasi (murni tabel)")
    report = {
        "schema": SCHEMA,
        "summary": result["stats"],
        "chains": result["chains"],
        "unmapped": result["unmapped"],
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    hit = result["stats"]["ready"] + result["stats"]["candidates"] > 0
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
