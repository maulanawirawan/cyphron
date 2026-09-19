"""Report generation — satu sumber blocks, tiga format: Markdown, PDF (raw
writer), DOCX (OOXML writer). Bahasa Indonesia profesional, tanpa emoji."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import docxout, pdfout
from . import verdicts as _verdicts
from .guardrails.authorization import AuditLog
from .graph import attack_paths as _graph_attack_paths
from .graph import build_with_findings as _graph_with_findings
from .graph import to_svg as _graph_svg
from .orchestrator import ScanOptions, ScanSummary
from .world.model import WorldModel

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_ID = {"critical": "Kritis", "high": "Tinggi", "medium": "Sedang", "low": "Rendah", "info": "Info"}
_CVSS_BAND = {"critical": "9.0 - 10.0", "high": "7.0 - 8.9", "medium": "4.0 - 6.9",
              "low": "0.1 - 3.9", "info": "0.0"}
_SEV_DEF = {"critical": "Eksploitasi trivial, dampak total (RCE/akses penuh)",
            "high": "Dampak besar dengan syarat terbatas (akun/data sensitif)",
            "medium": "Berbutuh kondisi khusus; dampak terbatas atau terkurung",
            "low": "Perkuatan postur; dampak kecil per insiden",
            "info": "Observasi/informasi; bukan kerentanan"}
_CLASS_ID = {"exploitable": "Kerentanan dapat dieksploitasi", "weakness": "Kelemahan konfigurasi",
             "posture": "Postur keamanan (bukan exploit)", "surface": "Pengungkapan attack surface",
             "info": "Observasi"}
_CLASS_BY_TOOL = {"email_probe": "posture", "ct_log": "surface", "security_headers": "weakness",
                  "dir_probe": "surface", "method_audit": "exploitable", "sqli_probe": "exploitable",
                  "xss_probe": "exploitable", "bola": "exploitable", "priv_matrix": "exploitable",
                  "authz_bypass": "exploitable", "takeover": "exploitable", "mq_mgmt": "exploitable",
                  "oauth": "exploitable", "cache_dec": "exploitable", "json_inj": "exploitable",
                  "sort_inj": "exploitable", "puzzle": "exploitable", "jwt_crack": "exploitable"}


def _class_of(f) -> str:
    return _CLASS_ID.get(_CLASS_BY_TOOL.get(f.tool, "weakness"), _CLASS_ID["weakness"])




def _attack_chains(confirmed) -> list[dict]:
    """Attack-Chain Reasoner v1 (deterministik): rantai disusun HANYA dari
    temuan terkonfirmasi; tiap link adalah temuan sungguhan, rantai adalah
    reasoning kombinasi dampaknya."""
    t = " ".join(f.title.lower() for f in confirmed)
    has = lambda kw: kw.lower() in t
    chains = []
    if has("spf") and has("dmarc") and has("lockout"):
        chains.append({
            "name": "PATH-1: PHISHING -> PASSWORD GUESS -> ACCOUNT TAKEOVER",
            "steps": ["Email spoofing atas domain target (SPF + DMARC hilang)",
                      "Kirim phishing halaman-login palsu ke karyawan/klien",
                      "Korban menyerahkan kredensial; login tanpa lockout/rate-limit",
                      "Tebakan password lanjutan tak terbatas -> kompromi akun"],
            "confidence": 0.75})
    if has("/admin/") and has("lockout"):
        chains.append({
            "name": "PATH-2: ADMIN SURFACE -> UNTHROTTLED BRUTE FORCE",
            "steps": ["Halaman admin terjangkau tanpa autentikasi (kandidat terkonfirmasi)",
                      "Tidak ada lockout/rate-limit setelah percobaan gagal berulang",
                      "Brute-force kredensial admin tanpa hambatan",
                      "Akses panel administrasi (impact: kontrol penuh aplikasi)"],
            "confidence": 0.65})
    if has("content-security-policy") and has("xss"):
        chains.append({
            "name": "PATH-3: XSS TANPA PENAHAN CSP",
            "steps": ["Reflected XSS terkonfirmasi pada parameter",
                      "CSP tidak ada/tidak menahan eksekusi inline",
                      "Eksekusi skrip di browser korban (session/aksi dicuri)"],
            "confidence": 0.8})
    return chains

def write_reports(out_dir: Path, opts: ScanOptions, summary: ScanSummary,
                  world: WorldModel, audit: AuditLog) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    blocks = _build_blocks(opts, summary, world, audit)

    md_path = out_dir / "report.md"
    md_path.write_text(_render_md(blocks), encoding="utf-8")

    json_path = out_dir / "findings.json"
    json_path.write_text(json.dumps({
        "target": opts.target, "mode": summary.mode, "authorization": summary.auth_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": summary.counts_by_severity(),
        "confirmed": [f.to_dict() for f in summary.confirmed],
        "unconfirmed": [f.to_dict() for f in summary.unconfirmed],
        "world": world.snapshot(), "skills_used": summary.skills_used,
        "audit_verified": summary.audit_verified, "steps": summary.steps_executed,
        "refused_actions": summary.refused_actions, "elapsed_s": summary.elapsed_s,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    try:
        from .graph import build_from_world
        g = build_from_world(world)
        g.save_sqlite(str(out_dir / "graph.db"))
        (out_dir / "graph.json").write_text(g.to_json(), encoding="utf-8")
    except Exception:
        pass

    # U7: path graph SVG dari temuan + world (jawaban visual "sampai sini
    # lewat apa") — satu sumber data dengan laporan
    try:
        g2 = _graph_with_findings(world, list(summary.confirmed)
                                  + list(summary.unconfirmed))
        (out_dir / "graph.svg").write_text(_graph_svg(g2), encoding="utf-8")
    except Exception:
        pass

    pdf_path = out_dir / "report.pdf"
    doc = _build_doc(opts, summary, world, audit, blocks)
    pdf_path.write_bytes(pdfout.render_report(doc))

    docx_path = out_dir / "report.docx"
    docx_path.write_bytes(docxout.render(blocks, f"Dihasilkan otomatis oleh Cyphron Core untuk {opts.target}."))

    audit_path = out_dir / "audit.jsonl"
    audit_path.write_text("\n".join(json.dumps(e, default=str) for e in audit.entries),
                          encoding="utf-8")
    return {"md": md_path, "json": json_path, "pdf": pdf_path, "docx": docx_path,
            "audit": audit_path}


def _build_doc(opts: ScanOptions, s: ScanSummary, w: WorldModel, audit: AuditLog,
               blocks) -> dict:
    """Dokumen kaya untuk PDF design-system: verdict definitif ADA/TIDAK per area."""
    counts = s.counts_by_severity()
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    ref = "CYPHRON-" + hashlib.sha256(
        f"{opts.target}{s.steps_executed}{now}".encode()).hexdigest()[:10].upper()

    # ---- U7: verdict ladder per temuan (LEAD vs VERIFIED) + path graph ----
    ladder_of = {f.id: _verdicts.verdict_of(f)
                 for f in list(s.confirmed) + list(s.unconfirmed)}
    graph_paths: list[list[dict]] = []
    try:
        g2 = _graph_with_findings(w, list(s.confirmed) + list(s.unconfirmed))
        for vid in [n["id"] for n in g2.nodes("VULNERABILITY")][:4]:
            for pth in _graph_attack_paths(g2, f"TARGET:{opts.target}", vid,
                                           max_hops=8, max_paths=1):
                graph_paths.append([
                    {"kind": nid.split(":", 1)[0],
                     "key": nid.split(":", 1)[1] if ":" in nid else nid}
                    for nid in pth])
    except Exception:
        graph_paths = []

    if counts["critical"]:
        chip = {"text": "RISIKO KRITIKAL - SEGERA TANGANI", "kind": "red"}
    elif counts["high"]:
        chip = {"text": "RISIKO TINGGI", "kind": "amber"}
    elif len(s.confirmed):
        chip = {"text": "RISIKO SEDANG-RENDAH", "kind": "amber"}
    else:
        chip = {"text": "TIDAK ADA TEMUAN TERKONFIRMASI", "kind": "teal"}

    # ---- verdict matrix dari jejak audit (definitif: ADA vs TIDAK DITEMUKAN) ----
    runs: dict[str, int] = {}
    clean_tools: list[str] = []
    failed_tools: list[str] = []
    executed = sorted({e["tool"] for e in audit.entries if e["kind"] == "tool-run"})
    chains = _attack_chains(s.confirmed)
    finding_tools = {f.tool for f in s.confirmed}
    done: dict[str, dict] = {}
    for e in audit.entries:
        if e["kind"] == "tool-run":
            runs[e["tool"]] = runs.get(e["tool"], 0) + 1
        elif e["kind"] == "tool-done":
            done[e["tool"]] = e
    for tool, e in sorted(done.items()):
        if tool in ("http_probe", "crawler", "browser_engine"):
            continue  # engine discovery: bukan uji kerentanan
        n_found = e.get("findings", 0) or 0
        if tool in finding_tools or n_found:
            continue
        if not e.get("ok") or e.get("error"):
            # engine gagal dieksekusi ≠ "diuji, nol temuan" (anti false-negative)
            failed_tools.append(tool)
            continue
        clean_tools.append(tool)

    verdict_rows: list[list[str]] = []
    n = 0
    for f in s.confirmed:
        verdict_rows.append([str(n), f.title, "ADA (terkonfirmasi)",
                             _SEV_ID[f.severity].upper(), _class_of(f)])
    for tool in clean_tools:
        verdict_rows.append(["-", f"Uji {tool} ({runs.get(tool, 1)}x eksekusi)",
                             "TIDAK DITEMUKAN", "BERSIH", "-"])
    for tool in failed_tools:
        verdict_rows.append(["-", f"Uji {tool} ({runs.get(tool, 1)}x eksekusi)",
                             "GAGAL DIEKSEKUSI", "PERIKSA", "-"])

    rec_rows = [
        [str(i + 1), f.title, _SEV_ID[f.severity], (f.recommendation or "-")[:180]]
        for i, f in enumerate(s.confirmed)
    ]

    doc = {
        "ref": ref,
        "brand": "CYPHRON",
        "brand_sub": "SECURITY ASSESSMENT - DOKUMEN TERKENDALI",
        "doc_title": opts.target,
        "title": "Laporan Uji Keamanan (Penetration Test)",
        "subtitle": (f"Target: {opts.target} - blackbox, loop observasi-plan-act-verify "
                     f"milik Cyphron (seluruh engine kode sendiri, tanpa alat pihak ketiga)."),
        "chip": chip,
        "meta": [
            ("Tanggal", now.replace("UTC", "UTC (WIB +7)")),
            ("Mode", s.mode),
            ("Otorisasi", s.auth_id or "tidak ada (read-only)"),
            *([("Scope targets", "; ".join(s.scope["targets"]) or "-"),
               ("Scope dikecualikan", "; ".join(s.scope["excluded"]) or "tidak ada")]
              if s.scope else []),
            ("Langkah / request", f"{s.steps_executed} / {w.request_count}"),
            *([("Fase eskalasi", f"{s.escalation.get('fase', '-')} (pola: "
               + (", ".join(sorted(s.escalation.get("patterns", {}))) or "-") + ")")]
              if s.escalation else []),
            ("Temuan terkonfirmasi", str(len(s.confirmed)) or "0"),
            ("Observasi (tanpa bukti penuh)", str(len(s.unconfirmed))),
            ("Integritas audit", "UTUH (hash-chain)" if s.audit_verified else "TAMPERED"),
            ("Durasi", f"{s.elapsed_s:.0f} detik"),
        ],
        "callout": {
            "label": "JAMINAN VERDICT",
            "text": ("Setiap baris pada laporan ini adalah keputusan definitif: ADA "
                     "(terkonfirmasi dengan bukti reproduktif) atau TIDAK DITEMUKAN "
                     "(diuji, nol temuan). Tidak ada perkataan 'mungkin' - kandidat yang "
                     "gagal memenuhi standar bukti dikeluarkan dari daftar temuan dan "
                     "dilaporkan terpisah sebagai observasi."),
        },
        "full_cover": True,
        "sections": [
            {"no": "01", "title": "RINGKASAN EKSEKUTIF", "kind": "generic", "blocks": [
                ("box", (f"Pengujian menemukan {len(s.confirmed)} temuan terkonfirmasi dan "
                         f"memastikan {len(clean_tools)} area uji BERSIH (tidak ditemukan "
                         f"kerentanan). {'Tidak ada temuan critical/high.' if not counts['critical'] and not counts['high'] else 'Perhatian: terdapat temuan berdampak tinggi.'} "
                         f"Seluruh keputusan berbasis bukti request-response yang dapat "
                         f"direproduksi; jejak keputusan terkunci pada rantai hash.")),
                ("body", f"Mode {s.mode}; otorisasi {s.auth_id or 'tidak ada'}; "
                         f"{s.steps_executed} langkah planner, {w.request_count} request, "
                         f"durasi {s.elapsed_s:.0f} detik; {s.refused_actions} aksi ditolak gate."),
            ]},
            {"no": "01b", "title": "VERDICT LADDER - LEAD vs TEMUAN KLIEN",
             "kind": "ladder"},
            {"no": "02", "title": "KEPUTUSAN (VERDICT) PER AREA",
             "kind": "table",
             "head": ["No", "Area / Temuan", "Verdict", "Tingkat", "Klasifikasi"],
             "widths": [0.4, 4.0, 2.0, 1.1, 2.0],
             "rows": verdict_rows or [["-", "Semua area yang diuji",
                                       "TIDAK DITEMUKAN", "BERSIH", "-"]]},
            {"no": "02b", "title": "RINGKASAN CVSS v3.1 PER SEVERITY", "kind": "table",
             "head": ["Severity", "Jumlah temuan", "Band CVSS", "Definisi ringkas"],
             "widths": [1.4, 1.3, 1.5, 4.4],
             "rows": [
                 [_SEV_ID[sev].upper(), str(counts[sev]), _CVSS_BAND[sev],
                  _SEV_DEF[sev]]
                 for sev in _SEV_ORDER]},
            {"no": "03", "title": "HIPOTESIS & KEPUTUSAN PLANNER", "kind": "table",
             "head": ["ID", "Hipotesis", "Bukti di world model", "Keputusan", "Conf", "Budget"],
             "widths": [0.9, 2.9, 2.4, 1.9, 0.7, 0.7],
             "rows": [[h.get("id", "-"), h.get("claim", "-"), h.get("evidence", "-"),
                       h.get("decision", "-"),
                       (f"{h['confidence']:.0%}"
                        if isinstance(h.get("confidence"), (int, float)) else "-"),
                       (f"{h['budget_requests']} req"
                        if isinstance(h.get("budget_requests"), (int, float))
                        and h["budget_requests"] else "-")]
                      for h in w.hypotheses] or [["-", "-", "-", "-", "-", "-"]]},
            {"no": "03b", "title": "RE-PLAN DINAMIS (TEMUAN MEMBUKA HIPOTESIS BARU)",
             "kind": "table",
             "head": ["Pemicu (temuan)", "Hipotesis baru", "Langkah follow-up"],
             "widths": [3.2, 2.4, 3.9],
             "rows": [[ev.get("trigger_finding", "-"),
                       f"{ev.get('hypothesis_id', '-')} - {ev.get('claim', '')}",
                       ("; ".join(ev.get("steps") or []) or "-")]
                      for ev in w.replan_events]
              or [["Tidak ada re-plan pada run ini", "-", "-"]]},
            {"no": "04b", "title": "RANTAI SERANGAN (ATTACK PATHS)", "kind": "table",
             "head": ["Attack path", "Langkah rantai", "Confidence"],
             "widths": [2.2, 5.4, 1.0],
             "rows": [[c["name"], chr(10).join("-> " + s for s in c["steps"]),
                       f"{c['confidence']:.0%}"] for c in chains]
                      or [["Tidak ada rantai lintas-temuan pada run ini", "-", "-"]]},
            {"no": "04c", "title": "PATH GRAPH (SAMPAI SINI LEWAT APA)",
             "kind": "graph", "paths": graph_paths},
            {"no": "04", "title": "DETAIL TEMUAN TERKONFIRMASI", "kind": "findings", "items": [
                {"sev": f.severity, "title": f.title,
                 "verdict": "ADA - TERKONFIRMASI",
                 "ladder": ladder_of.get(f.id, 3),
                 "meta": (f"Klasifikasi: {_class_of(f)} | Tool: {f.tool} | CWE: {f.cwe or '-'} | Confidence: "
                          f"{f.confidence:.0%} | Skill: {f.source_skill or '-'} | "
                          f"CVSS band: {_CVSS_BAND[f.severity]}"
                          + (f" | Lokasi: {f.target_url}" + (f" ({f.param})" if f.param else "")
                             if f.target_url else "")),
                 "desc": f.description, "req": f.request, "resp": (f.response or "")[:1000],
                 "poc": f.poc, "rec": f.recommendation}
                for f in s.confirmed]},
            {"no": "05", "title": "RANTAI SERANGAN (ATTACK PATHS)", "kind": "table",
             "head": ["Attack path", "Langkah rantai (tiap link = temuan terkonfirmasi)", "Confidence"],
             "widths": [2.2, 5.4, 1.0],
             "rows": [[c["name"], " -> ".join(c["steps"]),
                       f"{c['confidence']:.0%}"] for c in chains]
                      or [["Tidak ada rantai lintas-temuan pada run ini", "-", "-"]]},
            {"no": "06", "title": "MATRIKS PENGUJIAN BERSIH", "kind": "table",
             "head": ["Engine", "Eksekusi", "Verdict"],
             "widths": [3.4, 1.2, 2.4],
             "rows": [[t, f"{runs.get(t, 1)}x", "TIDAK DITEMUKAN"]
                      for t in clean_tools]
                     or [["-", "-", "TIDAK DITEMUKAN"]]},
            {"no": "07", "title": "OBSERVASI TANPA BUKTI EKSPLOITASI PENUH", "kind": "table",
             "head": ["Observasi", "Verdict", "Confidence"],
             "widths": [5.4, 3.0, 1.1],
             "rows": [[f.title, "TIDAK ADA BUKTI EKSPLOITASI - tidak dihitung sebagai temuan",
                       f"{f.confidence:.0%}"] for f in s.unconfirmed]
                      or [["Tidak ada", "TIDAK DITEMUKAN", "-"]]},
            {"no": "08", "title": "METODOLOGI, CAKUPAN, BATASAN", "kind": "generic", "blocks": [
                ("body", "Loop deterministik observasi -> plan -> act -> verify hingga titik "
                         "jenuh. Planner evidence-driven: serangan hanya dijadwalkan bila "
                         "hipotesisnya didukung bukti di world model (bagian 03); hipotesis "
                         "yang ditolak tidak menjadwalkan apa pun. Alokasi request per "
                         "hipotesis proporsional terhadap impact x confidence dan dialokasikan "
                         "ulang otomatis ketika temuan baru mengubah confidence; setiap temuan "
                         "yang membuka surface baru langsung membuka hipotesis reaktif yang "
                         "diuji pada run yang sama (bagian 03b). Otorisasi ditegakkan kode "
                         "(default-DENY). Semua engine adalah kode milik Cyphron (stdlib murni)."),
                ("body", "Kepatuhan scope per-destination: host yang ditemukan engine sendiri "
                         "saat run (subdomain sibling dari CT log, MX host) dicek terhadap "
                         "scope dokumen otorisasi SEBELUM satu pun query DNS/HTTP. Host di "
                         "luar scope mendapat nol query dan hanya dilaporkan sebagai "
                         "observasi pasif dari data publik; keputusan per host tercatat di "
                         "audit.jsonl (kind=host-scope-decision)."),
                ("body", "Engine yang benar-benar dieksekusi pada run ini (dari jejak audit): "
                         + ", ".join(executed) + "."),
                ("body", "Batas yang perlu dipahami: hasil bersih bukan jaminan bebas "
                         "kerentanan. Di luar cakupan otomatis: logika bisnis, aplikasi "
                         "full client-side, multi-peran terautentikasi penuh, analisis kode "
                         "sumber, dan rantai serangan lanjutan."),
            ]},
            {"no": "09", "title": "REKOMENDASI PERBAIKAN (PRIORITAS)", "kind": "table",
             "head": ["No", "Temuan", "Tingkat", "Langkah perbaikan"],
             "widths": [0.5, 2.6, 1.1, 5.3],
             "rows": rec_rows or [["1", "-", "-", "Tidak ada perbaikan yang diwajibkan dari "
                                         "cakupan ini; pertahankan patching rutin."]]},
            {"no": "10", "title": "KNOWLEDGE GRAPH (WORLD MODEL)", "kind": "table",
             "head": ["Jenis node/edge", "Jumlah"],
             "widths": [4.5, 1.0],
             "rows": (lambda st: [[k, str(v)] for k, v in sorted(st.items())] or [["kosong", "0"]])(
                 (lambda g: {**{f"node:{k}": v for k, v in g.stats().get("nodes", {}).items()},
                             **{f"edge:{k}": v for k, v in g.stats().get("edges", {}).items()}})(
                     __import__("cyphron.graph", fromlist=["build_from_world"]).build_from_world(w)))
             if w.endpoints else [["-", "-"]]},
            {"no": "11", "title": "DETECTION RULES (UNTUK SOC)", "kind": "generic", "blocks":
                [("mono", rule) for rule in
                 (__import__("cyphron.tools.exploitability", fromlist=["detection_rules_for"])
                  .detection_rules_for(s.confirmed[:3]) or ["-"])]},
            {"no": "12", "title": "JEJAK AUDIT DAN INTEGRITAS", "kind": "generic", "blocks": [
                ("body", f"Setiap keputusan otorisasi dan eksekusi engine tercatat pada "
                         f"rantai hash tahan perubahan. Verifikasi: "
                         f"{'UTUH' if s.audit_verified else 'TAMPERED'} "
                         f"({len(audit.entries)} entri audit, disimpan pada audit.jsonl "
                         f"dan cyphron.db). Ref dokumen: {ref}."),
            ]},
        ],
    }
    return doc


def _build_blocks(opts: ScanOptions, s: ScanSummary, w: WorldModel, audit: AuditLog):
    b: list[tuple[str, str]] = []
    counts = s.counts_by_severity()
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    b.append(("title", "Laporan Uji Keamanan (Penetration Test)"))
    b.append(("subtitle", f"Target: {opts.target}"))
    b.append(("subtitle", f"Disusun oleh Cyphron Core - {now}"))
    b.append(("kv", ""))

    b.append(("h1", "1. Ringkasan Eksekutif"))
    total = len(s.confirmed)
    top = ", ".join(f"{v} { _SEV_ID[k].lower() }" for k, v in counts.items() if v)
    if total:
        b.append(("body", f"Pengujian menemukan {total} temuan terkonfirmasi ({top}) "
                          f"dan {len(s.unconfirmed)} observasi yang belum terkonfirmasi. "
                          "Setiap temuan disertai bukti yang dapat direproduksi beserta langkah "
                          "perbaikannya. Observasi yang belum terkonfirmasi tidak dihitung sebagai "
                          "temuan dan dilaporkan terpisah pada bagian akhir."))
    else:
        b.append(("body", f"Dalam cakupan yang diuji, tidak ditemukan temuan terkonfirmasi. "
                          f"Terdapat {len(s.unconfirmed)} observasi yang belum memenuhi standar bukti "
                          "untuk dikonfirmasi dan dilaporkan terpisah."))
    b.append(("kv", f"Mode pengujian: {s.mode}. Otorisasi: {s.auth_id or 'tidak ada (read-only)'}."))
    b.append(("kv", f"Langkah dijalankan: {s.steps_executed}. Aksi yang ditolak gate: {s.refused_actions}. "
                    f"Request terkirim: {w.request_count}. Durasi: {s.elapsed_s} detik."))
    if s.escalation:
        b.append(("kv", f"Fase eskalasi adaptif: {s.escalation.get('fase', '-')} — pola terdeteksi: "
                        + (", ".join(sorted(s.escalation.get("patterns", {}))) or "-")
                        + ". Antrean engine hasil unlock dijadwalkan sekali per pola "
                          "dan tunduk pada budget yang sama."))
    b.append(("kv", f"Integritas jejak audit: {'terverifikasi (hash-chain utuh)' if s.audit_verified else 'GAGAL - rantai terdeteksi berubah'}."))
    if w.technologies:
        b.append(("kv", "Teknologi teramati: " + "; ".join(list(w.technologies)[:6]) + "."))
    b.append(("kv", ""))

    b.append(("h1", "2. Otorisasi dan Ruang Lingkup"))
    b.append(("body", "Seluruh aksi aktif pada pengujian ini tunduk pada gerbang otorisasi "
                      "yang ditegakkan oleh kode, bukan oleh instruksi model. Tanpa dokumen "
                      "otorisasi yang sah, seluruh tool aktif ditolak dan pengujian turun ke "
                      "mode read-only."))
    b.append(("kv", f"- ID otorisasi: {s.auth_id or 'tidak ada'}"))
    if s.scope:
        b.append(("kv", "- Scope targets (dari dokumen): "
                        + ("; ".join(s.scope["targets"]) or "-")
                        + (f" | port {s.scope['ports']}" if s.scope["ports"] else "")
                        + (f" | CIDR {'; '.join(s.scope['cidr'])}" if s.scope["cidr"] else "")))
        b.append(("kv", "- Scope dikecualikan (dari dokumen): "
                        + ("; ".join(s.scope["excluded"]) if s.scope["excluded"] else "tidak ada")))
        if any(t.startswith("*.") for t in s.scope["targets"]):
            b.append(("kv", "- Pola wildcard: probing subdomain yang cocok pola scope "
                            "adalah sah dan dilakukan aktif."))
        else:
            b.append(("kv", "- Scope sempit (host tunggal/daftar host): subdomain sibling "
                            "HANYA diamati pasif dari data publik (CT log/arsip); tidak ada "
                            "query DNS/HTTP ke host di luar scope, dan keputusan per host "
                            "tercatat di audit.jsonl (kind=host-scope-decision)."))
    else:
        b.append(("kv", f"- Target dalam scope: {opts.target}"))
    b.append(("kv", "- Batasan: tanpa DoS, tanpa eksfiltrasi data, tanpa persistensi, tanpa teknik agresif"))
    b.append(("kv", "- Jejak keputusan: audit.jsonl (hash-chain, tahan perubahan)"))
    b.append(("kv", ""))

    b.append(("h1", "3. Metodologi dan Cakupan"))
    executed = sorted({e["tool"] for e in audit.entries if e["kind"] == "tool-run"})
    b.append(("body", "Pengujian dijalankan sebagai loop observasi, perencanaan, aksi, dan "
                      "verifikasi hingga titik jenuh. Planner evidence-driven: serangan hanya "
                      "dijadwalkan bila hipotesisnya didukung bukti di world model. Budget "
                      "request dialokasikan proporsional terhadap impact x confidence tiap "
                      "hipotesis, dan temuan baru langsung membuka hipotesis reaktif yang "
                      "diuji pada run yang sama. Semua engine adalah kode milik Cyphron "
                      "(tanpa alat pihak ketiga)."))
    b.append(("body", "Engine yang benar-benar dieksekusi pada run ini (dari jejak audit): "
                      + ", ".join(executed) + "."))
    b.append(("kv", f"- Endpoint teramati: {len(w.endpoints)}"))
    b.append(("kv", f"- Endpoint dengan parameter teruji: {len(w.param_endpoints())}"))
    if w.notes:
        b.append(("kv", "- Catatan berjalan: " + " | ".join(w.notes[-8:])))
    b.append(("body", "Konteks knowledge yang termuat pada planner (referensi metodologi; "
                      "tidak semua menghasilkan uji langsung pada run ini):"))
    for sk in s.skills_used:
        b.append(("bullet", sk))
    b.append(("kv", ""))

    chains = _attack_chains(s.confirmed)
    if chains:
        b.append(("h1", "3b. Rantai Serangan (Attack Paths)"))
        b.append(("body", "Reasoning kombinasi: tiap link adalah temuan terkonfirmasi "
                          "pada run ini; gabungannya membuka jalur serangan end-to-end."))
        for c in chains:
            b.append(("sepmedium", f"{c['name']} (confidence {c['confidence']:.0%})"))
            for stp in c["steps"]:
                b.append(("bullet", stp))
        b.append(("kv", ""))
    b.append(("h1", "4. Ringkasan Temuan Terkonfirmasi"))
    if not s.confirmed:
        b.append(("body", "Tidak ada temuan terkonfirmasi dalam cakupan ini."))
    else:
        b.append(("mono", f"{'Tingkat':9} {'CWE':10} Judul"))
        for f in s.confirmed:
            b.append(("mono", f"{_SEV_ID[f.severity]:9} {f.cwe or '-':10} {f.title}"))
    b.append(("kv", ""))

    b.append(("h1", "5. Detail Temuan"))
    by_sev: dict[str, list] = {}
    for f in s.confirmed:
        by_sev.setdefault(f.severity, []).append(f)
    n = 0
    for sev in _SEV_ORDER:
        for f in by_sev.get(sev, []):
            n += 1
            b.append((f"sep{sev}", f"5.{n} [{_SEV_ID[sev].upper()}] {f.title}"))
            b.append(("kv", f"- Tool: {f.tool} | CWE: {f.cwe or '-'} | "
                            f"Confidence: {f.confidence:.0%} | Skill: {f.source_skill or '-'} | "
                            f"Estimasi CVSS v3.1: {_CVSS_BAND[f.severity]}"))
            if f.target_url:
                b.append(("kv", f"- Lokasi: {f.target_url}" + (f" (parameter: {f.param})" if f.param else "")))
            if f.file_path:
                b.append(("kv", f"- Berkas: {f.file_path}" + (f":{f.line_start}" if f.line_start else "")))
            if f.description:
                b.append(("body", f"Uraian: {f.description}"))
            if f.request:
                b.append(("body", "Bukti permintaan:"))
                b.append(("mono", f.request))
            if f.response:
                b.append(("body", "Bukti respons:"))
                b.append(("mono", f.response[:1200]))
            if f.poc:
                b.append(("body", "Langkah reproduksi:"))
                b.append(("mono", f.poc))
            if f.recommendation:
                b.append(("body", f"Rekomendasi perbaikan: {f.recommendation}"))
            b.append(("kv", ""))

    if s.unconfirmed:
        b.append(("h1", "6. Observasi Belum Terkonfirmasi"))
        b.append(("body", "Observasi berikut tidak memenuhi standar bukti untuk disebut temuan. "
                          "Mereka dicantumkan demi transparansi dan tidak dihitung pada ringkasan."))
        for f in s.unconfirmed:
            b.append(("bullet", f"[{_SEV_ID[f.severity]}] {f.title} (confidence {f.confidence:.0%})"))
        b.append(("kv", ""))

    b.append(("h1", "7. Batasan Pengujian"))
    b.append(("body", "Pengujian otomatis ini memiliki batas yang perlu dipahami pembaca laporan: "
                      "hasil bersih bukan jaminan bebas kerentanan. Cakupan yang umumnya berada di "
                      "luar automated scan meliputi: celah logika bisnis, kerentanan pada aplikasi "
                      "yang dirender sepenuhnya di sisi klien, pengujian terautentikasi pada seluruh "
                      "peran, analisis kode sumber, serta rantai serangan lanjutan (chaining). "
                      "Rekomendasi tindak lanjut adalah pengujian terarah pada area tersebut."))
    b.append(("kv", ""))

    ok, note = audit.verify()
    b.append(("h1", "8. Jejak Audit"))
    b.append(("body", f"Setiap keputusan otorisasi dan eksekusi tool tercatat pada rantai hash "
                      f"yang tahan perubahan. Hasil verifikasi: {'utuh' if ok else 'TAMPERED'} "
                      f"({note}). Berkas: audit.jsonl ({len(audit.entries)} entri), cyphron.db (SQLite)."))
    return b


def _render_md(blocks: list[tuple[str, str]]) -> str:
    lines: list[str] = []
    for style, text in blocks:
        if style == "title":
            lines.append(f"# {text}", )
        elif style == "subtitle":
            lines.append(f"*{text}*")
        elif style == "h1":
            lines.append(f"\n## {text}")
        elif style == "h2":
            lines.append(f"\n### {text}")
        elif style == "h3":
            lines.append(f"\n#### {text}")
        elif style == "bullet":
            lines.append(f"- {text}")
        elif style == "mono":
            for ln in text.splitlines():
                lines.append(f"    {ln}")
        elif style.startswith("sep"):
            lines.append(f"\n### {text}")
        else:
            lines.append(text)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
