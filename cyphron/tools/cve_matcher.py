"""cve_matcher — CPE -> cpe.sqlite -> CVE exposure sebagai LEAD pasif.

NOL request jaringan (risk_tags passive+local). Keluaran:
- Temuan `info` (finding_class=surface, status=unconfirmed) per produk
  berversi: "CVE exposure: <produk> <versi> — N CVE rentang cocok (top ...)".
  Skor CVSS dicatat sebagai DATA; klaim kerentanan tetap butuh verifikasi
  ringan deterministik — skema severity program = penentu akhir.
- Versi tak diketahui / rentang ambigu -> world.note saja (zero-FP).
- KB belum ada -> note "belum tersinkron", bukan error.
"""

from __future__ import annotations

from pathlib import Path

from ..kb import nvd_sqlite
from ..kb import fingerprint as _fp
from ..kb.paths import load_manifest, resolve_kb_dir
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_DEFAULT_TOP = 10
_MAX_PRODUCTS = 12


def _fmt_score(score) -> str:
    return f"{score:.1f}" if isinstance(score, (int, float)) else "n/a"


class CveMatcherTool(Tool):
    name = "cve_matcher"
    description = ("Cocokkan CPE fingerprint dengan KB NVD lokal (cpe.sqlite)"
                   " -> lead CVE exposure ber-CVSS, pasif tanpa request.")
    risk_tags = {"passive", "local"}
    source_skill = "kb-godtier-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        kb_dir = resolve_kb_dir(args.get("kb_dir"))
        db = kb_dir / "cpe.sqlite"
        if not db.exists():
            note = ("cve_matcher: KB belum tersinkron — jalankan "
                    "`python -m cyphron kb --source nvd`")
            ctx.world.note(note)
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "kb-belum-tersedia"})
        top = max(1, min(int(args.get("top") or _DEFAULT_TOP), 25))

        # sumber CPE: args.cpe23 (list string/dict) ATAU fingerprint world
        cpe_inputs = args.get("cpe23")
        if cpe_inputs:
            matches = []
            for raw in cpe_inputs:
                text = raw if isinstance(raw, str) else str(raw)
                parsed = nvd_sqlite.parse_cpe23(text)
                if parsed is None:
                    continue
                part, vendor, product, version, _upd = parsed
                matches.append(_fp.CpeMatch(
                    cpe23=text, vendor=vendor, product=product,
                    version=version, versioned=(version not in ("*", "-", "")),
                    mapping_id="manual", source="args"))
        else:
            texts = _fp.fingerprints_from_world(ctx.world)
            matches = _fp.to_cpe(texts)
        matches = [m for m in matches if not m.note_only][:_MAX_PRODUCTS]
        if not matches:
            ctx.world.note("cve_matcher: tidak ada CPE untuk dicocokkan")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "tidak-ada-cpe"})
        try:
            manifest = load_manifest(kb_dir)
        except Exception:
            manifest = {"sources": {}}
        feed_info = (manifest.get("sources", {}).get("nvd") or {})

        findings: list[Finding] = []
        products: list[dict] = []
        for m in matches:
            if not m.versioned:
                ctx.world.note(
                    f"cve_matcher: {m.product} tanpa versi eksplisit — "
                    f"tidak mengklaim CVE (zero-FP)")
                products.append({"cpe23": m.cpe23, "matched": 0,
                                 "reason": "versi-tak-diketahui"})
                continue
            try:
                rows, ambiguous = nvd_sqlite.query_cves_for_product(
                    db, m.vendor, m.product, m.version)
            except Exception as exc:
                ctx.errors.append(f"cve_matcher[{m.product}]: {exc}")
                continue
            products.append({"cpe23": m.cpe23, "matched": len(rows),
                             "ambiguous": ambiguous})
            if not rows:
                ctx.world.note(f"cve_matcher: {m.product} {m.version} — "
                               f"tidak ada CVE rentang cocok di KB (bagus)")
                continue
            head = rows[:top]
            top_row = head[0]
            top_score_txt = _fmt_score(top_row["cvss_score"])
            detail = "\n".join(
                f"- {r['id']} CVSS {_fmt_score(r['cvss_score'])} "
                f"{r['cwe'] or 'CWE-?'} — {(r['description'] or '')[:110]}"
                for r in head)
            f = Finding(
                tool=self.name,
                title=(f"CVE exposure: {m.product} {m.version} — "
                       f"{len(rows)} CVE rentang cocok (top: "
                       f"{top_row['id']} CVSS {top_score_txt})"),
                severity="info",
                cwe=top_row["cwe"] or None,
                description=(
                    f"LEAD pasif dari KB NVD lokal (bukan klaim kerentanan): "
                    f"{m.cpe23} terimbas rentang versi {len(rows)} CVE menurut "
                    f"feed NVD. Top {len(head)}:\n{detail}\n"
                    f"Ambigu terbuang (zero-FP): {ambiguous}. Konfirmasi hanya "
                    f"lewat verifikasi ringan deterministik; skor CVSS = data, "
                    f"penentu akhir = skema severity program."),
                recommendation=(
                    "Cek referensi NVD/advosi vendor untuk CVE teratas; "
                    "jalankan edb_reference untuk info exploit publik; "
                    "patch/naikkan versi bila benar terimbas."),
                target_url=ctx.world.target or None,
                request=None,
                response=None,
                confidence=0.85,
                source_skill=self.source_skill,
                status="unconfirmed",
                evidence_kind="file",
                finding_class="surface")
            f.attach_evidence("kb", {
                "db": str(db), "cpe23": m.cpe23, "matched": len(rows),
                "top": [r["id"] for r in head],
                "nvd_years": feed_info.get("years", []),
                "nvd_origin": feed_info.get("origin", "")})
            findings.append(f)
        ctx.world.note(
            "cve_matcher: " + "; ".join(
                f"{p['cpe23']}={p['matched']}" for p in products[:8]))
        return ToolResult(tool=self.name, ok=True,
                          data={"products": products,
                                "kb_years": feed_info.get("years", [])},
                          findings=findings)
