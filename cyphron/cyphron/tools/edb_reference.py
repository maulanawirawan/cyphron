"""edb_reference — penunjuk exploit publik (Exploit-DB).

PASIF (nol request) dan TIDAK PERNAH menjalankan exploit. Untuk produk
berversi yang punya entri di files_exploits.csv (nama+versi disebut
eksplisit), tambahkan temuan info "Public exploit exists" — ini ALASAN
penaikan severity bagi analis, bukan klaim kerentanan baru. Baris yang
hanya menyebut nama produk dihitung sebagai konteks, bukan klaim.
"""

from __future__ import annotations

from ..kb import edb_index
from ..kb import fingerprint as _fp
from ..kb.paths import load_manifest, resolve_kb_dir
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_MAX_PRODUCTS = 8


class EdbReferenceTool(Tool):
    name = "edb_reference"
    description = ("Cocokkan fingerprint produk+versi dengan katalog exploit "
                   "publik Exploit-DB (referensi saja — tidak dieksekusi).")
    risk_tags = {"passive", "local"}
    source_skill = "kb-godtier-03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        kb_dir = resolve_kb_dir(args.get("kb_dir"))
        csv_path = kb_dir / "edb" / "files_exploits.csv"
        if not csv_path.exists():
            note = ("edb_reference: KB exploitdb belum tersinkron — jalankan "
                    "`python -m cyphron kb --source edb`")
            ctx.world.note(note)
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "kb-belum-tersedia"})
        try:
            rows = edb_index.load_index(csv_path)
        except Exception as exc:
            return ToolResult(tool=self.name, ok=True,
                              data={"error": f"csv: {type(exc).__name__}: {exc}"})
        try:
            manifest = load_manifest(kb_dir)
        except Exception:
            manifest = {"sources": {}}
        edb_info = (manifest.get("sources", {}).get("edb") or {})

        texts = _fp.fingerprints_from_world(ctx.world)
        matches = [m for m in _fp.to_cpe(texts) if m.versioned][:_MAX_PRODUCTS]
        if not matches:
            ctx.world.note("edb_reference: tidak ada produk berversi untuk "
                           "dicocokkan")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "tidak-ada-produk-berversi"})

        findings: list[Finding] = []
        products: list[dict] = []
        for m in matches:
            if not m.names:
                continue
            versioned, name_only = edb_index.find_exploits(
                rows, m.names, m.version)
            products.append({"product": m.product, "version": m.version,
                             "edb_ids": [r["id"] for r in versioned],
                             "name_only_rows": name_only})
            if not versioned:
                continue
            ids = ", ".join(f"EDB-{r['id']}" for r in versioned)
            titles = "; ".join(r["description"][:80] for r in versioned[:3])
            f = Finding(
                tool=self.name,
                title=(f"Public exploit exists: {m.names[0]} {m.version} "
                       f"({len(versioned)} entri: {ids})"),
                severity="info",
                description=(
                    f"Katalog Exploit-DB lokal memuat {len(versioned)} entri "
                    f"yang menyebut eksplisit {m.names[0]} {m.version} "
                    f"(+{name_only} entri produk tanpa versi spesifik). "
                    f"Referensi: {titles}. Ini DATA prioritas untuk analis "
                    f"(alasan penaikan severity), BUKAN klaim kerentanan dan "
                    f"BUKAN bukti eksploitasi — edb_reference tidak pernah "
                    f"menjalankan exploit. Penentu akhir = skema severity "
                    f"program."),
                recommendation=(
                    "Gunakan sebagai prioritisasi patching; verifikasi manual "
                    "oleh analis sebelum klaim; jangan pernah dieksekusi ke "
                    "produksi."),
                target_url=ctx.world.target or None,
                confidence=0.9,
                source_skill=self.source_skill,
                status="unconfirmed",
                evidence_kind="file",
                finding_class="surface")
            f.attach_evidence("edb", {
                "ids": [r["id"] for r in versioned],
                "cpe23": m.cpe23, "rows_total": len(rows),
                "origin": edb_info.get("origin", ""),
                "sha256": edb_info.get("sha256", "")})
            findings.append(f)
        ctx.world.note("edb_reference: " + "; ".join(
            f"{p['product']} {p['version']}={len(p['edb_ids'])} EDB"
            for p in products[:8]))
        return ToolResult(tool=self.name, ok=True,
                          data={"products": products, "rows": len(rows)},
                          findings=findings)
