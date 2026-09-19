"""remediate — deterministic fix-pack generator ("penambalan").

Each confirmed finding maps to a concrete remediation bundle: what to change,
ready-to-adapt config/code snippets, the verification command, and the
.kimchi knowledge citation. Deterministic rules (no LLM), sourced from
knowledge/remediation-playbook.md patterns. `cyphron verify` then proves
whether the fix worked by re-running the same probes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .findings import Finding

# match keywords (lowercased title/cwe) -> bundle
BUNDLES: list[dict] = [
    {
        "match": ("strict-transport", "CWE-319"),
        "title": "Aktifkan HSTS (Strict-Transport-Security)",
        "applies": "Semua host HTTPS di edge/origin",
        "steps": [
            "Set header di edge (nginx) ATAU di aplikasi — cukup satu sumber, hindari duplikat.",
            "Mulai dari max-age kecil (300) untuk validasi, lalu naik ke 31536000.",
            "Tambahkan preload hanya setelah yakin semua subdomain HTTPS.",
        ],
        "files": {
            "nginx.conf": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "nextjs-middleware.ts": ("// Next.js (middleware.ts)\n"
                                     "export function middleware() {\n"
                                     "  const res = NextResponse.next();\n"
                                     "  res.headers.set('Strict-Transport-Security',\n"
                                     "    'max-age=31536000; includeSubDomains');\n"
                                     "  return res;\n"
                                     "}"),
        },
        "verify": "curl -sI https://<host>/ | grep -i strict-transport-security",
        "knowledge": ".kimchi/skills/14-security-hardening-config.md + remediation-playbook.md",
    },
    {
        "match": ("content-security-policy", "CWE-79", "report-only"),
        "title": "Promosikan CSP dari Report-Only ke Enforcing",
        "applies": "Aplikasi web dengan CSP report-only berjalan bersih",
        "steps": [
            "Pastikan report-only tidak mencatat pelanggaran lagi (cek collector/report-uri).",
            "Ganti nama header: Content-Security-Policy-Report-Only -> Content-Security-Policy.",
            "Uji halaman kunci (login, signup, pembayaran) setelah enforcing.",
            "Jangan hapus directive secara mekanis — ikuti Skill 72 untuk migrasi nonce.",
        ],
        "files": {
            "csp-enforce.md": ("Header saat ini (report-only):\n"
                               "  Content-Security-Policy-Report-Only: <policy>\n"
                               "Ubah menjadi:\n"
                               "  Content-Security-Policy: <policy yang sama>\n"
                               "Hanya jika 0 pelanggaran dalam jendela observasi."),
        },
        "verify": "curl -sI https://<host>/ | grep -i '^content-security-policy:' | grep -v -i report-only",
        "knowledge": ".kimchi/skills/72-csp-engineering-migration.md",
    },
    {
        "match": ("lockout", "rate-limit", "CWE-307"),
        "title": "Tambahkan lockout/throttling progresif pada endpoint login",
        "applies": "Endpoint autentikasi (login/password reset/OTP)",
        "steps": [
            "Hitung kegagalan per akun DAN per IP; setelah ambang (mis. 5 gagal/10 menit) -> 429.",
            "Throttling progresif: tunda respons kegagalan (100ms -> 1s -> 5s).",
            "Respons generik (jangan bedakan user salah vs password salah — Skill 66).",
            "Catat event lockout ke log untuk monitoring.",
        ],
        "files": {
            "rate-limit.ts": ("// Next.js App Router — middleware-level bucket\n"
                              "const attempts = new Map<string, {n: number, reset: number}>();\n"
                              "export function checkLoginAttempts(key: string) {\n"
                              "  const now = Date.now();\n"
                              "  const a = attempts.get(key) ?? {n: 0, reset: now + 10 * 60_000};\n"
                              "  if (now > a.reset) { a.n = 0; a.reset = now + 10 * 60_000; }\n"
                              "  a.n += 1; attempts.set(key, a);\n"
                              "  if (a.n > 5) return new Response('Too Many Requests', {status: 429});\n"
                              "  return null;\n"
                              "}\n"
                              "// Produksi: pindahkan map ke Redis agar lintas instance."),
        },
        "verify": "python -m cyphron verify --target <host> --auth <doc> --baseline <folder-lama>",
        "knowledge": ".kimchi/skills/06-authn-authz-builder.md + skills/67-webhook-callback-trust-testing.md",
    },
    {
        "match": ("xss", "CWE-79"),
        "title": "Encoding output per-konteks untuk refleksi input",
        "applies": "Parameter yang direfleksikan ke HTML tanpa encoding",
        "steps": [
            "Encode di TITIK OUTPUT sesuai konteks: body HTML -> &amp;lt; dsb; atribut -> encode atribut; JS -> JSON.stringify.",
            "Validasi input di sisi masuk (allowlist) sebagai lapis kedua, bukan pengganti.",
            "Tambahkan CSP enforcing (lihat bundle CSP) sebagai lapis ketiga.",
        ],
        "files": {
            "encode.ts": ("// TypeScript helper\n"
                          "export function escapeHtml(v: string): string {\n"
                          "  return v.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))\n"
                          "           .replace(/\"/g, '&quot;')\n"
                          "           .replace(/'/g, '&#39;');\n"
                          "}"),
        },
        "verify": "python -m cyphron verify --target <host> --auth <doc> --baseline <folder-lama>",
        "knowledge": ".kimchi/knowledge/secure-patterns.md (XSS) + skills/12-owasp-top10-hardening.md",
    },
    {
        "match": ("sql injection", "CWE-89"),
        "title": "Parameterized query untuk seluruh jalur SQL",
        "applies": "Query yang menggabungkan input pengguna ke string SQL",
        "steps": [
            "Ganti konkatenasi dengan prepared statement/parameter binding di SEMUA query pada berkas terdampak.",
            "Validasi tipe di sisi server (angka tetap angka, UUID tetap UUID).",
            "Tambahkan regression test: payload lama harus tidak menghasilkan error DB lagi.",
        ],
        "files": {
            "parameterized.sql.ts": ("// BEFORE (rentan)\n"
                                     "// db.query(`SELECT * FROM items WHERE id = '${id}'`)\n"
                                     "// AFTER (aman)\n"
                                     "db.query('SELECT * FROM items WHERE id = $1', [id])"),
        },
        "verify": "python -m cyphron verify --target <host> --auth <doc> --baseline <folder-lama>",
        "knowledge": ".kimchi/knowledge/remediation-playbook.md paragraf 1 (SQL INJECTION)",
    },
    {
        "match": ("exposed", "sensitive path", "CWE-538"),
        "title": "Tutup akses publik ke path internal",
        "applies": "Path sensitif yang merespons publik (/.env, /.git, /backup, dll.)",
        "steps": [
            "Blokir di edge ATAU router aplikasi; balas 404 (bukan 403) agar tidak mengonfirmasi keberadaan.",
            "Audit berkas backup/arsip di direktori publik; pindahkan keluar webroot.",
        ],
        "files": {
            "nginx.conf": ("location ~ /^\\.(env|git|aws|ssh|npmrc|netrc) { deny all; return 404; }\n"
                           "location ~* \\.(bak|sql|sqlite3|zip|tar\\.gz)$ { deny all; return 404; }"),
        },
        "verify": "curl -s -o /dev/null -w '%{http_code}' https://<host>/.env   # harus 404",
        "knowledge": ".kimchi/skills/14-security-hardening-config.md",
    },
    {
        "match": ("crlf", "CWE-93"),
        "title": "Netralkan CR/LF dari input sebelum dipakai di header",
        "applies": "Parameter yang nilainya dipakai untuk header respons/redirect",
        "steps": [
            "Strip %0d/%0a (\\r\\n) dari seluruh input pengguna di gateway/validasi awal.",
            "Jangan pernah memasukkan input mentah ke set-header atau Location.",
            "Tambahkan regression test: payload CRLF harus menghasilkan respons tanpa header injeksi.",
        ],
        "files": {
            "sanitize.ts": "export const stripCRLF = (v: string) => v.replace(/[\\r\\n]/g, '');",
        },
        "verify": "python -m cyphron verify --target <host> --auth <doc> --baseline <folder-lama>",
        "knowledge": ".kimchi/skills/07-input-validation-sanitization.md",
    },
    {
        "match": ("spf", "dmarc", "CWE-290"),
        "title": "Publikasikan SPF + DMARC untuk domain",
        "applies": "Domain pengirim email (apex domain)",
        "steps": [
            "Publikasikan SPF sesuai provider email yang benar-benar dipakai (jangan include berlebihan).",
            "Publikasikan DMARC mulai p=none (pantau laporan), lalu ketatkan ke p=quarantine/reject.",
            "Tambahkan DKIM (selector provider) sebagai pelengkap.",
        ],
        "files": {
            "dns-records.txt": ("apex.  IN TXT  \"v=spf1 include:<provider> -all\"\n"
                                "_dmarc. IN TXT \"v=dmarc1; p=quarantine; rua=mailto:dmarc-reports@<domain>\""),
        },
        "verify": "nslookup -type=TXT <domain> && nslookup -type=TXT _dmarc.<domain>",
        "knowledge": ".kimchi/skills/22-email-security-engineering.md",
    },
    {
        "match": ("mixed content", "CWE-311"),
        "title": "Hidupkan semua subresource lewat HTTPS",
        "applies": "Halaman HTTPS yang memuat aset http://",
        "steps": [
            "Ubah seluruh referensi http:// menjadi https:// (atau relatif).",
            "Tambahkan CSP upgrade-insecure-requests sebagai jaring pengaman.",
        ],
        "files": {
            "csp.md": "Content-Security-Policy: ...; upgrade-insecure-requests",
        },
        "verify": "curl -s https://<host>/ | grep -E 'src=\"http://|href=\"http://'   # harus kosong",
        "knowledge": ".kimchi/skills/14-security-hardening-config.md",
    },
]

GENERIC = {
    "title": "Remediasi umum",
    "steps": [
        "Baca bagian remediasi pada temuan terkait di laporan (report.md, bagian Detail Temuan).",
        "Rujuk .kimchi/knowledge/remediation-playbook.md untuk resep lengkap per kelas kerentanan.",
    ],
    "files": {},
    "verify": "python -m cyphron verify --target <host> --auth <doc> --baseline <folder-lama>",
    "knowledge": ".kimchi/knowledge/remediation-playbook.md",
}


def _pick(f: Finding) -> dict:
    hay = f"{f.title} {f.description} {f.cwe or ''}".lower()
    for bundle in BUNDLES:
        if any(k.lower() in hay for k in bundle["match"]):
            return bundle
    return GENERIC


def fix_pack_for(f: Finding) -> dict:
    bundle = _pick(f)
    return {
        "finding_id": f.id,
        "finding_title": f.title,
        "severity": f.severity,
        "pack_title": bundle["title"],
        "applies": bundle.get("applies", ""),
        "steps": bundle["steps"],
        "files": bundle["files"],
        "verify": bundle["verify"],
        "knowledge": bundle["knowledge"],
    }


def build_fix_bundles(findings: list[Finding], out_dir: Path) -> Path:
    """Tulis patches/FIX-<n>-<slug>.md + patches/README.md. Return folder."""
    patches = out_dir / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    index: list[str] = ["# Fix Packs — rencana penambalan", "",
                        "Dibuat deterministik dari temuan (tanpa LLM). Setiap paket berisi langkah, "
                        "snippet siap adaptasi, perintah verifikasi, dan sitasi knowledge base.", ""]
    for i, f in enumerate(sorted(findings, key=lambda x: x.severity), start=1):
        pack = fix_pack_for(f)
        slug = hashlib.sha1(pack["pack_title"].encode()).hexdigest()[:8]
        lines = [f"# FIX-{i:02d}: {pack['pack_title']}", "",
                 f"- Menutup temuan: {pack['finding_title']} [{pack['severity'].upper()}] ({f.id})",
                 f"- Berlaku untuk: {pack['applies']}", "",
                 "## Langkah"]
        for s in pack["steps"]:
            lines.append(f"1. {s}")
        lines.append("")
        for name, content in pack["files"].items():
            lines.append(f"## Berkas: {name}")
            lines.append("```")
            lines.append(content)
            lines.append("```")
            lines.append("")
        lines.append("## Verifikasi setelah diterapkan")
        lines.append("```bash")
        lines.append(pack["verify"])
        lines.append("```")
        lines.append("")
        lines.append(f"Referensi: {pack['knowledge']}")
        (patches / f"FIX-{i:02d}-{slug}.md").write_text("\n".join(lines), encoding="utf-8")
        index.append(f"- [FIX-{i:02d}] {pack['pack_title']} -> {pack['finding_title']}")
    index.append("")
    index.append("Setelah diterapkan, jalankan verifikasi delta:")
    index.append("```bash")
    index.append("python -m cyphron verify --target <host> --auth <doc> --baseline <folder-ini> --out <folder-baru>")
    index.append("```")
    (patches / "README.md").write_text("\n".join(index), encoding="utf-8")
    return patches


def load_findings(findings_json: Path) -> list[Finding]:
    data = json.loads(findings_json.read_text(encoding="utf-8"))
    out: list[Finding] = []
    for f in data.get("confirmed", []):
        out.append(Finding(
            tool=f.get("tool", "unknown"), title=f.get("title", ""),
            severity=f.get("severity", "info"), description=f.get("description", ""),
            recommendation=f.get("recommendation", ""), cwe=f.get("cwe"),
            file_path=f.get("file_path"), line_start=f.get("line_start"),
            line_end=f.get("line_end"), target_url=f.get("target_url"),
            param=f.get("param"), request=f.get("request"), response=f.get("response"),
            poc=f.get("poc"), confidence=float(f.get("confidence", 0)),
            source_skill=f.get("source_skill", ""), status="confirmed",
            evidence_kind=f.get("evidence_kind", "")))
    return out
