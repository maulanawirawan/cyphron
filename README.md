# Cyphron Core

**AI pentest agent runtime yang berdiri sendiri** — zero third-party dependency, zero LLM provider, dibangun dari nol di atas Python stdlib. Membaca knowledge pack `.kimchi` (82 skill + guardrails + knowledge base) sebagai otak metodologinya.

> Posisi strategis: platform sejenis umumnya butuh Docker + pip + API key LLM berbayar untuk sekadar jalan.
> Cyphron Core butuh Python. Titik. Itu nilai jualnya.

---

## Yang sudah jadi (v0.1)

| Komponen | Status | Catatan |
|---|---|---|
| Skill Registry | ✅ | Parse `agent-config.yaml` (parser YAML sendiri — bukan PyYAML), muat 82 skill, retrieval top-k deterministik |
| Authorization Gate | ✅ | **Di-enforce kode, bukan prompt**: dokumen izin JSON (scope domain/wildcard/CIDR/port, expiry, restrictions), default DENY, degradasi ke read-only |
| Audit Log | ✅ | Hash-chain tamper-evident untuk setiap keputusan otorisasi & tool call (port dari `authorization-protocol.md`) |
| World Model | ✅ | Endpoint/param/teknologi terobservasi, snapshot, ringkasan ter-budget |
| Engine buatan sendiri | ✅ 7 unit | `http_probe`, `security_headers`, `crawler`, `dir_probe`, `sqli_probe` (error+boolean), `xss_probe` (marker konteks), `secret_scan` — **tanpa tool pihak ketiga** |
| Tool Guard | ✅ | Kill switch, rate limit, budget request, timeout, redaksi secret di semua evidence/log |
| Verifier | ✅ | Finding = CONFIRMED hanya dengan bukti konkret (request/response, probe-pair, code-line). Sisanya `unconfirmed`, dilaporkan terpisah |
| Deterministic Planner | ✅ | Loop observe→plan→act→update→verify **tanpa LLM sama sekali** |
| Reporting | ✅ | `report.md` (exec summary, PoC `curl`, remediasi, sitasi skill) + `findings.json` (skema interop) + `audit.jsonl` |
| Persistensi | ✅ | SQLite (stdlib `sqlite3`): scans, findings, audit chain |

## LLM Planner Slot (sengaja TIDAK dipasang)

Tim belum memilih model/provider — dan memang tidak dibutuhkan untuk jalan. Titik integrasinya sudah disiapkan:

- `cyphron/planner.py` → `DeterministicPlanner.plan()` adalah satu-satunya tempat keputusan diambil. Nanti tinggal implement `LLMPlanner.plan()` dengan signature sama dan pass ke `run_scan(...)`.
- Gate otorisasi, verifier, dan audit log **tidak akan pernah** bergantung pada LLM — enforcement tetap di kode, apa pun otaknya.

## Cara pakai

```bash
cd D:/GODMODE/training/cyphron

# 1. Cek skill registry (82 skill dari .kimchi)
python -m cyphron skills --query "sql injection di form login"

# 2. Validasi dokumen otorisasi saja
python -m cyphron check --target http://localhost:3000 --auth examples/authorization.localhost.json

# 3. Scan read-only (TANPA auth: tool aktif otomatis ditolak)
python -m cyphron scan --target http://localhost:3000 --out out_ro

# 4. Scan ofensif terotorisasi (butuh dokumen izin; target wajib in-scope)
python -m cyphron scan --target http://localhost:3000 --auth examples/authorization.localhost.json --out out_lab
```

Exit codes: `0` bersih · `2` ada temuan terkonfirmasi · `3` ditolak (otorisasi/scope) · `1` error.

Skema dokumen otorisasi: lihat `examples/authorization.localhost.json` (struktur mengikuti `guardrails/authorization-protocol.md`).

## Nilai jual Cyphron (vs platform sejenis)

| Dimensi | Pola umum platform sejenis | **Cyphron Core** |
|---|---|---|
| Mesin deteksi | sering sewa tool pihak ketiga | **kode sendiri, bisa diaudit** |
| Wajib LLM API (bayar/token) | umumnya ya | **tidak — jalan tanpa LLM** |
| Otorisasi | attestation teks / checkbox | **gate kode: scope CIDR/wildcard/expiry/restrictions + audit hash-chain** |
| Dependensi runtime | Docker+DB+queue+runtime khusus | **stdlib Python, NOL install** |
| Reasoning | sering delegasi ke pihak ketiga | **skill-driven, 65+ skill .kimchi + sitasi di laporan** |
| Temuan | authoritative per tool | **verifier bukti-basis: confirmed ≠ unconfirmed** |

## Klaim & benchmark (angka, bukan slogan)

Klaim pencocokan CVE Cyphron: **high-confidence deterministic matching with
ambiguity rejection** — rentang versi ambigu DITOLAK dan dicatat terpisah
(bukan false positive), bukan ditebak. Konsekuensinya precision naik dan
recall bisa turun; angkanya dilaporkan jujur, bukan disembunyikan.

Metrik kuantitatif (precision/recall/F1, CPE-resolution accuracy,
version-resolution accuracy, exploit-validation rate) dihitung dari pipeline
pencocokan NYATA atas dataset gold internal:

```bash
python -m cyphron benchmark                  # pakai KB lokal (kb sync nvd)
python -m cyphron benchmark --out docs/BENCHMARK.md
```

Hasil + metodologi: `docs/BENCHMARK.md`. Verdict ladder: hanya level >= 3
(deterministically verified ke atas) yang layak jadi temuan klien; level
0-2 = LEAD dilabel jelas dan tidak pernah dihitung sebagai temuan.

## Uji (self-owned lab, aman)

```bash
python -m unittest discover -s tests -v
```

`tests/test_e2e_fixture.py` menjalankan server lab rentan buatan sendiri (localhost, ephemeral port) dan membuktikan: (1) tanpa otorisasi, semua tool aktif DITOLAK; (2) dengan otorisasi in-scope, Cyphron menemukan SQLi error-based, reflected XSS, /.env, /.git/HEAD — dengan PoC; (3) target di luar scope ditolak; (4) audit chain terverifikasi & deteksi tamper.

## ROADMAP (setelah v0.1)

1. **Engine perluasan**: cookie/session handling, form-POST probing, NoSQLi probe, SSRF probe, open-redirect, template injection (SSTI), CORS audit, TLS quick-check.
2. **Skill atomization**: refactor 82 skill prosa → unit atomik (inputs/outputs/allowed_tools/preconditions) + index SQLite; retrieval embedding menyusul saat LLM slot dipasang.
3. **Skill synthesis**: pola sukses → skill baru status `proposed` di `.kimchi/ferments/` (review gate manual).
4. **LLM slot**: `LLMPlanner` (provider TBD oleh tim) untuk narasi laporan + hipotesis ad-hoc; gate tetap kode.
5. **Eval harness**: regresi otomatis terhadap Juice Shop (`../juice-shop`) — detection rate & false positive rate per engine.
6. **Headless browser plugin** (opsional): untuk XSS DOM-based — satu-satunya tempat non-stdlib dibenarkan, via subprocess terisolasi.
