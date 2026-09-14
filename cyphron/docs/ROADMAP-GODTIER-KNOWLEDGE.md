# ROADMAP-GODTIER-KNOWLEDGE — integrasi KB dunia (Nuclei + NVD/CVE + Exploit-DB)

> Dibuat 14 Sep 2026 atas permintaan user (misi "GOD-TIER" — HANDOFF-SESSION-
> 20260914.md bagian 2). Prinsip: KB = **senjata katalog** — semua matcher
> PASIF secara default; eksekusi template hanya untuk subset aman + scope
> berizin. Tetap: zero-FP, cease-on-data, redaksi, rate-limit 1, cap request.
> Status: [ ] = antrean, [>] = sedang, [x] = tuntas.
> **Parser YAML: DIPUTUSKAN user 14 Sep = perluas `cyphron/yamlite.py` yang
> sudah ada (no PyYAML, doktrin stdlib-only utuh).**
> **TUNTAS 14 Sep (batch 1-4b): komponen A-F live, 128 engine terdaftar,
> suite 438/438 hijau. Catatan realitas jaringan Sep 2026: feed NVD 1.1
> 403 → fallback API 2.0 otomatis (kb/nvd_api.py, jendela 120 hari +
> throttle etis); exploitdb pindah ke GitLab resmi → mirror fallback;
> UA default python-urllib diblokir → User-Agent eksplisit. Bukti: nuclei
> 14.094 berkas (1.653 lolos gerbang aman), EDB 47.161 entri.**

## 0. BUKTI NILAI (kenapa ini GOD-TIER)
123 engine kita menghasilkan temuan per-temuan (CWE biasa). Dengan KB dunia,
satu banner versi (`Server: nginx/1.24.0`, `X-Powered-By: PHP/8.1.34`,
meta generator OJS 3.4.0.7) berubah jadi:
**fingerprint → CPE 2.3 → ribuan CVE ber-CVSS → referensi exploit publik
(EDB-ID) → template nuclei yang bisa konfirmasi ringan** — semuanya offline,
tanpa satu request tambahan ke target. Ini kualitas laporan konsultan, dan
jalur menjadikan Cyphron layak dibayar (kasus pertama: BIM University).

## 1. SUMBER KB (offline-first, semua bisa sinkron ulang)
| Sumber | Isi | Bentuk lokal |
|---|---|---|
| nuclei-templates (ProjectDiscovery) | 10.000+ template YAML | `kb/data/nuclei/` (tarball HEAD / git --depth 1) |
| NVD (nvd.nist.gov) | CVE + CVSS 3.1 + CPE match rules | `kb/data/nvd/nvdcve-1.1-<tahun>.json.gz` (feed bulk; fallback API 2.0 incremental) |
| NVD CPE dictionary | kamus CPE 2.3 resmi | `kb/data/nvd/cpe-dictionary.xml.gz` (untuk verifikasi cpe_map) |
| exploitdb (OffSec) | files_exploits.csv (ID exploit publik) | `kb/data/edb/files_exploits.csv` (raw CSV, tanpa clone penuh) |
| Indeks turunan | CPE↔CVE (SQLite stdlib) | `kb/data/cpe.sqlite` (dibangun kb_sync dari feed NVD) |

- Semua unduhan: urllib/gzip/zipfile stdlib; fallback `git clone --depth 1`
  bila tarball gagal. Verifikasi hash + manifest versi.
- **`kb/data/` MASUK .gitignore** (berat + bukan kode). Yang di-commit: kode
  Python, `cpe_map.yaml`, manifest CONTOH, fixtures test kecil.

## 2. LAYOUT REPO
```
cyphron/kb/__init__.py        # paket KB
cyphron/kb/paths.py           # lokasi data dir + manifest (default: cyphron/kb/data)
cyphron/kb/kb_sync.py         # unduh/verifikasi/build — dipakai CLI `kb`
cyphron/kb/nvd_sqlite.py      # feed NVD -> cpe.sqlite (schema di §4)
cyphron/kb/fingerprint.py     # fingerprint -> CPE 2.3 (cve_matcher engine memakai ini)
cyphron/kb/cpe_map.yaml       # PETA KITA: pola fingerprint -> CPE (dipelajari dari kamus CPE NVD)
cyphron/kb/nuclei_loader.py   # baca template nuclei via yamlite (keputusan §7), skip yang gagal parse
cyphron/kb/edb_index.py       # files_exploits.csv -> indeks (vendor/product/versi)
cyphron/tools/fingerprint_to_cpe.py
cyphron/tools/cve_matcher.py
cyphron/tools/edb_reference.py
cyphron/tools/nuclei_bridge.py
cyphron/god_report.py         # gabung temuan live + exposure + konfirmasi + edb
docs/ROADMAP-GODTIER-KNOWLEDGE.md (file ini)
tests/fixtures/kb/            # template nuclei mini, feed NVD mini, CSV edb mini, cpe_map mini
tests/test_kb_sync.py, test_kb_cve.py, test_kb_nuclei.py, test_god_report.py
```

## 3. KOMPONEN (6)
### A. [ ] kb_sync — "pustakawan"
- CLI: `python -m cyphron kb --source all|nuclei|nvd|edb [--kb-dir DIR]`.
- Unduh/tarik sumber (§1), cek hash, tulis `kb/data/manifest.json`
  ({source: {synced_at, origin, sha256, jumlah_file, tahun_feed}}).
- Feed NVD dibangun → `cpe.sqlite` (schema §4) langsung di sini.
- Gagal jaringan = PESAN JELAS + KB lama tetap utuh (scan tidak boleh rusak).
- Tanpa KB sama sekali → semua engine KB no-op dengan note "KB belum
  tersinkron: python -m cyphron kb --source all" (jangan crash).

### B. [ ] fingerprint_to_cpe — "penerjemah"
- Input: `WorldModel.technologies` (header Server/X-Powered-By, meta
  generator, temuan banner engine lama) ATAU argumen manual
  `--tech "nginx/1.24.0" --tech "OJS 3.4.0.7"`.
- `cpe_map.yaml`: tiap entri = regex ketat (wajib ada versi untuk mapping
  penuh; tanpa versi → CPE version="*" tapi TANPA klaim CVE otomatis),
  vendor+product sesuai kamus CPE NVD (diverifikasi saat build).
- Output: list {cpe23, vendor, product, version, evidence}.
- Zero-FP: tidak menebak dari substring longgar (pelajaran "up"→"Sign up").

### C. [ ] cve_matcher — "pembanding pasif"
- risk_tags {"passive","local"} — NOL request jaringan, query sqlite saja.
- CPE → join cve_cpe + cve → urut CVSS desc → **LEAD**:
  - Temuan `info` / finding_class="surface" / status="unconfirmed" dengan
    judul "CVE exposure: <produk> <versi> — <n> CVE rentang cocok (top:
    CVE-XXXX CVSS y)" + cwe tiap item; cap top 10 produk/CVE di temuan,
    sisanya world.note.
  - Version TIDAK diketahui / aturan range ambigu → world.note saja
    (BUKAN temuan). Ini garis zero-FP.
  - Konfirmasi kerentanan = HANYA bila verifikasi ringan aman-deterministik
    memungkinkan (mis. endpoint GET PoC yang tidak merusak) → status
    "confirmed" + bukti request/response.
- Severity temuan tetap "info": skor CVSS dicatat sebagai DATA, bukan
  klaim — penentu akhir tetap skema severity program (aturan house).

### D. [ ] nuclei_bridge — "eksekutor template terkurasi"
- risk_tags {"active"} — lewat gate otorisasi seperti engine lain.
- Pemilihan template (fail-safe dua lapis):
  - WHITELIST tag: {cve, info, misconfig, config, exposure, token, redirect}
    (template wajib punya ≥1 tag ini) — DAN severity {info, low} untuk
    mode default. Medium/High hanya bila `--allow-severity medium` + user
    bilang gas eksplisit di sesi.
  - BLACKLIST tag: {dos, bruteforce, overflow, fuzz, intrusive, password,
    brute, stealth, interactsh} — satu tag hitam = buang.
  - Struktur aman: 1 request GET, path placeholder sederhana ({{BaseURL}}),
    matcher word/status/description saja, TANPA raw-payload destruktif,
    TANPA dependensi OOB. Template DSL/ kompleks / gagal parse = SKIP
    (dihitung di statistik, bukan error).
- Eksekusi: 1 request per template, throttle via ctx (rate-limit 1 saat
  produksi), cap `--max-templates` (default 25), skip path yang SUDAH
  diproba engine lain (world.endpoints probed) — dedup dengan registry.
- Zero-FP: match wajib STATUS + ISI body (word matcher), bukan status
  sendirian (pelajaran SIPAS catch-all 200).
- Hasil: Finding dari info template (severity template), evidence
  request/response, judul diawali "[nuclei:<id>]".

### E. [ ] edb_reference — "penunjuk exploit publik"
- risk_tags {"passive","local"} — TIDAK PERNAH menjalankan exploit.
- Match fingerprint/produk+versi → baris files_exploits.csv (description
  berisi nama produk+versi) → temuan info "Public exploit exists:
  EDB-<id> (<judul>)" + catatan "severity boost reason" untuk temuan
  cve_matcher terkait (attach_evidence, bukan naik-angka buta).
- Tidak cocok = note kecil, bukan temuan.

### F. [ ] god_report — "gabungan tier atas"
- CLI: `python -m cyphron god-report --from <folder-scan> [--kb-dir] --out <md>`.
- Baca findings.json + snapshot world → jalankan pipeline pasif
  (B→C→E) → tabel CVSS 3.1 urut skor + temuan live + konfirmasi nuclei +
  referensi EDB → satu markdown GOD-TIER.
- Bagian wajib: metodologi (sumber KB + versi manifest), disclaimer LEAD
  vs CONFIRMED, "skema severity program = penentu akhir".
- Bisa dipanggil dari scan biasa sebagai tahap pasca (`--god` pada scan,
  opsional batch 4).

## 4. SCHEMA cpe.sqlite (stdlib sqlite3)
```sql
CREATE TABLE cpe (cpe23 TEXT PRIMARY KEY, vendor TEXT, product TEXT,
                  version TEXT, update_kw TEXT);
CREATE TABLE cve (id TEXT PRIMARY KEY, published TEXT, modified TEXT,
                  cvss_score REAL, cvss_vector TEXT, cwe TEXT,
                  description TEXT);
CREATE TABLE cve_cpe (cve_id TEXT, cpe23 TEXT,
                      version_start_incl TEXT, version_end_incl TEXT,
                      version_start_excl TEXT, version_end_excl TEXT);
CREATE INDEX idx_cpe_vp ON cpe(vendor, product);
CREATE INDEX idx_cc ON cve_cpe(cve_id);
```
- Matching konservatif: vendor+product exact (fallback LIKE dilarang untuk
  klaim; hanya untuk kandidat yang lalu diverifikasi ketat), versi
  dibandingkan semantik terhadap bound range; wildcard "*" hanya bila versi
  target diketahui cocok semua ATAU ditandai LEAD rendah (note).

## 5. GUARDRAIL (tetap, tanpa kompromi)
1. Zero-FP: verifikasi ISI respons; matcher nuclei wajib body-match; versi
   ambigu = note bukan temuan.
2. Pasif default: cve_matcher/edb_reference nol request; nuclei_bridge
   whitelist+blacklist+severity gate; agresif hanya bila auth doc + "gas".
3. cease-on-data, redaksi PII, cap request, rate-limit 1 — lewat
   ToolContext/gate yang sudah ada.
4. TIDAK menjalankan exploit EDB; TIDAK template dos/bruteforce/overflow;
   TIDAK bukti palsu.
5. scratch/ tidak pernah di-push; kb/data/ ikut .gitignore; commit message
   Bahasa Indonesia; suite hijau sebelum tiap push.

## 6. UJI (semua offline, pola PatchedServer + fixture)
- kb_sync: monkeypatch unduhan → manifest benar; KB rusak → no-op aman.
- nvd_sqlite: feed mini fixture → sqlite benar → query CPE cocok/ tidak.
- fingerprint: banner/generator BIM nyata → CPE tepat; tanpa versi →
  version="*" tanpa klaim.
- cve_matcher: CPE dengan range cocok → lead; ambigu → note; cap 10.
- nuclei_bridge: template info GET cocok → temuan + 1 request; template
  dos/DSL → skip; body match wajib (catch-all 200 tidak lolos).
- edb_reference: CSV mini → EDB-ID ketemu; tidak cocok → note.
- god_report: folder scan dummy + KB fixture → markdown lengkap.
- Suite penuh 385+ harus tetap hijau di setiap batch.

## 7. KEPUTUSAN (selesai)
1. **Parser YAML nuclei**: [x] DIPUTUSKAN USER 14 Sep — PERLUAS
   `cyphron/yamlite.py` (stdlib-only; tambahan block-scalar pada item list
   `- |` + varian chomping; template yang tidak terbaca di-SKIP aman).
   Hasil nyata: 4.141/13.717 template nuclei terbaca yamlite, 1.653 lolos
   gerbang keamanan — cukup untuk kelas info/low/misconfig/panel.
2. Rentang tahun feed NVD default [x] 2018-2026 via API 2.0 (feed 1.1 403;
   API key opsional env NVD_API_KEY untuk kuota 50 req/30 dtk).

## 8. BATCH BUILD (commit + push per batch, pesan Bahasa Indonesia) — TUNTAS
- [x] Batch 1 7853382: fix flaky lockout (retry dihitung plafon)
- [x] Batch 1 1ecaba5: roadmap + kb package + kb_sync + loader nuclei + CLI kb
- [x] Batch 2 760af96: cpe_map + fingerprint_to_cpe + nvd_sqlite + cve_matcher
- [x] Batch 3 e257a04: edb_reference + nuclei_bridge + registry
- [x] Batch 4 d9534e1: god_report + CLI god-report + hook planner cve_matcher
- [x] Batch 4b 0f8a1cb: NVD API 2.0 fallback + mirror EDB GitLab + UA + test isolation
- [x] Batch 5: DEMO BIM (kerja di scratch/bim_bb/, TIDAK di-push): pipeline
      pasif atas fingerprint BIM nyata → GOD-REPORT-BIM + addendum "Analisis
      Exposure" untuk laporan Rektor. Demo nuclei_bridge live ke host BIM
      HANYA setelah user bilang gas di sesi.
- [ ] Batch 6 (tutup): update README/doktrin + handoff berikutnya.

## 9. KELUARAN YANG DIJANJIKAN (definisi selesai)
`python -m cyphron kb --source all` → KB lokal terverifikasi;
`python -m cyphron scan ...` + KB → temuan live + exposure;
`python -m cyphron god-report --from ...` → laporan tier konsultan;
suite hijau; zero temuan palsu di demo BIM; user bisa menunjukkan
"Cyphron tahu 240.000 CVE dan 40.000 exploit publik" ke Rektor.
