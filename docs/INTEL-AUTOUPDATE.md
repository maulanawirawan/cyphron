# Intel Auto-Update — mesin "selalu tahu" milik Cyphron (F67)

> Tujuan: setiap kali ada CVE/patch baru, produk **mengetahuinya tanpa
> operator menyentuh apa pun**, dan saat client menjalankan scan, hasil
> yang keluar adalah **lead tervalidasi** (bukan klaim kosong, bukan
> false positive). Prinsip lama tetap: fail-closed, zero-FP, ladder
> L-x..L5, local-first, dan **maksimum L1 untuk lead** — reportable
> tetap butuh bukti L3+.

## 1. Kenapa "realtime" penuh bukan jawabannya

Feed keamanan tidak streaming: KEV di-update beberapa kali sehari, NVD
mengalami lag enrichment, OSV di-update event-driven. Menarik data tiap
detik = kena rate limit + data setengah jadi. Desain yang benar:

- **TTL-based freshness** — feed cepat 6 jam, nuclei 12 jam, CWE 168
  jam; maksimum umur data diketahui dan dilaporkan;
- **live lookup di titik audit** untuk data yang memang per-query
  (OSV.dev saat mengaudit dependensi);
- **laporan freshness** yang jujur: kalau data basi, produk bilang basi.

Hasil praktis: umur data maksimum 24 jam, dan audit dependensi bisa
memakai data yang benar-benar live pada saat scan.

## 2. Arsitektur tiga lapis

```
        ┌─────────────────────────────────────────────────────┐
        │ LAPIS 1 — SYNC (intel_sync.py)                      │
        │ nuclei-templates · CISA KEV · CWE · watchlist ·     │
        │ nvd-ranges (CPE cpeMatch)                           │
        │ TTL · atomic write (tmp+replace) · manifest+delta   │
        └─────────────────────────┬───────────────────────────┘
                                  │ data lokal (assets/intel/)
        ┌─────────────────────────▼───────────────────────────┐
        │ LAPIS 2 — MATCHING                                  │
        │ cve_matcher.py   : fakta web -> KEV/KB/watchlist    │
        │ dependency_cve.py: paket lokal -> NVD ranges/OSV    │
        │ klaim versi HANYA dari rentang eksplisit            │
        └─────────────────────────┬───────────────────────────┘
                                  │ findings.json (satu pintu)
        ┌─────────────────────────▼───────────────────────────┐
        │ LAPIS 3 — ORKESTRASI (auto_update.py)               │
        │ sync semua (TTL-gated) -> freshness -> status.json  │
        │ + Windows Task Scheduler harian                     │
        └─────────────────────────────────────────────────────┘
```

## 3. Sumber data & otoritas

| Sumber | Isi | Update | Dipakai untuk |
|---|---|---|---|
| CISA KEV | CVE yang terkonfirmasi dieksploitasi | harian | lead product-level di cve-matcher |
| NVD API 2.0 | CVE + CVSS + **CPE cpeMatch range** | harian (delta 3 hari) | `nvd-ranges.json` → audit dependensi |
| OSV.dev | rentang per **ekosistem** (PyPI/npm/…) | live per query + cache 24 jam | `dependency_cve --osv` |
| nuclei-templates | 14 rb+ template komunitas | harian (sha commit) | active-probe lab-only |
| Operator KB | rentang versi dari advisory vendor | dikurasi | klaim versi di cve-matcher |
| Watchlist seeds | CVE kritis di luar KEV | kurasi + NVD window | lead breaking-CVE |

**Aturan anti-fabrikasi**: KEV tidak membawa rentang versi → selalu
product-level. Rentang versi hanya dari NVD CPE (mesin, otoritatif),
OSV (mesin, per ekosistem), atau KB operator (manusia, wajib
`source_url`).

## 4. Komponen `nvd-ranges`

- Menarik CVE **CRITICAL + HIGH** via `lastModStartDate`:
  bootstrap 120 hari; setelah indeks ada, delta 3 hari (merge).
- Hanya `cpeMatch` dengan `vulnerable: true` **dan** constraint
  eksplisit (`versionStart/EndIncluding/Excluding` atau versi exact);
  wildcard murni dilewati.
- Retensi **4 tahun** (default; override `CYPHRON_NVD_RETAIN_DAYS`);
  dedup by (cve, vendor, product, range); atomic write; manifest
  mencatat `entry_count`, `delta_from_prev`, `window_days`.
- **Backfill historis**:
  `python tools/intel_sync.py --backfill-days 730` — chunk <=120 hari,
  resumable via `assets/intel/nvd-backfill-state.json`; interupsi =
  lanjut dari titik terakhir; `--force` = ulang rentang. Rate limit
  sama (2 request/severity per chunk + jeda sopan).
- Rate limit: 2 request/sync (tanpa API key: jeda sopan 6,5 s);
  `NVD_API_KEY` opsional untuk batas lebih tinggi.
- Verifikasi: `python tools/intel_sync.py --verify --components
  nvd-ranges` (mismatch disk vs manifest = exit 2).

## 5. Audit dependensi (`tools/dependency_cve.py`)

Masukan: `requirements.txt`, `package-lock.json`, **CycloneDX JSON**,
dan **SPDX JSON** (ekosistem diambil dari purl, termasuk npm scoped
`%40scope/name`). `--format auto` mendeteksi dari nama file + sniffing
JSON; format bisa dipaksa eksplisit.

```
python tools/dependency_cve.py --file requirements.txt
python tools/dependency_cve.py --file package-lock.json --osv
python tools/dependency_cve.py --file bom.cdx.json
python tools/dependency_cve.py --file app.spdx.json
```

- **Offline**: nama paket ternormalisasi harus **SAMA PERSIS** dengan
  product CPE (bukan substring), lalu versi harus berada di rentang.
  `fixed` diambil dari `versionEndExcluding`.
- **Online opt-in (`--osv`)**: OSV.dev mengembalikan rentang eksplisit
  per ekosistem; interval `introduced`/`fixed`/`last_affected` diuji
  ketat; cache 24 jam per (ecosystem, package, version).
- Versi tak terurai (`1.2.3-rc1`) = dilewati dan dihitung di meta;
  tidak ada klaim.
- Nama yang tidak punya padanan CPE = `unmapped`, bukan "aman".
- Semua hasil **lead L1** — verifikasi manual tetap wajib.

Contoh live (2026-10-28, indeks NVD 6.787 entri):

| Paket | Versi | Temuan | Fix |
|---|---|---|---|
| pillow (PyPI) | 12.9.0 | 4 CVE (CVE-2026-112900 dkk), critical | 13.0.0 |
| undici (npm) | 8.12.1 | 2 CVE (CVE-2026-109829 dkk), high | 8.12.2 |

## 5b. Konfigurasi OSV & alias CPE↔paket

- `assets/intel/dependency-config.json` — `osv_default` (default
  **false** = lokal-first: tidak ada request keluar tanpa `--osv`) dan
  `osv_cache_ttl_hours`. CLI `--osv` / `--offline` menimpa config.
- `assets/intel/dep-aliases.json` — mapping terverifikasi
  `{ecosystem, package, product}` untuk nama paket yang berbeda dari
  product CPE. Kosong = tanpa penebakan; alias hanya membuka
  pencocokan rentang yang sudah ada, **bukan** menambah klaim. Paket
  tanpa padanan tetap dihitung `unmapped`.

Meta `cross_confirmed` / `eliminated` mencatat jumlahnya per run.

### Verifikasi bertingkat (eliminasi FP di jalur dependensi)

Query OSV dilakukan **per paket** (semua vuln paket itu; cache per
paket), lalu versi dievaluasi terhadap rentang masing-masing. Hasilnya
direkonsiliasi dengan NVD:

| Kondisi | Hasil |
|---|---|
| NVD range + OSV sepakat | **L2 cross-confirmed** (`sources: [nvd-range, osv]`) |
| NVD hit, OSV mengenal paket tapi tidak ada rentang valid yang mencakup CVE untuk versi ini | **L-x REJECTED** — FP tereliminasi, tercatat (kategori `FP-ELIMINATED`, status `false-positive`), tidak dilaporkan |
| Single-source (OSV off / gagal / paket tak dikenal OSV) | **L1 lead** |
| Record OSV `withdrawn` | bukan temuan, juga bukan bukti eliminasi |
| Reportable | tetap butuh L3+ (verifikasi manual/lab) |

Live 2026-10-28 (SBOM pillow+undici): 28 NVD hits → **28 L2
cross-confirmed**, +22 OSV-only L1, 0 eliminasi (sumber sepakat penuh);
jalur eliminasi terkunci oleh unit test (`ReconcileTest`).

## 6. Orkestrasi & penjadwalan

```
python tools/auto_update.py                 # sync semua (TTL-gated) + laporan
python tools/auto_update.py --force         # abaikan TTL
python tools/auto_update.py --check         # laporan freshness saja
python tools/auto_update.py --install-schedule 01:30 --interval-hours 6
python tools/auto_update.py --remove-schedule
```

- Task Windows: **`cyphron-intel-daily`** (interactive-only, tanpa
  password), **tiap 6 jam mulai 01:30** — feed cepat (KEV/watchlist/
  nvd-ranges) punya TTL 6 jam, jadi tiap run benar-benar menyegarkan;
  nuclei 12 jam; CWE 168 jam. Nightrun 02:00 memakai intel paling segar.
- Hasil tulis: `findings/intel/status.json` (kontrak findings; L0/L1).
- Satu komponen gagal tidak menghapus state lama (fail-closed) dan
  dicatat sebagai lead `INTEL-AUTOUPDATE`.

## 7. TTL & arti "segar"

| Komponen | TTL |
|---|---|
| nuclei-templates | 12 jam |
| CISA KEV | 6 jam |
| watchlist | 6 jam |
| nvd-ranges | 6 jam |
| CWE | 168 jam |

`detection_freshness.py` melaporkan komponen stale + drift (jumlah
nyata vs manifest). Kalau mau lebih agresif: jalankan auto_update tiap
3 jam — TTL membuatnya murah (sync hanya jalan saat lewat TTL).

## 8. Batasan yang harus jujur

1. **CPE product ≠ nama paket** selalu. Exact-match mengurangi FP,
   tetapi nama generik bisa bertabrakan; karena itu NVD-range selalu
   **lead**, dan OSV adalah sumber presisi untuk paket.
2. **NVD lag**: CVE baru bisa belum punya CPE/range; watchlist menutup
   jendela "belum terkonfirmasi".
3. **OSV butuh jaringan** saat `--osv`; tanpa itu audit offline tetap
   jalan dengan indeks lokal.
4. **Tidak ada auto-exploit**: semua hasil deteksi/lead; eksekusi tetap
   domain lab + gate fail-closed (docs/EXPLOIT-TIER.md).
5. **Backfill butuh waktu** (rate limit NVD): 240 hari ≈ 2 chunk;
   730 hari ≈ 7 chunk. Jalankan sekali, lalu delta harian menjaga tetap
   segar. Indeks menyimpan hingga 4 tahun (bisa diubah via env).
