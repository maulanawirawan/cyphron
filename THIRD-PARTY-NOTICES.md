# Third-party notices — Cyphron

Cyphron membangun di atas karya pihak ketiga. File ini mencantumkan sumber
eksternal dan status lisensinya sebagaimana dipakai proyek ini.

## Sumber data intelijen (diambil saat sync, tidak didistribusikan ulang di repo ini)
- **CISA Known Exploited Vulnerabilities (KEV)** — CISA/DHS; karya pemerintah
  AS, public domain.
- **NIST NVD (API 2.0)** — data publik pemerintah AS (public domain).
- **OSV.dev** — data kerentanan open source; diakses via API publik pada mode
  opt-in `--osv`. Terima kasih komunitas OSV/Google.
- **MITRE CWE (view 1000)** — sumber MITRE; CWE adalah merek dagang MITRE,
  digunakan dengan atribusi.

## Amunisi scanning
- **nuclei-templates** (projectdiscovery/nuclei-templates) — MIT License.
  Korpus di-ingest secara lokal via `intel_sync` dan TIDAK didistribusikan
  ulang di dalam repo ini.

## Runtime dependencies
- Dependensi Rust tercantum di `core-rs/Cargo.toml` / `Cargo.lock`, masing-
  masing di bawah lisensi open source-nya sendiri (umumnya MIT/Apache-2.0/BSD).
- Jalur skill utama memakai Python standard-library saja.

## Terkait komersial
Penggunaan komersial Cyphron memerlukan lisensi terpisah - lihat `LICENSE`
(PolyForm Noncommercial 1.0.0) dan hubungi pemilik repo via
https://github.com/maulanawirawan/cyphron/issues
