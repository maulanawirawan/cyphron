# Install — cyphron

Prasyarat dan cara mendapat binary vendored (folder `tools/bin` IKUT di
repo kerja tapi TIDAK ikut release OSS — 442 MB; unduh sendiri bila
membangun dari export).

## Prasyarat inti

| Komponen | Untuk | Cara |
|---|---|---|
| Python 3.10+ | semua skill/tools | `python --version` |
| Rust toolchain (stable) | engine core `cyphron` | `cargo build --release --manifest-path core-rs/Cargo.toml` |
| PyMuPDF (`pip install pymupdf`) | validasi hasil PDF report | import `fitz` |

Opsional:
- `pip install "mcp[cli]"` — MCP server (tools/mcp_server.py);
- `pip install pysocks` — egress socks5 (tanpa ini socks5 fail-loud,
  lihat docs/EGRESS-SETUP.md).

## Binary vendored (`tools/bin`)

Layout yang diharapkan (Windows; nama folder platform lain menyesuaikan):

```
tools/bin/
  typst-x86_64-pc-windows-msvc/typst.exe   # laporan PDF
  nuclei/nuclei.exe                        # skill lab-only nuclei-templates-scan
  zap/                                     # ZAP (port proxy opsional)
```

### typst (report PDF)

1. Unduh release resmi typst (arsip `typst-x86_64-pc-windows-msvc.zip`).
2. Ekstrak sehingga ada `tools/bin/typst-x86_64-pc-windows-msvc/typst.exe`,
   ATAU letakkan di mana pun lalu set env `CYPHRON_TYPST` ke path binary.
3. Alternatif: taruh `typst.exe` di `PATH`.
   Resolusi dicari berurutan: env `CYPHRON_TYPST` → tools/bin → PATH
   (fail-closed: tidak ada = report_pdf keluar dengan pesan jelas).

### nuclei (lab-only, TIDAK dipakai mode tier0)

1. Unduh release resmi nuclei (projectdiscovery).
2. Ekstrak ke `tools/bin/nuclei/nuclei.exe`.
3. Template korpus: `python tools/intel_sync.py` (mengisi assets/intel).
   Nuclei hanya dijalankan skill `nuclei-templates-scan` (safety_class
   active-probe) — HANYA mode lab dengan target milik sendiri.

### ZAP (opsional)

Unduh ZAP resmi bila memakai alur proxy/port-forward:
`tools/zap-portproxy.ps1` (Windows). Tanpa ZAP semua fitur inti jalan.

## Build & verifikasi

```
cargo build --release --manifest-path core-rs/Cargo.toml
python -m unittest discover -s tests
cargo test --release --manifest-path core-rs/Cargo.toml
python tools/nightrun.py --config nightrun.json --dry-run   # cek rencana
```

Binary hasil build: `core-rs/target/release/cyphron(.exe)` — dipakai
`tools/program_sweep.py`, `tools/nightrun.py`, `tools/merge_findings.py`
(wrapper; fallback python murni bila binary tidak ada).
