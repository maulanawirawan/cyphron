# Install — secai

*English first; **Bahasa Indonesia di bawah**.*

> The vendored binaries under `tools/bin` are kept in the working repo but
> are **not** shipped in the OSS release (~442 MB). The core runs fine
> without them — grab them yourself only if you need the features that use
> them (PDF report, nuclei, ZAP).

## Core prerequisites

| Component | For | Check |
|---|---|---|
| Python 3.10+ | every skill/tool | `python --version` |
| Rust toolchain (stable) | the native `secai` core | `cargo build --release --manifest-path core-rs/Cargo.toml` |
| PyMuPDF (`pip install pymupdf`) | validating the PDF report output | `import fitz` |

Optional:
- `pip install "mcp[cli]"` — MCP server (`tools/mcp_server.py`)
- `pip install pysocks` — socks5 egress (without it socks5 fails loud; see `docs/EGRESS-SETUP.md`)

## Vendored binaries (`tools/bin`) — optional

Needed only for PDF reports (typst), the lab-only nuclei skill, and the
optional ZAP proxy. Scan / validate / triage all work without them.

Expected layout (Windows; other platforms use the matching folder name):

```
tools/bin/
  typst-x86_64-pc-windows-msvc/typst.exe   # PDF report
  nuclei/nuclei.exe                        # lab-only nuclei-templates-scan skill
  zap/                                     # ZAP (optional proxy)
```

### typst (PDF report)

1. Download the official typst release (`typst-x86_64-pc-windows-msvc.zip`).
2. Extract so `tools/bin/typst-x86_64-pc-windows-msvc/typst.exe` exists, OR
   put it anywhere and set env `SECAI_TYPST` to the binary path.
3. Or just put `typst.exe` on your `PATH`. Lookup order: env `SECAI_TYPST`
   → `tools/bin` → `PATH` (fail-closed: missing = `report_pdf` exits with a
   clear message).

### nuclei (lab-only, NOT used in tier0)

1. Download the official nuclei release (projectdiscovery).
2. Extract to `tools/bin/nuclei/nuclei.exe`.
3. Template corpus: `python tools/intel_sync.py` (fills `assets/intel`).
   Nuclei only runs through the `nuclei-templates-scan` skill
   (safety_class `active-probe`) — lab mode, your own target only.

### ZAP (optional)

Download official ZAP only if you use the proxy/port-forward flow:
`tools/zap-portproxy.ps1` (Windows). Without ZAP, all core features work.

## Build & verify

```
cargo build --release --manifest-path core-rs/Cargo.toml
python -m pytest tests/ -q
cargo test --release --manifest-path core-rs/Cargo.toml
python tools/nightrun.py --config nightrun.json --dry-run   # check the plan
```

Build output: `core-rs/target/release/secai(.exe)` — used by
`tools/program_sweep.py`, `tools/nightrun.py`, `tools/merge_findings.py`
(wrapper; falls back to pure Python if the binary isn't built).

---

# Instalasi — secai

Prasyarat dan cara mendapat binary vendored (folder `tools/bin` IKUT di
repo kerja tapi TIDAK ikut release OSS — 442 MB; unduh sendiri bila
membangun dari export).

## Prasyarat inti

| Komponen | Untuk | Cara |
|---|---|---|
| Python 3.10+ | semua skill/tools | `python --version` |
| Rust toolchain (stable) | engine core `secai` | `cargo build --release --manifest-path core-rs/Cargo.toml` |
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
   ATAU letakkan di mana pun lalu set env `SECAI_TYPST` ke path binary.
3. Alternatif: taruh `typst.exe` di `PATH`.
   Resolusi dicari berurutan: env `SECAI_TYPST` → tools/bin → PATH
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

Binary hasil build: `core-rs/target/release/secai(.exe)` — dipakai
`tools/program_sweep.py`, `tools/nightrun.py`, `tools/merge_findings.py`
(wrapper; fallback python murni bila binary tidak ada).
