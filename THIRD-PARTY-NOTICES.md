# Third-party notices

Cyphron stands on other people's work. This is where that work gets
credited, along with how each piece is licensed and how Cyphron uses it.

*(Catatan ini sengaja ditulis dalam bahasa Inggris agar atribusi lisensi
mudah dirujuk lintas negara.)*

## Intel data sources

Pulled in at sync time, **not** redistributed inside this repo.

- **CISA Known Exploited Vulnerabilities (KEV)** — from CISA/DHS. A US
  government work, public domain.
- **NIST NVD (API 2.0)** — public US government data, public domain.
- **OSV.dev** — open-source vulnerability data, fetched through the
  public API only when you opt in with `--osv`. Thanks to the OSV and
  Google community for keeping it open.
- **MITRE CWE (view 1000)** — from MITRE. CWE is a MITRE trademark, used
  here with attribution.

## Scanning corpus

- **nuclei-templates** (projectdiscovery/nuclei-templates) — MIT License.
  The corpus is ingested locally through `intel_sync` and is **not**
  redistributed inside this repo.

## Runtime dependencies

- The Rust dependencies live in `core-rs/Cargo.toml` and `Cargo.lock`,
  each under its own open-source license (mostly MIT, Apache-2.0, or
  BSD).
- The main skill path runs on the Python standard library alone.

## Commercial use

Using Cyphron commercially needs a separate license — see
[LICENSE](LICENSE) (PolyForm Noncommercial 1.0.0) and get in touch
through https://github.com/maulanawirawan/cyphron/issues.
