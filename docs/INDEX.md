# INDEX — Dokumentasi Cyphron

> Peta semua dokumen. Quickstart satu-perintah ada di README §Cara pakai.

## Alur kerja utama
- [ROADMAP-UNITY.md](ROADMAP-UNITY.md) — brain/graph/verdict/bukti (status per batch)
- [ROADMAP-FULLPOWER-SHOWCASE.md](ROADMAP-FULLPOWER-SHOWCASE.md) — polyglot, mobile, code intelligence, showcase
- [ROADMAP-GODTIER-KNOWLEDGE.md](ROADMAP-GODTIER-KNOWLEDGE.md) — knowledge base lokal (NVD/EDB/nuclei)

## Laporan & klaim
- [BENCHMARK.md](BENCHMARK.md) — precision/recall/F1, CPE & version resolution (angka, bukan slogan)
- [STUDI-KASUS-GAMBLER-NETWORK.md](STUDI-KASUS-GAMBLER-NETWORK.md) — threat intel ter-redaksi (label [B]/[I])
- [DEMO-5-MENIT.md](DEMO-5-MENIT.md) — skrip golden demo
- [DEMO-VIDEO-3MENIT.md](DEMO-VIDEO-3MENIT.md) — storyboard video demo

## Referensi teknis
- [VULN-CLASS-CATALOG.md](VULN-CLASS-CATALOG.md) — katalog kelas kerentanan
- [ROADMAP-CAPABILITIES.md](ROADMAP-CAPABILITIES.md) — peta kapabilitas engine
- `guardrails/authorization-protocol.md` — skema dokumen otorisasi

## Quickstart satu-perintah (lab milik sendiri)

```bash
python -m cyphron scan --target http://127.0.0.1:3000 --auth examples/authorization.localhost.json --out out_lab
```

Kemampuan CLI lain: `check`, `verify`, `drift`, `fix`, `suggest`, `perf`,
`kb`, `god-report`, `benchmark`, `redteam`, `own`, `adapters`, `deobf`,
`apk-report`, `sast`, `dast`, `iac`, `proxy`, `tiers`, `skills`.
