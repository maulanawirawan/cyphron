"""Knowledge Base lokal Cyphron (offline-first) — senjata katalog dunia.

Isi paket:
- paths.py         : lokasi data KB + manifest versi
- kb_sync.py       : unduh/perbarui sumber (nuclei/nvd/edb) + verifikasi hash
- nuclei_loader.py : baca template nuclei (subset aman) via yamlite — no PyYAML
- nvd_sqlite.py    : feed NVD -> kb/data/cpe.sqlite (indeks CPE<->CVE)
- fingerprint.py   : fingerprint teknologi -> CPE 2.3 (cpe_map.yaml)

KB = "senjata katalog": matcher PASIF default; tidak ada satu pun request
ke target dari paket ini. Data hasil unduhan ada di kb/data/ (gitignored).
"""

from __future__ import annotations
