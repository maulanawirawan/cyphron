# Benchmark Cyphron — referensi fixture

Metrik referensi di bawah dihitung pada fixture KB kecil deterministik (dataset gold internal, offline — bisa direproduksi lewat `tests/test_benchmark.py`). Untuk angka atas KB penuh di mesinmu, jalankan `python -m cyphron benchmark`.


Metrik dihitung dari pipeline pencocokan nyata (fingerprint -> CPE -> KB NVD lokal) atas dataset gold internal. Bahasa klaim resmi: **High-confidence deterministic CVE matching with ambiguity rejection** — kasus ambigu DITOLAK (tercatat terpisah, bukan false positive); konsekuensinya recall bisa lebih rendah, dan angkanya dilaporkan jujur di sini.

| Metrik | Nilai |
|---|---|
| Precision (CVE matching) | 1.00 |
| Recall (CVE matching) | 1.00 |
| F1 | 1.00 |
| False positive | 0 |
| False negative | 0 |
| CPE-resolution accuracy | 1.00 (6/6) |
| Version-resolution accuracy | 1.00 (6/6) |
| Kasus ambigu ditolak | 0 |

## Rincian kasus

| Fingerprint | CPE | Prediksi | Gold | Ambigu ditolak | OK |
|---|---|---|---|---|---|
| WordPress 6.4.3 | wordpress/wordpress | CVE-2024-4439 | CVE-2024-4439 | 0 | ya |
| Open Journal Systems 3.3.0 | public_knowledge_project/open_journal_systems | CVE-2022-24181 | CVE-2022-24181 | 0 | ya |
| Open Journal Systems 3.4.0.7 | public_knowledge_project/open_journal_systems | - | - | 0 | ya |
| nginx/1.20.1 | f5/nginx | - | - | 0 | ya |
| WordPress 6.5.3 | wordpress/wordpress | - | - | 0 | ya |
| WordPress | wordpress/wordpress | - | - | 0 | ya |
