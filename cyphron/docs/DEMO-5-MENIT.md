# DEMO 5 MENIT — Golden Demo Cyphron (lab milik sendiri)

> Aturan: demo HANYA di lab milik sendiri (fixture rentan lokal / Docker
> vuln-app milik sendiri). BUKAN aset pihak ketiga. Semua alur yang
> didemokan punya test di suite (python -m unittest discover -s tests).

## Menit 0:00-0:45 — Masalah: tool overclaim

Tunjukkan PDF laporan lama/landing: verdict ladder — LEAD vs temuan klien
dilabel jelas (L0-L5). Kalimat kunci: "Kami tidak menjual angka; kami menjual
keputusan yang bisa dibuktikan. Temuan = bukti deterministik (L3+); sisanya
dilabel LEAD."

## Menit 0:45-1:30 — Scan berotorisasi pada lab lokal

```bash
python -m cyphron check --target http://127.0.0.1:PORT --auth examples/authorization.localhost.json
python -m cyphron scan --target http://127.0.0.1:PORT --auth examples/authorization.localhost.json --out out_demo
```
Poin: gate otorisasi ditegakkan kode (tanpa dokumen = read-only), planner
evidence-driven, adaptive escalation (fase PROBE → PATTERN → ESCALATE →
PROVE terlihat di output/log), budget request terlihat.

## Menit 1:30-2:30 — Bukti & verdict

Buka `out_demo/report.pdf`:
- cover brandable + verdict ladder;
- tabel keputusan per area: ADA (terkonfirmasi) vs TIDAK DITEMUKAN;
- detail temuan dengan bukti request-response + PoC + chip L3;
- path graph (sampai sini lewat apa) + graph.svg;
- audit hash-chain TAMPER-EVIDENT (`audit.jsonl`).

## Menit 2:30-3:30 — Nambal & buktikan

```bash
python -m cyphron fix --from out_demo
# (terapkan fix pack di lab) lalu:
python -m cyphron verify --target http://127.0.0.1:PORT --auth examples/authorization.localhost.json --baseline out_demo --out out_verify
```
Poin: fixed / open / new — perbaikan yang tidak menutup temuan tidak
dianggap selesai.

## Menit 3:30-4:30 — Kemampuan beda (30 detik per item)

- `python -m cyphron benchmark` — precision/recall/F1 + ambiguity rejection
  (angka, bukan slogan).
- `python -m cyphron god-report --from out_demo` — KB NVD/EDB offline →
  CVE exposure sebagai LEAD pasif (nol request ke target).
- `python -m cyphron apk-report --apk lab.apk` — assessment kesiapan uji
  mobile (perm/native/packer/anti-tamper).
- `python -m cyphron redteam --from out_demo` — MITRE-lite coverage matrix +
  deteksi-hint per temuan untuk tim biru.
- `python -m cyphron adapters` — engine polyglot (C++/Node/Go/Rust/Java)
  dengan auto-detect runtime, guardrail satu pintu.

## Menit 4:30-5:00 — Penutup

- Zero-FP = disiplin: hasil negatif dilaporkan ("area diuji bersih"),
  ambigu DITOLAK bukan ditebak.
- Semuanya stdlib Python (tanpa dependensi), gate + audit hash-chain +
  usage ledger, siap dipasang on-prem.
- Tutup dengan studi kasus ter-redaksi (docs/STUDI-KASUS-GAMBLER-NETWORK.md):
  threat intel nyata dengan disiplin label [B]/[I].
