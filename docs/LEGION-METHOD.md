# LEGION-METHOD — cara kerja multi-fase untuk asessment panjang

*(Bahasa Indonesia — bahasa kerja repo ini.)*

Dokumen ini mendokumentasikan tiga mekanisme yang diadopsi cyphron dari
metode "legion" — cara kerja multi-agen yang terbukti di kompetisi
offensive-security — dibangun from scratch di atas kontrak cyphron
(bukti dulu, klaim belakangan; fail-closed).

**Atribusi**: metode ini terinspirasi [sapper-v2](https://github.com/N1nEmAn/sapper-v2)
(MIT) — pasukan AI otonom juara 1 kualifikasi online Tencent Intelligent
Attack-Defense Challenge (634 tim, 8 jam tanpa pengawasan, 1B token).
Tidak ada kode yang disalin; yang diambil adalah pola kerjanya, dan
implementasinya tunduk pada lisensi serta rambu cyphron.

## Peta mekanisme → alat cyphron

| Mekanisme (sapper) | Implementasi cyphron | Status |
|---|---|---|
| **Scout** — recon murah menentukan tebal tipisnya tenaga | `tools/target_scout.py` — maks. 2 GET jinak per target → tier `SOFT / GUARDED / UNREACHABLE` + bukti | ✅ alat |
| **History** — fact-intent graph 3 lapis (judul/ringkasan/bukti) | `tools/session_ledger.py` — ledger JSONL append-only; sesi mati, graph survive; intent harus bertumpu fakta | ✅ alat |
| **Watchdog zero-strategy** — keep-alive terpisah dari keputusan | `schtasks` + `tools/nightrun.py` (exit code jujur untuk scheduler) | ✅ sudah ada |
| **Endgame reconciliation** — akhir sesi: semua temuan sudah dilaporkan? | `tools/verdict_audit.py` + gerbang bukti "No proof, no report" | ✅ sudah ada |
| **Economy** — model tiering (otak besar memutuskan, otak murah mengerjakan) | belum dibutuhkan — cyphron tidak meng-orkestrasi LLM saat ini | 💡 catatan desain |
| **Family transfer** — satu pola pecah, seluruh keluarga soal di-garap | `docs/AWARENESS-PATTERNS.md` + `tools/exploit_playbooks.py` | ✅ sudah ada |

## Cara pakai pasangan scout → scan → ledger

```bash
# 1. scout dulu — tenaga mahal jangan diboroskan ke target mati
python tools/target_scout.py --targets targets.txt --out scout.json

# 2. tier0 hanya untuk target yang layak (nightrun config: budget 0 = SKIP)
python tools/nightrun.py --config nightrun.json

# 3. catat hasil ke ledger — sesi berikutnya tidak mulai dari nol
python tools/session_ledger.py fact "staging X: tier0 3 temuan, 1 confirmed" \
    --summary "permukaan lembut, lanjut proof tier" \
    --evidence "findings/staging-x/tier0.json"
python tools/session_ledger.py intent --from F001 "proof tier untuk temuan F001"

# sesi berikutnya:
python tools/session_ledger.py recall --layer title        # kejelasan isyarat (gist)
python tools/session_ledger.py recall --layer summary      # untuk keputusan
python tools/session_ledger.py recall --layer evidence     # untuk verifikasi
```

## Rambu yang tidak boleh dilanggar

- Scout **bukan scanner**: 2 GET jinak, tanpa eksploitasi, tanpa klaim
  kerentanan — tier-nya heuristik permukaan, bukan verdict.
- Ledger hanya menyimpan **fakta terkonfirmasi**; intent tanpa dasar
  fakta ditolak. Baris korup dilaporkan, tidak diracuni senyap.
- Semua alat tetap tunduk pada rambu repo: target berizin, fail-closed,
  "No proof, no report".
