# Cyphron — Pricing Tiers (desain final)

> Prinsip: tier paling bawah = **pentest + laporan PDF saja**. Penambalan (fix packs +
> verifikasi delta) adalah fitur tier berikutnya. Setiap kenaikan tier membuka kemampuan,
> bukan sekadar kuota — ini pembeda dari model credit-based kompetitor.

## Tier 1 — Pentest Basic (Gratis uji / harga entry)
**Isi:** scan black-box penuh (16 engine) + **laporan PDF saja** (tanpa fix packs).
- Semua temuan + bukti + PoC, severity CVSS
- Tidak termasuk: fix packs, verify delta, perf report, grey/white-box
- Batas: 1 target, scan terjadwal manual, retensi laporan 7 hari
- **Kenapa PDF-only di bawah:** laporan adalah bukti kerja; penambalan adalah nilai
  jual berikutnya yang membuat pelanggan naik tier.

## Tier 2 — Pentest + Penambalan (inti bisnis)
**Isi Tier 1 + :**
- **Fix packs** per temuan (langkah + snippet + perintah verifikasi)
- **`cyphron verify`** — delta fixed/open/new setelah perbaikan diterapkan
- Re-scan terjadwal (regresi: skor tak boleh turun)
- Grey-box 1 akun uji (authenticated testing)
- Retensi laporan 90 hari + riwayat delta

## Tier 3 — Capacity & Continuous
**Isi Tier 2 + :**
- Perf engine penuh (skenario manual, ramp, multi-URL) + laporan kapasitas
- White-box code_audit pada repositori (SAST + secret scan)
- Multi-target (3 target), monitoring berkala, notifikasi

## Tier 4 — Full God Mode
**Isi Tier 3 + :**
- Grey-box multi-akun (ujian IDOR/tenant-isolation lintas peran — Skill 66)
- Attack-chain analysis (world model graph)
- On-prem runner (semua engine berjalan di infrastruktur klien)
- API akses + integrasi CI/CD

## Enterprise — kustom
- SLA, pentest bersertifikat manual (profesional di belakang alat), Compliance report

---

## Perbandingan dengan model credit-based (referensi pasar)

| Aspek | Model credit (kompetitor) | Cyphron tiers |
|---|---|---|
| Biaya AI pentest untuk klien | 700 credit utk 1 deep scan | Termasuk, engine sendiri |
| Biaya operasional kita | $5-50 token + 3.8GB sandbox per scan | ±$0 (tanpa LLM pihak ketiga) |
| Abstraksi klien | "kredit habis = stop" | "tier = kemampuan" |
| Naik tier karena | butuh kuota lebih | butuh kemampuan lebih (penambalan, dsb.) |

> Nilai jual inti: **temuan terjamin TRUE** (FP-guard wajib per skill), **penambalan
> terverifikasi** (bukan sekadar laporan), **privasi lokal** (tanpa token, tanpa data keluar).

## Level skill → tier mapping (tier pack 100 skills)

| Tier produk | Skill tier yang terbuka |
|---|---|
| Tier 1 (Pentest Basic) | LOW (25) + MEDIUM (25) — temuan + laporan |
| Tier 2 (+ Penambalan) | + HIGH (25) — temuan berbobot + fix packs + verify |
| Tier 3 (Capacity) | + CRITICAL (25) — teknik paling dalam + kapasitas |
| Tier 4 (God Mode) | Semua + grey-box multi-peran + chain analysis |
