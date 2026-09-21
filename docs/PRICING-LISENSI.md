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

## Harga final — tier × token × mode (2026-09-19)

Model hybrid: **tier = kemampuan, token = kuota konsumsi, mode = multiplier.**

1 token = 1 eksekusi tool, dibobot `risk_tag`: pasif 1, aktif 2, load 3,
agresif/eksploit 4. Mode scan mengalikan konsumsi: read-only ×1, active ×1.5,
offensive ×2. Sumber kode: `cyphron/pricing.py`; ledger: `cyphron/credits.py`.

| Paket | Harga/bln | Token | Target | Report | Trial gating |
|---|---|---|---|---|---|
| TRIAL | Rp 0 | 30 | 1 | **redacted** | 1 scan/24 jam, 7 hari, 1x/device |
| basic | Rp 299.000 | 150 | 1 | full | — |
| pro | Rp 799.000 | 600 | 2 | full + fix packs + verify | — |
| business | Rp 1.999.000 | 2.000 | 3 | full + perf + white-box | — |
| god | Rp 4.999.000 | 5.000 (fair-use) | unlimited | full + multi-akun + API | — |
| top-up | Rp 500.000 | +1.000 | — | — | semua tier |

Pasar internasional: ±×10 (USD $29 / $79 / $199 / $499) — di billing server.

### Kenapa trial pakai report redacted (bukan "beberapa fitur mati")
Trial menghasilkan **report beneran** tapi: PoC/request/response/fix pack
disembunyikan (`[redacted — trial]`), hanya 5 temuan teratas yang dirinci,
watermark TRIAL, dan `findings.json` berisi `report_mode: redacted +
total_confirmed` (jumlah jujur, detail dipangkas). Klien melihat kualitas
kerja — nilai jual penuh (bukti yang bisa direproduksi + penambalan) baru
terbuka saat berbayar.

### Anti-abuse (dua lapis, jujur soal batasnya)
Lapis lokal (`cyphron/antibuse.py`, kode-enforced):
- **Lisensi bertanda tangan HMAC** — tier di atas basic tanpa `sig` valid =
  INVALID (dulu `sig` cuma ada di docstring; file bisa diedit jadi "god").
- **Device binding** — `device_hash` (SHA256 platform+machine+MAC); lisensi
  yang disalin ke mesin lain REFUSED.
- **Token ledger rantai HMAC** — habis kuota = REFUSED di ToolRegistry
  (kode-enforced, bukan UI).
Lapis server (helper murni untuk billing/edge, pluggable):
- **JA3/JA4 TLS fingerprint** dari header CDN (`cf-ja3-hash`/`x-ja3`) —
  fingerprint klien nyata di balik IP rotasi.
- **IP reputation pluggable** (hosting/datacenter = VPN, proxy, Tor).
- **Signup velocity** — bulk-account detector per subnet-IP/device/domain
  email (10 akun 1 device = DENY).
- **Proof-of-work signup** — mahal untuk bot massal, tak terasa bagi manusia.
- **`abuse_verdict()`** — skor transparan: user sah di balik VPN = CHALLENGE
  (PoW), bukan DENY; device sama klaim trial lagi = DENY.
Batas jujur: penghapusan file ledger offline tidak bisa dicegah penuh —
kuota reset-proof dicatat billing server; modul ini tamper-EVIDENT lokal.

## Level skill → tier mapping (tier pack 100 skills)

| Tier produk | Skill tier yang terbuka |
|---|---|
| Tier 1 (Pentest Basic) | LOW (25) + MEDIUM (25) — temuan + laporan |
| Tier 2 (+ Penambalan) | + HIGH (25) — temuan berbobot + fix packs + verify |
| Tier 3 (Capacity) | + CRITICAL (25) — teknik paling dalam + kapasitas |
| Tier 4 (God Mode) | Semua + grey-box multi-peran + chain analysis |
