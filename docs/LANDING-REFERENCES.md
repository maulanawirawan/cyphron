# Landing Page Cyphron — Referensi & Prompt Final

> Sumber: riset live 21st.dev + motionsites.ai (2026-09-06).
> MotionSites = premium/berbayar (katalog bagus, prompt terkunci).
> 21st.dev = komponen gratis, kode bisa dicopy tanpa login (fitur "Copy prompt" butuh akun).

---

## 1. Komponen terpilih (21st.dev — gratis, kode siap)

| Komponen | URL | Pakai untuk |
|---|---|---|
| **HeroSection – Enterprise-Ready Landing Page with Dual CTAs** (Sonu kumar) | 21st.dev/@uniquesonu/components/hero-section-enterprise-ready-landing-page-hero-with-dual-ctas | Hero utama + CTA ganda (Mulai Scan Gratis / Lihat Fix Packs) |
| **Hero Section with Device Mockups** (solaceui) | cari di /s/hero | Pajang dashboard + contoh report.pdf dalam mockup laptop/HP |
| **Hero Parallax** (Manu Arora) | cari di /s/hero | Gerakan berlapis premium di hero |
| **Home Hero Landing Scroll Animation** | /s/landing-page | Cerita scroll: Temukan → Nambal → Buktikan |
| **Digital Serenity – Animated Landing Page** | /s/landing-page | Mood gelap-tenang khas produk security |
| **Pricing Section** (Mikolaj Dobrucki) | /s/pricing-section | Templat 4 tier (PRICING-LISENSI.md) |

## 2. Yang tidak dipakai
- **MotionSites.ai** — katalog premium ("Cyber Ronin", "Obsidian", "Portal" — miris cocok)
  tapi prompt di balik paywall "Go Unlimited". Katalognya bisa jadi referensi visual saja.

## 3. PROMPT FINAL (copy-paste ke AI builder)

```
Buatkan landing page produk keamanan siber bernama CYPHRON (React + Tailwind, dark mode):
latar near-black #0a0a0b, aksen amber #f5a524, tanpa biru, font Inter + JetBrains Mono
untuk kode/CVE. Referensi komponen: 21st.dev "HeroSection Enterprise-Ready with Dual
CTAs" + "Hero Parallax".

HERO
- Headline: "Pentester AI yang benar-benar memperbaiki — bukan sekadar melaporkan."
- Sub: "16 engine milik sendiri. 100+ skill serangan dengan FP-guard wajib. Temuan
  terjamin TRUE: false positive ditolak otomatis. Tanpa kredit, tanpa token, tanpa
  data keluar dari mesinmu."
- CTA ganda: [Mulai Scan Gratis] (amber, solid) + [Lihat Fix Packs] (outline).
- Background: grid parallax halus + partikel amber tipis, tidak ramai.

BAGIAN SCROLL (3 langkah, animasi saat masuk viewport)
1. TEMUKAN — "16 engine buatan sendiri: SAST, DAST, traversal, SSTI, SQLi, cmdi,
   CORS, JWT, sesi, email-spoofing, kapasitas." angka counter: 16 engine / 100+ skill.
2. NAMBAL — "Setiap temuan lahir dengan fix pack: langkah + snippet siap tempel."
3. BUKTIKAN — "cyphron verify: scan ulang, tunjukkan fixed / open / new. Delta atau
   gagal." dengan mockup terminal menampilkan output delta sungguhan.

BAGIAN KEBOCORAAN (social proof teknis)
- Kartu: "False positive ditolak — 6 temuan critical hipotesis ditarik otomatis
  karena bukti kurang. Tool yang tidak overclaim."
- Kartu: "Session analysis: JWE A256GCM + HttpOnly + SameSite diakui solid."

PRICING (4 tier, kolom tier 2 di-highlight)
- Tier 1 Pentest Basic: scan + laporan PDF. Tanpa fix packs.
- Tier 2 Pentest + Penambalan (paling populer): + fix packs + verify delta + grey-box 1 akun.
- Tier 3 Capacity & Continuous: + perf engine manual, white-box SAST, 3 target.
- Tier 4 Full God Mode: + grey-box multi-peran, attack-chain, on-prem runner, CI/CD.
- Baris pembanding: "Tanpa kredit. Tanpa biaya token. Naik tier karena kemampuan,
  bukan kuota."

FOOTER CTA
- "Mesin milikmu. Temuan terjamin TRUE. Pasang di VPS-mu hari ini."
- tombol waitlist + link dokumentasi.

TEKNIS
- Single landing (React/Vite atau Next), tanpa backend, form waitlist -> endpoint sederhana.
- Aksesibel (kontras AA), responsif mobile, Lighthouse > 90.
```

## 4. Cara pakai
1. Buka tiap URL komponen di 21st.dev → tab Code → copy kode (gratis, tanpa login).
2. Tempel ke proyek React/Tailwind, ganti copy/text dengan PROMPT FINAL di atas.
3. Atau paste PROMPT FINAL ke AI builder (v0/Cursor) untuk generate utuh.
