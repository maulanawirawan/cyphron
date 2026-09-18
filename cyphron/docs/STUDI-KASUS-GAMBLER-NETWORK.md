# Studi Kasus Threat Intel: Jaringan Afiliasi Judu "GAMBLER" (ter-redaksi)

> Status: publikasi riset defensive, dirapikan dari dossier internal 14 Sep 2026
> (izin pemilik kasus). Konteks: akun Instagram kerabat dibajak, dipakai
> menyebarkan DM yang mengarah ke situs kasino palsu. Semua analisis dilakukan
> PASIF: render headless ter-isolasi (browser_scout/CDP), dekoder rantai
> (chain_decoder), validasi wallet anti-FP (wallet_fp_guard), pemetaan afiliasi
> (affiliate_mapper). TANPA interaksi kredensial, TANPA serangan aktif.
>
> Label: **[B]** = bukti terekam langsung (trafik/DOM/berkas) ·
> **[I]** = inferensi berlabel.

## 1. Rantai serangan [B]

DM dari akun dibajak → link `kamipex.com?r=<token>` → loader terobfuskasi
(RC4 + rotasi berantai, nol konten statis) → `/verifyjs` (gate anti-bot,
HTTP 666 untuk non-browser) → `/verify?r=` → cookie `cs-uuid`/`cs-resp` →
aplikasi kasino Next.js.

Teknik analisis yang memungkinkan (semua milik Cyphron, stdlib/CDP):
- `browser_scout`: render JS-heavy dengan profil sekali-pakai, request pihak
  ketiga diblokir DI DALAM browser (scope per-destination), trafik + DOM +
  cookie terekam.
- `chain_decoder`: dekode rantai base64/RC4/rotasi pada loader; marker
  loader (`eval`, `unescape`, `fromCharCode`) = LEAD terstruktur.
- `affiliate_mapper`: klaster parameter `?r=`/`utm_campaign` lintas URL.

## 2. Data yang diambil dari korban [B]

Begitu link dibuka: alamat IP, perangkat/OS/browser, bahasa, waktu, dan
fakta datang dari DM. Pengikatan afiliasi: token `?r=` → cookie → pixel
postback clickId `gambler`. Form register/login mengirim Email + Password ke
`/api/mammoth/auth/register|login`. TIDAK ada OTP/2FA, form nomor HP, reset
password, maupun dorongan APK — diverifikasi.

## 3. Atribusi (lapisan induk) [B]

- Program afiliasi **gambler-partners.is** ("GAMBLER", berbahasa Rusia)
  mempublikasi sendiri: 20.000+ partner, komisi 60–80% dari deposit korban,
  payout otomatis kripto (kanal resmi mereka: bot & akun Telegram yang
  mereka cantumkan di dokumentasi sendiri).
- Wiki internal mereka (pengakuan sendiri): korban disebut *mamont*
  (mammoth) — backend kasino pun memakai path `/api/mammoth/`; ada manual
  spam per-platform (bab khusus Instagram) dan panduan anonimitas VPN.
- Rantai pasok domain: bot penjual domain mempromosikan jaringan; afiliasi
  meminta NS dari panel — setiap domain hanyalah "skin" di atas mesin GAMBLER.
- `kamipex.com`: domain tua (terdaftar 2014) dibeli ulang 11 Sep 2026 [B —
  RDAP], sertifikat baru 11 Sep [B — CT log], tema berganti-ganti [B — kode].

### Lapisan langsung (afiliasi lokal) [I]

Pemilik token `?r=` hanya diketahui server-side (bisa dibuka oleh platform
atau penegak hukum). Indikasi keberadaan afiliasi lokal: DM berbahasa
Indonesia dan metode deposit lokal (OVO/DANA/QRIS/Gopay/bank) di kode [I].

## 4. Jejak uang [B — hasil negatif yang penting]

1.261 kandidat alamat kripto dari regex murni → **0 lolos validasi checksum
base58check** (engine `wallet_fp_guard`). Tanpa validasi checksum, analisis
akan membanjiri laporan dengan alamat palsu — pola regex saja menghasilkan
miliaran kemungkinan false positive. Alamat deposit diterbitkan dinamis oleh
backend; pelacakan dompet membutuhkan akun aktif atau proses hukum.

## 5. Rekomendasi tindakan (defensif)

1. Blokir indikator (domain utama + jaringan afiliasi) di level ISP/respon
   insiden nasional.
2. Laporkan jaringan abuser ke platform sosial dengan kutipan manual spam
   yang mereka publikasi sendiri.
3. Kepada penegak hukum: dossier + token `?r=` dari DM asli → platform
   afiliasi memegang data lengkap afiliasinya.
4. Laporkan domain berlindung CDN ke penyedianya (jalur abuse resmi).

## 6. Pembelajaran teknis untuk Cyphron

- Pattern kasus ini memangkitkan kit B2 (`chain_decoder`,
  `phishing_kit_extract`, `wallet_fp_guard`, `affiliate_mapper`) dan
  `browser_scout` (U4) — alur kamipex kini formalisasi bawaan engine.
- Zero-FP berarti bersedia melaporkan hasil negatif: "tidak ada wallet
  valid di frontend" adalah temuan analitik, bukan kegagalan alat.
- Guard anti-bot (HTTP 666 untuk non-browser) hanya bisa dipetakan dengan
  browser nyata — bukti nilai render headless ter-isolasi.

## 7. Redaksi

- Tidak ada data pribadi korban/kerabat dalam dokumen ini.
- Token afiliasi `?r=` tidak dipublikasi (mencegah penyalahgunaan balik).
- Kanal Telegram operator tidak dicantumkan di versi publik (masih di
  dossier internal untuk penegak hukum).
- Semua klaim keberadaan infrastruktur mengutip publikasi operator sendiri
  atau artefak terekam [B]; inferensi selalu dilabel [I].
