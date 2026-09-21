# PRODUCTION-READY CHECKLIST — Cyphron web + engine

> Dibuat 2026-09-22. Urutan = urutan eksekusi yang disarankan. Simbol:
> [x] selesai · [~] sebagian · [ ] belum. Prinsip: engine sudah produksi-grade
> (suite 683 hijau, gate kode-enforced); yang menuntun ke produksi adalah
> INFRA + BILLING + LEGAL di sekelilingnya.

## A. Selesai (tidak perlu disentuh)
- [x] Engine 145 terdaftar, tier-gate + token + trial kode-enforced (ToolRegistry)
- [x] Lisensi HMAC + device binding + credit ledger tamper-evident
- [x] Verdict ladder enforcement + redaksi trial + transparansi pihak ketiga
- [x] Wizard web minimal-klik + job runner subprocess + unduh laporan
- [x] Web hardening dasar: session store TTL, kuota scan harian, threading,
      body cap, login rate limit (5 gagal/15 menit), path blocking
- [x] EVAL.md + gerbang regresi otomatis (scripts/eval_report.py)

## B. Infrastruktur (bloker utama produksi)
- [ ] **HTTPS + domain**: nginx reverse proxy di depan serve.py (TLS/ACME),
      bind tetap 127.0.0.1; wajib sebelum kredensial/otorisasi mengalir.
- [ ] **Database nyata** untuk akun + sesi + job: pindahkan accounts.json /
      sessions.json / jobs ke SQLite (atau Postgres). Hash password → argon2id
      (masih SHA-256+salt tanpa stretching).
- [ ] **Worker terpisah dari web**: job sekarang subprocess di proses web —
      pisahkan queue worker (1-2 konkuren per akun, retry, batas waktu, cleanup
      folder jobs otomatis per retensi paket: trial 7 hari / basic 90 hari).
- [ ] **Licensing server**: CYPHRON_LICENSE_SECRET tetap di server; penerbitan
      lisensi pindah dari serve.py ke endpoint billing (issue + revoke + renew);
      klien memvalidasi sig. Ledger token resmi di server (anti-reset penuh).
- [ ] **Backup + monitoring**: backup DB harian; log terstruktur; alert ketika
      job gagal massal / disk penuh (folder jobs + report PDF tumbuh).

## C. Billing & onboarding
- [ ] **Payment gateway** (Midtrans/Xendit untuk IDR): webhook → issue/renew
      lisensi otomatis; invoice + denda nol — trial tetap gratis tanpa kartu.
- [ ] **Verifikasi email** sebelum trial aktif (tautan 1x) + rate limit signup
      + PoW (antibuse.pow_*) → gabungkan dengan JA3/IP-reputation di endpoint
      signup (antibuse sudah siap, tinggal dipasang di edge).
- [ ] **Halaman paket & upgrade** di web (sekarang kartu pricing sudah ada di
      landing; tombol upgrade → billing; tier akun disimpan di DB).
- [ ] **Pembatasan target**: konfirmasi kepemilikan domain otomatis (DNS TXT —
      `ownership.py` sudah punya mekanisme ini; dipakai untuk mode aktif).

## D. Legal & kebijakan (wajib sebelum publik)
- [ ] **ToS + Privacy Policy** (data scan disimpan di mana, berapa lama, siapa
      yang bisa lihat) + pernyataan wajib otorisasi target.
- [ ] **NDA/perjanjian program** template untuk klien enterprise.
- [ ] Retensi: auto-delete laporan/scan hasil trial (7 hari) — jalankan cron.
- [ ] Halaman "Lapor penyalahgunaan" (bila ada yang scan aset orang lain).

## E. Kualitas & observabilitas
- [x] Gerbang regresi otomatis (eval_report.py) — jadikan CI (GitHub Actions:
      unittest + eval_report tiap push).
- [ ] Metric per engine (detection rate / FP rate / waktu) dari fixture →
      tabel di EVAL.md (R6 sisa).
- [ ] Error reporting (Sentry self-hosted / log alerting).
- [ ] Uji beban halaman web sendiri dengan perf_engine (dogfooding).

## F. Rilis minimal yang disarankan (urutan)
1. B → Infrastruktur (HTTPS + DB + worker terpisah + licensing server).
2. C → Billing + verifikasi email + PoW signup.
3. D → Legal page + retensi cron.
4. E → CI + monitoring.
Setelah 1-4: **production-ready** untuk klien berbayar; engine & laporan sudah
di level produksi sejak awal (zero-FP + bukti reproduktif).
