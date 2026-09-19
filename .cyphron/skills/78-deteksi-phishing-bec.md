# Skill 78 — Deteksi Phishing & BEC (Triage Email)

> Workflow triage email mencurigakan dari header dan struktur pesan:
> melacak asal sebenarnya, menilai hasil autentikasi (SPF/DKIM/DMARC),
> dan mengenali pola impersonasi/BEC. Semua penilaian pasif — membaca
> pesan, bukan menghubungi pengirim. Ditopang engine `email_intel` untuk
> pemeriksaan header deterministik.

---

## WHEN TO ACTIVATE

- User melaporkan email mencurigakan ("cek ini phishing atau bukan").
- Insiden: karyawan sempat klik/membalas — butuh penilaian cepat sebelum
  containment.
- Kebutuhan BEC: permintaan transfer/pengubahan rekening via email.
- Batch triage: banyak email dari kampanye yang sama (kaitkan indikator).

---

## METHODOLOGY

### Step 1: Raw message dulu, bukan tampilan klien
- Analisis dari sumber mentah (.eml/header penuh) — tampilan klien email
  menyembunyikan apa yang penting dan menyembunyikan apa yang palsu.
- Jangan mengeksekusi/membuka lampiran; triage = inspeksi pasif.

### Step 2: Autentikasi email — baca hasilnya dengan benar
| Hasil | Arti | Konsekuensi |
|---|---|---|
| SPF fail/softfail | IP pengirim tidak diizinkan domain From | indikator kuat spoofing (bila From terlihat "internal/brand") |
| DKIM fail + tidak ada sig | isi mungkin dimodifikasi / tidak ditandatangani | indikator sedang |
| DMARC fail | SPF+DKIM gagal terhadap domain From | kuat: domain From tidak memvalidasi pengirim |
| Semua pass | autentikasi sah | BUKAN jaminan sah — BEC memakai domain/account asli |
- Kesalahan klasik: menganggap "SPF pass = aman". Autentikasi membuktikan
  domain, bukan niat. Perhatian maksimal justru pada email yang lolos
  autentikasi tapi isinya meminta uang/aksi.

### Step 3: Jalur asli (Received chain)
- Baca dari bawah ke atas (hop terdekat pertama): hop pertama mengungkap
  infrastruktur pengirim sebenarnya, bukan yang diklaim From.
- Red flag: hop pertama dari infrastruktur mass-mailer/free yang tidak
  sesuai klaim pengirim korporat; lonjakan geografis aneh antar hop.

### Step 4: Identitas — spoofing & impersonasi
- **Display-name spoof**: nama tampilan "PT X / Bu Direktur" dengan
  domain pengirim yang tidak berhubungan (freemail) = pola BEC klasik.
- **Reply-To vs From**: domain berbeda (atau freemail) = jawaban akan
  lewat ke penipu — indikator kuat.
- **Lookalike domain**: IDN/punycode (`xn--`), karakter serupa
  (rn↔m, 0↔o, l↔I), TLD beda (.co vs .com). Bandingkan dengan daftar
  domain sah milik organisasi (--brand di engine email_intel).
- **Return-Path (envelope) vs From header**: beda domain = perlu
  penjelasan di hop pertama.

### Step 5: Isi & tekanan psikologis
- Pola BEC: urgensi + kerahasiaan + perubahan rekening + pemisahan dari
  prosedur ("jangan lewat proses biasa", "CEO sedang rapat").
- Frasa dorong (ID+EN): "segera", "rahasia", "jangan beri tahu siapa pun",
  "urgent", "confidential", "perubahan rekening".
- Lampiran: nama file ganda ekstensi, arsip, makro — catat sebagai LEAD
  (verifikasi statis = skill 74, tanpa eksekusi).
- Link: jangan diklik; ekstrak domain, cocokkan dengan reputasi pasif
  (host_lookup / passive_dns).

### Step 6: Verdict & tindak lanjut
- Struktur verdict: setiap indikator = LEAD dengan bukti (header terkait);
  kombinasi >= 2 indikator independen (mis. DMARC fail + reply-to beda
  domain) = kandidat kuat, tetap dilaporkan dengan bukti, bukan klaim.
- Tindak lanjut organisasi: karantina pesan sejenis (kaitkan Message-ID,
  domain, infrastruktur hop pertama), cek penerima lain yang menerima
  kampanye sama, pelaporan ke tim keamanan/insiden (skill 10).
- Jika korban sudah membalas/mentransfer: jalur resmi — bank + pelaporan
  sesuai skill 81 (playbook fraud), BUKAN usaha penelusuran sendiri.

---

## VERIFICATION

- Engine `email_intel` dipakai untuk cek header deterministik (tanpa
  jaringan); hasilnya LEAD yang masuk laporan, bukan keputusan otomatis.
- Setiap klaim spoofing punya bukti header yang dikutip di laporan.
- Email yang lolos autentikasi TIDAK otomatis dinyatakan aman — disiplin
  zero-FP berlaku dua arah (jangan tuduhan palsu, jangan jaminan palsu).
