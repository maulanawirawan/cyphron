# Skill 81 — Playbook Penanganan Fraud

> Playbook penanganan fraud per vektor (rekkening, phishing, social
> engineering, penipuan aplikasi/pinjaman): apa yang dilakukan korban
> dan pendamping dalam jam-jam pertama, bukti apa yang dikumpulkan,
> dan jalur resmi mana yang dijalankan. Sinergi dengan `fraudintel`
> (analisis prefix operator/bank + dossier pengaduan). Batas tetap:
> tidak ada resolusi identitas pelaku dan tidak ada aksi ofensif
> "penagihan sendiri".

---

## WHEN TO ACTIVATE

- Korban melapor: transfer penipuan, rekkening, permintaan uang via
  email/chat/telepon, pinjaman online macet + intimidasi.
- Keamanan/HR menangani kasus impersonasi pimpinan (BEC internal).
- Perlu dossier pengaduan resmi (fraudintel) atau cek status laporan
  nomor/rekening di registry publik resmi (cekrekening.id).

---

## METHODOLOGY

### Step 1: Stabilkan — hentikan kerugian lebih dulu
- Jika transfer baru terjadi: SEGERA hubungi call center bank untuk
  pembekuan/reversal (tiap menit penting) — sebelum dokumentasi panjang.
- Jika kredensial bocor: ubah password + cabut sesi/token (referensi
  skill 46/18 untuk sisi posture).
- Baris pertama bukti: screenshot + simpan pesan asli (jangan hanya
  forward; metadata hilang). Raw email = skill 78.

### Step 2: Klasifikasi vektor
| Vektor | Tanda | Playbook utama |
|---|---|---|
| Rekkening (transfer ke rekening penipu) | korban transfer, penerima tak dikenal | Step 3 + dossier bank |
| Phishing/link palsu | kredensial/OTP dimasukkan ke situs palsu | Step 3 + skill 78 + posture |
| Social engineering telepon | "cs bank/olshop" meminta OTP/kode | edukasi + pelaporan operator |
| Impersonasi pimpinan (BEC) | permintaan transfer "atas nama bos" | skill 78 + jalur internal |
| Pinjaman online tidak sah | aplikasi tidak berizin + intimidasi data | pelaporan resmi (OJK/afiling) |
| Penipuan jual-beli | barang/uang tidak kunjung | bukti + pelaporan platform + polisi |

### Step 3: Kumpulkan bukti yang LAYAK hukum
- Identitas saluran: nomor pengirim, no. rekening/nama penerima, link,
  aplikasi + paket installer-nya, email + header penuh.
- Kronologi dengan waktu (dari bukti, bukan ingatan): laporan → bukti
  → kronologi → dampak (nilai kerugian, data yang bocor).
- PII korban di dokumen: masking default (fraudintel sudah menerapkan
  masking); akses penuh hanya untuk pihak penanganan.

### Step 4: Jalur resmi — urutan yang benar
1. Bank/e-wallet korban + bank penerima (pembekuan, track record).
2. Registry resmi publik: laporkan/cek nomor & rekening (cekrekening.id)
   — status laporan = data pasif yang sah, bukan tuduhan pribadi.
3. Polisi (pengaduan) dengan bukti terkompilasi — dossier dari
   `fraudintel` disusun untuk keperluan ini.
4. Pelaporan tambahan sesuai vektor: operator (SMS/telepon), platform
   marketplace, regulator (pinjaman online).
- Batas: dossier = bantuan pengaduan untuk korban. TIDAK ada penelusuran
  identitas pelaku sendiri, TIDAK ada konfrontasi, TIDAK ada aksi
  "balik" ke nomor/rekening pelaku.

### Step 5: Penguatan agar tidak kejadian lagi
- Korban: edukasi pola (OTP tidak pernah diminta siapa pun; perubahan
  rekening selalu diverifikasi via kanal kedua).
- Organisasi: proses verifikasi pembayaran dua kanal, pelatihan phishing
  (skill 46), laporkan indikator ke tim keamanan untuk blokir.
- Sistem: indikator kampanye (nomor/rekening/link) masuk watchlist internal.

### Step 6: Ambiguitas = kejujuran
- Nomor/rekening bisa jadi pinjaman/mule orang yang tidak bersalah —
  laporan disusun sebagai "indikasi" dengan bukti, bukan tuduhan nama
  orang. Klaim "100% tahu pelaku" dari data publik = resep tuduhan salah
  orang; disiplin zero-FP berlaku penuh di sini.
- Yang bisa diucapkan: vektor, bukti saluran, status laporan resmi,
  dan jalur hukum yang sedang berjalan.

---

## VERIFICATION

- Setiap dossier punya: bukti saluran lengkap, kronologi berbasis waktu
  bukti, nilai dampak, dan bukti jalur resmi sudah ditempuh.
- Masking PII aktif di semua dokumen yang berpindah tangan.
- Tidak ada langkah playbook yang mengandung resolusi identitas pelaku
  atau aksi konfrontasi.
