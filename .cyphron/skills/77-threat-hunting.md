# Skill 77 — Threat Hunting Berbasis Hipotesis

> Kerangka hunting yang disiplin: rumuskan hipotesis yang BISA dibuktikan
> salah, pilih sumber data yang benar-benar ada, kueri, analisis, lalu
> dokumentasikan — termasuk hasil NEGATIF. Hunt tanpa hipotesis adalah
> penglihatan acak; hunt tanpa dokumentasi akan diulang terus tanpa
> kemajuan.

---

## WHEN TO ACTIVATE

- "Cari tahu kalau ada yang bocor/nyusup" tanpa alert spesifik.
- Menutup celah deteksi: ada asumsi "kalau X terjadi, EDR/SIEM akan lihat"
  yang belum pernah dibuktikan.
- Intel ancaman baru masuk (TTP/campaign) dan perlu dicek terhadap lingkungan.
- Setelah insiden (skill 10/76): hunt varian serupa di mesin lain.

---

## METHODOLOGY

### Step 1: Rumuskan hipotesis yang bisa dibuktikan salah
Format wajib: "Saya percaya [ancaman/aktivitas] akan meninggalkan [jejak
spesifik] di [sumber data] dan [tidak] tertangkap [deteksi ada]."
- Contoh buruk: "mungkin ada malware" (tidak bisa diuji).
- Contoh baik: "jika ada persistence via scheduled task, ia meninggalkan
  event pembuatan task di Security log dan file task di C:\Windows\System32\
  Tasks — dan saat ini tidak ada alert untuk keduanya."
- Anchor pada kategori perilaku: persistence, lateral movement, eksfiltrasi,
  kredensial akses, eksekusi aneh, C2.

### Step 2: Inventaris sumber data — jujur dulu
- Sumber yang ADA dan retensi-nya cukup? (jangan merancang hunt untuk data
  yang tidak pernah dikumpulkan).
- Sumber yang TIDAK ada → hunt berubah jadi temuan posture ("butuh logging
  X untuk hunt Y") — itu keluaran sah, bukan kegagalan.
- Prioritas sumber: log autentikasi, log proses/ command line, network
  flow, task/service/registry, proxy/DNS.

### Step 3: Kueri & analisis
- Mulai dari agregasi (skill 76 Step 3), bukan dari daftar IOCs mentah.
- Analisis frekuensi: beaconing = interval berkala pada koneksi keluar;
  bandingkan distribusi inter-arrival, bukan sekadar volume.
- Analisis LOLBin: proses binary bawaan OS yang jarang punya argumen
  tertentu (unduhan, eksekusi inline) — kejadian Jarang + fungsionalitas
  Berbahaya = prioritas, bukan kejadian otomatis jahat.
- Toleransi nol untuk kesimpulan dari satu data point: satu anomaly =
  LEAD; analisis lanjut wajib.

### Step 4: Verifikasi & eskalasi
- Temuan kandidat divalidasi dengan sumber kedua (memori skill 75, disk
  statis skill 74, log skill 76).
- Jika terbukti kegiatan nyata → beralih ke skill 10 (incident response)
  dengan rantai bukti utuh dari hunt.
- Jika tidak ada → hasil NEGATIF tetap berharga.

### Step 5: Dokumentasi & penutupan lingkaran
- Catat: hipotesis, sumber data, kueri (persis), hasil (termasuk nihil),
  dan keputusan.
- Hasil nihil + deteksi tidak ada → jadikan aturan deteksi baru (skill 09)
  atau rekomendasi logging. Hunt yang tidak menghasilkan artefak apapun
  (aturan/log/laporan) = hunt yang dibuang.
- Jadwalkan ulang: hunt rutin untuk hipotesis yang datanya berubah.

---

## KATALOG HUNT AWAL (per kategori perilaku)

| Kategori | Hipotesis contoh | Sumber utama |
|---|---|---|
| Persistence | task/service/run-key baru tidak dikenal | Security 4698/7045, registry, cron |
| Lateral movement | akun servisa logon interaktif | 4624/4648, auth.log |
| C2 beacon | interval berkala ke domain/IP berumur pendek | netflow, proxy, DNS |
| Eksfiltrasi | upload keluar besar jam tidak wajar | netflow, proxy |
| Kredensial | akses LSASS/proses sensitif anomali | Sysmon 10/8, memori (skill 75) |
| Webshell | proses anak web server dengan shell | log proses, log akses web |

---

## VERIFICATION

- Setiap hipotesis punya kriteria batal/terbukti SEBELUM kueri dijalankan.
- Kueri tersimpan apa adanya (reproducible).
- Klaim "tidak ada" selalu menyertakan cakupan data (sumber + rentang +
  retensi) — "tidak ditemukan dalam data ini" ≠ "tidak pernah terjadi".
