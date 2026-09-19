# Skill 75 — Forensik Memori (RAM)

> Workflow akuisisi dan analisis memori (RAM) untuk mengungkap artefak yang
> tidak pernah menyentuh disk: proses terinjeksi, malware fileless, koneksi
> C2, dan bukti pencurian kredensial. Pelengkap skill 74 (triage statis) —
> disk menunjukkan "apa yang tersisa", memori menunjukkan "apa yang sedang
> hidup".

---

## WHEN TO ACTIVATE

- Insiden aktif dan endpoint sudah di-contain; bukti volatile harus
  diambil SEBELUM shutdown/reboot.
- EDR/AV memberi alert proses injection atau malware fileless yang tidak
  ketemu di disk.
- Dugaan pencurian kredensial (dumping LSASS, token theft) perlu
  dikonfirmasi dari bukti memori.
- Dugaan rootkit/kernel compromise: analisis disk tidak menjelaskan.
- Ransomware mengenkripsi data dan kunci berpotensi masih ada di memori
  (hanya relevan SEBELUM mesin dimatikan).

**Jangan dipakai untuk** analisis disk image / file system (itu ranah
forensik disk). Jangan menunda akuisisi hanya karena "tool belum lengkap"
— memori ter-degrade setiap detik.

---

## METHODOLOGY

### Step 1: Akuisisi — urutan keputusan
- **Prioritas 1 — capture memori dulu**, baru disk image. Shutdown =
  bukti hilang (pagefile/hiberfil menyusul saat idle, bukan saat mati).
- Tool akuisisi harus jalan dari media eksternal yang write-protected;
  catat: jam (dengan zona waktu + basis waktu mesin), versi tool, hash
  hasil capture (sha256), ukuran RAM fisik vs ukuran dump.
- Jika mesin TIDAK boleh disentuh (bukti hukum): dokumen semuanya,
  gunakan akuisisi yang menghasilkan artefak minim, jangan install apa pun
  di mesin korban.
- Linux: pakai modul kernel akuisisi / proc dump sesuai distro; catat
  versi kernel (symbol table memori wajib cocok dengan build kernel).

### Step 2: Validasi sample
- Cocokkan hash dump dengan catatan akuisisi.
- Pastikan profil/symbol table sesuai OS build (build number, bukan hanya
  "Windows 10").
- Dump yang terpotong (memory desatur) = laporkan keterbatasan di laporan,
  jangan diam-diam analisis sebagian dan menyimpulkan seolah utuh.

### Step 3: Proses — daftar hidup vs jejak mati
- Daftar SEMUA proses (termasuk yang ter-terminate) beserta PID, PPID,
  waktu start, path binary.
- Cari anomali struktural:
  - PPID tidak logis (proses "anak" dari parent yang tidak pernah
    menjalankannya),
  - path binary kosong/anomali (berjalan dari temp, dari memori saja),
  - proses sistem yang timestamp start-nya di luar waktu boot,
  - dua versi proses sistem (salah satunya palsu).
- Berhenti mencari "nama file aneh" — malware baik-baik menyamar dengan
  nama asli; yang membedakan adalah STRUKTUR (parent, timestamp, lokasi).

### Step 4: Injeksi & hooking
- Deteksi injeksi klasik: region memori RWX di proses yang tidak perlu,
  kode di heap/stack yang executable, DLL unlinked (dembunuh dari daftar
  modul tapi masih di memori), thread yang start-nya bukan di module.
- Cek hooking SSDT/kernel saat dugaan rootkit — tapi laporkan sebagai
  indikator, bukan kepastian, sebelum ada verifikasi silang.

### Step 5: Jaringan & C2
- Tabel koneksi per proses (PID → remote IP/port + state) — memori
  memetakan koneksi ke proses, hal yang netstat biasa tidak selalu kasih.
- Kaitkan dengan World Model / hasil pasif_dns: IP yang tidak punya
  sejarah DNS jelas = prioritas investigasi.
- Catat koneksi yang sudah "pernah ada" (artefak socket ter-terminate).

### Step 6: Kredensial & rahasia (bukti, bukan panen)
- Tujuan: MEMBUKTIKAN pencurian kredensial (artefak dumping LSASS,
  string kredensial di proses yang tidak seharusnya), BUKAN mengumpulkan
  kredensial itu sendiri.
- Indikator: proses yang membuka LSASS dengan akses aneh, dump credential
  manager, token domain di sesi yang tidak logis.
- TEMUKAN = laporkan sebagai bukti (dengan hash artefak), redaksi nilai
  kredensial di semua laporan (aturan redaksi wajib).

### Step 7: Timeline & pelaporan
- Gabungkan temuan memori dengan timeline disk/log (skill 76): proses
  injeksi jam X harus terlihat jejaknya di log/disk setelah jam itu.
- Laporan: metode akuisisi + hash + alat analisis + tiap temuan dengan
  bukti (alamat memori, potongan struktur) + keterbatasan analisis.
- Klasifikasi disiplin: temuan yang butuh interpretasi = LEAD; yang
  punya bukti struktural konkret = confirmed sesuai verdict ladder.

---

## VERIFICATION

- Akuisisi ulang di mesin yang sama harus konsisten (proses inti sama;
  isi memori memang dinamis — yang dibandingkan adalah artefak struktural).
- Temuan injeksi divalidasi silang: ada di >= 2 sumber bukti (memori +
  log/disk/network).
- Setiap klaim "malware" diiringi artefak konkret; klaim tanpa bukti
  struktur = LEAD dilabel jelas.
