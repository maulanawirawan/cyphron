# Skill 79 — Audit Cloud & IAM (Read-Only)

> Checklist audit identitas dan akses di cloud (IAM) secara read-only:
> konfigurasi yang paling sering jadi pintu eskalasi — aksi wildcard, MFA
> absen, kunci berumur panjang, kebijakan trust yang terlalu percaya,
> dan bucket/layanan yang terekspos publik. Semua pemeriksaan pasif;
> tidak ada perubahan konfigurasi dari tool.

---

## WHEN TO ACTIVATE

- "Audit akses cloud kami" / "cek siapa bisa apa".
- Persiapan pentest (pemetaan permukaan identitas) sebelum pengujian aktif.
- Post-incident: menutup jalur eskalasi yang dipakai/dipakai-coba penyerang.
- Review kebijakan trust (delegasi antar akun/layanan).

---

## METHODOLOGY

### Step 1: Inventaris identitas (apa yang ada)
- Akun human vs service account/machine — hitung, catat yang "bersama"
  (shared) — akun bersama = temuan posture (akuntabilitas hilang).
- Kredensial jenis apa saja: password, access key, token OAuth, sertifikat,
  federated identity. Setiap jenis = permukaan terpisah.
- Catat trust relationship: siapa yang BOLEH assume role/impersonate siapa.

### Step 2: Aksi wildcard & trust terlalu luas
- Kebijakan berisi `Action: *` atau `Resource: *` pada identitas yang
  aktif = temuan (prinsip hak minimum dilanggar) — prioritaskan yang
  punya akses tulis/privilese.
- Trust policy yang menerima "Anyone/anonymous" atau prinsip dari akun
  lain tanpa kondisi (external id / pembatasan sumber) = temuan eskalasi
  lintas batas.
- Kebijakan berbasis kondisi IP/VPC: cek benar-benar diterapkan (bukan
  hanya ada).

### Step 3: MFA & jalur privilese
- Akun privilese tanpa MFA = temuan tinggi.
- Jalur eskalasi: identitas biasa yang bisa (1) membuat/mengubah kebijakan,
  (2) membuat access key untuk identitas lain, (3) mengubah trust policy,
  (4) melampirkan role privilese ke dirinya. Setiap jalur = temuan
  (dicatat sebagai jalur, dengan bukti kebijakan — bukan dieksekusi).
- Break-glass account: ada? dipantau? MFA kuat? (akun darurat tanpa
  monitoring = pintu belakang diam-diam).

### Step 4: Kredensial & kunci
- Access key berumur panjang (> 90 hari tanpa rotasi) = temuan posture.
- Kunci yang tidak pernah dipakai (usia terakhir > 30-90 hari) = cadangan
  yang harus dicabut (kunci mati yang masih valid = risiko murni).
- Secret di kode/config repositori (lintas-referensi skill 01 +
  secret_scan) — kredensial cloud yang bocor di git adalah akses jarak
  jauh yang diberikan cuma-cuma.

### Step 5: Ekspos layanan & data
- Bucket/objek policy publik; database yang accessible-from-internet;
  snapshot/image publik berisi data. Cocokkan dengan hasil
  `cloud_bucket_probe` (engine ada; hasil = bukti konkret).
- Logging & audit trail (audit akses cloud) AKTIF dan disimpan cukup
  lama — tanpa audit log, semua temuan di atas tidak bisa dituding
  waktunya. Log mati = temuan tersendiri.

### Step 6: Laporan & prioritisasi
- Format: temuan → bukti (policy/document/bucket) → dampak (jalur eskalasi
  konkret, bukan perasaan) → rekomendasi berurutan (apa yang menutup
  jalur terbanyak dulu).
- Semua hasil = penilaian konfigurasi (posture); tidak ada klaim
  "tereksploitasi" tanpa pengujian terotorisasi terpisah.
- Rekomendasi pertahanan lanjut: skill 80; jalur uji aktifnya: hanya
  dengan dokumen otorisasi (gate Cyphron).

---

## AUDIT CHECKLIST

- [ ] Inventaris identitas + jenis kredensial lengkap
- [ ] Wildcard action/resource dicatat semua (dengan pemiliknya)
- [ ] Trust policy lintas akun punya pembatasan eksplisit
- [ ] MFA utk akun privilese: 100% (yang tidak = temuan)
- [ ] Jalur eskalasi terpetakan dan dijelaskan dampaknya
- [ ] Kunci: umur + pemakaian terakhir dicatat; kunci mati dicabut
- [ ] Audit log cloud aktif, terpusat, retensi cukup
- [ ] Tidak ada perubahan konfigurasi dilakukan tool (read-only disiplin)
