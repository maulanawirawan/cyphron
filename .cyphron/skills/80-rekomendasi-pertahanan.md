# Skill 80 — Rekomendasi Pertahanan Terpetakan

> Dari temuan → kontrol defensif yang konkret dan terprioritaskan. Melengkapi
> remediate.py (yang berhenti di "perbaiki celahnya") dengan sisi pertahanan
> berlapis: deteksi, pencegahan, dan respons — informed oleh kerangka
> pemetaan pertahanan D3FEND, disajikan dalam bahasa keputusan (apa yang
> dilakukan minggu ini vs bulan ini).

---

## WHEN TO ACTIVATE

- Laporan temuan sudah ada (scan/redteam/insiden) dan user bertanya
  "terus bagaimana cara nge-bloknya?"
- Rencana perbaikan pasca-audit perlu diprioritaskan dengan anggaran terbatas.
- Manajemen butuh terjemahan temuan teknis → kontrol & dampaknya.

---

## METHODOLOGY

### Step 1: Kelompokkan temuan per kategori ancaman, bukan per server
- Satu temuan = satu celah; satu kategori = satu pola ancaman (mis. "semua
  endpoint yang menelan input tanpa sanitasi" > "SQLi di file A dan XSS di
  file B").
- Untuk tiap kategori, tetapkan: vektor masuk → apa yang disentuh penyerang
  → apa yang ia inginkan. Kontrol efektif memutus TAHAP, bukan menambal
  satu pintu.

### Step 2: Pilih kontrol per lapisan (D3FEND-informed)
Untuk setiap kategori, isi matriks ini — rekomendasi yang hanya punya satu
lapisan belum lengkap:
| Lapisan | Pertanyaan | Contoh bentuk kontrol |
|---|---|---|
| Keras-kan (harden) | bagaimana membuat celah tidak ada? | sanitisasi terpusat, konfigurasi aman default, hapus fitur tak dipakai |
| Batasi dampak (isolate) | kalau celah ada, dampaknya terbatas? | segmentasi, hak minimum, container user non-root |
| Tipu (deceive) | bagaimana penyerang terlambat/terlihat? | honeypot akun/kredensial, tautan canary |
| Deteksi | bagaimana kita tahu sedang diserang? | aturan log (skill 76), alert perilaku, audit chain |
| Tanggapi (respond) | kalau terdeteksi, apa langkahnya? | runbook (skill 10/43), isolasi otomatis bounded |

### Step 3: Prioritaskan dengan argumen, bukan selera
Urutan argumen: (1) menutup jalur dengan dampak terbesar, (2) kontrol yang
sekaligus mematahkan kategori lain (kontekstual multiplier), (3) kemudahan
implementasi vs cakupan. Sajikan sebagai tiga gelombang:
- **Gelombang 1 (hari-1..7)**: konfigurasi/pin yang murah dan memutus jalur
  paling panas.
- **Gelombang 2 (30 hari)**: perubahan kode/arsitektur terkontrol.
- **Gelombang 3 (90 hari)**: perbaikan struktural (desain, segmentasi,
  program).

### Step 4: Nyatakan sisa risiko dengan jujur
- Kontrol belum terpasang = risiko SISA yang dilaporkan, bukan dihapus
  dari laporan.
- Kontrol yang butuh trade-off (mis. kenyamanan vs keamanan) disebut
  eksplisit; keputusan tetap milik pemilik risiko.
- Tidak ada jaminan "aman 100%" — bahasa laporan mengikuti klaim disiplin
  Cyphron (laporan kelas konsultan: bukti + batas jelas).

### Step 5: Definisikan ukuran berhasil
- Tiap kontrol: bagaimana memverifikasi terpasang (cek konkret, bukan
  "sudah diterapkan") + indikator efektivitas (temuan sejenis turun,
  waktu deteksi naik).
- Kaitkan ke detection_coverage: kontrol deteksi yang direkomendasikan
  harus bisa diuji (lab/fixture), bukan hanya dokumen.

---

## VERIFICATION

- Setiap rekomendasi merujuk temuan konkret (ID/bukti) — tidak ada
  rekomendasi generik tanpa anchoring.
- Matriks lima lapisan terisi untuk tiap kategori ancaman prioritas.
- Sisa risiko + batas rekomendasi ditulis eksplisit di laporan.
