# Skill 82 — Recon Eksternal Pasif (Satukan Workflow)

> Satu workflow recon eksternal yang seluruhnya pasif untuk tahap awal
> engagement: permukaan profil publik (`username_osint`), konteks
> infrastruktur (`ip_intel`), dan pemetaan host (`passive_dns`,
> `http_probe`). Semua hasil = LEAD/data pasif — target utama TIDAK
> disentuh sebelum otorisasi.

---

## WHEN TO ACTIVATE

- Awal engagement terotorisasi: bangun gambaran permukaan sebelum sentuhan
  pertama ke target.
- "Cari semua jejak publik dari domain/username/IP ini" (mode pasif).
- Threat intel defensif: profil palsu yang meniru brand (sinergi skill 78).

---

## METHODOLOGY

### Step 1: Kumpulkan benih
- Domain utama + varian; nama brand; username resmi organisasi (dari
  situs/domain, bukan tebakan); IP publik dari hasil sebelumnya.
- Cek dokumen otorisasi: scope engagement menentukan apa yang boleh
  disentuh SETELAH fase pasif (L0-L2).

### Step 2: Pemetaan host pasif
- `passive_dns` (census historis, nol trafik ke target) + klasifikasi
  staging yang ditolak otomatis (out-of-scope umum).
- `http_probe` hanya pada host yang SUDAH dipastikan in-scope di dokumen
  otorisasi — gate menolak yang di luar scope.
- Catat ke world model: host → IP → ASN.

### Step 3: Konteks infrastruktur
- `ip_intel` untuk setiap IP publik menonjol: geo/ASN/operator — konteks
  untuk dossier & laporan.
- Jangan menuduh: geo/ASN bukan identitas (cloud/proxy umum). Data masuk
  laporan sebagai konteks, bukan kesimpulan.

### Step 4: Permukaan profil publik
- `username_osint` untuk username resmi brand: profil apa yang ADA —
  baseline utk mendeteksi impersonasi berikutnya.
- LEAD keberadaan ≠ identitas pemilik; platform ambigu dilaporkan jujur.

### Step 5: Satukan & laporkan
- Masukkan semua LEAD/data ke laporan engagement (otomatis: engine
  ter-registrasi masuk coverage matrix RECON + audit trail).
- Format: temuan (bukti) → LEAD (indikasi, dilabel) → data (konteks).
- Prioritas tindak lanjut: host live in-scope (skill 16/51), indikator
  impersonasi (skill 78), jalur pelaporan resmi bila fraud (skill 81).

---

## VERIFICATION

- Nol trafik ke infra target pada fase pasif (bukti: audit trail hanya
  menyentuh layanan intel publik + host ber-scope).
- Semua LEAD punya bukti request/status; yang ambigu dilabel tidak-pasti.
- World model terisi (host/IP/ASN) sebelum fase aktif dimulai.
