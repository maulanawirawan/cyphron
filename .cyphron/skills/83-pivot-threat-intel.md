# Skill 83 — Pivot Analisis Threat Intel

> Workflow pivot indikator → konteks → indikator berikutnya (informed
> kerangka Diamond Model: penyerang, infrastruktur, korban, kapabilitas).
> Satu indikator (IP/domain/hash) tidak pernah cukup — nilainya muncul saat
> dipivot jadi graf yang bisa dijawab: siapa, pakai apa, menyerang siapa.

---

## WHEN TO ACTIVATE

- Punya satu indikator (IP IOC, domain phishing, hash malware) dan perlu
  memetakan lingkup kampanye.
- Insiden: pertanyaan "masih ada yang lain pakai infrastruktur yang sama?"
- Validasi laporan intel publik sebelum dipakai keputusan (hindari slop intel).

---

## METHODOLOGY

### Step 1: Klasifikasi indikator & mutability
- Stable: hash, watermark kit, pola TTP, branding phishing.
- Semi-stable: domain, sertifikat, JA3/fingerprint, pola path.
- Mutable: IP, nama file, user-agent, URL penuh.
- Prioritas pivot dari sisi STABLE; pivot dari IP saja = rentan salah sasaran
  (hosting bersama) — selalu cek apakah IP dedicated/CDN dulu.

### Step 2: Pivot infrastruktur (pasif)
- IP → pasangan domain lain di IP sama (pasif_dns/reverse — data pasif).
- Domain → registrasi, NS, MX, sertifikat (SAN/transparency log).
- Sertifikat → domain lain dengan fingerprint/issuer sama.
- Trackers/analytics ID yang tertanam di halaman phishing (GA/TKX) — ID
  analitik sering dipakai lintas kampanye penyerang.
- Semua query ke sumber intel publik; nol trafik ke infra penyerang.

### Step 3: Pivot kapabilitas
- Kit phishing → hash statis, pola path, struktur HTML, branding.
- Malware → konfigurasi C2, mutex, pola kripto (deobf kit).
- Cocokkan kapabilitas ke katalog TTP (MITRE-lite) untuk menghubungkan
  kampanye.

### Step 4: Pivot korban
- Siapa yang ditarget (brand, negara, bahasa halaman)?
- Cek overlap dengan aset yang dilindungi (apakah kampanye menyentuh
  klien kita?).

### Step 5: Graf, confidence, keluaran
- Setiap relasi punya: sumber data, waktu, confidence. Relasi 1 sumber =
  LEAD; >= 2 sumber independen = lebih kuat; jangan pernah menggabung
  kampanye hanya karena satu IP bersama (shared hosting!).
- Keluaran: graf relasi + daftar indikator baru utk watchlist + klaim
  yang DIBATALKAN (jujur: hipotesis yang tidak terbukti dicatat, bukan
  dibuang diam-diam).

---

## VERIFICATION

- Setiap pivot punya bukti (snapshot sumber + waktu).
- Tidak ada klaim atribusi (nama grup) tanpa >= 2 kapabilitas unik cocok.
- Indikator baru diuji false-positive-nya sebelum masuk watchlist.
