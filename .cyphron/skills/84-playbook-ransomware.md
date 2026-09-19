# Skill 84 — Playbook Ransomware (Pertahanan & Respons)

> Playbook dua sisi: (A) mempersiapkan organisasi agar ransomware gagal,
> (B) langkah pertama 1-24 jam saat terjadi. Ransomware bukan malware
> tunggal — ia AKHIR dari rantai: akses awal → eskalasi → lateral →
> eksfiltrasi → eksekusi. Melawan rantai lebih murah daripada melawan
> enkripsinya.

---

## WHEN TO ACTIVATE

- Persiapan: "kalau kita kena ransomware besok, apa yang menyelamatkan kita?"
- Insiden aktif: indikasi enkripsi massal / pencurian data sebelum enkripsi
  (double extortion).
- Uji kesiapan: tabletop exercise / gap assessment.

---

## METHODOLOGY

### A. Persiapan (sebelum kejadian)
1. **Backup 3-2-1-1-1**: 3 salinan, 2 media, 1 offsite, 1 offline/immutable,
   1 diuji restore. Backup yang belum pernah di-restore = asumsi, bukan
   pertahanan.
2. **Kurangi akses awal**: patch edge (VPN/RDP/firewall), MFA di semua
   akses remote, hilangkan layanan internet yang tidak perlu (skill 79).
3. **Persempit lateral**: segmentasi, akun admin terpisah, blokir SMB ke
   workstation, LAPS untuk password lokal.
4. **Deteksi dini** (skill 76/77): shadow copy deletion (event 1102, vssadmin),
   service baru aneh, proses membuka file massal, eksfiltrasi ke cloud
   storage aneh. Canary file/direktori umpan.
5. **Rencana keputusan**: siapa yang boleh menyatakan insiden, siapa
   menghubungi polisi/penyedia asuransi, template komunikasi.

### B. Respons (1-24 jam)
1. **Isolasi, JANGAN shutdown**: cabang jaringan (broadcast), matikan WiFi;
   power off menghancurkan bukti memori (skill 75) dan kadang memicu
   wiper. VM rentan: snapshot dulu bila aman.
2. **Identifikasi varian** dari catatan ransom (tanpa membayar/menghubungi
   dulu): nama, ekstensi, note hash. Varian menentukan: ada decryptor?
   adakah bug keluarga itu? (cek sumber decryptor resmi, bukan situs
   samar).
3. **Tentukan cakupan**: patient zero, jam mulai, akun dipakai (log 4624
   lain), apakah data DIEKSKFILTRASI (log traffic — double extortion).
4. **Lindungi yang belum kena**: isolasi segmen, reset kredensial privilese,
   blokir C2 yang sudah dikenali (dari config varian), freeze backup job.
5. **Bukti untuk hukum/asuransi**: image disk, log terpusat, chain of
   custody. Jangan wipe sebelum foto/hash.
6. **Keputusan restore**: hanya setelah akses awal tertutup; restore
   bertahap + monitoring ketat; uji integritas data.
7. **Pembayaran**: keputusan bisnis/legal (bukan teknis) — nyatakan risiko:
   tidak menjamin decryptor benar, menandai kamu jadi target berikutnya,
   sisi hukum masih risiko sanctions. KONSULTASI legal dulu.
8. **Post-incident**: root cause jalur akses awal, perbaiki, tambahkan
   deteksi untuk TTP yang terpakai (skill 80).

---

## AUDIT CHECKLIST

- [ ] Backup teruji restore + 1 salinan offline/immutable
- [ ] MFA semua akses remote; edge ter-patch
- [ ] Segmentasi + akun admin terpisah
- [ ] Deteksi shadow-copy deletion & enkripsi massal
- [ ] Kontak darurat (penyedia, legal, polisi) teruji
- [ ] Rencana keputusan pembayaran dibahas SEBELUM insiden
