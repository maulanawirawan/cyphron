# Skill 86 — Deception & Canary (Teknik Umpan)

> Deception defense: membuat penyerang membuang waktu di umpan yang
> menyatu dengan produksi, dan — yang lebih penting — membuat SETIAP
> sentuhan umpan menjadi alarm dengan false-positive rate mendekati nol.
> Prinsip inti: tidak ada alasan sah bagi siapa pun menyentuh umpan — jadi
> tiap sentuhan = sinyal nyata (berbeda dari alert biasa yang melimpah).

---

## WHEN TO ACTIVATE

- Organisasi punya deteksi tapi butuh sinyal dini berkualitas tinggi.
- Setelah insiden: pasang umpan agar kalau penyerang kembali, terlihat.
- "Kami tidak tahu kalau kami sudah disusup berapa lama" — butuh tripwire.

---

## METHODOLOGY

### Step 1: Pilih umpan yang sah untuk lingkunganmu
| Umpan | Bentuk | Sinyal saat disentuh |
|---|---|---|
| Akun canary | user "backup-admin" tanpa aktivitas sah | login attempt = alarm |
| File canary | `passwords.xlsx`, `db-credentials.txt` di share | dibuka/di-copy = alarm |
| Token canary | AWS key palsu di repo/config | dipakai di cloud API = alarm |
| Server decoy | VM "lupa" di jaringan dengan port umum | koneksi = alarm |
| URL canary | link unik di dokumen internal | diklik = alarm (phishing check) |
- Aturan: umpan TIDAK BOLEH bisa dipakai penyerang merugikan (token palsu
  harus benar-benar mati; decoy tanpa akses ke produksi).

### Step 2: Penempatan — jalur wajib penyerang
- Tempatkan di titik yang dilalui setiap jalur serangan: share internal,
  credential manager, folder backup, memory of domain admin (terbatas),
  halaman intranet jarang diakses.
- Satu umpan di jalur wajib > seratus umpan di sudut mati.

### Step 3: Alarm yang dijaga kredibilitasnya
- Tiap umpan punya identitas unik → tahu TEPAT umpan mana yang disentuh
  (menunjuk tahap serangan: file canary dibuka = pasca-eskalasi).
- Rute alarm lewat kanal yang tidak bisa dimatikan penyerang (eksternal
  bisa: webhook ke layanan canary pihak ketiga / email out-of-band).
- Uji sendiri tiap umpan sebelum dianggap aktif (sentuh umpan → alarm datang).

### Step 4: Integrasi respons
- Alarm canary = prioritas tinggi langsung (skill 10), bukan antrian biasa.
- Dokumentasikan lokasi umpan di lembar rahasia terpisah — jangan sampai
  tim sendiri mengira umpan adalah aset nyata (atau sebaliknya, menghapusnya).

---

## VERIFICATION

- Setiap umpan diuji berfungsi (sengaja disentuh → alarm tercatat).
- Umpan tidak bisa dipakai merugikan (token mati, decoy terisolasi).
- Peta umpan tersimpan rahasia dan diperbarui.
