# Skill 87 — Analisis Traffic Jaringan (Defensif)

> Membaca traffic jaringan sebagai sumber bukti: baseline dulu, anomali
> kemudian. Traffic adalah saksi yang sulit dipalsukan penyerang — tapi
> hanya kalau kamu tahu yang mana "normal" dan punya disiplin menolak
> kesimpulan dari satu sinyal.

---

## WHEN TO ACTIVATE

- "Ada aktivitas aneh di jaringan kami" tanpa petunjuk spesifik.
- Investigasi: butuh konfirmasi trafik keluar-masuk yang tidak wajar.
- Hunt C2/eksfiltrasi (pasangan skill 77, sumber: netflow/proxy/DNS).
- Validasi pasca-insiden: apakah data benar keluar? ke mana? seberapa besar?

---

## METHODOLOGY

### Step 1: Sumber data & keterbatasannya
- Netflow/sFlow: siapa-ke-siapa + volume + waktu (tanpa isi).
- Proxy log: domain/URL + user + ukuran (HTTP; HTTPS hanya SNI/domain).
- DNS log: kueri domain — sering paling jujur untuk C2/tunneling.
- PCAP penuh: paling kaya, paling mahal — hanya untuk jendela sempit.
- Jujur dulu: HTTPS mengaburkan isi; analisis = metadata, BUKAN isi.
  Klaim berbasis metadata dilabel sesuai keterbatasannya.

### Step 2: Baseline perilaku normal
- Per subnet/host: volume per jam, tujuan luar biasa, port, protokol.
- Baseline butuh data cukup lama (1-2 minggu) — jangan menyimpulkan
  anomali dari baseline yang baru dibuat.
- Dokumentasikan pengecualian sah (backup malam, sync cloud resmi, monitoring)
  supaya tidak jadi temuan palsu.

### Step 3: Kueri berlapis (agregat → sempit)
1. Volume keluar per host per jam — puncak di luar pola = kandidat.
2. Koneksi keluar ke domain baru (belum pernah muncul di baseline).
3. Interval koneksi berkala (beacon) — distribusi inter-arrival konsisten.
4. DNS: kueri TXT besar/sering (tunneling), NXDOMAIN massal (DGA),
   domain panjang acak.
5. Sempitkan ke host kandidat → kecilkan jendela waktu → PCAP/inspeksi
   hanya pada kandidat itu (hemat dan terarah).

### Step 4: Verifikasi silang
- Kandidat C2/eksfiltrasi wajib dikonfirmasi >= 2 sumber (traffic + endpoint
  log + host artifact skill 75/76). Metadata saja = LEAD.
- Sinkronkan timeline dengan log endpoint: proses yang menyalakan trafik itu
  apa? (proses → PID → binary → hash).

### Step 5: Keluaran
- Timeline trafik + host kandidat + bukti (query, log) + sisa pertanyaan.
- Rekomendasi: blokir IOC (dengan risiko false-positive diukur dulu),
  aturan deteksi baru (skill 09), kebijakan egress yang lebih ketat.

---

## VERIFICATION

- Baseline terdokumentasi sebelum klaim anomali.
- Setiap klaim eksfiltrasi punya volume + tujuan + waktu + proses pemiliknya.
- Metadata ≠ isi: klaim di-label jujur sesuai sumber datanya.
