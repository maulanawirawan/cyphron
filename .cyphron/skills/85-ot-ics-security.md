# Skill 85 — Keamanan OT/ICS (Operational Technology)

> Teknologi operasional (SCADA, PLC, DCS, RTU) punya prioritas terbalik dari
> IT: KETERSEDIAAN dan KEAMANAN FISIK di atas kerahasiaan. Uji keamanan IT
> biasa (scan agresif, exploit) bisa menghentikan produksi atau merusak
> peralatan fisik — di OT itu BUKAN temuan, itu KECELAKAAN. Disiplin utama:
> pasif dulu, pasif terus, dan semua uji aktif wajib lewat environment
> staging/replica.

---

## WHEN TO ACTIVATE

- Pabrik/utilitas/energi: "audit keamanan sistem kontrol kami".
- Konektivitas IT-OT baru (remote access vendor, cloud monitoring) perlu
  ditinjau sebelum diaktifkan.
- Insiden di jaringan OT atau dugaan perangkat aneh di jaringan kontrol.

---

## METHODOLOGY

### Step 1: Peta pasif — jangan kirim satu paket pun ke jaringan kontrol
- Sumber pasif: konfigurasi switch/router yang diberikan admin, diagram
  jaringan, inventaris asset manual, port-mirroring/SPAN untuk mendengarkan
  traffic (bukan mengirim).
- Protokol yang umum terlihat: Modbus/TCP, S7comm, EtherNet/IP, DNP3,
  OPC — identifikasi vendor & model dari traffic, jangan dari probing.
- Hasil: peta zona (produksi, supervisi, IT) + conduits (jalur antar zona)
  mengikuti model zone/conduit — selisih antara dokumentasi dan kenyataan
  adalah temuan pertama.

### Step 2: Temuan struktural (dari peta, bukan dari scan)
- IT dan OT dalam satu flat network / tanpa DMZ industrial = temuan tinggi.
- Akses remote vendor: always-on, tanpa MFA, tanpa jendela waktu = temuan.
- Perangkat Windows di jaringan kontrol tanpa patch/AV karena "tak boleh
  downtime" = temuan posture + rencana mitigasi (virtual patching di firewall).
- Akun default perangkat (PLC/engineering workstation) yang tak pernah diganti
  = temuan (dicek dari dokumentasi/vendor advisory, bukan login coba-coba).

### Step 3: Uji aktif HANYA di staging/replica
- Build testbed: PLC simulator/replica atau perangkat bekas. Uji kerentanan
  di sana; hasilnya di-transfer ke perangkat produksi hanya sebagai
  "perlu di-patch saat jendela maintenance".
- Scan aktif ke jaringan produksi: TIDAK dilakukan tanpa persetujuan
  tertulis + jendela waktu + engineer OT standby. Beberapa perangkat
  lawas reboot/lock saat disken — itu kerusakan, bukan temuan.

### Step 4: Monitor & deteksi
- Pasif monitoring di SPAN: alert protokol aneh (Modbus function code yang
  jarang, firmware download, perubahan logic PLC), host baru di jaringan OT.
- Baseline komunikasi normal dulu 1-2 minggu sebelum alert diaktifkan
  (hindari FP yang bikin alert diabaikan).

### Step 5: Pelaporan dengan bahasa risiko fisik
- Dampak dinyatakan sebagai konsekuensi fisik/produksi (downtime, kerusakan
  alat, keselamatan orang) — bukan sekadar CVSS teknis.
- Rekomendasi selalu: (1) segmentasi/DMZ industrial, (2) kontrol akses
  remote, (3) hardening bertahap lewat jendela maintenance, (4) deteksi
  pasif. TANPA rekomendasi yang mengharuskan downtime mendadak.

---

## VERIFICATION

- NOL paket aktif ke jaringan produksi (bukti: log pengujian + metode).
- Temuan bersumber dari peta/dokumentasi/traffic pasif — setiap klaim bisa
  ditunjuk lokasinya di arsitektur.
- Uji eksploitasi hanya di staging; bukti produksi = foto/log, bukan
  pencobaan ulang.
