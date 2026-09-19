# Skill 76 — Analisis Event Log (Windows/Linux)

> Triage log event secara sistematis: ID event mana yang penting, bagaimana
> menyusun timeline, dan bagaimana mengorelasikan antar sumber log. Log
> adalah sumber bukti termurah di insiden — kebanyakan penyerang meninggalkan
> jejak di sini, dan kebanyakan tim membaca log-nya terlambat atau salah
> fokus.

---

## WHEN TO ACTIVATE

- Insiden/post-incident: "cek log-nya, ada yang aneh tidak?" tanpa petunjuk
  spesifik.
- Validasi temuan memori/disk (skill 75/74) ke jejak waktu di log.
- Hunt hipotesis (skill 77) butuh kueri log konkret sebagai sumber data.
- Audit posture logging: "apakah logging kita cukup untuk mendeteksi X?"

---

## METHODOLOGY

### Step 1: Tentukan sumber & rentang waktu SEBELUM kueri
- Windows: Security, System, PowerShell/Operational, Sysmon (jika ada),
  RDP/TS logs, IIS/W3SVC (untuk web).
- Linux: auth.log/secure, syslog, journalctl, cron, sudo, wtmp/btmp.
- Kunci rentang waktu dari konteks (jam insiden, timestamp temuan lain),
  dengan +/- buffer. Basis waktu: konfirmasi zona waktu dan skew jam
  mesin SEBELUM menyimpulkan urutan.

### Step 2: Daftar ID prioritas (Windows Security/System)
| ID | Arti | Kenapa penting |
|---|---|---|
| 4624/4625 | Logon sukses/gagal | basis deteksi brute force + jam anomali |
| 4648 | Logon with explicit creds | dugaan lateral movement / pass-the-hash |
| 4672 | Special logon | akun privilese aktif — cocokkan dengan keharusan |
| 4720/4722/4724/4725 | akun dibuat/diaktifkan/reset/dinonaktifkan | manipulasi akun |
| 4728/4732/4756 | anggota grup privilese baru | eskalasi hak |
| 4698/4699 | scheduled task dibuat/dihapus | persistensi |
| 7045 | service baru ter-install | persistensi favorit |
| 1102 | audit log dibersihkan | tanda anti-forensik |
| 4692/4699 (DPAPI) & 4662 | operasi objek privilese | dumping kredensial |
- Tamper-indicator SELALU dicek dulu: 1102, event log service stop (7036
  pada log service), kekosongan waktu aneh di log.
- Sysmon jika ada: event 1 (proses), 3 (network), 7 (image load), 8
  (remote thread), 11 (file create), 13 (registry set) = tulang punggung.

### Step 3: Kueri berlapis (bukan sapu satu pola)
- Lapis 1 — kejadian agregat: hitung 4625 per akun/IP (brute force),
  logon sukses per jam non-kerja, service baru per mesin.
- Lapis 2 — urutan: susun timeline campur (logon → proses → network →
  service → log clear). Urutan yang "tidak masuk akal" = temuan.
- Lapis 3 — korelasi lintas mesin: akun yang sama muncul di banyak mesin
  dalam jendela pendek = lateral movement; gunakan world model/graph
  Cyphron untuk menyimpan relasi.

### Step 4: Anomali perilaku (bukan hanya kata kunci)
- Jam akses: akun admin aktif jam 03:00 — cek kebiasaan normal dulu
  (shift? backup otomatis?), jangan langsung tuduh.
- Geometri: 1 akun → banyak mesin (lereng), banyak akun → 1 mesin
  (target bertumpuk).
- Kegagalan yang berhenti mendadak setelah sukses = brute force yang
  BERHASIL — ini temuan penting yang sering terlewat.

### Step 5: Log Linux (kanal yang setara)
- auth.log: su/sudo gagal-sukses, SSH accepted untuk akun tak wajar,
  session open tanpa session close.
- cron/at: job yang baru muncul = persistensi.
- journal: unit service baru, clock change (pengaburan timeline).

### Step 6: Kesimpulan & posture
- Kesimpulan per klaim selalu dengan bukti: event ID + record + waktu +
  mesin. Tanpa itu = LEAD.
- Keluaran posture: daftar logging yang BUKAN kekurangan data (event yang
  seharusnya terekam tapi tidak ada) — jadikan rekomendasi konfigurasi
  logging (mengaktifkan audit policy yang hilang).

---

## AUDIT CHECKLIST

- [ ] Rentang waktu & skew jam tercatat sebelum analisis
- [ ] Tamper indicators dicek lebih dulu (1102/log clear/service stop)
- [ ] Agregasi dilakukan sebelum pencarian kata kunci
- [ ] Setiap temuan punya (event ID, waktu, mesin, akun)
- [ ] Korelasi lintas mesin disimpan di world model
- [ ] Kekurangan logging dilaporkan sebagai temuan posture, bukan diabaikan
