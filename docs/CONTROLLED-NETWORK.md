# CONTROLLED NETWORK ENGINE (Fase 2-B) — Penegakan Budget Pre-Connect

Status: DESAIN + SKELETON TERUJI (implementasi integrasi runner menyusul)
Terinspirasi kritik reviewer B: budget request saat ini ditegakkan
post-hoc (hard-fail setelah run) + proyeksi pra-run. Yang diminta:
penegakan SEBELUM koneksi terkirim, untuk proses eksternal (skill).

## 1. Masalah

- Skill dieksekusi runner Rust sebagai subprocess Python. Budget
  request per skill dinyatakan di registry (safety class) dan
  diproyeksikan SEBELUM run, tetapi penghitungan aktual terjadi
  SETELAH: baris findings dibaca + `requests` di meta dibandingkan
  proyeksi. Skill yang bocor (bug, loop, untracked request) baru
  ketahuan setelah request terkirim ke target.
- Kelas skill non-HTTP nyata: `dns_light` (UDP 53 + AXFR TCP mentah)
  dan `tls-heartbeat-overread` (TLS 1.2 custom socket). Kontrol
  berbasis HTTP proxy TIDAK melihat keduanya.

## 2. Opsi yang dipertimbangkan

| Opsi | Cakupan | Keputusan |
|---|---|---|
| A. Proxy lokal pembatas (single egress) | Semua HTTP via env proxy; metering + tolak sebelum forward | DITOLAK sebagai inti: DNS/UDP/AXFR/TLS-custom tidak lewat proxy — dua kelas skill lolos metering |
| B. Socket wrapper di skill SDK (sitecustomize) | SEMUA socket TCP+UDP; tolak SEBELUM connect() | **DIPILIH** — paling fail-closed untuk cakupan penuh; tanpa jaringan tambahan, tanpa root, lintas platform |
| C. cgroup / Job Object | Isolasi level OS | DITOLAK: Windows Job Object tidak punya filter network per-koneksi; WFP butuh driver; Linux cgroup+iptables butuh root; platform-locked |

Kriteria operator: "paling fail-closed dan sederhana". B menutup semua
kelas socket dengan SATU mekanisme; A dan C masing-masing meninggalkan
gap atau butuh infrastruktur OS.

## 3. Arsitektur (Opsi B)

```
runner Rust (run_skill_with_env)
  env untuk skill:
    CYPHRON_NET_GUARD=1
    CYPHRON_NET_BUDGET_FILE=<path JSON atomik, milik runner>
    CYPHRON_NET_AUDIT=<path JSONL append-only>
    PYTHONPATH=<root>;tools/net_guard   (Windows: ';', POSIX ':')
  setelah skill selesai:
    verifikasi audit log ADA dan skill tidak melebihi budget
    -> audit log hilang = hard-fail skill (skill berjalan tanpa
       guard = tidak bisa dinilai, seperti fetch failed)
        │
        ▼
proses skill Python
  sitecustomize (auto-import Python saat startup, dari PYTHONPATH)
    bila CYPHRON_NET_GUARD=1:
      patch socket.socket.connect / connect_ex / sendto
      patch socket.create_connection
  setiap upaya koneksi:
    1. baca budget file {limit, used} (atomik via os.replace)
    2. used >= limit  -> tolak SEBELUM connect (raise OSError)  [fail-closed]
       budget file hilang/korup -> tolak                          [fail-closed]
    3. lolos -> increment used (atomic replace) -> connect asli
    4. tulis baris audit JSONL {ts, kind, host, port, allowed, used}
```

### Kebijakan fail-closed (ladder tidak dilonggar)

1. `CYPHRON_NET_GUARD=1` + budget file tidak ada/tak terbaca → SEMUA
   koneksi outbound ditolak. Guard aktif tanpa kontrak budget = blok.
2. Budget habis → koneksi berikutnya ditolak. Skill yang membaca
   penolakan (exception) mengalir ke jalur error skill yang sudah ada
   (unconfirmed/fail-closed) — TIDAK ada koneksi berlebih yang lolos.
3. Skill dijalankan runner TANPA audit log wrapper → runner menandai
   hard-fail (implementasi runner: fase berikutnya).
4. Budget DNS vs HTTP: skeleton menghitung SATU counter per proses
   skill (sesuai safety class per skill di registry). Pemisahan per
   jenis (dns vs http) bisa jadi pengembangan, bukan syarat.

### Batas jujur (didokumentasikan, tidak disembunyikan)

- Ini GUARD KESALAHAN proses sendiri (skill bug/loop/untracked), BUKAN
  sandbox keamanan adversarial: kode Python yang sengaja bisa
  memuat ulang socket murni (importlib reset, ctypes, subprocess baru).
  Model ancaman = mencegah KESALAHAN, bukan melawan kode jahat.
- Proses non-Python yang di-spawn skill (mis. biner eksternal) tidak
  di-patch; runner tidak pernah mem-whitelist skill yang spawn proses
  jaringan eksternal (aturan safety class tetap berlaku).
- Wrapper tidak mengubah perilaku skill yang patuh: budget selalu >=
  estimasi proyeksi (runner yang menetapkan limit dari proyeksi).

## 4. Kontrak modul

- `core/net_guard.py`:
  - `install(budget_file, audit_file) -> callable` — pasang patch,
    kembalikan fungsi `uninstall()` (untuk test; proses nyata tidak
    pernah uninstall).
  - `try_take(budget_file, n=1) -> int|None` — ambil n token atomik;
    None = ditolak (budget habis / file hilang / korup).
  - Patch: `socket.socket.connect`, `socket.socket.connect_ex`,
    `socket.socket.sendto`, `socket.create_connection`.
  - Idempotent: `install` dua kali tidak menumpuk patch.
- `tools/net_guard/sitecustomize.py`: entry tipis yang di-import
  otomatis Python; hanya bertindak bila `CYPHRON_NET_GUARD=1`.
- Runner (fase berikutnya): set env + PYTHONPATH, verifikasi audit
  log per skill, hard-fail tanpa log.

## 5. Status implementasi

- [x] Desain (dokumen ini)
- [x] `core/net_guard.py` — patch + budget atomik + audit JSONL
- [x] `tools/net_guard/sitecustomize.py` — entry tipis
- [x] `tests/test_net_guard.py` — budget ok/habis/hilang, TCP+UDP,
      tolak SEBELUM connect (server hanya melihat koneksi sah),
      idempotent, uninstall bersih
- [ ] Integrasi runner Rust (env + verifikasi audit log) — fase berikutnya
- [ ] Budget proyeksi -> limit file di runner — fase berikutnya
