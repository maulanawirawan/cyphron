# Awareness Patterns — pelajaran dari temuan nyata yang terverifikasi

> **Tujuan edukasi.** Dokumen ini merangkum pola celah yang benar-benar kami
> telusuri sampai tuntas (diff resmi dua versi, mock server, matriks
> vuln/patched/non-target/honeypot) dan dikirim sebagai template ke
> projectdiscovery/nuclei-templates. Semuanya celah **request-detectable
> read-only** — bukan exploit, tidak ada payload destruktif.
>
> **Aturan main:** hanya untuk aset milik sendiri, laboratorium lokal, atau
> target dengan izin tertulis (sesuai AGENTS.md). Pola-pola ini dipublikasikan
> oleh vendor advisory resmi — tujuan halaman ini adalah membantu developer
> **mengenali polanya di kode sendiri sebelum orang lain melakukannya**.

Format setiap pola: `Celah → Kenapa terjadi → Sinyal deteksi → Perbaikan → Referensi`.

---

## Pola 1 — Signing key JWT hardcoded di repo

- **Celah:** Aplikasi menandatangani token JWT dengan kunci yang ter-commit
  di `appsettings.json`. Siapa pun yang membaca repo (publik atau via bocor)
  bisa menandatangani token sendiri secara offline dan masuk sebagai admin —
  tanpa pernah login.
- **Kenapa terjadi:** default config demi "mudah dijalankan" tidak pernah
  dipaksa diganti di startup. Validasi signature tetap lulus karena kuncinya
  memang benar — yang salah adalah **provenance token**, bukan matematikanya.
- **Sinyal deteksi (in-band):** permintaan dengan token yang di-sign pakai
  kunci default → `200` + data admin, sementara token acak → `401`.
  Selisih dua status inilah buktinya.
- **Perbaikan:** gagalkan startup bila `SecurityKey` masih placeholder;
  bind token ke sesi server-side agar token yang "tidak pernah diterbitkan"
  ditolak walau signature valid.
- **Referensi:** CVE-2026-120442 (ape-volo-admin), fix `938f7ec`,
  template `nuclei-templates` PR maulanawirawan#17676 (CI clean).
  pola setara: `SecretKey` Laravel/`SECRET_KEY` Flask yang ter-commit.

## Pola 2 — Middleware terdaftar dengan kunci yang tidak pernah match

- **Celah:** Framework mendaftarkan middleware auth di config dengan key
  `'platformapi'` (nama *URL prefix*), padahal framework menginferensi key
  dari *namespace controller* (`app\platform`). Key tidak pernah cocok →
  middleware auth **tidak pernah dieksekusi** → seluruh API admin terbuka.
- **Kenapa terjadi:** kesenjangan antara "nama yang tertulis di config" dan
  "nama yang dipakai framework untuk routing". Tidak ada error — config yang
  tidak match diam-diam diabaikan.
- **Sinyal deteksi (in-band):** endpoint yang seharusnya terproteksi membalas
  `200 + data` untuk request anonim; setelah patch, `401` sebelum controller.
- **Perbaikan:** uji "endpoint admin harus 401 untuk anonim" sebagai **test
  unit/integration** — perubahan framework config harus mematahkan test itu.
- **Referensi:** CVE-2026-120446 (madong-admin-saas), fix `2a199a15`,
  PR#17675 (CI clean).

## Pola 3 — Route publik memakai serializer yang membocorkan field privat

- **Celah:** Endpoint publik (produk terbaru, terlaris) memakai fungsi
  serialisasi yang sama dengan endpoint internal, sehingga field khusus
  vendor ikut keluar: tautan file unduhan, catatan pembelian, **nilai komisi
  per produk**, URL edit dashboard lengkap dengan nonce.
- **Kenapa terjadi:** satu serializer untuk banyak konteks. Permission check
  ada di *route*, bukan di *field* — menambah route publik tidak otomatis
  mem-filter field.
- **Sinyal deteksi (in-band):** field yang nilainya seharusnya kosong untuk
  tamu (`"edit_url":""` pada versi patch) berisi URL absolut di versi rentan.
- **Perbaikan:** pisahkan serializer publik (allow-list field) dari
  serializer internal; uji respons anonim sebagai bagian dari CI.
- **Referensi:** CVE-2026-119485/119487 (Dokan Lite, patch 5.3.3 menambah
  `can_view_private_product_data()`), PR#17673; pola serupa CVE-2026-121555
  (Foxel — route stream/thumbnail tanpa guard sama sekali, PR#17674).

## Pola 4 — Cache menulis respons internal ke file statis publik

- **Celah:** Plugin cache menyimpan hasil render **semua** halaman, termasuk
  halaman internal yang responsnya berisi kredensial (`wp-activate.php`
  multisite memuat username + password plaintext hasil aktivasi). File cache
  jadi bisa dibaca siapa pun tanpa login.
- **Kenapa terjadi:** daftar "halaman yang diabaikan cache" tidak mencakup
  halaman tersebut; cache menganggap semua respons = konten publik.
- **Sinyal deteksi (in-band):** file cache statis berisi marker yang hanya
  muncul di halaman hasil (bukan form) — contoh `signup-welcome`.
  404 = tidak ada masalah; 200 + marker = terbukti.
- **Perbaikan:** exclude-list halaman auth/aktivasi, `pagenow` guard, dan
  hapus cache lama saat upgrade. Rotasi kredensial yang terekspos.
- **Referensi:** CVE-2026-111464 (WP Fastest Cache, patch 1.5.4), PR#17671;
  kini dideteksi otomatis oleh skill `skills/cached_sensitive_files.py`
  (fail-closed, 2 GET).

## Pola 5 — Input dicetak mentah di halaman error

- **Celah:** Parameter URL dari pengguna dirender tanpa encoding di halaman
  error → reflected XSS. Halaman error sering "lupa" karena dianggap bukan
  bagian dari aplikasi.
- **Kenapa terjadi:** string buatan developer dicetak langsung; framework
  tidak meng-escape `echo`/template engine non-autoescape di jalur error.
- **Sinyal deteksi (in-band):** refleksi payload yang ter-encode di URL
  muncul **ter-decode** di body, DITAMBAH **anchor konteks** halaman target
  (class/tag hardcoded) agar tidak tertukar dengan echo di tempat lain.
- **Perbaikan:** `esc_html()`/encoding kontekstual di semua jalur error;
  uji refleksi di halaman error, bukan hanya halaman utama.
- **Referensi:** CVE-2026-120597 (Welcart e-Commerce, patch 2.12.7
  `esc_html`), PR#17672. Pelajaran teknis penting: honeypot penguji CI
  meng-echo query ter-decode — matcher refleksi tanpa anchor konteks akan
  false-positive; uji dulu ke `honey.scanme.sh` sebelum klaim.

## Pola 6 — Parameter internal dibuka untuk publik

- **Celah:** Query pencarian menerima parameter internal (`post_type`)
  langsung dari request tanpa allow-list. Tamu memaksa pencarian ke tipe
  posting internal (`revision`) dan membaca draf/autosave yang belum
  dipublikasikan.
- **Kenapa terjadi:** "sanitize" ≠ "authorize" — nilainya dibersihkan
  (`sanitize_title`) tapi tidak **dibatasi** pada tipe yang boleh dilihat.
- **Sinyal deteksi (in-band):** respons pencarian menampilkan permakan hasil
  untuk tipe internal; versi patch mengosongkan hasil (type di-stripped).
- **Perbaikan:** allow-list tipe posting yang *publicly_queryable*; jangan
  menerima tipe dari request.
- **Referensi:** CVE-2026-119495 (Better Search, patch 4.5.3 menambah
  `get_allowed_post_types()`), PR#17669.

## Pola 7 — Alur "praktis untuk pengguna" melewati nonce/validasi

- **Celah:** Aksi AJAX terdaftar untuk tamu (`wp_ajax_nopriv_...`) dengan
  jalur "lewat nonce karena datang dari URL statis" dan tanpa validasi
  ID — tamu bisa memilih/menetapkan paket membership yang seharusnya
  tidak tersedia.
- **Kenapa terjadi:** pintu kemudahan untuk flow tertentu (checkout via
  URL) membuka cabang logika yang tidak memeriksa *selectable/not*.
- **Sinyal deteksi (in-band):** respons mengarahkan ke langkah registrasi
  (`vmstep=registration` di Location) untuk ID yang seharusnya ditolak;
  versi patch memanggil `wp_send_json_error`.
- **Perbaikan:** satu gerbang `is_selectable()` untuk SEMUA cabang, termasuk
  jalur URL; jangan pernah mengecualikan nonce pada aksi yang mengubah
  state sesi.
- **Referensi:** CVE-2026-39743 (WCFM Membership, patch 2.12.1 menambah
  `wcfm_is_selectable_membership()`), PR#17670.

## Pola 8 — Diferensial patched-vs-vulnerable adalah satu-satunya saksi

- **Celah (meta):** Beberapa perbaikan tidak mengubah respons sama sekali
  (mis. hanya menghapus `update_option` — CVE-2026-119509 ClickCease).
  Tanpa saksi in-band, scanner **tidak boleh** mengklaim deteksi —
  itulah mengapa banyak berita CVE besar tidak bisa (dan tidak boleh)
  dijadikan template otomatis: NetScaler 88771 (eksekusi asinkron via
  maintenance script), Cisco FMC 20131 (gadget chain tak publik).
- **Pelajaran:** sebelum mengklaim "terdeteksi", buktikan dulu bahwa
  respons server rentan ≠ respons patch. Kalau identik → hentikan,
  fail-closed. Dokumen ini dan template yang dirujuk hanya memuat pola
  yang lolos matriks: **vuln MATCH / patched NO / non-target NO /
  honeypot NO**.

## Pola 9 — Default config yang "aman-demi-kemudahan" adalah kelas celahnya sendiri

- **Celah yang berulang di Pola 1-7:** kunci default, key config yang
  tidak pernah diverifikasi, allow-list yang belum dibuat, exclude-list
  cache yang pendek. Hampir semua temuan bukan bug logika rumit — tapi
  **default yang tidak pernah dipertanyakan**.
- **Perbaikan proses:** tambahkan "golden test" per jalur auth/privasi:
  anonim harus ditolak (401/403/kosong) di endpoint internal, respons publik
  tidak memuat field internal, file cache tidak memuat marker internal.
  Tiga tes ini mencegah sebagian besar pola di atas sejak commit pertama.

---

## Ringkasan pola → kelas CWE

| Pola | CWE | Kelas temuan Cyphron |
|---|---|---|
| 1 Hardcoded JWT key | CWE-798 | auth-bypass |
| 2 Middleware key mismatch | CWE-306 | missing-auth |
| 3 Serializer bocor | CWE-862 | exposure |
| 4 Cache file sensitif | CWE-538 | exposure |
| 5 Reflected XSS error page | CWE-79 | injection (reflected) |
| 6 post_type bebas | CWE-862 | exposure |
| 7 Bypass nonce-by-url | CWE-352/CWE-862 | access-control |

Skill otomatis yang lahir dari halaman ini: `skills/cached_sensitive_files.py`
(Pola 4). Pola lain dikirim sebagai template deteksi ke
`projectdiscovery/nuclei-templates` (tautan PR di atas) karena butuh
payload spesifik per produk; halaman ini adalah versi awarnessnya.
