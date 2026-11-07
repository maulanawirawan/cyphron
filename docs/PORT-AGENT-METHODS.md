# PORT-AGENT-METHODS — distilasi metodologi dari skill antrean yang di-skip

Beberapa skill di SKILL-PORT-QUEUE di-SKIP sebagai tool (tanpa inti yang
bisa dieksekusi kode), tapi inti metodologinya tetap berguna untuk
AGENT yang bekerja di repo ini. Dokumen ini mendistilasinya dari
trailofbits/skills (CC-BY-SA-4.0 — konsep, bukan teks) ke checklist
yang dipakai saat review/audit di cyphron. Kontrak repo tetap di atas
semuanya: no proof, no report; fail-closed; target berizin saja.

## 1. Konteks pra-audit (dari tob/audit-context-building)
Sebelum menilai kode baru/fitur, bangun peta dulu — jangan menilai dari
nama file:
- [ ] identifikasi entry point nyata (route, handler, command) dan siapa
      yang bisa mencapainya (anon? user? service?)
- [ ] petakan trust boundary yang dilintasi data (request -> DB -> render)
- [ ] catat asumsi framework (middleware, sanitasi bawaan) SEBELUM
      menyebut sesuatu rentan — asumsi keliru = laporan FP
- [ ] satu temuan tanpa peta konteks = SUSPECTED, bukan confirmed

## 2. Review diff C (dari tob/c-review) — checklist kelas kerentanan
- [ ] buffer: strcpy/strcat/sprintf tanpa bound; off-by-one di loop index
- [ ] format string: printf(var) tanpa format literal
- [ ] integer: cast signed/unsigned sebelum alloc (malloc(size) dgn size
      hasil perkalian tak dicek)
- [ ] use-after-free/double-free di jalur error (early return sebelum
      free/reset pointer)
- [ ] API berbahaya: gets, strcpy tanpa _s, system()
Catatan cyphron: repo fokus web/app — checklist ini dipakai hanya bila
menyentuh kode C nyata (core-rs Rust dikecualikan; gunakan rust-review
mental yang sama: unwrap/panic di jalur attacker-controlled, unsafe block).

## 3. Review PR (dari tob/review-pr, panel-review) — urutan hemat
- [ ] baca deskripsi PR -> klaim apa yang diubah? (klaim = target cek)
- [ ] stat dulu, baru per-file: file auth/crypto/secret =Prioritas
- [ ] baris TAMBAHAN saja di-pindai dulu (added lines), konteks belakangan
- [ ] untuk tiap temuan: alasan BUKAN FP ditulis eksplisit (jalur
      pencapaian + kondisi); tanpa itu -> simpan sebagai lead L0-L1
- [ ] panel: satu reviewer + satu pembantah (devil's advocate) lebih
      murah daripada lima reviewer sepakat

## 4. Triage issue/PR GitHub (dari tob/github-triage) — tanpa gh CLI
Cyphron tidak memasang gh CLI; protokol yang setara via REST API:
- [ ] cari dulu PR/issue duplikat sebelum menulis apa pun (anti-dup v2
      repo: tools/antidup_check.py + search API)
- [ ] niat author ("I'd like to add...") = JANGAN diambil
- [ ] CI wajib hijau sebelum dianggap selesai (check-runs API)

## 5. Sisi-waktu (dari tob/constant-time-analysis) — level sumber
- [ ] compare rahasia loop-per-byte -> pakai constant-time compare
- [ ] akses array yang diindeks rahasia (table lookup) = cache-timing
      lead; konfirmasi butuh asm/toolchain — catat needs-validation
- [ ] branch pada rahasia di jalur panjang = lead, bukan confirmed

## 6. Mutasi (dari tob/mutation-testing) — versi hemat
- [ ] sebelum menambah test: matikan satu cabang kondisi di kode target;
      kalau test tetap hijau, test itu tidak menguji cabang tsb.
- [ ] cukup operator: != <-> ==, true/false flip, boundary +/- 1
- [ ] di cyphron: suite 1584+ test — mutasi manual ini dipakai saat
      menambah test untuk tool baru (lihat pola test_fail_* di tests/)

## 7. Triage vuln (dari tob/vulnerability-triage-brocards) — SUDAH
diekstrak menjadi tools/brocards_triage.py; skill aslinya tinggal
referensi penjelasan tiap brocard.

## 8. Patch proof (dari tob/prove-patch) — SUDAH diekstrak menjadi
tools/patch_proof.py (three-arm proof).
