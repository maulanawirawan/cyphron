# PROMPT SKILL HARVEST — Panen skill baru dari project AI sebelah

> **Alur final (disepakati):** paste **PROMPT A** ke project AI sebelah → salin jawabannya → **paste jawabannya langsung ke roomchat tempat agent Cyphron bekerja** (room ini). PROMPT B tidak perlu diketik ulang — prosedurnya sudah jadi pegangan agent (file ini + BRIEFING-CYPHRON.md), agent langsung eksekusi langkah 3–5 PROMPT B begitu hasil ditempel. Kalau hasil A kurang lengkap, pakai **PROMPT C** di project sebelah.

---

## PROMPT A — untuk project AI sebelah (minta inventaris test)

```text
Kamu adalah Security Test Archivist untuk project ini.

TUGAS: Enumerasikan SEMUA test keamanan/pentest yang pernah DILAKUKAN, DIPELAJARI,
atau DIUSULKAN dalam project/konteks ini — termasuk yang tidak persis bernama
"pentest" (vulnerability assessment, hardening check, secure code review, SAST/DAST,
config audit, dsb). Usahakan lengkap, urut dari yang paling penting/most used.

ATURAN JUJUR: tandai status tiap test —
[DILAKUKAN] = benar-benar dieksekusi · [DIPELAJARI] = hanya dibahas/diuji konsep ·
[DIUSULKAN] = pernah disebut sebagai rencana. JANGAN mengarang; kalau ragu, tulis
[PERLU KONFIRMASI: apa yang kurang].

Untuk SETIAP test, keluarkan kartu dengan format persis ini:

### [NOMOR] Nama Test (alias umum)
- Status: DILAKUKAN | DIPELAJARI | DIUSULKAN
- Kategori: recon | scanning | exploitation | post-exploit | detection | hardening | compliance | lainnya
- Target type: web | api | mobile | network | cloud | repo-cicd | ai-llm | database | lainnya
- Mapping: CWE-xxx / OWASP A0x / CVE (tulis "—" jika murni prosedur)
- Metodologi: langkah bernomor yang bisa dieksekusi ulang
- Payload/indikator: contoh GENERIK & tersanitasi (tanpa target nyata)
- Bukti keberhasilan: apa yang muncul kalau test berhasil (request/response? log? file berubah?)
- Tool/perintah yang dipakai: nama tool + parameter penting
- Prasyarat & otorisasi: apa yang harus siap sebelum test boleh jalan
- Remediasi: cara memperbaiki jika temuan terjadi
- Sudut pertahanan: cara mendeteksi/mencegah serangan ini

DI AKHIR, keluarkan blok JSON ringkas untuk pemrosesan mesin:
{"tests":[{"nama":"...","status":"...","kategori":"...","target":"...","cwe":"...","owasp":"...","ringkasan_metodologi":"...","bukti":"...","tool":["..."]}]}

Mulai sekarang. Jika konteks project ini tidak menyebut satu test pun, katakan
jujur dan tanyakan area mana yang ingin direkonstruksi.
```

---

## PROMPT C — follow-up (kalau kartu dari PROMPT A belum lengkap)

```text
Untuk setiap test yang kartunya belum lengkap, jawab 8 pertanyaan ini satu per satu:
1. Nama teknis + alias umumnya apa? (biar bisa dicocokkan ke standar)
2. Kelas kerentanan/prosedur apa, dan mapping CWE/OWASP-nya?
3. Langkah eksekusinya apa (berurutan, bisa diulang orang lain)?
4. Payload/indikator generiknya apa (tersanitasi, tanpa target nyata)?
5. Bukti apa yang dihasilkan kalau test BERHASIL vs GAGAL?
6. Tool/perintah apa yang dipakai (nama + parameter penting)?
7. Prasyarat & otorisasi apa yang dibutuhkan sebelum test ini sah dijalankan?
8. Kalau temuan terjadi: remediasinya apa, dan bagaimana cara mendeteksinya dari sisi pertahanan?
```

---

## PROMPT B — untuk agent di project Cyphron ini (harmonisasi + tambah skill)

```text
Tugasmu: mengharmonisasikan hasil inventaris test dari project AI lain ke dalam
project Cyphron (knowledge pack .kimchi + runtime cyphron). Kerjakan berurutan,
jangan lewati satu langkah pun, jangan spawn sub-agent.

1) BACA STANDAR LOKAL DULU (jangan berasumsi):
   - training/.kimchi/agent-config.yaml          -> registry 65 skill (id, name, triggers, priority, mode)
   - training/.kimchi/skills/                    -> judul + WHEN TO ACTIVATE tiap skill
   - training/.kimchi/pentest/offensive-skills.md-> katalog offensive + tool
   - training/cyphron/docs/ROADMAP.md            -> engine & skill atomik yang direncanakan
   - training/cyphron/cyphron/tools/             -> engine yang SUDAH ADA
   - training/cyphron/cyphron/guardrails/authorization.py -> capabilitas gate

2) MASUKAN — hasil kartu test dari project sebelah:
   [TEMPEL HASIL PROMPT A DI SINI]

3) KLASIFIKASI setiap test ke salah satu (pakai SEMANTIK, bukan nama persis —
   "test IDOR" dianggap dekat ke skill 06/16 meski kata "IDOR" tak tertulis):
   - SUDAH TERCAKUP     -> sebut id skill .kimchi + kutip alasannya (WHEN TO ACTIVATE/METHODOLOGY)
   - SEBAGIAN TERCAKUP  -> sebut skill id + celah spesifik yang belum dijelaskan
   - SKILL BARU         -> lanjut langkah 4

4) UNTUK SETIAP SKILL BARU:
   a. Buat file .kimchi/skills/NN-nama.md (NN = nomor berikutnya, mulai 66) dengan
      format WAJIB sama seperti skill lama: Title -> Description -> WHEN TO ACTIVATE
      -> METHODOLOGY -> Secure Patterns -> Audit Checklist.
   b. Framing wajib: defensive + authorized-offensive (patuhi guardrails/ethics-boundary.md).
      Payload generik/tersanitasi. TANPA target nyata. TANPA weaponization.
   c. Daftarkan ke .kimchi/agent-config.yaml (id, name, file, triggers, priority, mode).
   d. Jika sifatnya offensive: tambahkan ke .kimchi/pentest/offensive-skills.md
      (katalog + guardrail) DAN petakan tool-nya. Tool pihak ketiga TIDAK BOLEH
      dijanjikan — kalau butuh engine baru, tambahkan baris di ROADMAP Fase R1 dengan
      catatan estimasi implementasi stdlib-only.
   e. Jika bisa dipetakan ke engine Cyphron Core yang ada (sqli_probe, xss_probe,
      dir_probe, secret_scan, crawler, security_headers, http_probe): tulis mapping
      allowed_tools + source_skill-nya.
   f. Tambahkan minimal 1 eval case untuk Fase R6 (target: lab fixture/juice-shop).

5) LAPORAN AKHIR (tampilkan, lalu BERHENTI tunggu approvalku):
   - Tabel: Test | Keputusan | Skill id/bukti | File dibuat/diubah
   - Daftar file yang berubah + ringkasan diff
   - Data yang masih kurang dari project sebelah (kalau ada)

ATURAN KERAS: jangan ubah isi 65 skill lama; jangan install apa pun; runtime tetap
stdlib-only; gate otorisasi tidak boleh dilewati; skill baru TIDAK AKTIF untuk
testing sebelum kuberi dokumen otorisasi yang sah.
```

---

## Checklist hasil yang sehat (cara menilai output PROMPT A sebelum dipakai)

- [ ] Ada blok JSON `{"tests":[...]}` di akhir — wajib, ini yang diproses mesin
- [ ] Tiap test punya status jujur (DILAKUKAN/DIPELAJARI/DIUSULKAN)
- [ ] Mapping CWE/OWASP terisi atau "—" (bukan dikarang)
- [ ] Metodologi bisa dieksekusi ulang orang lain tanpa bertanya
- [ ] Bukti keberhasilan konkret (bukan "berhasil" doang)
- [ ] Tidak ada payload yang menyasar target nyata

---

## PROMPT C2 — follow-up SPESIFIK batch #1 (30 test sudah diterima 2026-09-03)

> Status klasifikasi Cyphron: 13 sudah tercakup · 14 bahan 8 skill baru (66-73) · 3 parkir.
> Data yang masih bolong dikumpulkan lewat prompt ini. ATURAN: hanya minta data yang sudah ada, larang eksekusi test baru.

```text
Arsip 30 test-mu sudah diterima dan bagus. Sekarang PULASKAN DATA berikut.
ATURAN KERAS: JANGAN mengeksekusi test baru, jangan membuat/memperbaiki apa pun.
Yang kuminta hanya data/catatan yang SUDAH ADA di konteksmu. Kalau tidak ada,
tulis "TIDAK ADA" lalu lanjut. Jangan mengarang.

A — PERBAIKAN STATUS (wajib dijawab):
1. Test #28 (SAST custom-rule engine eksternal): JSON-mu bilang DILAKUKAN tapi catatannya
   bilang "never recorded as run". Mana yang benar? Kalau belum pernah jalan,
   nyatakan status finalnya DIUSULKAN.
2. Test #17 (Local ZAP baseline): tanggal pelaksanaan + di mana laporan/alert-nya disimpan?
3. Test #18 (Authenticated route baseline 41 routes): di mana lokasi script automation-nya,
   role apa saja yang dipakai untuk login, dan daftar 41 route itu tersimpan di mana?

B — LENGKAPI DATA test yang memang DILAKUKAN (ini bahan skill baru di project lain).
   Untuk setiap nomor di bawah, tambahkan juga 4 field kartu yang belum ada di
   JSON-mu: (a) payload/indikator generik tersanitasi, (b) prasyarat & otorisasi,
   (c) remediasi jika temuan terjadi, (d) sudut pertahanan/deteksi.
4. #2 Route authorization matrix: lokasi + format daftar 103 route (inventory-nya
   disimpan di mana?) dan bagaimana caller model diklasifikasikan.
5. #3 Cross-tenant isolation: sebutkan daftar skenario boundary yang dites
   (tenant A mencoba akses apa saja ke tenant B — 15 skenario itu apa saja).
6. #5 Idempotency & replay: window/TTL Idempotency-Key-nya berapa, disimpan di
   mana (DB unique constraint? Redis?), dan contoh request replay-nya.
7. #6 Trusted-proxy / IP spoof: urutan semantik header yang dites (right-to-left
   walk) + contoh forged XFF chain yang dipakai + perilaku saat TRUSTED_PROXIES kosong.
8. #7 SSRF validation corpus: berapa jumlah entri, kategori apa saja, contoh 5 URL
   paling representatif (loopback/private/metadata/credential), dan alasan kebijakan
   redirect manual.
9. #20 CSP nonce/hash migration (H14): desainnya — nonce digenerate di mana,
   directive apa yang berubah, apa regresi yang direncanakan.
10. #21 Reverse proxy / origin trust: daftar forged chain yang diuji
    (X-Forwarded-For / X-Forwarded-Host / X-Real-IP dst) + apa definisi konfigurasi
    nginx "yang benar" menurut catatanmu.
11. #29 Attack-path chain AP1-AP10: tempel teks lengkap tabel skenarionya
    (chain + test terkait + owner) dari plan §4.

C — YANG BERSTATUS DIUSULKAN/DIPELAJARI: TIDAK PERLU DILAKUKAN, jangan mulai apa pun.
    Hanya jika catatan/desainnya SUDAH ADA, tempel ringkasnya; kalau tidak ada,
    tulis "BELUM ADA" dan biarkan:
12. #8 (DNS rebinding), #23 (payment/order abuse replay), #25 (resilience),
    #30 (media matrix), dan teks tabel #29 kalau memang sudah tertulis.

FORMAT: jawab per nomor (1-12), ringkas tapi utuh. Daftar panjang (route, tabel AP)
tempel apa adanya — jangan diringkas sampai hilang detailnya.
```

### Peta pemakaian datanya (untuk agent Cyphron)
- Jawaban 1-3 → memperbaiki status arsip (mengubah klasifikasi #28 bila perlu)
- Jawaban 4,5 (+#18) → isi skill **66** Authorization Coverage Testing
- Jawaban B #4/#5 (webhook), 6 → isi skill **67** Webhook & Callback Trust
- Jawaban 8 → isi skill **68** SSRF Ingestion (+ engine `ssrf_probe` R1)
- Jawaban 7, 10 → isi skill **69** Proxy & Origin Trust (+ engine `proxy_trust_probe` R1)
- Jawaban 9 → isi skill **72** CSP Engineering (+ upgrade `security_headers` v2)
- Jawaban 11 (+12 bila ada) → isi skill **73** Attack Path Chain (+70/71 dari desain bila ada)
- Test #23/#30 tetap jadi skill 70/71 walau DIUSULKAN — metodologinya bisa ditulis dari
  desain yang ada; bagian "hanya jika sudah ada" dipatuhi.

---

## HASIL BATCH #1 — SELESAI (2026-09-03)

**30 test → 73 skill total.** Eksekusi final:

| Output | Detail |
|---|---|
| 8 skill baru ditulis | `skills/66-authorization-coverage-testing.md` … `skills/73-attack-path-chain-modeling.md` (format lama persis) |
| agent-config.yaml | 66–73 terdaftar (triggers, priority 1–3, mode defensive) — registry termuat 73/73 |
| offensive-skills.md | §6 "Application-Layer Specialized Testing" ditambahkan (mapping tool + guardrail + honesty note) |
| ROADMAP R1 | +3 engine stdlib (`ssrf_probe`, `proxy_trust_probe`, `upload_probe`) + `security_headers` v2 (CSP) + 2 assisted modes (`replay_probe`, `route_inventory`) + seed AP1–AP10 untuk R3 |
| R6 | 8 eval case dipetakan per skill |
| Test suite | 23/23 pass (termasuk 2 test baru: pack=73 + retrieval skill 67/68) |

**Koreksi klasifikasi dari follow-up:**
- #28 SAST engine eksternal → **DIUSULKAN final** (kartu memang sudah menulis itu; field `bukti` JSON-nya adalah success_criteria, bukan evidence)
- #17 ZAP baseline → DILAKUKAN tapi tanpa tanggal/lokasi laporan (disimpan di luar Git per plan §14) — tercatat sebagai evidence lemah
- #18 route baseline 41 routes → klaim ledger tanpa artefak reproducible (script/daftar route tidak ditemukan; `automation/` ternyata milik local companion Tokopedia/Facebook)
- Aturan honesty baru: field `bukti` untuk item DIUSULKAN = `success_criteria` — selalu ditandai demikian di skill 69/70/71/72

**Skill yang diisi data konkret:** 66 (103-route matrix + 15 skenario tenant + marker guard), 67 (digest tenant-scoped SHA-256, insert-first reservation, 9-callback matrix), 68 (kategori validator + 5 URL korpus + alasan redirect manual), 69 (semantik resolveClientIp + forged chain table + kontrak overwrite nginx), 70 (matriks 9 abuse + kontrol terverifikasi source), 71 (matriks media + magic bytes), 72 (CSP verbatim + desain nonce-at-proxy + report-only rollout), 73 (tabel AP1–AP10 verbatim).
