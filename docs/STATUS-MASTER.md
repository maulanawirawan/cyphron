# CYPHRON — STATUS MASTER (dokumen tunggal konsolidasi)

> Dikonsolidasikan: **2026-09-21** dari 9 dokumen yang sebelumnya berserakan
> (kini di docs/arsip/ dengan nama sesuai isi: PLAN-R1-R6-FASE-AWAL,
> PLAN-EXPLOIT-40-TUNTAS, PLAN-FULLPOWER-B1-B5-TUNTAS, PLAN-KB-GODTIER-TUNTAS,
> PLAN-UNITY-U1-U10-TUNTAS, PRINSIP-CAPABILITY-LEAN, GAP-MATRIX,
> AUDIT-2026-09-19 — peta lengkap di INDEX.md).
> Sumber kebenaran status = kode + suite (683 tests, hijau per 2026-09-21) +
> git log (commit timestamp).

## 0. Snapshot produk hari ini (2026-09-21)

| Komponen | Kondisi |
|---|---|
| Engine registry | **109 engine** terdaftar (semua tier-mapped, fail-closed) |
| Skill registry | 87 skill `.cyphron` + tier packs + KB (nuclei/NVD/EDB lokal) |
| Suite | **683 tests OK** (2 skipped) |
| Lisensi | tier basic/pro/business/god + HMAC sig + device binding + token |
| Trial | 30 token, report redacted, 7 hari, 1x/device |
| Web | landing + wizard minimal-klik (job runner, unduh PDF) |
| Audit internal | 3 batch tuntas (56+ temuan diperbaiki; dead code dipetakan) |

## 1. ROADMAP UTAMA (ROADMAP.md, dibuat ±13 Sep — status per item)

Legenda: [x] SELESAI · [~] SEBAGIAN · [ ] BELUM · [!] DISCONNECTED (ada, tapi belum tersambung CLI/alur)

**R1 Engine perluasan** — [x] SELESAI via jalur berbeda:
- Session/cookie jar + login flow → [x] `auth_login` + `sessions` ctx (grey-box)
- Form POST probing SQLi → [x] `sqli_probe` + `json_inj` (POST body didukung)
- NoSQL injection probe → [x] `nosqli_probe`
- SSRF probe → [x] `ssrf_oob` + `ssrf_chain`; open-redirect → [x] `redirect_probe`
- SSTI probe → [x] `ssti_rce`; CORS audit → [x] `cors` + `cors_wildcard_subdomain`
- TLS quick-check → [x] `tls_audit` + `tls_mismatch_leak`
- upload_probe (Skill 71) → [~] multipart ada di `traversal`/`wp_dataexp`; upload
  analyzer khusus BELUM sebagai engine terpisah
- proxy_trust_probe (Skill 69) → [x] `header_reflection_double` + `header_variant_matrix`
  (XFF/Original-URL spoof matrix)
- security_headers v2 (kualitas CSP) → [x] `csp_analyzer` terpisah + `exploitability`
- replay_probe assisted → [x] `blind.py` (replay) + `cyphron verify` (delta)
- R3 seed AP1-AP10 taksonomi chain → [x] `chaining.py` rule-based (compose) —
  AP-label legacy diganti chain_id rule

**R2 Skill atomik** — [ ] BELUM DIMULAI (skema {id,preconditions,...}, generator
prose→atomik, index SQLite FTS5). Prioritas: sedang. *Timestamp terakhir disentuh:
— (tidak ada commit).* Catatan: `skillgen.py` ADA tapi dedup-nya nondeterministik
(audit: perlu `sorted()` + cek lintas-pack).

**R3 Verifier/zero-FP lanjutan** — [x] SELESAI + MELEBIHI RENCANA:
- re-probe konfirmasi → [x] `blind.py` (blind reproducer L5) + `quorum`
- attack chain graph + skor dampak → [x] `chaining.py` + `graph.py` + PDF path graph
- dedup lintas-engine → [x] fingerprint + status-bucket deterministik (batch 2)

**R4 LLMPlanner slot** — [ ] BELUM (dengan sengaja: deterministik dulu; `llm_probe`
adalah probe target, bukan planner). Fallback deterministik = satu-satunya planner
hari ini. Prioritas: rendah sampai LLM slot diputuskan.

**R5 Ferments (pola sukses → skill atomik)** — [~] `.cyphron/ferments/` folder ada;
CLI `cyphron ferments list/promote` BELUM ada. Prioritas: rendah.

**R6 Lab & metrik** — [~] `../juice-shop` + fixture internal ada (`tests/fixtures`);
metric per engine + regression gate → [x] `benchmark.py` (CVE bench) + suite CI;
`docs/EVAL.md` → [ ] BELUM. Prioritas: sedang.

## 2. ROADMAP-EXPLOIT-40 (13 Sep) — [x] **TUNTAS 40/40** (4 batch commit:
1d3a88b critical, 297b244 high, 3ee5913 medium, 7d6e36a low; suite saat itu
385/385). Kini terintegrasi + tier-mapped. TIDAK ADA sisa.

## 3. ROADMAP-GODTIER-KNOWLEDGE (14 Sep) — [x] TUNTAS:
- [x] yamlite diperluas (parser block scalar, list same-indent, folded `>` —
  dipoles lagi 21 Sep: folding benar + parent indent key)
- [x] KB NVD (sqlite + feeds), Exploit-DB (edb_index), nuclei templates (bridge
  aman: matcher pasif, eksekusi subset berizin)
- [x] `cyphron kb` CLI sync eksplisit (nvd/edb/nuclei) + manifest
- Sisa catatan audit batch 3: KB sync error kini tercetak (tidak senyap).

## 4. ROADMAP-UNITY (14→18 Sep) — [x] **TUNTAS U1–U10** (brain/planner adaptif,
graph evidence, verdict ladder, bukti berantai, laporan terkendali). Polesan
lanjutan 21 Sep: verdict ladder kini DIENFORCE di `finalize` (bukan cuma label);
dedupe lintas-bucket deterministik.

## 5. ROADMAP-FULLPOWER-SHOWCASE (18 Sep) — [x] TUNTAS B1–B5:
- [x] B1 adapter + manifest eksternal; B2 deobf; B3 APK kit (androguard opsional);
  B4 proxy/intercept + IaC/SBOM; B5 CI + SAST + slop gate
- Polesan 21 Sep (batch audit): proxy 4xx asli diteruskan + body utuh + queue
  lifecycle benar; APK kit androguard guard jelas; SAST diff fail-closed.

## 6. ROADMAP-V2 CYBER INTELLIGENCE (07 Sep) — status per modul:
- [x] World model (endpoints/params/tech/notes) — ada
- [~] **objects/identities/auth flows/trust boundaries** sebagai entitas graaf →
  BELUM utuh (identity_matrix + auth_probe memakai konsep ini tapi belum
  dimodelkan sebagai node graaf)
- [x] persistence graph SQLite (`graph.db` per scan)
- [ ] **LLM planner slot** → belum (sengaja; lihat R4)
- [x] **anomaly detector** → `anomaly.py` (zero-day candidates FAZ 3; kegagalan
  kini tercatat, tidak senyap)
- [~] **invariant library** → `business_logic.py` (tabel legalitas IDENTITY×
  OBJECT×ACTION×STATE) — dasar ada, library invariant umum belum
- [~] **zero-day mode** → `deep_probe` + `fuzz_engine` + `variant_sweep`
  (diferensial semantik via varian encoding — baru tambah 21 Sep)
- [~] **exploitability probe** → [x] `exploitability.py` (FAZ5 verifier) — SELESAI
- [x] **root cause** → sebagian (classification + chain rationale)
- [x] **patch generation** → [x] `cyphron fix` (fix packs) + `remediate.py`
  (urutan prioritas dibenahi 21 Sep)
- [x] **regression validator** → [x] `cyphron verify` (delta fixed/open/new)
- [ ] **detection generation** → [~] `detection_rules_for()` (Sigma-lite text
  generator) ada; SIEM-rule lengkap + test coverage → BELUM
- [ ] **defender loop penuh** → belum (verifikasi + fix + delta sudah; loop
  otomatis periodik belum)

## 7. GAP-MATRIX (studi 818 skill komunitas) — ringkas:
- **ADA** (mayoritas): web core, injection family, auth/authz, recon/OSINT,
  mobile (APK), IaC/SBOM, SAST/SCA, perf, KB, reporting.
- **PARSIAL**: LLM/AI probing (`llm_probe` canary saja), cloud lanjutan (baru
  bucket probe), blockchain/IoT (privesc_scan dasar saja), SIEM/detection gen.
- **GAP** (belum ada): malware/RE penuh, network penting tingkat lanjut,
  wireless, fisik/social-engineering (by design — luar kode).
  Detail lengkap per subdomain tetap di GAP-MATRIX.md (arsip).

## 8. FITUR SUDAH DIIMPLEMENT 19–21 SEP (post-roadmap, terbaru → terlama)

| Tanggal | Fitur | Commit |
|---|---|---|
| 21 Sep (malam) | Batch 3 audit: sast fail-closed diff, yamlite folding benar, license exact-id (LGPL), planner error tercatat, reportslop code-block, crawl_depth tersambung sampai crawler, dll (18 file) | 94db9c9 |
| 21 Sep | Transparansi pihak ketiga: tag external 13 engine + restriction no_external_intel + section laporan | a9eb51d |
| 21 Sep | Wizard web minimal-klik: /api/scan job runner + unduh PDF | ab8489a |
| 21 Sep | Pricing token per tier/mode + trial redacted + lisensi HMAC + device binding + credit ledger + antibuse | (batch pricing) |
| 21 Sep | Red team variants pack: variant_sweep, method_override_matrix, header_variant_matrix | 48e1b5e |
| 21 Sep | Batch 2 audit: proxycore 4 bug, perf ramp, verdict determinism, ladder enforcement, coverage matrix, chains terpadu | a9da5b5 |
| 19 Sep | Batch 1 audit: bug mati (WorldModel import, knowledge_path, guard kredensial) + tekan mesin FP (sast/blind/WCD/dir_probe) | 450db96, 11dae30, 506fbf1 |
| 19 Sep | Audit pihak ketiga: 15 engine luar dipetakan (semua fitur sah, kini transparan) | d8ebc88 |

## 9. DEAD CODE / DISCONNECTED (audit AST 21-09-2026)

Skanner AST (definisi top-level dengan NOL referensi repo-wide). Kebijakan:
TIDAK dihapus sembarangan — dipilah:

### A. DISCONNECTED — fitur ada tapi belum tersambung alur (keputusan user):
- `tierpack2.build2()`, `tierpack3.build3()` — generator pack 2/3 tidak pernah
  dipanggil CLI (yang ekspos cuma `tierpack.build` + `build_bounty`).
  → Opsi: tambah argumen CLI `--pack 2|3` ATAU hapus.
- `god_report.build_with_quality_gate()` — gerbang kualitas GOD dibuat (batch
  U) tapi CLI `god-report` masih panggil `build()` tanpa gate.
  → Opsi: switch CLI ke build_with_quality_gate (perilaku laporan berubah).

### B. API SENGAJA (keep — dipakai di luar repo / server / masa depan):
- `verification.confirm_classic/confirm_timing` — protokol 3-gate, API stabil
  (semantik min_delay sudah diperjelas 21 Sep).
- `antibuse.pow_challenge/pow_solve` — sisi billing server (challenge signup).
- `pricing.plan_for/price_table/estimate_scan_cost` — API pricing (price_table
  dipakai CLI; sisanya kontrak modul).

### C. DEAD SUNGGUHAN (hapus kalau mau bersih — kecil, aman):
- `sast._spec` (helper builder tanpa pemanggil)
- `languages._sink_rows` (duplikat logic yang sudah pindah ke sast)
- `payloads.by_severity` (tak pernah dipakai)
- `fleet.queue_file_roundtrip` + `fleet.run_fleet` (konsep multi-mesin belum
  jadi produk; jangan hapus kalau masih direncanakan — catat saja)

### D. BUKAN KODE KITA (jangan disentuh):
- `kb/data/nuclei/.github/scripts/*` — skrip upstream vendor (data KB).

## 10. ANTRIAN AKTUAL (belum, urutan saran)

1. **[KEPUTUSAN USER]** Sambungkan atau hapus item 9.A (tierpack2/3 + quality gate).
2. **Verdict enforcement lanjutan**: pusatkan label LEAD di laporan (saat ini
   bucket sudah benar; label per-temuan ladder tampil di PDF detail).
3. **V2 objects/identities/trust-boundaries sebagai node graaf** (butuh desain).
4. **detection generation** penuh (Sigma/SIEM rule + fixture test).
5. **Skill atomik R2 + ferments CLI** (R5).
6. **docs/EVAL.md** + metric per engine terhadap fixture.
7. Kosmetik: pdfout meta multi-baris + guard overflow baris tabel (layout PDF).
8. Sisa grep "TODO/FIXME" repo — belum diinventarisasi penuh.

---
*Dokumen ini satu-satunya sumber status ke depannya. Dokumen lama = arsip.*
