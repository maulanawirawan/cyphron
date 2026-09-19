# ROADMAP-UNITY — Cyphron satu kesatuan utuh: brain, graph, verdict, bukti [TUNTAS]

> Status: EKSEKUSI TUNTAS 18 Sep 2026 — batch U1-U10 selesai dengan suite
> hijau per batch. Dibuat 14 Sep, difinalisasi 16 Sep dengan mapping jujur
> ke kode existing.
> Prinsip tetap: zero-FP, deterministic-verifiable, guardrail tanpa kompromi,
> tanpa narasi provenance eksternal di seluruh codebase.
> tanpa narasi provenance eksternal di seluruh codebase.

## 0. TESIS
Cyphron punya "otot" (127 engine + KB dunia). Yang menentukan kelas global
bukan jumlah otot melainkan: **brain + chaining + independent validation +
safety + coverage enterprise** — dan "DDoS" tidak masuk daftar (skill paling
bawah, tidak bisa dijual legal). Uji ketersediaan = Cyphron Resilience
(bounded, berotorisasi — lihat Fullpower §2d).

## 1. MAPPING JUJUR: analisis eksternal vs kode nyata
> Analisis eksternal menilai dari tabel; koreksi kami setelah baca kode.

| Rekomendasi analisis | Status nyata di Cyphron | Gap sebenarnya |
|---|---|---|
| "Semua observation masuk satu world state" | **ADA** — `WorldModel` (technologies, endpoints, params, findings_seen, replan_events, budget_ledger); semua engine menulis ke situ | Masih flat-dict; belum GRAPH berelasi (Asset→Host→Service→App→Endpoint→Identity→Role→Object→Vuln→Evidence) |
| "Autonomous Planner + Re-planner" | **ADA** — `DeterministicPlanner` v0.4 FAZ 2 adaptive: observe_findings → confidence hypothesis → re-plan per step | Reaktiv per-hypothesis; belum reasoning di atas graph ("saya sampai sini lewat apa → eksploit berikutnya") |
| "Independent Validator (bukan self-judge)" | **ADA** — `quorum.py`: TIGA validator rule-based deterministik (runtime-evidence, provenance, impact) → CONFIRMED/PROBABLE/INCONCLUSIVE/REJECTED | Belum BLIND re-production: validator diberi claim+tanpa reasoning awal, membuktikan ulang sendiri secara aman |
| "Attack Chaining" | **ADA** — `chaining.py` Attack Chain Composer (impact gabungan, bukan per-temuan) + Evidence Ledger hash-chain per finding | Belum attack path LINTAS-identity berbasis graph (anonymous→user→org→admin) |
| "Scope & Safety Kernel" | **ADA & KUAT** — `guardrails/authorization.py` (gate per-request, scope/expiry/refusal), audit tamper-evident, kill switch, request budget, redaksi otomatis | Tinggal dipertahankan; jadikan kontrak formal semua bahasa (polyglot adapter wajib lewat sini) |
| "Retest/verified-fixed lifecycle" | **ADA** — `verify` (scan ulang → fixed/still/new), `drift`, `remediate` (fix packs) | Naikkan ke level file/function + auto-attach ke laporan |
| "Browser-Native Agent" | **PARSIAL** — `browser_engine.py` (dump-dom passive) + **CDP capability terbukti di kasus kamipex** (decoder/sandbox/network capture — masih script temp) | Formalisasi CDP jadi engine `browser_scout`: interaktif (klik, form, OAuth/MFA guarded, SPA, localStorage, WS), relasi UserAction→DOM→Request→API→Object→Authz |
| "Business Logic Reasoning" | **BARU** — belum ada | IDENTIty×OBJECT×ACTION×STATE; illegal transition (refund ganda, CANCELLED→APPROVED, coupon reuse, harga pasca-approval) |
| "Multi-Identity / Identity Matrix" | **PARSIAL** — priv_matrix/bola/authz_bypass/idor_mass + orchestrator multi-session (`--accounts`) | Engine matrix: expected-behavior model + deteksi deviasi antar identity (tabel Anonymous/A/B/Staff/Admin × CRUD/Invite/Approve) |
| "API Semantic Mapper" | **BARU** | OpenAPI/observed endpoints → semantik objek+aksi → input graph & business-logic agent |
| "Adaptive Path Discovery" | **PARSIAL** — dir_probe statis (53 path), crawler, js sweep, wayback | Kandidat path kontekstual: fingerprint framework, robots, sitemap, JS, sourcemap, historical, OpenAPI, konvensi routing |
| "Adaptive payload generation" | **PARSIAL** — payloads.py + exploitability.py | Generasi payload situasional berbasis graph/response |
| Cloud/IAM/AD/K8s | **BARU (P2)** | AWS/Azure/GCP/Entra/AD/K8s/IAM/CI-CD — setelah Web+API+Mobile matang |
| Mobile glow-up | **PARSIAL** — apk_surface_probe (MobSF-lite) | Lihat Fullpower §2a: APK→API correlation, deeplink, runtime |

## 2. ARSITEKTUR TARGET (lapisan brain)
```
MISSION/SCOPE (auth doc -> gate; TIDAK berubah)
      |
CYPHRON BRAIN  (deterministic core + opsional LLM-advisor yang TIDAK memegang kendali)
      |-- planner v5: graph-aware, memilih aksi berikutnya dari path yang belum
      |   dieksplorasi (bukan hanya hypothesis ledger)
      |-- OBSERVE -> GRAPH (evidence graph tunggal, schema di bawah)
      |-- VALIDATE -> quorum + BLIND re-producer (level 4: Deterministically Verified)
      `-- DECIDE -> continue/escalate/stop (cease-on-data, budget, safety)
```
Graph schema (node+edge, stdlib; export JSON/dot):
Asset→Host→Service→Application→{Endpoint, Identity, Role, Object, Credential,
Vulnerability, Evidence}; edge = relasi + provenance ("dicapai via X",
"membutuhkan credential Y"). Setiap temuan WAJIB punya path node di graph —
inilah jawaban "saya sampai di sini melalui apa".

## 3. VERDICT LADDER (deterministik sampai ujung — permintaan inti user)
```
0 OBSERVED   -> sinyal mentah (indikasi, BUKAN klaim)
1 SUSPECTED  -> pola cocok + konteks (masih bukan klaim)
2 REPRODUCED -> respons diferensial konsisten (A/B + kontrol)
3 DETERMINISTICALLY VERIFIED -> bukti aritmetika/marker unik/OOB-timestamp
4 IMPACT VERIFIED -> dampak minimal terbukti (data terbatas, tersaksi)
5 BLIND-VALIDATED -> validator independen reproduksi ulang dari claim saja
X REJECTED / FALSE-POSITIVE -> dicatat + jadi rule anti-FP baru
```
Aturan: laporan klien hanya menerima level >=3 sebagai temuan; 0-2 = LEAD
(dilabel jelas). Tidak ada temuan "setengah jalan".

## 4. KLAIM & BENCHMARK (hasil analisis pasar)
- Ganti bahasa klaim CVE: **"High-confidence deterministic CVE matching with
  ambiguity rejection"** (bukan "zero-FP"; menolak ambigu menaikkan precision,
  bisa menurunkan recall — jujur soal ini).
- Benchmark wajib (fixture + dataset): Precision/Recall/F1, FP-rate, FN-rate,
  CPE-resolution accuracy, version-resolution accuracy, exploit-validation
  rate; hasil dicantumkan di docs + laporan (angka, bukan slogan).
- Marketing: JANGAN jual angka ("53 paths", "40 engines") — jual kemampuan
  komposisi & verdict ladder. (Masuk juga Fullpower CI-6.)

## 5. GOLDEN DEMO (definisi selesai yang bisa ditunjukkan ke lead)
Anonymous -> petakan app -> temukan registrasi -> buat identitas uji
BERIZIN -> bangun graph -> deteksi inkonsistensi authz antar 2 identitas ->
susun attack path -> minimum-impact proof -> blind validator reproduksi ->
CEASE (berhenti) -> root cause + remediasi -> developer fix -> RETEST ->
**VERIFIED FIXED**. Repeatable, evidence-backed, aman, otonom.
Target demo venue: lab lokal (Dockers vulnerable-app milik sendiri) — BUKAN
aset pihak ketiga.

## 6. WORKSTREAM & BATCH
- [x] U1 Evidence Graph v2 (graph.py: ROLE/OBJECT/CREDENTIAL/VULNERABILITY/
      EVIDENCE + EXPOSES/TARGETS/REACHED_VIA/ACCESSES/VERIFIED_BY +
      attack_paths + provenance) + verdicts.py (tangga 0-5/REJECTED) + 10 test — SELESAI
- [x] U8 Sweep narasi eksternal repo-wide (kode/docs/README) — SELESAI
- [x] U2 Planner v5 graph-aware + ADAPTIVE ESCALATION MODE (probe -> pelajari
      pola -> eskalasi ofensif terukur; LLM hanya advisor opsional) — SELESAI:
      planner/orchestrator mengonsumsi escalation_plan(graph): fase PROBE->
      PATTERN->ESCALATE->PROVE tercatat di world note + ScanSummary.escalation,
      unlocked_engines dijadwalkan sebagai step H-escalate (dedup `_once`,
      sekali per pola, budget-aware, fail-closed tanpa otorisasi offensive)
      [UPGRADE]
- [x] U3 Blind re-producer (verdict level 5: validator independen
      mereproduksi dari claim saja) — SELESAI (Unity batch 2: blind.py,
      GET-only, marker+status, evidence "blind" -> BLIND_VALIDATED)
      [UPGRADE]
- [ ] U4 browser_scout engine (formalisasi CDP) + SPA/OAuth guarded [PARSIAL]
- [x] U5 Identity Matrix + Business Logic agent (IDENTITY x OBJECT x ACTION
      x STATE: illegal transition) + API semantic mapper — SEBAGIAN SELESAI:
      engine identity_matrix (expected-behavior anonymous/A/B, deviasi
      differential GET-only, satu temuan per endpoint, zero-FP) + engine
      business_logic (tabel legalitas order/refund/coupon/account/approval,
      illegal transition + repeated-terminal, rekaman tunggal = LEAD,
      rekaman ganda = weakness terkonfirmasi, nol request state-changing);
      API semantic mapper menyusul [BARU]
- [x] U6 Adaptive path/payload + benchmark suite (Precision/Recall/F1, CPE &
      version resolution accuracy) + claim language — SEBAGIAN SELESAI:
      cyphron/benchmark.py (metrik murni + runner pipeline nyata atas dataset
      gold + render markdown) + CLI `python -m cyphron benchmark` +
      docs/BENCHMARK.md + sweep bahasa klaim di README/landing/god_report/
      reporting (test anti-klaim-terlarang); adaptive path/payload menyusul
      [CAMPURAN]
- [x] U7 PDF god-tier sempurna (template brandable, exec summary, path graph
      visual, tak setengah jalan) — SELESAI: halaman cover penuh brandable,
      verdict ladder visual LEAD vs TEMUAN (chip L0-L5 di tiap kartu temuan),
      ringkasan CVSS per severity, path graph vektor (PDF) + artifact
      graph.svg (graph.to_svg) dari temuan+world — sumber tunggal findings +
      world model [UPGRADE]
- [x] U9 RED-TEAM WORKSTREAM: katalog tradecraft berotorisasi (initial-access
      demo, C2-simulation lab, persistence-matrix, privesc playbook,
      lateral-movement), tag MITRE-lite per engine (coverage matriks),
      deteksi-hint per temuan (nilai jual tim biru) — SEBAGIAN SELESAI:
      cyphron/redteam.py (tabel MITRE-lite ~110 engine + fallback heuristik,
      coverage matrix fase x engine dengan gap jujur, deteksi-hint per
      temuan, engagement report + checklist pembersihan) + CLI
      `python -m cyphron redteam --from DIR`; katalog tradecraft lab
      (C2-simulation dsb.) — SELESAI PENUH 19 Sep: redteam_lab.py
      (RTL-01..12, c2-sim loopback berotorisasi, privesc read-only,
      detection coverage purple-team) [BARU]
- [x] U10 PRODUK/OPS: ownership proof (DNS TXT/well-known sebelum mode
      ofensif diterima), usage ledger per scan, safe-update script,
      landing v2 + demo 5 menit — SEBAGIAN SELESAI: cyphron/ownership.py
      (token deterministik dari dokumen otorisasi; kanal DNS TXT via DoH +
      well-known; fail-closed turun read-only; CLI `own`), cyphron/ledger.py
      (usage-ledger.jsonl per scan + agregasi), scripts/safe-update.sh
      (gerbang suite dua kali + rollback otomatis), landing v2 (verdict
      ladder + benchmark + KB section); demo 5 menit menyusul di B5 [BARU]
- P2 (belakangan): Cloud/IAM/AD/K8s, mobile runtime penuh.

## 7. PAGAR
Semua tetap: authorization gate per aksi, rate-limit, cease-on-data, redaksi,
budget, audit tamper-evident; golden demo hanya di lab sendiri; tanpa modul
DDoS (resilience = bounded & berotorisasi); tanpa menyebut sumber inspirasi
eksternal di narasi produk (prinsip user).