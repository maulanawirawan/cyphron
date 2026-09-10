# CYPHRON V2 — CYBER INTELLIGENCE ROADMAP

> Status: 2026-09-07. Sumber: diskusi strategis user + GPT (analisis cyphron-reports)
> + OpenAI Daybreak/Codex Security/Defense Factory sebagai referensi arsitektur.
> Prinsip: **skill count bukan moat. Yang menjadi moat: World Model + Planner adaptif +
> Hypothesis/Zero-Day Reasoner + Attack-Chain + Verifier + Defender loop.**

## Struktur target

```
CYPHRON CYBER INTELLIGENCE
├── Attacker Intelligence   (recon, web, api, auth/iam, bizlogic, attack-path, zero-day)
├── Defender Intelligence   (verifier, root-cause, patch, detection, regression, IR)
└── Core Reasoning          (world model, planner, hypothesis, evidence, risk, memory)
```

Empat kelas kemampuan: **DISCOVER → REASON → VALIDATE → DEFEND**

---

## FAZ 0 — FONDASI (SELESAI 2026-09-06/07) ✅

| Komponen | Status |
|---|---|
| 53 engine milik sendiri (stdlib murni) | ✅ LIVE |
| Authorization gate kode-enforced + audit hash-chain | ✅ LIVE |
| Verifier bukti-basis (confirmed ≠ unconfirmed) + truth guarantee (5 FP tertahan) | ✅ LIVE |
| Reporting PDF design system + DOCX + MD + Downloads | ✅ LIVE |
| Evidence-driven planner v1 (hypothesis gating: 19 engine di-gate bukti) | ✅ LIVE |
| World model v1 (endpoints, params, technologies, JWT detect, hypotheses trail) | ✅ LIVE |
| Finding taxonomy (exploitable/weakness/posture/surface) | ✅ LIVE |
| Multi-akun god mode (bola, priv_matrix) | ✅ LIVE |
| Fix/verify loop (`cyphron fix` + `cyphron verify`) | ✅ LIVE |

## FAZ 1 — WORLD MODEL / SECURITY KNOWLEDGE GRAPH (prioritas #1) — v1 ✅ 2026-09-07 (cyphron/graph.py: KnowledgeGraph + build_from_world + SQLite/JSON persist + queries; graph.db + graph.json di setiap folder laporan; section 10 di PDF)

Graaf state target yang jadi sumber keputusan semua agent. Perluasan dari WorldModel:
- [ ] **objects**: entitas bisnis yang teramati (user, order, invoice, file) + id pattern
- [ ] **identities**: anonymous / user-A / user-B / admin (+ sesi aktif per peran)
- [ ] **auth flows**: mekanisme login/logout/reset/OAuth yang teramati (dari auth_probe + crawler)
- [ ] **trust boundaries**: apa yang dipercaya (header, cookie, referer, X-Forwarded-*)
- [ ] **observations**: setiap respons anomali masuk graaf, bukan hanya notes
- [ ] **persistence**: SQLite graph tables + query API untuk planner
Acceptance: planner membuat keputusan HANYA dari graaf; graaf bisa di-dump JSON untuk inspeksi.

## FAZ 2 — ADAPTIVE PENTEST PLANNER v2 (prioritas #2) — v2 ✅ 2026-09-08 (deterministik; LLM slot tetap terbuka)

Sudah jalan: 19 engine di-gate bukti; hoplite 30 langkah vs target kaya 41 langkah
(bukti audit; tidak ada lagi urutan 40-tool identik lintas target).
- [x] **prioritas biaya/manfaat**: urutan langkah EV = impact×confidence/max(cost,1)
      descending, tie-break deterministik (tool, url, param) — dua world logis identik
      menghasilkan sekuens plan identik (2026-09-08)
- [x] **re-plan setelah setiap temuan**: observe_findings() dipanggil orchestrator tiap
      step ber-temuan; hipotesis reaktif H-react-* (params/deep/exploit) dibuka dan
      follow-up dieksekusi DALAM run yang sama; audit kind=hypothesis-opened +
      world.replan_events + tabel 03b di laporan (2026-09-08)
- [x] **budget allocation**: alokasi request per hipotesis proporsional impact×confidence
      (reserve minimum per ronde, hard-stop di budget, re-allokasi saat confidence berubah);
      ledger planner.budget_ledger() == world.budget_ledger, kolom Conf+Budget di
      tabel hipotesis laporan (2026-09-08)
- [ ] **LLM PLANNER SLOT** (R4): frontier model memilih hipotesis berikutnya dari graaf;
      deterministik tetap fallback bila LLM tidak tersedia (jangan pernah bergantung pada LLM untuk safety)
Acceptance: dua target berbeda menghasilkan plan berbeda yang dapat dijelaskan
(hipotesis → bukti → keputusan tercetak di laporan). — TERBUKTI produksi 2026-09-08:
aron 31 langkah / 0 re-plan (tidak ada primitive), airon 40 langkah / 2 re-plan
(H-react-exploit + H-react-params dari temuan HIGH exploitability step-6).

## FAZ 3 — HYPOTHESIS + ZERO-DAY RESEARCH ENGINE (prioritas #3) — v1 ✅ 2026-09-07 (cyphron/anomaly.py: ResponseBaseline anomaly + InvariantLibrary 3 invariant + zero_day_candidates feed -> hipotesis H-zd-* di planner)

Dari "observe unusual behavior → hypothesis → safe validation → reproduce → root cause".
- [ ] **invariant library**: invariant bisnis generik (A tidak boleh mentransisikan objek B;
      refunded tanpa fulfilled = mustahil; harga validasi ≠ harga settlement = mustahil)
- [ ] **anomaly detector**: respons yang menyimpang dari baseline kelasnya memicu hipotesis baru
- [ ] **safe validation constructor**: dari hipotesis → uji canary read-only (tanpa payload merusak)
- [ ] **zero-day mode (god tier)**: differential fuzzing semantik (bukan hanya payload acak) pada
      state transitions; reproduce-before-report tetap wajib
Acceptance: minimal 1 temuan "tanpa signature" (bukan CVE-match) terkonfirmasi di lab.

## FAZ 4 — ATTACK-CHAIN REASONER (prioritas #4) — v1 deterministik ✅ 2026-09-07

Output bukan "7 low 3 medium" tapi **ATTACK PATH #n**: langkah rantai dari temuan
terkonfirmasi → dampak, dengan confidence per rantai.
- [x] v1: chain composer deterministik dari temuan (mis. SPF+DMARC+lockout → phish→guess→ATO)
- [ ] v2: chain lintas-target (CT subdomain → aplikasi kedua → surface → bypass)
- [ ] v3: chain disusun LLM di atas graaf, tiap link diverifikasi engine (bukan LLM-none)

## FAZ 5 — EXPLOITABILITY VERIFIER + DEFENDER (prioritas #5)

- [x] finding_class taxonomy: exploitable / weakness / posture / surface (+ kolom laporan)
- [x] exploitability probe CSP->primitive (cyphron/tools/exploitability.py, business tier) + detection_rules_for (Sigma-lite) -> appendix SOC di laporan
- [ ] **exploitability probe**: temuan konfigurasi diuji "apakah ada jalur eksploit nyata?"
      (mis. CSP hilang → cari injection primitive; tanpa primitive = hardening recommendation)
- [ ] **root cause**: temuan → komponen penyebab (edge vs app vs config)
- [ ] **patch generation**: fix-pack otomatis per temuan (perluasan `cyphron fix`)
- [ ] **regression validator**: verify loop membuktikan fixed; laporan delta
- [ ] **detection generation**: dari temuan → log/SIEM rule untuk SOC

## FAZ 6 — PERSONA AGENTS (setelah FAZ 1-5)

Attacker / Defender persona sebagai orchestrator di atas reasoning core:
Threat Modeler (pra-scan, SaaS → tenant isolation prioritas), Business Logic Agent
(domain pack: e-commerce/fintech/SaaS/booking), Identity Reasoner (authorization matrix
otomatis WHO×WHAT×WHICH×STATE, tanda "?" = hipotesis riset), Detection Engineer, IR Agent.

## METRIC KEBERHASILAN V2

1. % langkah yang dipicu hipotesis terkonfirmasi (target > 80%)
2. Temuan exploitable terkonfirmasi per run (naik, tanpa FP)
3. Rantai serangan terkonfirmasi per run (dari 0)
4. waktu-temukan per temuan (turun)
5. tetap: 0 false positive yang lolos ke daftar temuan

## CATATAN JUJUR POSISI SAAT INI

Label yang benar hari ini: **autonomous web security assessment & pentest orchestration
engine** dengan fondasi produk (gate, audit, verifier). Menuju "AI Pentester Sejati"
lewat FAZ 1-5 — bukan dengan menambah jumlah probe.
