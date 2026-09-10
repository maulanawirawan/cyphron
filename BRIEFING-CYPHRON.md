# BRIEFING PEGANGAN — Bedah Hoplite vs Cyphron (training)

> ## 🔄 PERINTAH BERJALAN (standing order — TIDAK perlu user mengetik apa-apa)
> **Setiap sesi baru: langsung kerjakan BATCH BERIKUTNYA dari slot [ROADMAP] di
> `skills-tiers2/INDEX.md` + `skills-tiers3/INDEX.md` (urut: batch 3 dulu, lalu 4, 5, ...).**
> 5–10 slot per sesi, tiap slot: engine + FP-guard + unit test + bukti live, lalu tandai
> LIVE di INDEX dan hapus dari daftar. Setelah selesai: laporan singkat ke user.
> Jangan tanya izin — user sudah memberi izin penuh ("SAYA GA HARUS NGETIK NGETIK").
> Batch yang sudah AKTIF (LIVE): sourcemap_probe (b1), header_policy + ws_probe (b2),
> **batch 3-7 (2026-09-06): +38 slot — lihat ADDENDUM 19-20. skills-tiers2 kini
> 70 LIVE / 50 ROADMAP; sisa mayoritas butuh alur khusus (JWT-chain, OTP/2FA,
> k8s/imds cloud, webshell) atau skill proses (tiers3). Total engine 53.**

> ## ⚡ STATUS TERVERIFIKASI (baca ini dulu — Addendum 1-18 di bawah sebagian sudah terlampaui)
>
> **LOKASI 355 SKILL FILE (semua ada, terverifikasi):**
> - `.kimchi/skills/` = **74** skill inti | `.kimchi/skills-tiers/` = **101** (100+INDEX)
> - `.kimchi/skills-tiers2/` = **121** (120+INDEX) | `.kimchi/skills-tiers3/` = **41** (40+INDEX)
> - `.kimchi/skills-gen/` = **18** hasil generator dedup
>
> **SCRIPT YANG MEMBUKTIKAN = 19 engine di `training/cyphron/cyphron/tools/`:**
> auth_probe, browser_engine, code_audit, crawler, deep_probe, dir_probe, email_probe,
> fuzz_engine (zero-day hunt), http_engine, http_probe, load_probe, method_audit,
> redirect_probe, sca_probe, secret_scan, security_headers, session_probe, sqli_probe,
> template_probe, tls_audit, xss_probe — + runtime inti (licensing, verification 3-gate,
> impact, tierpack 1-3, skillgen, reporting PDF/DOCX/MD, store SQLite, CLI).
>
> **YANG TERBUKTI KERJA (ada bukti eksekusi nyata):** 23/23 tests, scan grey-box login
> sukses di airon.astheron.my.id, tier-gate license REFUSED ter-audit, impact probe
> (3 PROVEN/1 HARDENING/2 CONDITIONS), laporan PDF/DOCX/MD di Downloads.
>
> **YANG MASIH DESAIN (jangan dikira jadi):** 88+ slot ROADMAP di skills-tiers2/3
> (bertanda [ROADMAP] di INDEX) — wajib lewat pipeline test+FP-guard dulu.
> Dashboard UI shell belum dibuat (enforcement-nya sudah di engine).
>
> **PENAPISAN:** Addendum 1-9 = fase awal (sebagian sudah terlampaui oleh 10-18).
> Baca berurutan kalau butuh konteks; angka terkini yang dipercaya = Addendum 16-18.

> **Untuk siapa:** Agent (ZCode/Claude Code) yang nanti menyempurnakan timeline "Cyphron → AI Pentester Sejati".
> **Status riset:** Selesai. Semua klaim di bawah diverifikasi langsung dari kode sumber di `D:\GODMODE\Hoplite` dan `D:\GODMODE\training` pada 2026-09-03. TIDAK ada timeline yang dikerjakan — dokumen ini hanya pegangan.
> **Aturan main user:** jangan spawn banyak sub-agent (limit concurrency akun), kerjakan satu per satu sendiri.

---

## 0. TL;DR — Jawaban Pertanyaan Kunci User

1. **Apakah Hoplite bisa berdiri sendiri tanpa tool security terkenal?** **TIDAK.** Hoplite punya **nol kemampuan deteksi/eksploitasi sendiri**. Enam mesin intinya semua milik pihak ketiga: Opengrep, OSV-Scanner, OWASP ZAP, Nuclei, K6, dan Strix. Kode Hoplite sendiri hanya orkestrasi (queue, UI, normalisasi, laporan PDF). Bukti: `packages/scanner/src/adapters/` hanya berisi adapter spawn ke binary luar; tidak ada satu pun modul deteksi buatan sendiri.
2. **Apakah tool yang dipakai Hoplite berbayar?** **Software-nya semua gratis/open-source** (Nuclei MIT, ZAP Apache-2.0, Strix Apache-2.0, Opengrep, OSV-Scanner, K6). Yang **berbayar adalah pemakaian**: token LLM (default OpenAI `gpt-4.1-mini`, budget Strix dibatasi `STRIX_MAX_BUDGET_USD=50` per scan, review pihak ketiga mengukur ~$17/run), API Perplexity (opsional), plus infra (Cloudflare R2, Sentry, VPS, domain `hoplite.astheron.my.id`).
3. **Ironi kecil:** katalog offensive milik Cyphron sendiri (`training/.kimchi/pentest/offensive-skills.md`) justru mendaftar tool yang **beneran berbayar** untuk manusia — Burp Suite Pro dan Nessus Professional. Kalau Cyphron mau "berdiri sendiri", katalog ini juga harus direvisi.
4. **Yang di `training` terkait Cyphron:** folder `.kimchi` (inti), `catatan_pengalaman_ai_pentester.txt` (riset 5 repo AI pentester), `juice-shop` (target lab untuk eval). **Yang dibuang (juice):** `test_notion_ai.js`, `test_notion_streaming.js`, `package-lock.json`, `progress_terakhir_cybersecurity.txt` — tidak ada kaitannya dengan Cyphron. ⚠️ **P0: `test_notion_ai.js` masih berisi cookie session Notion ASLI (`token_v2` dll.) ter-hardcode — hapus file-nya dan rotasi/ logout session Notion itu.**
5. **Konflik terbesar timeline lama dengan tujuan baru:** Master prompt bilang *"JANGAN membangun ulang scanner dari nol, bungkus tool yang sudah ada"* — ini PERSIS strategi Hoplite yang user kritik. Timeline harus direvisi: mesin deteksi dibuat sendiri (scratch) dan tool pihak ketiga cuma jadi plugin opsional. Konflik kedua: Fase 8 menyuruh memangkas 65 skill jadi 15–25, sedangkan user mau skill bisa ribuan (bahkan 7500). Konflik ketiga: tujuan "standalone" menuntut definisi skill yang executable, bukan prosa Markdown panjang seperti sekarang.

---

## 1. Peta `D:\GODMODE`

```
D:\GODMODE\
├── Hoplite\                  ← project TEMAN (SaaS pentest platform, milik Astheron)
│   ├── apps/web, apps/worker
│   ├── packages/ (api, auth, db, env, llm, logger, queue, report, scanner, storage, ui)
│   ├── docs/ (phase plans 16–37, tools_docs.md, system_design)
│   ├── e2e/ (t8.x static/dynamic, t12 nuclei, t15 strix)
│   ├── docker-compose.yml (web + worker + migrate + postgres + redis + zaproxy)
│   └── LICENSE → PROPRIETARY (Astheron Technologies, All Rights Reserved) ⚠️
│        (badge README bilang "MIT" — TIDAK SESUAI dengan isi LICENSE)
└── training\                 ← project USER
    ├── .kimchi\              ← INTI CYPHRON (65 skill + guardrails + knowledge + Modelfile)
    ├── juice-shop\           ← OWASP Juice Shop v20.1.1 (clone; target lab rentan, sudah pernah jalan di localhost:3000)
    ├── catatan_pengalaman_ai_pentester.txt   ← riset 5 repo AI pentester (PENTING, simpan)
    ├── progress_terakhir_cybersecurity.txt   ← transkrip sesi deploy Juice Shop + Coach Kimchi (arsip; kandidat buang)
    ├── test_notion_ai.js, test_notion_streaming.js ← eksperimen API Notion (BUANG; ada kredensial asli!)
    └── package-lock.json     ← sisa npm dari tes Notion (BUANG)
```

---

## 2. BEDAH HOPLITE (project teman)

### 2.1 Apa itu
Hosted security testing platform (SaaS proprietary, dioperasikan **Astheron**, prod: `https://hoplite.astheron.my.id`). Monorepo Bun + Turborepo. Frontend TanStack Start (React 19), API oRPC, auth Better Auth (Google+GitHub OAuth), DB PostgreSQL 18 + Drizzle, antrean Redis + BullMQ, storage Cloudflare R2, observability Sentry.

Kemampuan jualannya 4 jenis scan (`packages/queue/src/types.ts:23`):
| Tipe scan | Mesin | Sumber kemampuan |
|---|---|---|
| `static` (SAST+SCA) | Opengrep + OSV-Scanner | pihak ketiga |
| `dynamic_zap` (DAST) | OWASP ZAP (container `zaproxy`, 8 mode scan) | pihak ketiga |
| `dynamic_nuclei` | Nuclei (template di-bake ke image) | pihak ketiga |
| `dynamic_strix` ("AI Pentest") | **Strix** (Python CLI v1.5.3, sandbox Docker sendiri) | pihak ketiga |
| (+ perf test) | Grafana K6 | pihak ketiga |

### 2.2 Bukti "nol deteksi sendiri"
- `packages/scanner/src/adapters/` hanya berisi: `k6.ts`, `nuclei.ts`, `opengrep.ts`, `osv-scanner.ts`, `strix.ts`, `zap.ts`, `spawn-helper.ts`, `index.ts`. Semua `run*()` = spawn binary + parse output. Tidak ada modul rule/detektor/fuzzer buatan sendiri di seluruh repo.
- `packages/scanner/src/versions.ts` — `PROBED_TOOLS = ["opengrep","osv-scanner","nuclei","k6","strix"]` → admin panel hanya memantau versi binary luar.
- `apps/worker/Dockerfile` — semua mesin di-install pinned: K6 v2.2.0, Nuclei v3.11.1 (+ `nuclei -ut -duc` bake templates), Opengrep v1.27.1, OSV-Scanner v2.5.1, docker-ce-cli, uv, Strix 1.5.3; ZAP datang dari container `zaproxy` terpisah.
- "AI Pentest"-nya = **Strix murni**. `adapters/strix.ts` spawn `strix -n -t <target> --scan-mode ... --max-budget ...`, lalu baca `vulnerabilities.json` + `penetration_test_report.md` milik Strix. Komentar di file itu sendiri: *"Unlike other scanners, Strix is itself an AI agent."* Worker bahkan skip LLM sendiri dan pakai teks laporan Strix (`modelUsed: "strix-provided"`).
- `docs/tools_docs.md:3` secara eksplisit: *"Upstream engine names (opengrep, osv-scanner, zap, nuclei, k6, strix) may appear here but never in customer-facing copy"* → nama engine pihak ketiga sengaja disembunyikan dari klien. (Ini poin yang persis dikhawatirkan user: kalau klien tahu mesinnya, mereka bisa langsung pakai mesinnya.)

### 2.3 Yang jadi IP milik Hoplite (jujur, bukan nol nilai)
- Orkestrasi & UX: BullMQ pipeline, SSE real-time, dashboard admin, GitHub App untuk repo privat, izin/attestation checkbox untuk dynamic scan.
- Normalisasi + fingerprinting + dedup temuan per-tool; skema severity 5 level.
- **LLM FP-review untuk Opengrep saja** (`packages/llm/fp-agent.ts`) — satu-satunya "reasoning" yang ditulis sendiri; ZAP/Nuclei/Strix/K6 dianggap authoritative apa adanya.
- Laporan: exec summary + worst-case, chart SVG, PDF Chromium (Playwright), ekspor Markdown.
- Pentest berkredensial (phase 37): secret store AES-256-GCM, TTL 24 jam / 3 pemakaian, instruction via `--instruction-file`, redaksi kredensial.
- 37 fase rencana pengembangan terdokumentasi rapi di `docs/plans/`.

### 2.4 Inventaris biaya Hoplite (dari `.env.example` + Dockerfile)
| Item | Gratis/Berbayar | Catatan |
|---|---|---|
| Opengrep, OSV-Scanner, ZAP, Nuclei(+templates), K6, Strix | **Gratis** (open-source) | binary pinned di image |
| `LLM_API_KEY` (default `https://api.openai.com/v1`, `gpt-4.1-mini`) | **Berbayar** (per token) | dipakai 3 peran: laporan, FP-review, dan di-pass ke Strix via `STRIX_LLM` |
| `STRIX_MAX_BUDGET_USD=50` | **Berbayar** | cap belanja LLM per pentest run; riil ~$17/run menurut review pihak ketiga |
| `PERPLEXITY_API_KEY` | **Berbayar** (opsional) | OSINT Strix |
| Cloudflare R2, Sentry, VPS, domain, OAuth Google/GitHub | freemium/infra | kebutuhan operasional SaaS |
| GitHub App | gratis | untuk clone repo privat |

Kesimpulan biaya: **tidak ada lisensi tool yang berbayar, tapi setiap scan AI itu berbayar via token** — dan Strix (produksi asing) bisa dijalankan langsung oleh siapa pun tanpa Hoplite.

### 2.5 Verdict "berdiri sendiri?"
**Tidak.** Analogi: Hoplite adalah ruang kontrol untuk 6 drone buatan orang lain. Lepas 6 drone itu, yang tersisa cuma UI + PDF generator. Argumen user valid sebagian ("klien bisa langsung pakai Strix/Nuclei/ZAP") — nilai Hoplite ada di kemudahan operasional, bukan di kemampuan mendeteksi. CATATAN ADIL: itu strategi yang sah (banyak produk SaaS begitu), hanya saja memang **bukan produk yang berdiri sendiri**, dan *moat*-nya tipis terhadap klien teknis.

---

## 3. BEDAH CYPHRON (`training/.kimchi`) — project user

### 3.1 Apa itu
**Cyphron** = agen AI keamanan siber lokal berbasis Ollama (model `qwen2.5-coder:32b`, `num_ctx` 32768, temp 0.3). Saat ini **murni kumpulan Markdown + config untuk model chat** — **belum ada runtime/program apa pun** (satu-satunya `.js` di `training` adalah tes API Notion, bukan bagian Cyphron). Punya 2 mode di atas kertas: Defensive (default) dan Offensive (authorized pentesting).

### 3.2 Inventaris terverifikasi
| Komponen | Jumlah | Status verifikasi |
|---|---|---|
| `skills/*.md` | **65 file** (~19.252 baris, ~300–470 baris/skill) | ✅ semua ada; format konsisten: Title → WHEN TO ACTIVATE → METHODOLOGY → Secure Patterns → Audit Checklist (dicek skill 03 & 52) |
| `agent-config.yaml` | 65 entri skill (id, name, file, triggers, priority, mode) | ✅ 65/65 terdaftar; **semua `mode: defensive`** |
| `guardrails/` | 4 file: ethics-boundary, action-protocol, **authorization-protocol**, refusal-templates | ✅ ada; authorization-protocol sudah mendefinisikan skema JSON dokumen izin, validasi scope (domain/wildcard/CIDR), restriction check, audit log ber-hash-chain |
| `knowledge/` | 4 file: attack-encyclopedia, secure-patterns, remediation-playbook, tool-templates | ✅ ada; semuanya orientasi defensif (template kode alat deteksi: SAST pattern scanner, dll.) |
| `pentest/offensive-skills.md` | 1 katalog | ✅ ada TAPI **tidak direferensikan agent-config.yaml** dan tidak ada eksekutor; mendaftar tool: nmap, subfinder/amass, httpx, nuclei, theHarvester, ZAP, **Nessus/OpenVAS**, Nikto, testssl.sh, sqlmap, **Metasploit**, **Burp Suite**, Hydra, Wireshark; 4 mode operasi (assist/agent/crew/interact) |
| `ollama/Modelfile` | 1 | ✅ FROM qwen2.5-coder:32b + SYSTEM kondensasi (defense-first + protokol otorisasi) |
| `ferments/` | 0 file | kosong (target skill synthesis) |
| `RINGKASAN-UNTUK-TEMAN.md`, `README.md`, `HOMEWORK-LANJUTAN.md` | 3 | ada; README & HOMEWORK **sudah basi** (lihat §5) |

### 3.3 Yang SUDAH kuat di Cyphron (modal penyempurnaan)
1. **Metodologi & etika tertulis sangat matang** — action-protocol 4-gate, harm test, skema dokumen otorisasi lengkap (id, scope CIDR/wildcard, excluded, restrictions, signature, expiry), audit log tamper-proof ber-hash-chain. Ini fondasi "Authorized Offensive Mode gate" yang bisa dieksekusi runtime nanti.
2. **65 skill cakup luas** (7 kategori: Defensive Core 01–15, Platform 16–25, Architecture & Data 26–35, Ops & Intel 36–45, Human/Physical 46–48, Advanced 49–55, Enterprise & Emerging 56–65).
3. **Knowledge base kode nyata** (secure-patterns, remediation-playbook, tool-templates berisi kode scanner siap pakai) — ini aset yang Hoplite tidak punya sama sekali.
4. **Target lab sudah siap**: OWASP Juice Shop v20.1.1 di `training/juice-shop`, pernah terverifikasi jalan di `localhost:3000` (lihat `progress_terakhir_cybersecurity.txt`) → langsung cocok untuk Fase 8 (eval harness).
5. **Riset kompetitor sudah dilakukan** (`catatan_pengalaman_ai_pentester.txt`): PentestGPT, Shannon, Strix, PentestAgent, PentAGI — dianalisis konsepnya (belum di-clone). Catatan: **Strix dari daftar riset user = persis mesin yang dipakai Hoplite.**

### 3.4 Yang BELUM ada (gap nyata)
1. **Runtime nol** — tidak ada program yang membaca agent-config.yaml, routing skill, memanggil tool, atau men-enforce guardrail. Semua "gate" saat ini hanya teks yang di-inject ke prompt model chat.
2. **Tidak ada Tool/Actuator layer, sandbox, scope guard** sama sekali.
3. **Tidak ada World Model / memory / findings store.**
4. **Skill tidak executable** — format prosa metodologi, bukan unit yang punya input/output/allowed_tools/preconditions yang bisa dijalankan dan diukur.
5. **Defense-first di level prompt, bukan di level sistem** — model bebas menolak/menuruti karena tidak ada enforcement mekanis (beda dengan Hoplite yang attestation-nya dicek kode sebelum job masuk queue).
6. **Modelfile statis** — 65 skill tidak otomatis termuat; `num_ctx` 32768 tidak akan cukup menampung 19 ribu baris skill sekaligus (dibutuhkan retrieval/dynamic loading).

---

## 4. VERIFIKASI KLAIM MASTER PROMPT vs KONDISI NYATA

| # | Klaim di master prompt | Fakta | Verdict |
|---|---|---|---|
| 1 | 65 skill .md datar, format konsisten, semua `mode: defensive` | 65 file, ~19.252 baris, semua defensive | ✅ BENAR |
| 2 | agent-config.yaml "SUDAH berisi skill registry + referensi knowledge + response format + ollama + `custom_skills_dir: ferments/`" | Benar, 65 entri lengkap | ✅ BENAR |
| 3 | guardrails berisi ethics, action, **authorization**, refusal | 4 file ada | ✅ BENAR |
| 4 | (implisit) authorization-protocol sudah tersambung ke config | `agent-config.yaml` bagian `guardrails:` **hanya mencantumkan 3 file — authorization-protocol.md TIDAK direferensikan** | ❌ PERLU DIPERBAIKI |
| 5 | (implisit) offensive-skills.md tersambung | **Tidak direferensikan di agent-config.yaml sama sekali** — file yatim | ❌ PERLU DIPERBAIKI |
| 6 | ollama/Modelfile FROM qwen2.5-coder:32b + SYSTEM condensed | Benar | ✅ BENAR |
| 7 | "Belum ada runtime (file .js yang ada hanya tes API Notion)" | Benar | ✅ BENAR |
| 8 | (tak disebut) README & HOMEWORK mutakhir | **README.md masih bilang "15 skill" + struktur `.Cyphron/` + guardrails 3 file; HOMEWORK-LANJUTAN.md bilang 48/65 selesai (aslinya sudah 65/65 + config ter-update)** — dua-duanya basi dan akan menyesatkan agent yang membacanya | ⚠️ DOKUMENTASI BASI |
| 9 | (tak disebut) lab eval tersedia | Juice Shop v20.1.1 ada & pernah jalan | ➕ BONUS: Fase 8 langsung punya target |

---

## 5. "JUICE" YANG DIBUANG / DISINGKIRKAN dari `training`

Per instruksi user: bagian project yang tidak ada kaitannya dengan Cyphron disingkirkan.

| Item | Keputusan | Alasan |
|---|---|---|
| `test_notion_ai.js` | **HAPUS (P0)** | Eksperimen memanggil API privat Notion `getCompletion`. Bukan Cyphron. **Berisi cookie session Notion ASLI ter-hardcode: `token_v2`, `notion_user_id`, device_id, dsb.** Ini kebocoran kredensial aktif di dalam repo — hapus file DAN rotasi session (logout all devices / ganti password Notion). |
| `test_notion_streaming.js` | **HAPUS (P0 juga)** | Eksperimen streaming NDJSON Notion; tidak menyentuh Cyphron. **Terverifikasi juga membawa cookie session Notion (`token_v2`)** — sama-sama kredensial aktif di repo. |
| `package-lock.json` | HAPUS | Sisa dependensi tes Notion, tanpa `package.json` pun tidak berguna. |
| `progress_terakhir_cybersecurity.txt` | ARSIPKAN (bisa dihapus) | Transkrip mentah sesi deploy Juice Shop + mode Coach Kimchi. Info uniknya (Juice Shop jalan di :3000, challenge butuh ALCHEMY_API_KEY/Ollama) sudah dirangkum di dokumen ini; sisanya log. |
| `catatan_pengalaman_ai_pentester.txt` | **SIMPAN** | Riset user atas 5 repo AI pentester — konteks strategis langsung untuk penyempurnaan timeline. |
| `juice-shop/` | **SIMPAN** | Target lab rentan milik user sendiri (lokal), kebutuhan Fase 8. Bukan bagian "core" Cyphron tapi bagian ekosistem eval. |

⚠️ Catatan kebersihan tambahan: `.kimchi/README.md` + `HOMEWORK-LANJUTAN.md` sebaiknya di-update/dihapus saat penyempurnaan dimulai, agar tidak menyesatkan (lihat §4 #8).

---

## 6. ANALISIS STRATEGIS — posisi Cyphron vs Hoplite

| Dimensi | Hoplite (teman) | Cyphron (user, target) |
|---|---|---|
| Kemampuan deteksi | 100% sewa (6 engine luar) | harusnya BUILT-IN (dari nol) |
| Reasoning AI | FP-review Opengrep saja; sisanya Strix | skill-driven: retrieval + world model + verifier (moat utama) |
| Skill | tidak ada sistem skill | 65 → target ribuan (lihat §7) |
| Otorisasi | attestation checkbox + secret store (runtime-enforced) | sudah desain bagus di kertas, belum di-enforce runtime |
| Laporan | matang (PDF branded, chart) | belum ada |
| LLM | API berbayar (OpenAI default) | lokal Ollama (gratis) — privacy jadi nilai jual |
| Lisensi | PROPRIETARY (README bilang MIT — tidak akurat) | milik user sendiri |
| Kelemahan terbesar | tanpa engine luar = mati; klien teknis bisa bypass | belum bisa menjalankan apa pun |

Argumen user "klien akan bilang lebih baik pakai tool pihak ketiga langsung" **terbukti relevan** untuk Hoplite (bahkan `docs/tools_docs.md:3` menunjukkan nama engine sengaja disembunyikan dari klien). Maka arah "standalone + dari scratch" untuk Cyphron **konsisten dan defensible**: yang dijual bukan wrapper, tapi (a) mesin deteksi sendiri, (b) lapisan reasoning + skill yang berlipat, (c) privacy lokal, (d) otorisasi mekanis.

---

## 7. KONFLIK TIMELINE LAMA vs TUJUAN BARU (masukan penyempurnaan — JANGAN dieksekusi, ini catatan)

**Konflik A — "Jangan bangun ulang scanner" (aturan master prompt) vs "berdiri sendiri / dari scratch gapapa" (tujuan baru).**
Fase 2 lama menyuruh MEMBUNGKUS nmap/semgrep/nuclei/sqlmap/httpx — persis arsitektur Hoplite yang dikritik. Revisi yang disarankan: ganti hierarki mesin menjadi **own-core engines first** (mis. HTTP fuzzer & request engine sendiri, static analyzer berbasis parser AST sendiri, secret scanner sendiri, crawler sendiri, template engine deteksi sendiri ala-nuclei dengan format template milik Cyphron), lalu **tool pihak ketiga hanya plugin opsional** (tetap lewat sandbox + scope guard) agar coverage tidak hilang di awal. Ukuran keberhasilan berubah dari "tool terbungkus jalan" menjadi "X% temuan bisa direproduksi tanpa plugin eksternal".

**Konflik B — Fase 8 "pangkas 65 → 15–25 skill" vs "skill bisa ribuan (7500 pun gas)".**
Ini bukan bertentangan kalau definisinya diubah: prosa panjang 300–470 baris per skill TIDAK scalable ke ribuan. Skill perlu direfactor jadi **unit atomik executable** (id, preconditions, inputs/outputs, allowed_tools, langkah terukur, eval case) yang bisa: di-generate massal, di-index (vector/BM25), di-retrieval top-k, di-eval otomatis per skill. Dengan arsitektur itu, 7500 skill tidak masalah; tanpa itu, 65 skill pun sudah melebihi context window (`num_ctx` 32768 ≈ ~24 ribu token vs 19 ribu baris skill + knowledge). Jadi: **pruning Fase 8 lama harus diganti menjadi "kurasi + komposisi"** (skill granular digabung jadi playbook), bukan menghapus.

**Konflik C — "Model lokal qwen2.5-coder:32b" vs "setiap keputusan LLM = structured output tervalidasi".**
Model lokal 32b mampu, tapi JSON mode/structured output di Ollama lebih rapuh daripada API besar. Runtime sebaiknya dukung dua provider (Ollama lokal + API opsional) dengan retry/schema-repair, dan fallback deterministik (kode, bukan LLM) untuk gate keamanan — **gate otorisasi tidak boleh bergantung pada kerendahan hati model** (ini kelemahan fundamental pendekatan prompt-only yang sekarang ada; bandingkan dengan Hoplite yang men-check attestation di kode sebelum job masuk queue).

**Konflik D (kecil) — nomenklatur folder.** Master prompt memakai path `.kimchi/...`; struktur aktual sudah benar di `training/.kimchi/...` — pastikan revisi timeline konsisten memakai path relatif yang benar dan menyebut file yang selama ini yatim (authorization-protocol.md, offensive-skills.md) ikut terdaftar di agent-config.yaml baru.

**Perbaikan cepat yang bisa masuk Fase 0 revisi:** update README.md & hapus HOMEWORK-LANJUTAN.md; daftarkan `guardrails/authorization-protocol.md` + `pentest/offensive-skills.md` ke agent-config.yaml; pindahkan katalog tool berbayar (Burp Pro, Nessus) ke bagian "human-assisted / opsional" bukan jalur runtime.

---

## 8. PERTANYAAN TERBUKA UNTUK USER (jawab sebelum timeline direvisi)

1. **Tingkat "standalone":** 100% tanpa binary luar, atau "core engines sendiri + plugin opsional untuk coverage awal"? (Rekomendasi: opsi kedua — realistis untuk 1 orang, tetap bisa klaim standalone karena plugin bisa dicopot.)
2. **Bahasa runtime:** timeline lama bilang TypeScript+Bun. Untuk "dari nol" (parser AST sendiri, fuzzer sendiri), Python/Rust/Go kadang lebih praktis. Tetap Bun, atau mixed?
3. **Target jumlah skill:** berapa angka realistis v1 (mis. 300 atomik) sebelum target 7500? Kualitas per skill harus tetap ter-eval.
4. **Offensive capability:** sampai level mana "dari nol"? (recon + scanning + PoC HTTP saja? atau sampai exploit chaining seperti yang dijanjikan Strix?)
5. **Model:** qwen2.5-coder:32b tetap default, atau pindah ke model reasoning yang lebih kuat untuk loop agent (qwen3/deepseek-r1 distill) — cek `ollama/model-recommendations.md` saat revisi.

---

## 9. SUMBER EKSTERNAL

- Strix (open-source, Apache-2.0, ~50k★, pip `strix-agent`, biaya riil ~$17/run token): [github.com/usestrix/strix](https://github.com/usestrix/strix), [strix.ai/open-source-pentesting](https://www.strix.ai/open-source-pentesting), [review biaya XHack](https://xhack.io/blog/cheapest-ai-pentest-tool/), [panduan self-host Contabo](https://contabo.com/blog/self-host-strix-pentest-vps/)
- Dokumen internal Hoplite: `README.md`, `AGENTS.md`, `docs/tools_docs.md`, `.env.example`, `apps/worker/Dockerfile`, `packages/scanner/src/adapters/strix.ts`, `packages/queue/src/types.ts`, `LICENSE`
- Dokumen internal Cyphron: seluruh isi `training/.kimchi/` + `training/catatan_pengalaman_ai_pentester.txt`

*Dokumen ini adalah pegangan riset — bukan hasil kerja timeline. Langkah berikutnya (setelah user menjawab §8): menyempurnakan master prompt + Fase 0–8 sesuai konflik A–D di §7.*

---

## ADDENDUM (2026-09-03) — Konteks baru dari user + framework keputusan dependensi

**Fakta baru:** Riset 5 repo di §3.3 poin 5 DIPERINTAHKAN oleh teman (owner Hoplite). Teman bilang mau "buat AI Pentester" dan meminta user mencari tahu repo-repo itu. User dan teman **satu startup yang sama** ("kami kan startup"). Pertanyaan strategis user: "sebagai startup, bukankah harus dari scratch/zero dan tidak mengandalkan third party?"

**Jawaban yang disepakati (catatan strategis):**
- Rule yang benar BUKAN "semua harus scratch", melainkan: **miliki layer yang menjadi nilai jual (moat), sewa layer komoditas.**
- 4 risiko posisi "full wrapper" ala Hoplite: (1) bypass klien langsung ke tool gratis; (2) **supplier = kompetitor** — Strix adalah produk AI pentester komersial 50k★ dengan offering managed sendiri, jadi Hoplite efektif reseller tanpa moat; (3) risiko perubahan lisensi upstream (preseden industri: Redis, Terraform BUSL, Elastic, MinIO AGPL); (4) utang maintenance pin 6 upstream + template freeze.
- 4 risiko "full scratch puris": coverage awal pasti kalah dari wrapper (Nuclei ribuan template komunitas, ZAP puluhan policy), lambat ke pasar, biaya besar, dan nilai jual yang benar bukan "kami scratch" melainkan: **privat/lokal, tanpa biaya token per scan, auditable, tidak bisa di-bypass, tahan perubahan lisensi.**
- Framework 4 pertanyaan per dependensi: bisa dibypass klien? membawa core value? upstream bisa berubah lisensi/harga? upstream kompetitor? Dua+ "ya" → WAJIB dimiliki sendiri.
- Peta keputusan: Postgres/Redis/Docker/R2/PDF = sewa aman; Opengrep/OSV/ZAP/Nuclei/K6 = abu-abu, jadikan plugin opsional yang bisa dicopot; **Strix = MERAH, wajib diganti engine sendiri**; lapisan reasoning/skill/verifier = wajib milik sendiri.
- Dari 5 repo riset: **PentestGPT, Strix, PentAGI = produk AI pentester utuh** (jangan jadi dependensi; pelajari arsitekturnya saja), Shannon & PentestAgent = tool kecil (aman sebagai referensi).
- **Jalur eksekusi startup (strangler fig):** Hoplite-sekarang = MVP cepat untuk validasi + revenue (fase 1 yang sah); Cyphron = moat jangka panjang (engine + reasoning sendiri). Ganti kategori kemampuan dengan engine sendiri satu per satu, mulai dari nilai tertinggi (recon, HTTP probing, secret scanning, template engine deteksi sendiri). **Metric independensi: % temuan yang berasal dari engine sendiri** — naikkan tiap iterasi sampai plugin eksternal opsional murni.

**ADDENDUM 3 — Cyphron Core v0.1 SUDAH DIBANGUN (2026-09-03)**
- Lokasi runtime: `D:\GODMODE\training\cyphron\` (membaca knowledge pack `training/.kimchi`). Stack final: **Python 3.12 pure-stdlib — NOL dependensi pihak ketiga, NOL LLM provider** (yamlite = parser YAML sendiri, SQLite = store, planner deterministik; LLM slot sengaja tak dipasang sampai tim pilih provider — gate/verifier/audit tetap kode).
- Terpasang: SkillRegistry (65 skill + retrieval top-k), AuthorizationGate kode-enforced (scope domain/wildcard/CIDR/port, expiry, restrictions, default-DENY → read-only), AuditLog hash-chain tamper-evident, WorldModel, 7 engine sendiri (http_probe, security_headers, crawler, dir_probe, sqli_probe error+boolean, xss_probe marker, secret_scan), ToolGuard (kill switch, rate limit, budget, redaksi secret), Verifier bukti-basis (confirmed ≠ unconfirmed), Reporting MD+JSON+PoC curl, SQLite persist, CLI (`python -m cyphron scan|check|skills`).
- Verifikasi nyata: **22/22 unit test pass**; demo CLI vs lab fixture sendiri — read-only: 5 temuan pasif; authorized: **10 confirmed (2 critical: SQLi error-based SQLite + /.git/HEAD; 3 high: 2 XSS + /.env)**, 36 request, 0.72s, audit chain 28 entri verified; gate REFUSED target luar scope (exit 3). Output demo: `training/cyphron/out_readonly/` & `out_lab/`.
- Jawaban "mana yang pantas disebut AI Pentester" kini konkrit: Strix masih standar; Cyphron Core v0.1 sudah punya tangan (engine) + kunci (gate) + pembuktian (verifier), tinggal diperluas per `training/cyphron/docs/ROADMAP.md` (R1 engine perluasan → R2 skill atomization → R3 chaining → R4 LLM slot → R5 ferments → R6 eval harness vs juice-shop).

**ADDENDUM 4 — SKILL HARVEST BATCH #1 (2026-09-03): pack kini 73 skill**
- Workflow panenan jalan penuh: PROMPT A (30 test dari project aron) → PROMPT C2 (pelengkap data, aturan: tidak mengeksekusi test baru) → klasifikasi final: **13 sudah tercakup, 14 jadi bahan 8 skill baru (66–73), 3 parkir** (migration rehearsal/resilience→30/35, accessibility→non-security).
- Skill baru (format lama persis, terdaftar di agent-config.yaml): **66** Authorization Coverage Testing, **67** Webhook & Callback Trust, **68** SSRF & URL Ingestion, **69** Proxy & Origin Trust, **70** Payment & Business-Logic Abuse, **71** File Upload & Media Abuse, **72** CSP Engineering & Migration, **73** Attack Path Chain Modeling (tabel AP1–AP10 verbatim).
- Koreksi honesty: #28 Semgrep = DIUSULKAN (tak pernah jalan); field `bukti` untuk item DIUSULKAN = `success_criteria` (bukan evidence) — ditandai di skill 69–72; #17 tanpa tanggal/lokasi laporan; #18 klaim 41-route tanpa artefak reproducible.
- Runtime terverifikasi pasca-harvest: registry 73/73 termuat, retrieval benar (67 & 68 top untuk query-nya), **test suite 23/23 pass**.
- ROADMAP R1 bertambah: engine `ssrf_probe`, `proxy_trust_probe`, `upload_probe`, upgrade `security_headers` v2 (CSP), assisted `replay_probe`/`route_inventory`; R6 punya 8 eval case baru. Detil lengkap: `training/cyphron/docs/PROMPT-SKILL-HARVEST.md`.

**ADDENDUM 5 — CLIENT ACCEPTANCE TEST PRODUKSI (2026-09-03): aron.iliterate.ai**
- Target produksi nyata di-scan dengan AUTH-ARON-001 (owner self-authorized; scope domain:443; restrictions no_dos/no_exfil/no_persistence/no_aggressive; rate-limit 0.3s, budget 120 req).
- Bukti gate dua arah: tanpa dokumen → REFUSED dengan **0 request**; dengan dokumen → ALLOWED.
- Scan produksi: **26 request / 11.6 detik**, 4 step, audit chain 13 entri verified. Temuan: **HSTS missing (medium, terkonfirmasi manual)** + `/admin/` 200 (low, 70% "verify") — verifikasi manual menunjukkan `/admin` 307 redirect ke login → **properly gated, bukan vuln** (tool jujur minta verifikasi, bukan mengklaim).
- Observasi lapisan analis (via Skill 72/69): **CSP header ganda** di / (app + layer Cloudflare; semua CSP di-enforce = interseksi) dan `connect-src http://127.0.0.1:43127` (port telemetry localhost) bocor ke CSP produksi — hygiene/info-leak level.
- Batas jujur v0.1 di target ini: tidak ada endpoint ber-query-param yang ditemukan crawler (24 endpoint) → sqli/xss engine idle; auth-bypass/business-logic/stored-XSS di luar jangkauan; crawler belum baca robots.txt; SPA surface butuh headless browser (R2).

**ADDENDUM 6 — SUITE LAPORAN + DISCOVERY MENYELURUH (2026-09-03)**
- Reporting dirombak: satu sumber `blocks` → tiga format **report.md + report.pdf + report.docx** (PDF writer raw-stdlib, DOCX writer OOXML-stdlib — tetap zero-dependency). Bahasa Indonesia profesional, TANPA emoji, struktur 8 bagian (Ringkasan Eksekutif → Otorisasi → Metodologi → Ringkasan → Detail Temuan → Observasi Belum Terkonfirmasi → Batasan → Jejak Audit).
- Engine baru v0.2: `tls_audit` (sertifikat/protokol/SAN), `method_audit` (OPTIONS/TRACE/PUT/DELETE **dengan self-critique**: response dibandingkan baseline GET — PUT/DELETE yang cuma membalas halaman normal otomatis diturunkan ke unconfirmed 30%), `redirect_probe` (canary host), `dir_probe` diperluas ke ~60 path, crawler dalam (robots.txt + sitemap ingest, HTML comments, email, fingerprint aset, security.txt).
- Hasil scan menyeluruh aron.iliterate.ai: **88 request / 38,6 detik**, 72 endpoint teramati, fixpoint tercapai di 7 langkah. Temuan: HSTS missing (medium) + /admin/ verify (low); observasi unconfirmed: PUT/DELETE no-op. Discovery: TLSv1.3 + cert 60 hari, sitemap 5 URL, email di halaman, security.txt tidak ada, 3 form, fingerprint aset Next.js.
- Kisah self-critique untuk client: dua "CRITICAL" (PUT/DELETE 200) otomatis diturunkan setelah perbandingan baseline — bukti produk tidak overclaim.

**ADDENDUM 7 — TARGET #2: airon.astheron.my.id + ENGINE AUTH (2026-09-03)**
- Engine baru `auth_probe` (Skill 06): discovery login (form + common paths), username enumeration, uji lockout/rate-limit (6 percobaan gagal terbatas), bounded spray hanya ke akun probe `cyphron-probe-9f3x@example.test` (tidak pernah ke akun asli), deteksi registrasi terbuka.
- Fix kapabilitas: parser crawler kini menangkap input **tanpa atribut name** (Next.js controlled component) via `input[type=...]` — kunci untuk SPA.
- Hasil airon: **2 confirmed (CSP Report-Only saja; tidak ada lockout setelah 6 gagal login di /login — CWE-307, terverifikasi POST benar diproses app)** + 2 unconfirmed (PUT/DELETE no-op). Discovery: 104 endpoint, registrasi terbuka di /register, TLSv1.3 cert 70 hari, security.txt tidak ada, /api/auth/* diblokir 403 di edge (kontrol protektif).
- Laporan 3 format disimpan ke folder Downloads user: `C:\Users\lenovo\Downloads\cyphron-airon-report\`.
- Fase berikutnya (tertunda approval user): pengujian terautentikasi butuh akun uji disposable dari owner (atau izin auto-register di /register).

**ADDENDUM 8 — JS RENDERING + BOUNDED LOAD TEST (2026-09-03)**
- Engine baru: `browser_engine` (headless Chrome/Edge via `--dump-dom`, zero-install, fallback antar-browser — Edge sering menolak dump-dom, Chrome andal; 5 halaman kunci dirender, +4 form client-rendered terlihat, /register & /dashboard terungkap) dan `load_probe` (**finite-quota availability test**: 3 stage 30/60/100 request, konkurensi 5, hard caps, stop conditions, TIDAK ada eskalasi-.until-down — garis DoS ditegakkan).
- Planner v0.3: one-shot phases dilacak via memori `_emitted` (bukan marker endpoint) — memperbaiki bug fixpoint prematur.
- Hasil final airon: **3 confirmed** — CSP Report-Only saja (medium), **tidak ada lockout di /login** (medium, CWE-307), **p95 spike 3640ms di stage-1 load** (low, lalu turun 625/547ms) + 2 unconfirmed (PUT/DELETE no-op). Load 190 request: 100% sukses, 0 error, 0 429 — edge Cloudflare menyerap tanpa bergidik; kapasitas sesungguhnya perlu load-gen sendiri (k6/VPS staging).
- Tests 23/23 hijau. Laporan terbaru selalu di-regenerate ke `C:\Users\lenovo\Downloads\cyphron-airon-report\`.

**ADDENDUM 9 — CAPACITY PROFILING + PANDUAN VPS (2026-09-03)**
- `load_probe` v2: profile "capacity" — tangga tetap 50/100/200/400 request (conc 10, total 750), knee detection (2x baseline p95 / error onset), **timestamp UTC per stage** untuk korelasi log server.
- Hasil airon: 750 request staged, **100% sukses, 0 error, 0 429, 0 5xx; p95 stabil 516-765ms** → temuan INFO "no degradation within envelope" (bukan klaim kapasitas maksimum). Nol knee terdeteksi dalam envelope.
- Catatan akurasi: counter `world.request_count` (155) TIDAK termasuk 750 request load stage (load_probe memakai http_engine langsung) — total trafik riil ±905 request; patch penambahan counter masuk untuk run berikutnya.
- `panduan-monitoring-vps.md` dibuat di folder report (Bahasa Indonesia, untuk operator VPS: nginx histogram, docker stats, pm2/journalctl, postgres/redis, Cloudflare analytics, cara baca knee, aturan main).
- Menunggu keputusan user: akun uji disposable / izin auto-register untuk fase authenticated grey-box.

**ADDENDUM 11 — "PENAMBALAN" + PERF ENGINE + MENU AI (2026-09-03, v0.3)**
- Permintaan user: product harus "10 langkah di depan" Hoplite — bukan cuma nyari tapi NAMBAL, punya kemampuan k6-class sendiri, dan UX "AI kasih menu user tinggal pilih + manual mode tetap penuh".
- **`cyphron fix`**: remediate.py — fix-pack deterministik per kelas temuan (HSTS/CSP/lockout/XSS/SQLi/exposed-path/generic): langkah bernomor + snippet config/code siap adaptasi + perintah verifikasi + sitasi knowledge base. Hasil: `patches/FIX-NN-*.md` + README. Tanpa LLM.
- **`cyphron verify`**: scan ulang → delta **fixed / still-open / new** vs baseline (fingerprint match) + persist laporan penuh di folder verify. Ini loop "penambalan terverifikasi" yang Hoplite tidak punya (dia berhenti di temuan).
- **`cyphron perf`**: perf_engine.py k6-class (stdlib): VU/duration/ramp/multi-URL/method/body via `--scenario` JSON (manual god mode) atau profile bounded quick/standard/stress; output RPS timeline per 5s, p50/90/95/99, histogram status. Gate auth tetap wajib.
- **`cyphron suggest`**: menu AI-recommended (1 NAMBAL / 2 BUKTI / 3 UJI BEBAN / 4 MASUK LOGIN / 5 MANUAL) — pilih nomor langsung dieksekusi.
- Hasil live airon: perf standard 476 req/30s (15,5 RPS, p95 718ms, p99 4406ms, 1 net-err); verify delta run-1 menangkap 1 temuan baru "5xx under bounded load" (intermittent — run-2 hilang lagi, konsisten dengan 522 transient), run-2: fixed=0 still=3 new=0 (patch memang belum diterapkan di server).
- Positioning vs Hoplite pricing ($149-1199/credit): Cyphron = unlimited scan cost ~$0 (engine sendiri, tanpa LLM), find→fix→verify loop, tools k6-class inclusive.

**ADDENDUM 12 — DEEP_PROBE: 7 TEKNIK ATTACK BARU + KISAH FALSE POSITIVE (2026-09-06)**
- Engine `deep_probe`: traversal, SSTI, cmdi time-based, CORS misconfig, host-header injection, GraphQL introspection, API unauth-access matrix — semuanya **incremental payload + early-stop-on-hit** (desain user), budget keras 60 request/run, baseline-aware.
- **Kisah self-critique terbaik**: run pertama melaporkan 6 "CRITICAL" SSTI di /signup?plan=... (7*7=49 terdeteksi). Verifikasi manual membongkarnya: baseline tanpa payload SUDAH mengandung "49" (nama chunk JS + lineHeight:49px — halaman pricing!) dan payload unik {{999*999}} → 998001 TIDAK pernah muncul. **False positive**. Predikat diperkuat: dual-payload discriminator + baseline check. Re-run: 0 SSTI, 4 temuan asli tersisa.
- Hasil final airon (black-box penuh, ±450 request seluruh sesi): 3 MEDIUM (CSP report-only; lockout login tidak ada CWE-307; 5xx intermiten di bawah load) + 1 INFO (envelope kapasitas 750 req tanpa degradasi) + 2 unconfirmed (PUT/DELETE no-op). Traversal/SSTI/cmdi/CORS/host-header/GraphQL/API-auth: **bersih**.
- Laporan client-ready (ID, tanpa emoji, PDF/DOCX/MD + findings.json + audit.jsonl + patches/ + panduan-monitoring-vps.md) di `C:\Users\lenovo\Downloads\cyphron-airon-report\` — siap diberikan ke pemilik situs.
- Kisah false-positive ini adalah jualan utama ke client: tool yang TIDAK overclaim — 6 critical hipotesis diteliti dan ditarik karena bukti tidak cukup.

**ADDENDUM 13 — ATTACK SUITE v4: 6 ENGINE BARU, GREY/WHITE-BOX, TRUTH GUARANTEE (2026-09-06)**
- Engine baru: `deep_probe` v3 tambahan (CRLF injection dgn marker header definitif, mixed content, CSRF-form info), `dir_probe` + directory-listing marker (CWE-548), `email_probe` (SPF/DMARC via **DNS TXT client raw UDP stdlib-murni** + heuristik public-suffix my.id/co.uk), `code_audit` (WHITE-BOX SAST regex pack 10 rule: SQLi f-string, shell=True, eval, weak hash, TLS verify=False, unsafe deserialization, innerHTML, hardcoded creds), **grey-box `--account USER:PASS`** (login via form discovery → session cookie → seluruh probe jalan terautentikasi).
- Truth guarantee (pelajaran SSTI): semua predikat hit = marker definitif ATAU dual-payload + baseline check. Bukan kebetulan angka.
- Hasil final airon (5 confirmed, semua TRUE/definitif): CSP report-only (medium), **SPF hilang di astheron.my.id (medium, fakta DNS)**, **DMARC hilang di astheron.my.id (medium, fakta DNS)**, lockout login tidak ada (medium), kapasitas 750 req tanpa degradasi (info). 5xx intermiten muncul-hilang antar run (2 dari 4 run) — dicatat sebagai pola. 2 unconfirmed (PUT/DELETE no-op).
- Total capability Cyphron kini: **16 engine** (vs Hoplite 6 engine sewa), grey/white/black-box, find→fix→verify loop, perf engine, menu AI.
- Paket laporan lengkap untuk teman: `C:\Users\lenovo\Downloads\cyphron-airon-report\` (report.pdf/docx/md, findings.json, audit.jsonl, patches/ 5 fix packs, verify-1/, perf-metrics.json, panduan-monitoring-vps.md).

**ADDENDUM 14 — GREY-BOX TERBUKTI DENGAN AKUN ASLI (2026-09-06)**
- Owner memberi akun uji (pentest@pentester.com). Dibangun: `session_probe` (entropi cookie, struktur/tamper JWT, authz diff) + NextAuth dance di grey-box login (GET /api/auth/csrf → POST /api/auth/callback/credentials; kunci: kirim SEMUA cookie csrf karena Set-Cookie kembar) + crawler anti-logout + `--account USER:PASS` di CLI.
- **Login SUCCESS** — sesi `__Secure-next-auth.session-token` aktif, seluruh pengujian berjalan terautentikasi (crawler melihat 7 endpoint baru).
- **Dua false positive tertahan oleh truth-guarantee**: (1) auth_probe spray melaporkan "weak credential CRITICAL" — ternyata sesi aktif membuat halaman login membalas state logged-in; diperbaiki: POST auth dipaksa tanpa cookie + guard diferensial (respons kredensial harus ≠ respons password-salah). (2) /admin/ "exposed" saat sesi aktif → diturunkan info + status unconfirmed.
- **Temuan keamanan sesi: SOLID (positif)** — token adalah JWE terenkripsi (alg=dir, A256GCM), HttpOnly+Secure+SameSite=Lax, alg:none tamper gagal, authz diff admin menunjukkan gating benar. session_probe: 0 temuan.
- **Verdict jujur final airon**: 6 confirmed (5 medium + 1 info), 0 critical. Critical-sejati tidak ada pada permukaan yang diuji — dan itu kesimpulan profesional, bukan kelemahan tool. Yang tersisa untuk mencari critical (RCE/bypass/IDOR lintas-tenant): butuh akun KEDUA (beda tenant/role) + pengujian business-logic pada billing/webhook, koordinasi owner.
- Laporan final + 6 fix packs (SPF/DMARC DNS, CSP promote, rate-limit middleware, dll) di `C:\Users\lenovo\Downloads\cyphron-airon-report\`.

**ADDENDUM 16 — CATCH-UP 6/6 SELESAI + LANDING DIBANGUN (2026-09-06)**
- **6/6 padanan pihak ketiga kini VERSI SENDIRI**: K6→perf_engine ✅, Strix→reasoning core ✅, ZAP→DAST probes ✅, Opengrep→code_audit (15 rule SAST) ✅, **Nuclei→template_probe (mini-Nuclei: 15 template marker definitif, no-redirect-follow, wajib 200)** ✅, **OSV-Scanner→sca_probe (kueri publik OSV.dev, parser package.json/requirements.txt)** ✅.
- **Truth story tambahan**: template_probe run-1 melaporkan "Supervisor exposed" — verifikasi manual: 307 redirect + marker generik "status" (FP). Diperbaiki menyeluruh: no-redirect-follow + marker brand-definitif + wajib 200. Lockout finding sempat hilang karena sesi grey-box menyembunyikan form login — diperbaiki: auth_probe wajib anonymous (Cookie:""). Re-verify manual: lockout tetap ada (6×200) → temuan TRUE kembali dilaporkan.
- **Landing page Cyphron DIBANGUN**: `landing/index.html` (single-file, near-black #0a0a0b + amber #f5a524): hero dual-CTA, 3 langkah Temukan/Nambal/Buktikan + terminal output nyata, kartu truth (FP rejection story), pricing 4 tier + tabel vs credit-based, waitlist. Langsung bisa dibuka di browser.
- Final airon: **6 confirmed TRUE** (CSP, SPF, DMARC, lockout, 5xx-load, kapasitas-info), 0 unconfirmed, tests 23/23. Total FP tertahan sepanjang proyek: SSTI×6, supervisor×1, weak-cred×1 — semua terdokumentasi sebagai bukti keandalan.

**ADDENDUM 15 — TIER PACK 100 SKILL + PRICING + RETRY RESILIENCE (2026-09-06)**
- `tierpack.py` + CLI `cyphron tiers --build/--list/--show`: **100 skill (25 × 4 severity tier: LOW/MEDIUM/HIGH/CRITICAL)** di `.kimchi/skills-tiers/` + INDEX.md. Setiap skill: teknik + **FP-GUARD wajib** (syarat TRUE) + verifikasi + pemetaan engine. Engine LIVE hari ini menutup ~38 slot (17 engine); 32 slot HIGH/CRITICAL adalah desain ROADMAP (chain/JWT-chain/race/upload-webshell/dll) yang wajib lewat pipeline test+FP-guard sama sebelum boleh TRUE.
- **docs/PRICING-TIERS.md** (desain user): Tier 1 = pentest + PDF saja; Tier 2 = + penambalan (fix packs + verify delta); Tier 3 = + kapasitas/white-box; Tier 4 = god mode (multi-akun, chain, on-prem). Level skill → tier mapping tertulis. Pembeda dari model credit kompetitor: naik tier karena KEMAMPUAN, bukan kuota; cost per scan ±$0.
- **Bug fix penting**: planner siluman berhenti di 4 langkah ketika http_probe kena 522/timeout transien Cloudflare (world kosong → cabang recon sudah _emitted → fixpoint prematur). Perbaiki: http_probe retry hingga 2x dengan key attempt unik. Full-throttle run setelah fix: 12 langkah semua engine jalan.
- Full-throttle run final (grey-box, akun owner, rate 0.15): **6 confirmed (5 medium + 1 info), 0 unconfirmed**, audit verified. Semua TRUE; tidak ada critical palsu dipaksakan.

**ADDENDUM 17 — INTEL GITHUB DIADOPSI + IMPACT PROBE (2026-09-06)**
- Riset 2 repo: anthropic-cybersecurity-skills (32.2k★, 817 skill/34 domain, progressive-disclosure, mapping MITRE/NIST) + CyberStrike (2.6k★, 13+ agent, 7600 skill signed, **3-gate protocol baseline→attack→response**).
- Diadopsi (desain sendiri): (1) **`skillgen.py`** — generator skill dedup + progressive-disclosure (frontmatter ringan utk indeks + BODY BERAT lengkap = dua-duanya bisa); run pertama: **18 skill baru ditulis, 7 ditolak duplikat otomatis** (malware-traffic≈39, ad-attack-path≈73, cicd≈42, mobile≈01, phishing≈46) — ke `.kimchi/skills-gen/`. (2) **`verification.py` Truth Guard v2** — protokol 3-gate formal (gate1 marker absen di baseline, gate2 marker hadir di attack, gate3 diff material) + confirm_timing; siap dipakai semua engine. (3) **`licensing.py` + tier gate engine-level** — lisensi JSON (basic/pro/business/god); engine tanpa akses = REFUSED sebelum eksekusi (terbukti demo: session_probe butuh GOD, BLOCKED utk PRO). (4) **`tierpack2.py`** — 120 skill BARU 30×4 (32 LIVE: sourcemap/js-secret/CRLF-ulang/ws/proto-pollution/dns-rebind... + 88 desain ROADMAP: smuggling-chain/algnone-chain/imds/jndi/zero-day-fuzz...). (5) **`impact.py` Impact Probe** — titik akhir TRUE-not-FALSE: tiap temuan digrade **PROVEN / HARDENING / REQUIRES-CONDITIONS** (run airon: 3 proven, 1 hardening, 2 conditions).
- Landing dibangun: `landing/index.html` (hero, 3 langkah, truth card, pricing 4 tier, waitlist). Dashboard UI shell menyusul; enforcement tier sudah engine-level.
- `.kimchi/HOMEWORK-LANJUTAN.md` dihapus (superseded — disebut user).
- Pertanyaan bahasa & zero-day terjawab di chat: runtime stdlib-Python tepat; power ada di teknik+verifikasi; zero-day hunting milik sendiri = differential fuzzing (slot critical-30).

**ADDENDUM 18 — GITHUB SWEEP + TIER PACK 3 + ZERO-DAY LIVE (2026-09-06)**
- Sweep GitHub "cybersecurity" (159k repo): 3 raksasa dipanen — Anthropic-Cybersecurity-Skills (32.2k★), CyberStrike (2.6k★, 7600 skill signed), CAI (9.8k★, archive), + Microsoft Security-101.
- **`tierpack3.py`**: 40 skill HARVEST domain baru (OT/robotik/MQTT, APT emulasi, AD kerberoast, prompt-injection defense untuk agen AI, dependency confusion, race-upload, benchmark Cybench, CVE workflow, G-CTR Nash, blackboard multi-scaffold, **zero-day fuzz = LIVE**). Struktur dict per-tier (bug parse awal diperbaiki).
- **`fuzz_engine.py` LIVE**: zero-day hunt differential fuzzing (6 kelas mutasi, reproduce-before-report) — slot CRITICAL-30 tierpack2 kini LIVE.
- **Total aset skill Cyphron: 74 core + 100 tier1 + 120 tier2 + 40 tier3 + 18 generated = 352 file skill** (`find .kimchi -path "*skills*" -name "*.md"` = 356 termasuk INDEX).
- **`licensing.py` TIER GATE terbukti di scan nyata**: tanpa lisensi → session_probe (GOD) & load_probe (BUSINESS) REFUSED; dengan license.god.json → semua jalan. Blokir akses = kode, bukan UI.
- **`verification.py` Truth Guard v2** (3-gate: baseline→attack→response, dari pola CyberStrike) + **`skillgen.py`** (18 baru, 7 dedup-reject otomatis).
- Keputusan mandiri atas poin menggantung: 88 slot ROADMAP = pipeline bertahap (FP-guard→test→LIVE); dashboard UI shell menyusul dengan gate lisensi yang sama; landing detail cukup di LANDING-REFERENCES.md.

**ADDENDUM 19 — ROADMAP PIPELINE BATCH 3-6: 33 SLOT BARU LIVE (2026-09-06)**
- 4 batch selesai dalam satu sesi, urut dari INDEX skills-tiers2. TOTAL engine sendiri: **51** (dari 23). Semua lewat pipeline wajib: engine + FP-guard (truth-guarantee: marker/diferensial definitif, server yang menolak BUKAN temuan) + unit test + bukti live. **Test suite: 23 → 63/63 hijau.**
- **BATCH 3 (10 slot)**: low-02 wayback (CDX arsip 200 + live 404 = rute hilang), low-17 id_seq (dua ID sekuensial isi beda + kontrol jauh GAGAL), low-29 ct_log (crt.sh → fallback certspotter, apex-aware), medium-01 smuggle (divergensi timing CL.TE/TE.CL, baseline wajib cepat, 2x konsisten = confirmed), medium-02 cache_dec (.css ≈ halaman akun > body 404), medium-03/04/05 oauth (state hilang + redirect_uri canary + nonce OIDC; client_id ditolak = bukan temuan), medium-06 puzzle (password[] type-confusion: baseline salah GAGAL lalu payload SUKSES), medium-07 json_inj (kunci `injected_key` + marker unik — **verifikasi struktural via json.loads, refleksi ter-escape json.dumps TIDAK dihitung**).
- **BATCH 4 (10 slot)**: medium-08 ct_conf (JSON diparse saat Content-Type salah, marker), medium-09 verb_over (X-HTTP-Method-Override → DELETE dieksekusi), medium-14 smtp_probe (EHLO tanpa STARTTLS, MX via raw DNS), medium-15 dkim_probe (modulus DER dari TXT selector umum < 1024 bit), medium-16 api_ver (v1 200-berisi-data vs v2 401), medium-17 gql_batch (array-of-queries 3 respons), medium-18 gql_depth (500 alias dijawab = cost unbounded), medium-19 gql_alias (didedup = guard), medium-20 pagin (limit=10000 → body ≥ 3x baseline), medium-21 sort_inj (error DB terkonfirmasi).
- **BATCH 5 (8 slot)**: medium-22/23 jwt_jku+jwt_x5u (tamper-replay: token dgn header attacker DITERIMA sementara tamper polos DITOLAK — diferensial ketat), medium-24 jwt_crack (HMAC offline wordlist, secret 'changeme' pada token sintetis = MATCH), medium-25 ws origin-bypass (upgrade ditolak same-origin tapi 101 dgn origin evil), medium-27 proto_c, medium-28 proto_s (marker merge __proto__), medium-29 clobber (lead statis unconfirmed), medium-30 css_inj (breakout `</style><style>` + canary).
- **BATCH 6 (5 slot)**: high-17/18 sourcemap2 (sourcesContent > 1000 char pulih + pola kredensial dari secret_scan PATTERNS), high-16 mq_mgmt (RabbitMQ `management_version` / ActiveMQ brand marker), high-19 dom_xss (sink+source di JS = lead high unconfirmed), high-21 clickj (halaman ber-form tanpa XFO/frame-ancestors).
- **BUKTI LIVE produksi (airon, god license)**: scan penuh b3: 6 confirmed; scan penuh b4: **ct_log menghasilkan temuan nyata baru — "CT log membocorkan 8 subdomain astheron.my.id (1 sensitif: cms)"**; semua engine 3-6 jalan tanpa crash, nol FP; audit chain verified; laporan di `training/cyphron/out_airon_b3/` & `out_airon_b4/`.
- **FIX REGRESI PENTING (ditemukan & diperbaiki saat pipeline)**: (1) `http_engine.http_get(follow_redirects=False)` TIDAK PERNAH bekerja — default HTTPRedirectHandler tetap ikut; sekarang build_opener(_NoRedirect) — memperbaiki redirect_probe/template_probe/oauth/puzzle. (2) Planner reorder: probe param (SQLi/XSS/redirect) kini SEBELUM 20 engine ekstra; load_probe terakhir — mencegah temuan inti terpotong max_steps. (3) Parser DNS pre-existing: `_read_name` salah offset saat compression pointer (jawaban multi-record rusak), dns_txt tidak tangani TC=1 (respons besar = false "missing") → kini fallback TCP + fix offset; bonus: dns_mx baru + socket leak ditutup. (4) Guard IP/lokal utk engine DNS/OSINT (dkim pada "0.1" membakar 160 detik query).
- **Catatan lingkungan**: crt.sh/web.archive.org sering tak terjangkau dari jaringan ini (502/timeout/UDP-drop) — semua engine OSINT turun anggun (graceful, tanpa FP); fallback certspotter + DNS-over-TCP dipasang untuk jaringan normal.
**ADDENDUM 20 — BATCH 7: GOD-MODE MULTI-AKUN (2026-09-06)**
- **Infrastruktur multi-akun**: `tools/auth_login.py` (login reusable: NextAuth dance + form POST), `ToolContext.sessions` (user → cookie), `ScanOptions.accounts` + CLI `--accounts userA:pass,userB:pass`. Sesi pertama jadi cookie global (crawler/browser), sesi lain dipakai eksplisit per-request. Tier lisensi: bola/priv_matrix = **GOD** (sesuai PRICING-TIERS Tier 4 multi-akun).
- **Engine baru**: `bola` (high-02 bola + high-28 tenant-cross + high-01 idor-seq: sesi B menerima objek milik sesi A dengan body ≈, sementara ANONIM DITOLAK — diferensial 3-peran wajib), `priv_matrix` (high-03: ≥2 sesi berbeda menerima panel admin identik padahal anonim ditolak = role tidak ditegakkan; early-skip hemat budget), `ws_probe` v3 (high-06: handshake 101 tanpa auth LALU kirim frame masked `{"action":"list"}` — server balas data = temuan high).
- **Bug sesi-bleed kritikal ditemukan & diperbaiki**: cookie global otomatis menempel di request "anonim" → pengujian lintas-akun tidak pernah benar. Fix: request multi-akun selalu MENIMPA header Cookie (anonim = Cookie kosong) + `follow_redirects=False` (3xx ke login = ditolak, body redirect-target tidak boleh tercampur perbandingan).
- **Bukti live**: scan orkestrasi penuh terhadap fixture 3-akun (alice/bob/admin, lisensi god): **bola HIGH terkonfirmasi ("alice mengambil objek milik admin") + priv_matrix HIGH ("/admin identik untuk semua sesi")**, audit chain verified. Test suite **70/70 hijau**. Planner: langkah bola/priv_matrix hanya di-emit bila ≥2 sesi.
- Status akhir sesi: **skills-tiers2 = 70 LIVE / 50 ROADMAP** (sisa: chain/JWT-alg-confusion/k8s/imds/OTP 2FA yang butuh alur khusus atau infra cloud), skills-tiers3 = 40 ROADMAP (mayoritas skill proses/dokumen). Engine total = **53**.

**ADDENDUM 21 — BUG BOUNTY PACK + BLACKBOX HOPLITE (2026-09-06)**
- **Riset 6 sumber atas permintaan user**: yaklang/hack-skills (101 skill: 401/403 bypass, param miner, takeover multi-provider, race, LLM injection), matty69v/Bug-Bounty-Agents (43 persona: scope-guard, exploit-chainer, poc-validator), skraft9/vulnerability-research (cheatsheet + agentic-AI workflow "Quarry VRC"), patientzerosecurity.com (WSTG + individual→chained→business impact), owlshield.ai (LLM firewall → ide probe AI endpoint), Rise The Ranger 2 Satsiber TNI (AD/Forensics/IR).
- **`skills-bounty/` pack dibangun**: `tierpack_bounty.py` + CLI `cyphron tiers --build-bounty` = **33 skill baru (tanpa duplikat tiers2/3), 4 LIVE**. Mapping engine→slot diperbarui.
- **4 engine bounty baru LIVE**: `param_miner` (arjun-style hidden-param diff), `authz_bypass` (matriks bypass 401/403: path trick + X-Original-URL/X-Rewrite-URL, guard: baseline 403 + konten nyata ≠ 403 page), `takeover` (CNAME raw-DNS + NXDOMAIN + fingerprint 10 provider: S3/Azure/GitHub/Heroku/Shopify/Fastly/...; critical saat brand signature, medium lead saat dangling tanpa signature — memakai subdomain dari CT log), `llm_probe` (kepatuhan kebijakan AI endpoint via canary instruction — tanpa payload berbahaya). Test suite **75/75 hijau**.
- **Blackbox pentest hoplite.astheron.my.id**: AUTH-HOPLITE-001 dibuat (owner self-authorized; restrictions no_dos/no_exfil/no_persistence/no_aggressive). Hasil final `out_hoplite_bb2/`: **4 confirmed (3 medium + 1 low), 0 critical, 0 unconfirmed, audit verified** — CSP missing, SPF hilang, DMARC hilang (sama seperti apex airon), CT log 8 subdomain. 4 engine bounty live: takeover (8 subdomain, 0 dangling), param_miner (39 request, 0 param tersembunyi), authz_bypass (0 kandidat 403), llm_probe (0 endpoint AI terbuka).
- **Kisah truth-guarantee baru (FP ke-4 tertahan)**: run pertama melaporkan **2 CRITICAL palsu** ("PUT/DELETE accepted" di root hoplite). Verifikasi manual: PUT/DELETE/PATCH mengembalikan halaman landing yang IDENTIK (36.4KB, beda 1 byte = sentry-trace ID dinamis). **Akar: self-critique method_audit pakai exact-match yang pecah oleh ID dinamis** → diperbaiki dengan normalisasi nilai dinamis (sentry-trace/nonce/csrf/request-id) + similarity ratio bertingkat (≥0.95 = no-op; 0.7-0.95 = unconfirmed; <0.7 = critical sah). Re-scan: FP hilang, 4 temuan asli tersisa. Total FP tertahan sepanjang proyek: SSTI×6, supervisor×1, weak-cred×1, method-audit×2.
- **Re-scan aron.iliterate.ai (57 engine) + scan pertama compro astheron.my.id (AUTH-ASTHERON-001, subdomain lain di-exclude)**: aron = 4 confirmed (SPF, DMARC, lockout, CT-log) + 2 unconfirmed (PUT/DELETE no-op — kini turun benar); **CSP report-only temuan lama HILANG = owner sudah memperbaiki (bukti loop find→fix→verify bekerja)**. astheron compro = 5 confirmed (SPF, DMARC, HSTS missing, CT-log 8 subdomain, Permissions-Policy). Engine bounty live: param_miner (0), llm_probe (0), takeover (0 dangling).
- **FP ke-5 tertahan**: authz_bypass sempat melaporkan "Bypass 403 /api/admin via X-Original-URL" di aron. Verifikasi manual: respons = homepage yang identik (sim 1.0 vs kontrol, beda byte hanya nilai dinamis Next.js); /api/admin sendiri 401 JSON rapi. **Akar: guard membandingkan dengan halaman-403 tapi tidak dengan homepage kontrol** → fix: kontrol homepage + normalisasi dinamis + ambang 0.85 dua arah. Verifikasi live: FP hilang. Total FP tertahan: SSTI×6, supervisor×1, weak-cred×1, method-audit×2, authz-bypass×1. Test suite **75/75 hijau**.

**ADDENDUM 22 — VERDICT DEFINITIF + PDF DESIGN SYSTEM (2026-09-06)**
- **Permintaan user: tanpa bahasa "mungkin" — semua verdict harus ADA/TIDAK, bisa/tidak bisa.** PUT/DELETE aron diselesaikan definitif: **TIDAK VULNERABLE** (PUT path baru → 404 + GET → 404 = tidak ada resource dibuat; PUT/DELETE root → body similarity 1.0 vs GET). Bukti no-write, bukan no-op spekulasi.
- **PDF design system baru** (`pdfout.py` rewrite, standar visual = project MoM `apps/worker/app/render.py`): cover brand+chip risiko, tabel metadata, callout "JAMINAN VERDICT", section bernomor, tabel navy/zebra, kartu temuan (chip severity + band ADA-TERKONFIRMASI + blok bukti mono + PERBAIKAN teal), **matriks "PENGUJIAN DENGAN HASIL TIDAK DITEMUKAN"** (per engine, dari jejak audit — jawaban "tidak ada" juga eksplisit), rekomendasi berprioritas, footer ref+halaman. Tetap **raw-stdlib** (tanpa reportlab). Section 02 = VERDICT PER AREA (ADA/TIDAK untuk semua area). Unicode-safe (em-dash dst dipetakan).
- **Landing page**: section "Contoh Laporan Nyata" + tombol download **PDF / Word / Markdown** (file contoh di `landing/reports/`). Pipeline: satu scan → 3 format (md/docx/pdf).
- PDF di-regenerate untuk out_astheron, out_aron_re, out_hoplite_bb2 (6-7 halaman, diverifikasi visual per halaman via pdfium ke `training/cyphron/pdfcheck/`). **4 bug layout ditemukan & diperbaiki setelah review user**: (1) kartu temuan terbelah antar halaman -> keep-together (hitung tinggi total + strict mode); (2) label bukti yatim di dasar halaman; (3) heading section yatim; (4) **halaman terakhir hilang** (p.ops tidak pernah di-flush ke p.pages - section 05-08 terpotong dari PDF). Plus: duplikasi daftar 33 engine dihapus (02 ringkas + 04 matriks bersih), unicode-safe, label spacing.
- **Deploy VPS**: belum bisa jalan — TIDAK ada kredensial/akses SSH di workspace. Semua aset siap deploy (runtime pure-stdlib Python, CLI `python -m cyphron`, docs PRICING-TIERS). Begitu user memberi host+akses, langkah: rsync `training/cyphron` + `training/.cyphron`, systemd service, nginx reverse proxy, license.json per klien.

**ADDENDUM 10 — INTEL GITHUB HOPLITE (2026-09-03, 6 komit baru Sep 3-4: lokal user 6 komit di belakang origin/main)**
- **LAUNCH PREP**: waitlist automation via Google Apps Script (code.gs 423 baris, `docs/waitlist/`) + pricing docs (`docs/pricing/`: pricing.md draf awal, gpt.md = review ChatGPT, sol.md = review AI kedua). Arah final pricing: Evaluation $0/7d → Professional $149 (300 cr) → Team $449 (1.200 cr) → Business $1.199 (4.000 cr) → Enterprise $3.000+. Model = subscription + credit wallet; semua tier akses semua scanner, kredit jadi gerbang konsumsi.
- Credit weights membengkak drastis di sol.md: static 10 cr, ZAP pen-test 200 cr, **strix quick 120 / standard 300 / deep 700 cr** (= 70 static scan). Dokumen mereka sendiri mengakui cost "1:10:50 heterogen" dan strix "$5-50 LLM + 3.8GB sandbox = very expensive" — **validasi langsung positioning Cyphron (zero LLM cost, zero credit, lokal)**.
- Phase 38-41 = ops/scale (scalability tanpa hardware baru, VPS ops script + backup jadwal WIB + in-app restore, announcements + bell + Resend email). **NOL kemampuan deteksi baru** — scanner cuma version bump.
- **Kasus peringatan**: di tools round mereka menemukan bahwa bake template Nuclei di Dockerfile adalah silent no-op (`nuclei -ut -duc` menghasilkan 0 template) — artinya **setiap scan Nuclei runtime mereka gagal diam-diam sampai kemarin diperbaiki** (bake pakai bare `nuclei -ut`, verifikasi 40 match). Risiko wrapper-dependency yang persis dihindari Cyphron (engine sendiri + test per engine).
- Tools: opengrep 1.29.0, strix 1.6.1 (sandbox tetap 1.3.0), JS deps (ai 7.0.92). "JS catalog" di judul komit = update paket JS, bukan katalog rule.
- Lokal `D:\GODMODE\Hoplite` bisa sync via `git pull` (origin/main = 480a543).

**ADDENDUM 2 — Siapa yang pantas disebut "AI Pentester"?**
Bar (kriteria) AI Pentester sejati — 5 syarat, semua harus terpenuhi: (1) **autonomi** — agen yang menyusun langkah berikutnya dari bukti (hipotesis → uji → keputusan), bukan checklist; (2) **actuation** — benar-benar menyentuh target via tool (HTTP/browser/terminal) dalam sandbox; (3) **eksploitasi + PoC** — membuktikan impact dengan bukti reproducible, bukan sekadar menamai temuan; (4) **chaining** — merangkai temuan jadi attack chain; (5) **reporting**. Yang cuma nge-run checklist = **scanner** (ZAP/Nuclei/Opengrep). Yang membimbing manusia = **asisten** (PentestGPT). Yang otonom + membuktikan = **AI Pentester**.

Ranking kandidat (tertinggi dulu):
1. **Strix** — penuh di 5 syarat; standar referensi saat ini (multi-agent, sandbox Docker, PoC-validated). Ironi: inilah mesin yang dijual Hoplite sebagai fitur.
2. **PentAGI** — nyaris penuh (multi-agent recon/exploit/reporter, sandbox); lebih berat di infra/token.
3. **Shannon** — otonom tapi validasi & coverage lebih dangkal.
4. **PentestGPT** — BUKAN AI pentester; **asisten** human-in-the-loop (manusia yang mengeksekusi).
5. **PentestAgent** — kerangka agen CLI mini; belum matang.

Di luar 5 repo:
- **Hoplite** = BUKAN AI pentester; **platform pemanggil AI pentester milik orang lain**. Komponen "AI"-nya sendiri (FP review Opengrep, penulisan laporan) bukan aktivitas pentesting. Cabut Strix → menu "AI Pentest"-nya hilang.
- **Cyphron sekarang** = belum; otak tanpa tangan (pengetahuan + etika tanpa actuation).
- **Cyphron setelah runtime yang direncanakan** = pantas gelar itu JIKA loop+tool+verifier jalan — dan jadi satu-satunya kandidat yang **memiliki** lapisan reasoning-nya sendiri, bukan menyewa. Peta fase: Fase 2 (actuator) = tangan, Fase 4 (loop + gate) = autonomi, Fase 5 (verifier + PoC) = pembuktian.

**ADDENDUM 23 - REGENERASI PENUH 4 TARGET + REPORT FINAL DI DOWNLOADS (2026-09-07)**
- Semua folder report lama dihapus (out_aron, out_aron_full, out_aron_re, out_airon_b3/b4, out_hoplite_bb/bb2, out_lab, out_readonly + Downloads lama). Pentest diulang dari nol untuk **4 target** dengan 57 engine + PDF design system final.
- Hasil (semuanya audit verified, 0 critical): aron 5 confirmed (DMARC/SPF/lockout/dir admin/CT-log) + 2 observasi no-write; astheron compro 5 (DMARC/SPF/HSTS/CT/Permissions-Policy); hoplite 5 (CSP/DMARC/SPF/CT/dir admin) + 2 observasi; airon 5 (CSP/DMARC/SPF/lockout/CT) + 2 observasi.
- **Laporan final user**: C:/Users/lenovo/Downloads/cyphron-reports/ berisi 4 folder (aron-iliterate-ai, astheron-my-id, hoplite-astheron-my-id, airon-astheron-my-id), masing-masing PDF+DOCX+MD+findings.json+audit.jsonl. Contoh landing di-update dari scan aron terbaru. Pola konsisten lintas target: CSP/HSTS header + SPF/DMARC apex + lockout login = 3 kelompok perbaikan yang sama, satu patch DNS+middleware menutup semuanya.
**ADDENDUM 24 - RESPONS KRITIK GPT + V2 CYBER INTELLIGENCE (2026-09-07)**
- GPT menilai (dari 4 report lama): engine 8/10, safety 9/10, verification 6/10, depth 5-6/10, autonomy 4/10 - '40 langkah identik = deterministic pipeline, bukan agent'. Kritik DITERIMA dan dieksekusi, bukan dibantah.
- **Planner v2 evidence-driven LIVE**: 19 engine di-gate bukti world model (gql_depth/alias butuh endpoint graphql; jwt_* butuh token JWT terdeteksi di cookie; pagin/sort/id_seq/json_inj/css_inj/proto_c butuh param; sourcemap2/dom_xss butuh aset JS; OSINT butuh host publik). **Reasoning trail hipotesis (H-graphql, H-jwt, H-params, H-idor, H-pagination, H-sortinject, H-jsassets, H-graphql-discovery) tersimpan di world + TABEL BARU di laporan (bagian 03)**. Bukti adaptif: hoplite 30 langkah, astheron 30, aron 32, airon 40 (target ber-parameter) - tidak ada lagi 40 identik.
- **Temuan agresif diredam**: /admin/ 200 kini KANDIDAT unconfirmed (bisa halaman login); lockout wajib sinyal (429/423/403 + kata CAPTCHA + delay progresif terukur, bukan cuma 200); CT log diganti 'Attack surface disclosure' tanpa CWE (bukan vulnerability).
- **Taxonomy finding_class**: exploitable / weakness / posture / surface - kolom baru di verdict table + detail temuan (CSP/SPF/DMARC tidak lagi setara exploit).
- **Report jujur**: metodologi mencantumkan engine yang BENAR-BENAR dieksekusi (dari jejak audit); skill ditandai sebagai konteks knowledge (bukan klaim pengujian).
- **Attack-Chain Reasoner v1 LIVE (deterministik)**: rantai disusun hanya dari temuan terkonfirmasi (mis. aron: PATH-1 phishing->guess->ATO karena SPF+DMARC+lockout hilang; confidence 75%).
- **ROADMAP V2 CYBER INTELLIGENCE** ditulis: docs/ROADMAP-V2-CYBER-INTELLIGENCE.md - struktur Attacker/Defender/Core-Reasoning, 4 kelas kemampuan DISCOVER-REASON-VALIDATE-DEFEND, FAZ 0 (selesai) s.d. FAZ 6 (persona agents), metric keberhasilan. FAZ 1 World-Graph, FAZ 2 planner adaptif penuh (LLM slot), FAZ 3 zero-day research, FAZ 4 chain v2, FAZ 5 defender loop.
- Semua laporan final user di C:/Users/lenovo/Downloads/cyphron-reports/ (4 target, PDF+DOCX+MD+findings+audit). Test suite 75/75 hijau.
**ADDENDUM 25 - FAZ 1/3/5 V1 SELESAI VIA SUB-AGENT TEAM (2026-09-07)**
- Dieksekusi pakai 3 implementer sub-agent paralel (semua sukses, 0 gagal): (A) cyphron/graph.py Knowledge Graph v1 - 19 test; (B) cyphron/tools/exploitability.py Exploitability Verifier + detection_rule Sigma-lite - 6 test; (C) cyphron/anomaly.py ResponseBaseline + InvariantLibrary (3 invariant bisnis) + zero_day_candidates feed - 20 test.
- Integrasi: exploitability = engine ke-54 (tier business), planner menjalankannya sebagai verifier CSP; anomaly feed -> hipotesis H-zd-*; reporting: section 10 KNOWLEDGE GRAPH (stats), 11 DETECTION RULES (SOC), graph.db+graph.json per folder laporan.
- **Test suite kini 120/120 hijau** (75 + 45 baru). Keempat laporan di Downloads di-regenerate (graph + detection appendix termasuk).
- Sisa V2: FAZ 2 (re-plan/budget/LLM slot), FAZ 4 v2 chain lintas-target, FAZ 6 persona agents.

**ADDENDUM 26 - FAZ 2 SELESAI: ADAPTIVE PLANNER v2 (RE-PLAN + BUDGET + EV) (2026-09-08)**
- **Tiga fitur FAZ 2 LIVE (deterministik; LLM slot tetap terbuka per R4)**: (1) EV ordering - urutan langkah = impact x confidence / max(cost,1) descending, tie-break deterministik (tool,url,param) sehingga dua world logis identik menghasilkan sekuens plan identik; (2) re-plan setiap temuan - orchestrator memanggil planner.observe_findings() tiap step ber-temuan, hipotesis reaktif H-react-* (params/deep-sqli/deep-xss/exploit) dibuka DAN follow-up-nya dieksekusi dalam run yang sama; (3) budget allocation - alokasi request per hipotesis proporsional impact x confidence (reserve minimum per ronde, hard-stop di budget, re-allokasi saat confidence naik), ledger planner.budget_ledger() == world.budget_ledger.
- **API baru**: Step.cost + Step.hypothesis_id; DeterministicPlanner(..., request_budget=N).observe_findings(findings, clean_tools=None) -> [hipotesis baru]; world dapat field findings_seen/replan_events/budget_ledger (+snapshot). Laporan: tabel 03 + kolom Conf+Budget, tabel 03b RE-PLAN DINAMIS (pemicu -> hipotesis -> follow-up), metodologi 08 menjelaskan alokasi proporsional + re-plan otomatis.
- **Eksekusi via sub-agent (catatan jujur infra)**: dispatch paralel pertama (implementer+test-engineer) balas error transport ("captcha verify failed"/"Model request failed"), TETAPI implementernya ternyata sempat menulis sebagian besar kode sebelum mati. Dispatch implementer ulang menemukan state setengah-jadi (5 test gagal), memperbaiki akar masalah (reserve alokasi per ronde, funding follow-up antar-plan, gate bukti clobber/authz_bypass, dedup replan_events) sampai 155/155. Pass validasi adversarial (test-engineer kedua, +27 test test_faz2_adversarial.py) menemukan 3 temuan: crash reporting pada steps:None (FIXED), determinisme bergantung urutan insert dict (FIXED via tie-break sekunder), rationale exploitability tumbuh tak-idempoten (FIXED). Ke-3 fix diterapkan langsung oleh agent utama; decorator expectedFailure dilepas.
- **Test suite 182/182 hijau** (120 basis + 35 FAZ2 implementer/acceptance + 27 adversarial), 0 expectedFailure.
- **Bukti produksi (4 target di-regenerate ke C:/Users/lenovo/Downloads/cyphron-reports/)**: acceptance FAZ 2 terbukti nyata - aron 31 langkah 0 re-plan (tak ada primitive -> tak ada hipotesis reaktif; DMARC+SPF confirmed, lockout TIDAK muncul lagi karena auth_probe dieksekusi dan BERSIH - indikasi owner memasang rate-limit, pola find->fix->verify; /admin/ + PUT/DELETE jadi unconfirmed sesuai redaman Addendum 24); astheron 29 langkah 5 confirmed (DMARC/SPF/HSTS/CT/Permissions-Policy); **hoplite 29 langkah - HIGH pertama: "Exploitability CONFIRMED: injection primitive tanpa penahan CSP" (refleksi marker mentah + CSP absent)** + H-react-exploit terbuka (1 hypothesis-opened di audit); **airon 40 langkah - HIGH sama pada param q (CSP Report-Only tak menegakkan) + 2 re-plan (H-react-exploit + H-react-params) -> follow-up param-probe ekstra dieksekusi run yang sama**. Semua audit chain verified, 0 FP.
- Catatan: temuan HIGH exploitability adalah keluaran desain FAZ 5 (verifier "apakah CSP yang hilang meninggalkan primitive nyata?") yang kini dinaikkan lebih awal oleh EV ordering (step 6) dan memicu re-plan - bukti tiga lapis FAZ 2+5 bekerja bersama. DOCX tetap format ringkas 8-bagian (tidak memuat tabel 03/03b - perilaku yang sudah ada sebelumnya; PDF memuat semuanya, terverifikasi via ekstraksi stream).
- Sisa V2: FAZ 4 v2 (chain lintas-target), FAZ 6 (persona agents), R4 LLM slot.

**ADDENDUM 27 - PRECISION LAYER: SCOPE ENFORCEMENT + SEMANTIK CT-LOG + APP-LIVENESS (2026-09-08)**
- **Pemicu (kasus FP roomchat)**: rekan (owner Hoplite) menyebut hasil attack-surface Cyphron "false positive" - host astheron (inti/s3) terlihat hidup padahal aplikasinya sudah dihapus ("config nginx masih enabled tapi aplikasi aslinya gk ada"). Diagnosis: deteksinya benar (host MEMANG hidup), yang salah adalah SEMANTIK temuan: nginx live != app live, TLS valid != app live, CT entry != app live. Tiga perbaikan dieksekusi (urutan: kepatuhan dulu).
- **TUGAS 2 - scope enforcement per-destination (prioritas tertinggi; bug kepatuhan nyata)**: (1) `AuthorizationGate.evaluate_host(host, port)` + `ToolContext.host_scope()` - cek ScopeSpec untuk host DESTINASI mana pun TANPA fast-path passive (DNS resolve dan HTTP ke host penemuan engine = aksi aktif, wajib in-scope); (2) **takeover** ditemukan bocor total: risk_tags={"passive"} padahal melakukan getaddrinfo+dns_cname+http_get ke SEMUA kandidat sibling dari CT log tanpa cek scope - kini dipartisi dulu per-destination: in-scope -> uji aktif; out-of-scope -> NOL query, jadi passive OSINT lead (temuan class=surface, status=unconfirmed, metodologi "dari data CT publik saja, tidak diuji aktif karena di luar scope"); excluded -> tidak disentuh dan tidak dilaporkan; tiap kandidat tercatat di audit kind=host-scope-decision; risk_tags diperbaiki jadi {"passive","active"}; (3) **smtp_probe** juga dicek: MX host di luar scope -> NOL koneksi EHLO, lead pasif saja; (4) sweep seluruh tools/*.py: crawler terbukti same-host saja, wayback/ct_log/sca_probe menuju API OSINT publik (bukan infra target), dkim/email = DNS record domain in-scope - bersih. (5) Laporan: scope AKTIF dari dokumen (targets/excluded/CIDR/ports) tampil di MD+DOCX bagian 02 dan PDF meta+bagian 08, dengan kalimat eksplisit: wildcard = probing sibling sah; scope sempit = sibling hanya diamati pasif.
- **TUGAS 1 - semantik CT log**: Finding direstrukturisasi OBSERVASI (objektif, satu-satunya yang confirmed: "N hostname teramati di CT publik") / KANDIDAT SENSITIF (HEURISTIK nama, BUKAN FAKTA, "perlu konfirmasi policy owner") / DAMPAK: TIDAK DIKLAIM ("penilaian host boleh publik sepenuhnya milik policy pemilik domain"). Frasa "tidak semestinya diketahui publik" dihapus; severity info default, low hanya bila ada kandidat heuristik; kata "bocor" dibersihkan dari title/description/tool description.
- **TUGAS 3 - engine `liveness_probe` (total engine kini 59, tier pro)**: klasifikasi 4 lapis eksplisit di data temuan - (1) host liveness (HTTP merespons), (2) server fingerprint (header), (3) application liveness (framework/form/konten diharapkan dari world model + baseline + 6 path umum), (4) backend liveness: TIDAK DAPAT DIKONFIRMASI dari luar, tidak pernah diklaim. Server hidup + fingerprint app tidak terbentuk -> temuan "Stale/orphaned surface candidate" (class=surface, status=unconfirmed, low bila halaman default server terdeteksi / info; rekomendasi matikan vhost/hapus DNS). FP-guard: minimal 1 respons sukses; fingerprint dicek dulu; halaman login = aplikasi HIDUP; predikat hanya "app fingerprint not established", bukan klaim backend mati. Integrasi planner: hipotesis H-stale (impact 1) + step setelah crawler/browser di mode offensive.
- **Test suite 193/193 hijau** (182 + 11 baru di tests/test_precision_layer.py: scope 5, CT semantik 2, liveness 4). Semua pure stdlib.
- **Bukti live 4 target di-regenerate ke Downloads** (semua audit chain verified): airon 40 langkah - CT semantik baru ("8 nama subdomain... 1 kandidat sensitif - heuristik nama", kandidat = inti), **8 host-scope-decision SEMUA DENIED = nol query ke sibling (inti, s3, cms, hoplite, dll. kini passive lead)**, liveness = app TERBENTUK (10 bukti); hoplite 30 langkah - sama (8 denied; liveness app terbentuk 2 bukti; CT 1 kandidat sensitif heuristik); aron 32 langkah - 5 denied, app terbentuk (4 bukti); astheron apex - host tidak merespons di run ini (edge), liveness TIDAK menilai apa-apa sesuai FP-guard (tanpa respons sukses = tanpa kesimpulan). Hasil scan inti tidak berubah (6/5/4/4 confirmed) - precision layer menambah SEMANTIK, bukan menambah noise.
- **Jawaban atas kritik "false positive"**: temuan attack-surface sekarang tidak bisa lagi dibaca salah - CT entry diberi label heuristik + passive-only, host luar scope tidak disentuh sama sekali (bukti audit per-host), dan "server hidup tanpa aplikasi" menjadi temuan hygiene eksplisit dengan 4 lapis liveness. FP tertahan sepanjang proyek tetap 10 (SSTI x6, supervisor, weak-cred, method-audit x2, authz-bypass) - kasus roomchat bukan FP deteksi, melainkan gap semantik yang kini tertutup.
- Keputusan konservatif yang dicatat: (1) takeover/smtp_probe risk_tags dinaikkan jadi aktif (dulu passive yang tidak jujur) - artinya di mode read-only keduanya ditolak penuh; (2) kandidat excluded tetap tercatat di audit (keputusan, tanpa query) tapi tidak muncul di temuan; (3) sinyal JS asset saja TIDAK dihitung app fingerprint kuat (bisa SPA shell kosong) - hanya dipakai sebagai bukti pendukung.

