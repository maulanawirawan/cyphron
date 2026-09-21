# ROADMAP-FULLPOWER-SHOWCASE — Cyphron level "dilirik korporat" [DIPARKIR]

> **[DIKONSOLIDASIKAN 21-09-2026] Status terkini seluruh item ada di [STATUS-MASTER.md](STATUS-MASTER.md) — dokumen ini jadi arsip rincian.**

> Status: dieksekusi 18 Sep 2026 (semua batch B1-B5 tuntas, suite hijau per
> batch). PRINSIP PENYERAPAN ILMU: pahami teknik dari riset publik → tulis
> ulang versi Cyphron sendiri (bukan tempel kode; hasil akhir = pemikiran &
> kode kita; sekaligus bersih dari sisi lisensi); tanpa narasi provenance
> eksternal di seluruh repo.

## 0. TESIS (dari bukti pasar)
Yang bikin researcher/produk "dilirik" korporat — terbukti dari data:
1. **Kedalaman satu niche** + publikasi terbuka (bukan lebar tanpa kedalaman).
2. **Tool yang benar-benar dipakai orang** (bintang/usage = bukti sosial).
3. **Demo nyata yang bisa ditunjukkan** dalam 5 menit ke lead.
4. **Laporan kelas konsultan** (kebutuhan terbesar korporat Indonesia: bukti
   kepatuhan + narasi risiko, bukan payload).
5. Bukan DDoS — volume trafik itu skill paling bawah, tidak bisa dijual legal,
   dan menghancurkan kredibilitas. Yang korporat beli: **red team berizin,
   uji ketahanan (resilience), pentest mobile, threat intel**.

## 1. ARSITEKTUR POLYGLOT ENGINE (fondasi)
- Core Python tetap: orchestrator + guardrails + evidence ledger (satu pintu).
- **Engine Adapter Layer**: engine non-Python dideklarasikan via manifest
  (nama, bahasa, runtime, risk_tags, scope), dijalankan lewat bridge
  subprocess; auto-detect environment (g++/go/node/jdk/rustc ada atau tidak),
  fallback anggun bila runtime absen.
- Guardrail tetap memaksa semua bahasa: authorization gate, rate-limit,
  cease-on-data, redaksi, cap request.
- Target bahasa batch-1: **C++ (latar user)** + Go; batch-2: Rust/Node.
- Hasil showcase: "Cyphron = agent multi-bahasa yang tahu lingkungannya" —
  klaim yang jarang dimiliki tool sejenis.

## 2. SUITE SHOWCASE (skill/script/engine level corporate)
### 2a. Mobile/APK pentest kit (niche terbesar Indo: bank & fintech APK)
- Perluas `apk_surface_probe` → analisis statis APK: perm berbahaya, native
  lib inspection, signature-verification assessment, anti-tamper check,
  Frida-detection assessment (untuk laporan "seberapa siap app Anda diuji").
- Keluaran: laporan pentest mobile siap kirim ke dev bank/fintech.
- Ilmu referensi publik: teknik bypass/hook/hardening (reimplement sendiri,
  dibingkai untuk ASSESSMENT defensif — bukan cracking app orang).

### 2b. Deobfuscation & attribution kit (sudah terbukti di kasus kamipex)
- Formalisasi alur yang tadi berhasil: decoder RC4/base64/rotasi berantai,
  sandbox DOM + CDP capture, ekstraksi kit phishing, pemetaan afiliasi,
  validasi anti-FP (base58check dll) → 3-4 engine + CLI.
- Bonus showcase: **publikasi studi kasus kamipex (GAMBLER network)** dengan
  redaksi — ini artefak "dilirik" tercepat yang kita punya, riset intel
  fraud-as-a-service asli, bukan teori.

### 2c. Red-team tradecraft catalog (berizin, lab-terisolasi)
- Katalog teknik simulasi APT-lite untuk engagement berotorisasi: initial
  access demo, C2- simulation di lab, evasion assessment, purple-team notes.
- Setiap teknik: lab-sandbox + dokumentasi + batas otorisasi eksplisit.
- Fungsi: bukti kemampuan ofensif TINGKAT ATAS tanpa menyentuh infra orang.

### 2d. Resilience & load (versi legal dari "DDoS") — SELESAI 19 Sep
- `resilience.py`: ladder VU bertahap bounded (cap 50 VU / 180s total, rate
  tetap, tanpa eskalasi) + knee detection deterministik + verdict
  SURVIVE/DEGRADE/FAIL + RESILIENCE-REPORT.md siap klien; CLI `resilience`
  wajib --auth (gate active+load). Modul flood/DDoS TETAP tidak ada —
  kebutuhan "tes website sendiri" terjawab penuh di sini.

### 2h. Fraud-intel & attribution kit (baru, selesai 19 Sep)
- `fraudintel.py` + CLI `fraud-dossier`: analisis nomor HP (E.164 + blok
  prefix operator ID, confidence + catatan porting) dan nomor rekening
  (kandidat bank dari panjang terdokumentasi; ambigu DILABEL, hint klien
  mempersempit); dossier pengaduan teredaksi dengan urutan langkah resmi
  (CekRekening.id / bank / OJK 157 / Polri Tipid Siber) + checklist bukti.
- BATAS ditegakkan: TANPA resolusi identitas orang; TANPA data kebocoran
  (UU PDP/UU ITE) — Cyphron menyiapkan paket pengaduan korban, identitas
  pelaku tetap kewenangan operator/bank/penegak hukum.

### 2e. SAST/Taint polyglot (dari ROADMAP-UNITY)
- Rule engine + taint source→sink→sanitizer untuk Python/JS/C++ — C++ masuk
  batch-1 (latar user).

## 2f. CODE INTELLIGENCE — GAP-CLOSING MASTER LIST (semua yang belum setara)
> Kondisi 16 Sep: `code_audit` = SAST bibit (regex pack ~15 rule konservatif,
> file:line + saran remediasi, Python/JS-centric); `sca_probe` = OSV-Scanner
> equivalent (manifest → OSV.dev); `secret_scan`/`js_cred_sweep`/`apk_surface_probe`
> pelengkap. Ini BUKAN setara kelas dunia — berikut target paritas penuh:

### CI-1. SAST kelas dunia (prioritas #1 — jantung Code Intelligence)
- **AST-based rules** (bukan regex): parser pohon per bahasa (Python: `ast`
  stdlib; JS/TS: acorn-lite via bridge; C/C++: libclang binding; PHP/Java
  bertahap) — rule = pattern terstruktur dgn **metavariable** (`$X`, `$F`),
  bukan teks mentah.
- **Taint tracking** dataflow: source (input user) → sink (query/exec/render)
  → sanitizer (escape/param binding) — mendeteksi SQLi/XSS/RCE yang regex
  tidak akan pernah tangkap; hasil = jalur lengkap baris-demi-baris
  (bukti kelas konsultan).
- **Rule pack besar bertingkat**: core (30-50 rule AST sendiri) + pack
  per-kategori (injection, deserialization, crypto, authz, SSRF, path
  traversal, SSTI, XXE, race) + kustom per-klien (file .cyphron-rules).
- **Autofix suggestion** per rule (patch proposal, bukan auto-apply).
- **CI mode**: exit code, sarif/json output, diff-aware (scan hanya file
  berubah) — bahasa bikin perusahaan tinggal pasang di pipeline.
- Zero-FP tetap: tiap rule punya `confidence` + contoh positif/negatif test.

### CI-2. Proxy / Intercept layer (kelas Burp, versi CLI-first)
- **Proxy HTTP(S) lokal** (mitm via ssl stdlib + cert CA lokal) dengan
  intercept/repeat/history — TUI (bukan GUI dulu) + `--proxy` mode.
- **CDP bridge** (sudah terbukti di kasus kamipex): drive browser nyata,
  tangkap trafik/DOM/cookie — formalisasi jadi engine `browser_scout`.
- Repeater/fuzzer lanjutan: encoding chains, payload insertion points otomatis.

### CI-3. Distributed scanning (kelas multi-worker fleet)
- Queue + worker multi-proses/multi-mesin (stdlib multiprocessing + antrean
  file/redis opsional), target partition, progress merge, laporan gabungan.
- Mode "fleet": satu koordinator + N worker (VM/VPS milik sendiri, berizin).

### CI-4. DAST orchestration (kelas OWASP ZAP)
- Spider aktif bertahap (crawl-depth profiles: dev-cicd/standard/full),
  active-scan policy per fase, semua tetap lewat authorization gate +
  budget — DAST yang sopan tapi lengkap.

### CI-5. Code Intelligence tambahan
- **IaC/container config check**: Dockerfile/docker-compose/kubernetes
  misconfig (root user, latest tag, secrets di env, privileged).
- **License compliance scan** (SCA lanjutan) + **SBOM generator** (CycloneDX
  JSON) — korporat suka SBOM.
- **Diff-aware verdict**: temuan baru vs baseline (sudah ada `drift`/`verify`
  — ditingkatkan ke level file/function).

### CI-6. Packaging & publikasi (supaya dilirik)
- Landing/demo page interaktif + video demo 3 menit + kasus studi
  (kamipex/GAMBLER redaksi) + halaman credibility (Hall of Fame, laporan).
- Docs site + quickstart satu-perintah + badge CI.
- **Bahasa klaim (disiplin)**: jangan jual angka mentah ("53 paths",
  "40 engines") — jual kemampuan komposisi/verdict; klaim CVE memakai
  "High-confidence deterministic matching with ambiguity rejection" +
  tabel benchmark (Precision/Recall/F1, CPE & version resolution accuracy,
  exploit-validation rate). Selaras ROADMAP-UNITY §4.

## 2g. LANGUAGE FLEET — 36 bahasa (B6, selesai 19 Sep)
- Registry `languages.py`: 36 bahasa (python, js, ts, java, kotlin, scala,
  groovy, clojure, c, cpp, csharp, fsharp, vb, go, rust, swift, dart, php,
  ruby, perl, lua, r, julia, fortran, pascal, haskell, ocaml, erlang,
  elixir, zig, nim, crystal, d, powershell, shell, sql) dengan ekstensi +
  fingerprint isi + shebang + sink-rules + runtime binary kandidat.
- Deteksi otomatis zero-FP: ekstensi = sinyal kuat, konten menambah skor;
  dua kandidat berdekatan tanpa ekstensi = AMBIGU DITOLAK (bukan ditebak).
- SAST: sink-rules per bahasa (command injection/deser/eval/dynamic exec)
  menyatu ke sast.py; bahasa non-AST dilabel confidence lebih rendah (jujur).
- Runtime fleet: adapter B1 kini tahu binary tiap bahasa; JVM end-to-end
  terbukti (javac -d + java -cp fixture adapter).
- lang-sync: hash knowledge pack versioned + deteksi versi runtime terpasang
  (--version, tanpa instal); CLI `lang-scan` / `lang-sync`. Auto-update =
  update pack via repo; kompiler TIDAK diinstal otomatis.
- Lesson AV: fixture uji berisi pola webshell literal membuat Defender
  mengkarantina file test — payload dipecah string + test penjaga AV-safe.

## 3. SHOWCASE ARTIFACTS (cara dilirik)
- Landing/demo page Cyphron (folder landing/ sudah ada) + demo 5-menit script.
- Publikasi riset: kasus kamipex/GAMBLER (dengan izin user, redaksi data pribadi).
- Track record: Hall of Fame & laporan diterima (BINUS/BSSN/Bali) jadi halaman
  "credibility" — ditambah hasil program berbayar begitu panen.
- Konsistensi: suite ini menghasilkan MATERI DEMO setiap kali dipakai di
  engagement nyata (dengan izin) — konten menjual dirinya sendiri.

## 4. PAGAR TETAP
- Tidak ada modul DDoS/DoS; "stress" hanya bounded + berotorisasi.
- Semua teknik bypass/evasion = untuk assessment defensif & lab, bukan
  menyerang sistem orang.
- Penyerapan ilmu = reimplementasi hasil pemahaman (bukan salin-tempel);
  lisensi repo publik dihormati (GPL tidak dicampur).
- Zero-FP, evidence ledger, redaksi — tidak kompromi di suite manapun.

## 5. BATCH (dieksekusi 18 Sep 2026 — suite hijau per batch, commit+push)
- [x] B1: Engine Adapter Layer + manifest + auto-detect + 1 engine C++ pilot
      (ca40537 — adapter.py + entropy_audit.cpp; runtime absen = skipped
      anggun; jalur eksekusi dibuktikan via fixture node).
- [x] B2: Deobfuscation/CDP/attribution kit (fa24543 — chain_decoder,
      wallet_fp_guard base58check, phishing_kit_extract, affiliate_mapper;
      sisi DOM = browser_scout U4).
- [x] B3: APK pentest kit v1 + laporan mobile (997090b — apk_kit.py:
      perm berbahaya via string-pool AXML, native/packer, signing v1/v2,
      anti-tamper coverage, MOBILE-REPORT.md).
- [x] B4: SAST/Taint + CI-1..CI-6 (6c02272 — sast.py AST+metavariable+taint
      +SARIF+diff-aware; proxycore intercept; fleet partisi/merge; dast
      profil fail-closed; iac/sbom CycloneDX + license).
- [x] B5: Showcase artifacts (studi kasus GAMBLER ter-redaksi + DEMO-5-MENIT
      + DEMO-VIDEO-3MENIT + INDEX docs) — commit ini.
- Tiap batch: test offline, suite hijau, commit+push per batch. ✅
- [x] B6 (19 Sep): Language Fleet 36 bahasa (§2g) + red-team lab expansion
      (RTL-01..12, c2-sim loopback, privesc read-only — Unity U9 full).
