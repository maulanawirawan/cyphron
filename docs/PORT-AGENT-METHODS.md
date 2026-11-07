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

---
Blok B10 (#0271-#0300, 8 Nov) — sumber mukul975/Anthropic-Cybersecurity-
Skills (Apache-2.0 — konsep, bukan teks). Dua entri diekstrak jadi tool
(#0271 -> tools/ct_baseline_diff.py, #0289 -> tools/ioc_defang.py);
sisanya didistilasi di bawah. #0272/#0285/#0296 = di luar domain.

## 9. Pengayaan IOC via SOAR (dari mukul975/automating-ioc-enrichment)
- [ ] routing per tipe dulu (ip/domain/url/hash -> sumber berbeda) sebelum
      fan-out; jangan query semua sumber untuk semua tipe
- [ ] skor keyakinan komposit eksplisit (mis. rasio malicious VT x bobot +
      skor AbuseIPDB x bobot, cap 100) — selalu tulis formulanya di output
- [ ] budget rate limit dicatat per API (VT free 4/menit), throttle sebelum
      kirim, backoff pada HTTP 429 (patuhi header Retry-After)
- [ ] cache hasil pengayaan (TTL ~24 jam) — query ulang IOC sama = buang biaya
- [ ] kegagalan API TIDAK boleh menghasilkan "bersih" — log + fallback,
      tandai partial (prinsip fail-closed cyphron)
- [ ] skor otomatis tidak pernah memicu blokir sendiri — manusia yang
      konfirmasi (keputusan berdampak butuh persetujuan)

## 10. Benchmark Kubernetes (dari mukul975/benchmarking-kubernetes-with-kube-bench)
- [ ] runbook eksternal (kube-bench butuh node/cluster) — cyphron mengaudit
      offline via tools/k8s_audit_triage.py + k8s_rbac_audit.py
- [ ] triase output: FAIL = perbaiki sekarang, WARN = kategorikan risiko,
      PASS = bukti kepatuhan; re-run untuk verifikasi remediasi
- [ ] scope per target: master/node/etcd/policies — audit satu per satu,
      jangan campur temuan lintas komponen

## 11. Pelacakan infrastruktur adversary (dari mukul975/building-adversary-infrastructure-tracking-system)
- [ ] pivot berlapis dari seed: IP (reverse-IP), domain (riwayat pasif-DNS),
      WHOIS (registran/registrar), sertifikat (SAN sama), NS/MX
- [ ] simpan graf relasi (node = indikator, edge = resolves_to/whois_same/
      cert_shared) — pivot berikutnya baca graf, bukan daftar datar
- [ ] pola yang dicatat per aktor: registrar favorit, hosting, pola penamaan,
      DGA, reuse sertifikat antar kampanye
- [ ] sumber pasif-DNS/SecurityTrails = jaringan+API key — di cyphron cukup
      rdap-enrichment (read-only) untuk pivot registrar

## 12. Pustaka pola serangan dari laporan CTI (dari mukul975/building-attack-pattern-library-from-cti-reports)
- [ ] ekstraksi perilaku per kalimat: kata kerja aksi (used/deployed/
      exfiltrated) + kata kunci teknis -> kandidat teknik ATT&CK
- [ ] tabel kata kunci -> T-ID dikelola eksplisit (dapat diaudit, bukan
      NLP gelap); alat/malware dikenali via daftar nama, bukan tebakan
- [ ] setiap pola disimpan sebagai objek terstruktur (STIX Attack Pattern
      SDO) + tautan laporan sumber — provenance wajib
- [ ] output akhir = template deteksi (Sigma/YARA) + gap telemetri, bukan
      ringkasan prosa

## 13. Pipeline submission malware (dari mukul975/building-automated-malware-submission-pipeline)
- [ ] pre-screen hash (sha256) SEBELUM submit sandbox — sampel dikenal
      tidak perlu analisis ulang; dedup by sha256 dengan penyimpanan hasil
- [ ] karantina file ke nama sha256.sample — identitas konten = nama file
- [ ] sandbox terisolasi penuh dari produksi (jaringan one-way/independen)
- [ ] verdict sandbox = satu sinyal, bukan kesimpulan; gabung dengan IOCs
      yang diekstrak untuk triase

## 14. C2 Sliver (dari mukul975/building-c2-infrastructure-with-sliver-framework)
- [ ] sisi biru: yang dideteksi = listener mTLS/DNS/WG, implant beacon vs
      session (interval reguler = sinyal), operator config files
- [ ] audit lingkungan biru: pastikan egress tidak bisa ke port C2 umum
      (443/53/8888/51820 ke luar), DNS logging menangkap channel DNS
- [ ] tidak ada inti deterministik untuk di-build — runbook ops merah

## 15. Redirector C2 (dari mukul975/building-c2-redirector-infrastructure)
- [ ] bentuk yang dipantau (biru): reverse-proxy yang memfilter URI/UA
      profile-matching + 302 decoy untuk sisanya = T1090.002
- [ ] deteksi: host yang merespons berbeda utk UA/URI beda (kandidat
      redirector); TLS certificate reuse antar edge
- [ ] lab cyphron: verifikasi header/UA-filtering bisa diuji via playbook
      HTTP biasa (bandingkan respons dua permintaan)

## 16. Cloud SIEM Sentinel (dari mukul975/building-cloud-siem-with-sentinel)
- [ ] provisioning (az CLI) = runbook ops; yang layak distilasi = pola KQL
      deteksinya: impossible travel (jarak vs delta-waktu per user),
      konsol login multi-IP, mass deletion S3
- [ ] setiap aturan analytics wajib: mapping ATT&CK, severity, runbook
      respons — aturan tanpa runbook = noise

## 17. Pola aturan deteksi SPL (dari mukul975/building-detection-rule-with-splunk-spl)
- [ ] enam pola generik yang dipakai ulang di SEMUA SIEM: threshold
      (count>ambang per window), sequence (gagal lalu sukses), baseline
      anomaly (x > avg+3*stdev periode lalu), lateral (dc(host)>N per
      user+src), exfil (bytes_out besar / dest unik banyak), berbahaya-
      cmd (daftar token seperti encodedcommand/iex/downloadstring)
- [ ] setiap pola tulis sebagai: sumber log, agregasi, ambang, severity,
      mapping ATT&CK — konsep ini portabel lintas produk

## 18. Aturan Sigma (dari mukul975/building-detection-rules-with-sigma)
- [ ] lint sigma tidak di-build: butuh dep YAML (repo stdlib-first) dan
      belum ada konsumen sigma di cyphron — disiplinnya saja yang diambil
- [ ] anatomi rule yang benar: id (uuid stabil), status, level, logsource
      (category/product), detection (selection + filter + condition),
      falsepositives eksplisit, tags attack.tNNNN
- [ ] filter FP = kondisi negatif eksplisit di condition (not 1 of
      filter_*), bukan menghapus seleksi
- [ ] konversi lintas backend (SPL/Lucene/KQL) = tugas pySigma; uji hasil
      konversi dgn sampel event nyata sebelum dipakai

## 19. Pipeline DevSecOps GitLab CI (dari mukul975/building-devsecops-pipeline-with-gitlab-ci)
- [ ] urutan stage yang sehat: build -> test -> security (SAST, secret,
      dep, container) -> deploy-staging -> DAST -> deploy-production
- [ ] secret detection jalan di SETIAP commit (paling murah, paling
      bernilai); DAST hanya utk environment staging yang stabil
- [ ] gate: temuan critical = gagalkan pipeline (fail-closed), bukan catatan
- [ ] padanan cyphron: tools/exploit_ci_gate.py + diff_risk_scan untuk
      perubahan berisiko

## 20. Federasi identitas SAML (dari mukul975/building-identity-federation-with-saml-azure-ad)
- [ ] pilih model sadar-risiko: federated (AD FS) vs managed (PHS/PTA) —
      federasi menambah permukaan endpoint on-prem yang terpapar internet
- [ ] yang diaudit: rotasi token-signing cert, clock skew, enkripsi
      assertion, penutupan endpoint lama (AD FS tidak dipakai = matikan)
- [ ] audit dari sisi SP: validasi audience/recipient/NotOnOrAfter —
      assertion longgar = bypass autentikasi

## 21. Dashboard respons insiden (dari mukul975/building-incident-response-dashboard)
- [ ] panel minimum yang berguna: status insiden (host terdampak vs
      terkandung), timeline IOC per jam, IOC baru per sumber, umur insiden
- [ ] sumber kebenaran tunggal (lookup CSV/index insiden) — dashboard yang
      menghitung sendiri = angka berbeda antar panel

## 22. Playbook respons insiden (dari mukul975/building-incident-response-playbook)
- [ ] struktur playbook: pemicu (trigger) -> keputusan (decision tree) ->
      aksi per cabang -> bukti yang wajib dikumpulkan -> kriteria tutup
- [ ] setiap aksi punya owner + target waktu; aksi destruktif (isolate,
      power down) selalu punya cabang alternatif
- [ ] playbook hidup: diuji via tabletop, diperbarui pasca-insiden

## 23. Timeline insiden Timesketch (dari mukul975/building-incident-timeline-with-timesketch)
- [ ] deployment runbook (docker-compose); konsepnya: timeline tersentral
      dgn tag/star/saved-search kolaboratif
- [ ] ingesti dua jalur: plaso (menyeluruh) atau CSV/JSONL (cepat) —
      pilih berdasar ukuran kasus, bukan kebiasaan

## 24. Pengayaan IOC via OpenCTI (dari mukul975/building-ioc-enrichment-pipeline-with-opencti)
- [ ] TIP (OpenCTI/MISP) = sumber konteks, bukan penggabung alert; alirkan
      temuan -> TIP, bukan TIP -> temuan
- [ ] padanan cyphron: rdap-enrichment + intel_sync (KEV/nuclei) sudah
      menutup kebutuhan pengayaan statis

## 25. Template komunikasi insiden malware (dari mukul975/building-malware-incident-communication-template)
- [ ] SLA notifikasi per severity: P1 15 menit (CISO/CEO/legal), P2 1 jam,
      P3 4 jam, P4 24 jam — tulis di template, jangan diimprovisasi
- [ ] kanal berjenjang: out-of-band utk kritis, tiket utk dokumentasi,
      intranet utk umum — satu insiden satu kanal resmi
- [ ] setiap update wajib: ID insiden, waktu UTC, status, aksi berikutnya

## 26. Proses Patch Tuesday (dari mukul975/building-patch-tuesday-response-process)
- [ ] kategorisasi -> SLA: zero-day/KEV 24-48 jam, RCE kritis 3-5 hari,
      exploit publik/EPSS tinggi 7 hari, high 14, medium 30, low = window
      maintenance (tabel eksplisit, bukan perasaan)
- [ ] ring deployment: staging -> pilot 5-10% -> produksi berjenjang ->
      validasi scan; zero-day boleh lompat ring dengan change request
      darurat
- [ ] hari-H: cross-ref MSRC + CISA KEV + advisori vendor sebelum kelola

## 27. Tombol lapor phishing (dari mukul975/building-phishing-reporting-button-workflow)
- [ ] loop umpan balik wajib: terima laporan -> klasifikasi otomatis ->
      balas ke pelapor (<5 menit terima, hasil saat selesai)
- [ ] klasifikasi 4 kotak: phishing/spam/simulasi/legitim — email simulasi
      yang dilapor = poin positif utk pelapor (jangan dihukum)
- [ ] metrik program: tingkat laporan, MTTT, FP rate laporan

## 28. Playbook ransomware CISA (dari mukul975/building-ransomware-playbook-with-cisa-framework)
- [ ] pra-insiden (CISA): backup offline+enkripsi+DIUJI, MFA, segmentasi,
      RDP dibatasi, allowlisting, patch 48 jam utk internet-facing
- [ ] deteksi: rename massal, ransom note, vssadmin delete shadows,
      lonjakan Sysmon EID 11
- [ ] containment 1-4 jam: isolate -> matikan bila tak bisa isolate ->
      matikan share -> reset kredensial -> blok IOC -> preservasi bukti
- [ ] jangan lupa: identitas vektor akses awal + cek exfiltrasi (double
      extortion) sebelum keputusan pemulihan

## 29. Playbook SOC ransomware (dari mukul975/building-soc-playbook-for-ransomware)
- [ ] decision tree triase: indikator -> skala (1 host vs berjangkit) ->
      jalur contain berbeda; jangan tunggu kepastian ransomware utk isolate
- [ ] pasca: dokumentasi (fail, waktu, IOC) -> lessons learned ->
      perbarui playbook (dua arah dgn seksi 28)

## 30. C2 Havoc (dari mukul975/building-red-team-c2-infrastructure-with-havoc)
- [ ] sisi biru: profil malleable Havoc = pola traffic; deteksi = deviasi
      dari profil (UA/URIs/jitter), bukan signature statis
- [ ] ops merah: teamserver terpisah dari edge, OPSEC logging — tidak ada
      inti deterministik utk cyphron

## 31. Matriks eskalasi SOC (dari mukul975/building-soc-escalation-matrix)
- [ ] tier memegang severity: T1 = P3/P4 sampai tuntas, P1/P2 naik T2
      dalam SLA; T3 = hunting + malware RE, bukan antrean
- [ ] per severity tulis eksplisit: respon awal, ambang eskalasi, target
      resolusi, cadensi komunikasi (P1 = tiap 30 menit)
- [ ] jalur manajemen terpisah dari jalur teknis (CISO = keputusan dampak,
      legal/PR = notifikasi)

## 32. Metrik & KPI SOC (dari mukul975/building-soc-metrics-and-kpi-tracking)
- [ ] definisi wajib sebelum mengukur: MTTD (kejadian->deteksi), MTTA
      (alert->ack), MTTC (investigasi->contain), MTTR (deteksi->selesai)
      + FP/TP rate, coverage ATT&CK, dwell time, escalation rate
- [ ] buang data kotor sebelum agregasi (mttd < 0 atau > 24 jam = isu
      kualitas data, bukan performa)
- [ ] laporkan median + p90 selain rata-rata — rata-rata menutup outlier

## 33. Super timeline Plaso (dari mukul975/building-super-timelines-with-plaso)
- [ ] alur: log2timeline (--parsers selektif utk kecepatan) -> pinfo
      (sanity) -> psort (filter TZ UTC, json_line utk Timesketch)
- [ ] nilai forensik utama: deteksi T1070 — timestomping/log clearing
      menonjol sbg inkonsistensi MACB vs journal vs event log
- [ ] di cyphron konsep ini muncul sebagai korelasi multi-sumber di
      dns_log_triage/netflow_parse — timeline = pertanyaan, bukan alat

## 34. Di luar domain — catatan bidang (bukan "skip" polos)
- [ ] #0272 auditing-uefi-firmware-with-chipsec: firmware/UEFI hardware —
      butuh akses fisik+driver kernel, di luar web/app/infra cyphron.
      Inti yang layak diingat: bios_wp (BIOS_CNTL+PRR), spi_lock (FLOCKDN),
      smrr/smm, secureboot variables, s3bootscript — FAIL = precondition
      implant firmware (T1542.001); bukti = dump SPI vs image OEM
- [ ] #0285 identity governance lifecycle: proses IGA enterprise (JML:
      joiner-mover-leaver, status PRE_HIRE->ACTIVE->TERMINATED, orphan
      account) — administrasi identitas, bukan pengujian keamanan
- [ ] #0296 role mining RBAC: optimasi peran dari matriks user-permission
      (clustering Jaccard / Formal Concept Analysis, metrik WSC & coverage)
      — data-mining utk admin IAM, bukan temuan keamanan; padanan cyphron
      (k8s_rbac_audit) mengaudit hak berlebih, bukan mendesain peran

## 35. Profil aktor & atribusi OSINT (dari mukul975/building-threat-actor-profile-from-osint) — distilasi B11
- [ ] profil lengkap = alias lintas vendor, motivasi, sektor/geografi
      target, kampanye, TTP, toolset/malware, pola infrastruktur, timeline
- [ ] Diamond Model: tiap aktivitas diurai ke adversary / capability /
      infrastructure / victim — hubungan antar-sumbu = titik korelasi
- [ ] atribusi TIDAK diklaim dari satu indikator: Analysis of Competing
      Hypotheses — daftar hipotesis, cari bukti yang MENOLAK, bukan yang
      mendukung; level confidence ditulis eksplisit
- [ ] infrastruktur bersama (IP dipakai banyak domain, registrar/naming
      pattern sama) = korelasi kuat; butuh >=3 sumber independen sebelum
      disebut "confirmed"
- [ ] di cyphron: tidak ada tool atribusi (bagian API OSINT butuh kunci +
      jaringan) — checklist ini dipakai saat MENULIS profil dari bukti
      yang sudah terkumpul, output selalu memakai kalimat kepercayaan

## 36. Hipotesis threat hunt (dari mukul975/building-threat-hunt-hypothesis-framework) — distilasi B11
- [ ] hipotesis harus TERUJI: "jika <teknik TTP> dipakai, maka <artefak
      spesifik> akan terlihat di <sumber data X>" — tanpa ketiga bagian
      itu, bukan hipotesis melainkan kegelisahan
- [ ] sumber data disebut SEBELUM query: log apa yang membuktikan/menolak;
      sumber tidak tersedia = celah telemetri, dicatat (bukan dilewati)
- [ ] hasil per hipotesis: validated / refuted / inconclusive — refuted
      tetap bernilai (mengisi celah deteksi), inconclusive = sumber kurang
- [ ] tiap temuan: true/false positive dijelaskan kontekstual (pola yang
      sama dipakai proses sah?), lalu dikaitkan ke rantai serangan lebih
      luas
- [ ] output hunt standar: ID, teknik, host/akun, bukti, risk, confidence,
      tindakan — plus UPDATE rule deteksi dari apa yang dipelajari

## 37. Differential auth-enforcement (dari mukul975/bypassing-authentication-with-forced-browsing) — distilasi B11
- [ ] tes inti = DIFERENSIAL: respons endpoint tanpa sesi vs sesi sah —
      status & ukuran isi mirip tanpa redirect/login-page = auth tidak
      ditegakkan di endpoint itu
- [ ] path tak tertaut tetap wajib dites (forced browsing): backup/config
      (.bak/.old/.env/.conf), panel admin, debug/actuator — keberadaan
      cek cyphron: file-exposure-checker, directory-listing-detector,
      cached-sensitive-files
- [ ] enforcement kadang hanya ditegakkan pada METODE tertentu: HEAD/
      OPTIONS/PATCH atau method-override header bisa lolos sementara GET
      diblok — tes varian metode pada endpoint yang sama
- [ ] 403 bukan "aman": bandingkan isi respons 403 vs 404 vs 200 untuk
      membedakan "ada tapi dilindungi" vs "ada dan bocor"
- [ ] di cyphron: differential unauth-vs-auth sudah ada di
      AdminAccessPlaybook (exploit_playbooks); checklist ini utk review
      manual saat lead tersangka tapi playbook belum mencakup path-nya

## 38. Koleksi OSINT terarah (dari mukul975/collecting-open-source-intelligence) — distilasi B11
- [ ] mulai dari collection requirement: pertanyaan yang harus dijawab —
      tanpa itu, OSINT menjadi arsip tanpa arah
- [ ] lapisan sumber: pasif-DNS/WHOIS (kepemilikan), map infrastruktur
      (port/cert/hosting), pemantauan paste/darkweb (bocor, kredensial),
      repo kode (kunci keras) — tiap lapisan punya bias waktu berbeda
- [ ] korrelasi lintas sumber: domain yang sama muncul di WHOIS berbeda +
      cert + hosting = kandidat infrastruktur satu aktor
- [ ] catat sumber + waktu akses per fakta — bukti tanpa asal tak bisa
      dipakai ulang dan tak bisa dipercaya
- [ ] di cyphron: permukaan pasif sudah luas (rdap-whois, ct-inventory,
      subdomain-enum-surface, wayback-history, favicon-fingerprint);
      checklist ini utk MENYUSUN temuan lintas-tool menjadi narasi

## 39. Recon pasif eksternal (dari mukul975/conducting-external-reconnaissance-with-osint) — distilasi B11
- [ ] definisi pasif: NOL paket ke target — hanya arsip pihak ketiga (DNS
      history, CT log, wayback, repo, dokumen publik); pemindaian aktif =
      fase lain dengan izin lain
- [ ] peta footprint: domain/subdomain, rentang IP, teknologi, alamat
      email/staf, vendor pihak ketiga, artefak kebocoran lama
- [ ] artefak kedaluwarsa tetap berharga: subdomain lama di wayback =
      kandidat takeover; repo terlupa = kredensial lama yang belum dirotasi
- [ ] email staf + pola nama = bahan validasi keberadaan, bukan bahan
      serangan — di cyphron dipakai untuk menyempitkan scope audit sah
- [ ] padanan cyphron: program_discovery/target_scout + permukaan pasif
      registry (lihat seksi 38); checklist ini urutan pikirannya

## 40. Urutan volatilitas + chain of custody (dari mukul975/collecting-volatile-evidence-from-compromised-host) — distilasi B11
- [ ] urutan klasik (paling volatil dulu): register/RAM -> state jaringan
      -> proses -> data disk -> arsip cadangan/remote log — kumpulkan dari
      yang paling mudah hilang sebelum isolasi/power-off
- [ ] isolasi (network) lebih dulu daripada shutdown; power-off menghancurkan
      bukti memori dan artefak fileless
- [ ] chain of custody per artefak: siapa, kapan, dari mana, alat apa,
      hash (dua alat = hash ganda), penyimpanan baca-saja — tanpa itu
      bukti tak bernilai formal
- [ ] catat waktu SISTEM target vs waktu kolektor (skew) — timeline salah
      satuan jam adalah kesalahan forensik umum
- [ ] di cyphron: mft_scan/dpapi_blob_scan membaca artefak statis; checklist
      ini dipakai saat MEMINTA/MENCATAT bukti, bukan saat memparse-nya

## 41. OWASP API Top 10 dipetakan cyphron (dari mukul975/conducting-api-security-testing) — distilasi B11
- [ ] BOLA/IDOR: ganti id objek antar-prinsip — AdminAccessPlaybook
      (orders), IdorOrdersPlaybook; selalu dua bukti: respons objek lain +
      isi tidak sesuai pemilik sesi
- [ ] broken auth: token JWT lemah (JwtWeakSecretPlaybook,
      JwtAlgConfusionPlaybook), sesi tanpa kedaluwarsa/scope
- [ ] BFLA/mass-assignment: kirim field role/is_admin pada POST/PUT —
      MassAssignmentPlaybook; tes juga DELETE/ubah oleh role rendah
- [ ] property-level: respons memborong field sensitif (PSS) — bandingkan
      skema respons role rendah vs dokumentasi
- [ ] rate-limit: rate-limit-validator (tolok ukur + canary); consumen
      DoS = payload bentuk aneh yang mahal diparse
- [ ] SSRF/injection klasik: SsrfCallbackPlaybook/XxeCallbackPlaybook/
      SqliProductsPlaybook — callback eksternal = bukti lebih kuat daripada
      perbedaan respons
- [ ] urutan hemat: autentikasi dulu (murah), lalu otorisasi antar-objek,
      lalu validasi input, terakhir logika bisnis (paling mahal analisis)

## 42. Di luar domain — catatan bidang blok B11 (rincian di ADDENDUM B11)
- [ ] SOC platform ops (#0302 #0304 #0305 #0306 #0308 #0315): deploy MISP/
      Splunk ES/DefectDojo/OpenCTI/TIP + API produknya — integrasi produk
      pihak ketiga, bukan alat audit; konsep feed-quality tetap relevan
      (lihat intel_sync: freshness/delta/TTL)
- [ ] emulasi serangan AD (#0312 #0321 #0326): Coercer/PetitPotam/DCSync/
      BloodHound CE — alat ofensif infrastruktur AD, di luar fokus
      web/app cyphron dan bertentangan dengan kelas read-only
- [ ] IR/response ops (#0318 #0327): cloud IR + malware IR — proses
      respons insiden organisasi; triase statisnya sudah dilayani
      maldoc_triage/pdf_triage/packer_scan/ioc_defang
- [ ] pentest ofensif jaringan/cloud/mobile (#0319 #0323 #0325 #0328
      #0330): metodologi engagement ofensif penuh (MITM, internal network,
      cloud, MASTG) — pelaksanaan butuh izin per-engagement dan alat aktif;
      padanan statis cyphron: attack_planner (rencana, tanpa eksekusi),
      apk_firebase_scan (triase APK)
- [ ] forensik memori (#0329): parsing RAM dump (Volatility) — di luar
      kelas alat cyphron (artefak statis: mft_scan, dpapi_blob_scan)
- [ ] kepatuhan/privasi (#0324): asesmen GDPR Article 30/35 dst — tata
      kelola kepatuhan, bukan pengujian teknis

