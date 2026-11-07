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


---
Blok B13 (#0361-#0390, 8 Nov) — sumber mukul975/Anthropic-Cybersecurity-
Skills (Apache-2.0 — konsep, bukan teks). Lima entri diekstrak jadi tool
(#0363 -> ps_obf_scan, #0380 -> arp_pcap_scan, #0383 -> cloudtrail_scan,
#0386 -> iam_escalation_scan, #0390 -> zeek_beacon_scan); yang layak di
bawah ini didistilasi. Ops produk/deployment dicatat di seksi 48.

## 43. Triase skrip JavaScript ter-obfuscation (dari mukul975/deobfuscating-javascript-malware)
- [ ] urutan triase statis: ekstrak <script> dari HTML -> beautify ->
      kenali teknik -> dekode berlapis; JANGAN pernah eksekusi sampel
- [ ] taksonomi encoding: \xNN hex, \uNNNN unicode, atob(), unescape(),
      String.fromCharCode([...]), array-lookup var _0xNNNN[...]
- [ ] rantai eksekusi dinamis yang dicari: eval(atob(...)), new
      Function(...), setTimeout(decoded,0), document.write("<script>")
- [ ] anti-analisis = penanda kuat: debugger; dalam setInterval,
      override console.*, timing check performance.now(), deteksi
      window.outerWidth-innerWidth
- [ ] dekoder universal sudah ada: skills/deep_decode.py (base64/hex/
      unicode/octal/charCode/HTML entity/ROT13, hingga 8 lapis) —
      gunakan itu, jangan tulis dekoder baru; yang diputuskan manual:
      TAHAPAN (beautify, pendataan teknik) bukan dekodenya

## 44. Lapisan deteksi prompt injection (dari mukul975/detecting-ai-model-prompt-injection-attacks + defending-llms-with-guardrails)
- [ ] tiga lapis dengan biaya menaik: regex signature (sub-ms) ->
      heuristik struktural (densitas instruksi, anomali format) ->
      klasifikasi model; gabung dengan bobot eksplisit (mis. 0.3/0.2/0.5)
      dan threshold yang bisa diatur
- [ ] signature minimum: "ignore previous instructions", "you are now",
      "system prompt:", delimiter-escape (```, <|endoftext|>), payload
      terenkode dalam prompt
- [ ] padanan cyphron: tools/injection_guard.py melayani lapis 1-2 untuk
      bukti/teks yang masuk repo; lapis 3 (model klasifikasi) = butuh
      unduhan model + jaringan — di luar disiplin cyphron
- [ ] guardrail runtime (LLM Guard/NeMo/Llama Guard) = produk di jalur
      request aplikasi — konfigurasi/ops, bukan alat audit offline

## 45. Adversary engagement MITRE Engage (dari mukul975/designing-adversary-engagement-with-mitre-engage)
- [ ] mulai dari STRATEGIC GOAL (apa yang ingin dipelajari/diperlambat
      tentang adversary), bukan dari honeypot yang tersedia
- [ ] siklus: prepare (pilih approach + risiko) -> execute -> understand
      (kumpulkan temuan) -> effect (ukur dampak: deteksi, denial,
      intelligence dari engagement)
- [ ] setiap approach Engage dipetakan ke T-ID ATT&CK (mis. decoy
      content = T1546) + "engage-ability" target dinilai dulu
- [ ] kriteria aman-untuk-engage: konten decoy harus sah untuk disentuh,
      tidak mengganggu produksi, dan punya jalur alert jelas saat disentuh
- [ ] cyphron: tidak ada alat engagement — checklist ini dipakai saat
      MENDESAIN rencana deception di lab, selaras attack_planner

## 46. Pola anomali autentikasi (dari mukul975/detecting-anomalous-authentication-patterns)
- [ ] bedakan tiga pola: brute force (banyak gagal per AKUN), password
      spray (satu sumber, banyak AKUN, gagal merata), impossible travel
      (lokasi berpindah lebih cepat dari fisik) — ambang dan responsnya
      berbeda
- [ ] impossible travel butuh GeoIP + baseline per user; tanpa itu
      proksi yang bisa dicapai: perubahan ASN/negara per sesi, waktu
      login di luar pola user, konsol tanpa MFA
- [ ] sekuens bermakna: N gagal -> sukses (kompromi), gagal merata di
      banyak akun lalu satu sukses (spray berhasil), reset password
      + tambah MFA method (persistensi)
- [ ] padanan cyphron: brute force web = web_log_intrusion (ambang POST
      per window); konsol cloud tanpa MFA = cloudtrail_scan; k8s authz =
      k8s_audit_triage — pola di atas dipakai saat MEMBACA hasilnya

## 47. Deteksi enumerasi API dari access log (dari mukul975/detecting-api-enumeration-attacks)
- [ ] dua pola serangan: enumerasi ID objek berurutan (path berpola
      /api/v1/<res>/<int-id>, banyak id unik per sumber) dan BOLA (401/
      403 beruntun per identity dgn 200 selingan = sukses sebagian)
- [ ] aturan ambang portabel: unique_ids > 20 dalam window + rate
      stabil > 2 req/s = kandidat; failure_count > 10 per 5 menit per
      identity, unique_paths > 5 -> enumerasi, sisanya brute force
- [ ] mixed-status penting: 200 dan 403 bergantian pada objek berbeda =
      akses BOLA berhasil SEBAGIAN — jangan dinilai "hanya scan"
- [ ] pencegahan di sisi kode: otorisasi di lapisan data, UUID alih-alih
      id berurutan, rate limit per identity — cek cyphron: IdorOrders/
      AdminAccessPlaybook (aktif), rate-limit-validator
- [ ] di cyphron: parser CLF sudah ada di web_log_intrusion — pola
      enumerasi bisa ditambahkan di situ bila dibutuhkan, jangan tool baru

## 48. Di luar domain + ops produk — catatan bidang blok B13
- [ ] OT/ICS/SCADA (#0377 #0381 #0382): deteksi anomali proses ICS,
      historian, aturan Suricata Modbus/S7comm/DNP3 — domain teknologi
      operasional, di luar fokus web/app/infra cyphron; butuh jaringan
      OT tersegmentasi + sensor SPAN milik sendiri
- [ ] deployment deception (#0364 #0365 #0367 #0369 #0372): runbook
      membuat honeytoken/canary/decoy (AD, cloud, file) + alert-on-touch
      — konsepnya dicakup seksi 45; pelaksanaan = ops infrastruktur
- [ ] produk zero-trust/EDR (#0366 #0368 #0370 #0371 #0373 #0374):
      Cloudflare Access, CrowdStrike, osquery/Fleet, Prisma Access, SDP,
      Tailscale — integrasi produk pihak ketiga, bukan alat audit
- [ ] ops deteksi cloud (#0385 #0387 #0388 #0389): automation GuardDuty
      (EventBridge/Lambda), KQL Azure, query Graph utk service principal,
      az CLI storage — butuh kredensial live; padanan statis cyphron:
      cloudtrail_scan + iam_escalation_scan
- [ ] alat eksternal (#0384): TruffleHog = scanner secret pihak ketiga;
      padanan cyphron: secret_history_scan (riwayat git) + zeroize_scan

---
Blok B14 (#0391-#0420, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Tiga entri diekstrak jadi tool: #0392 -> tools/
api_property_scan.py, #0418+#0419 -> tools/kerberos_log_triage.py,
#0420 -> tools/ingest_gate.py (gerbang pra-ingesti; sisi pola instruksi
yang langsung terlihat di teks sudah dicakup seksi 44); sisanya
didistilasi di bawah.

## 49. BEC & kompromi akun email (dari mukul975/detecting-business-email-compromise + detecting-business-email-compromise-with-ai + detecting-email-account-compromise + detecting-email-forwarding-rules-attack)
- [ ] taksonomi FBI IC3: CEO fraud, account compromise, false invoice
      (ubah rekening vendor), attorney impersonation, data theft
      (W-2/PII dari HR) — BEC kerap TANPA link/lampiran; scanner URL
      meleset, indikatornya identitas & proses
- [ ] indikator deterministik per email (sudah di eml_phish_triage):
      Reply-To != From, domain Return-Path != domain From, domain
      homoglyph/mirip eksekutif-vendor; sisanya bahasa (urgensi +
      kerahasiaan "jangan beritahu siapa pun", perubahan payment
      detail) — bukti lemah bila sendirian
- [ ] persistence T1114.003: inbox rule forward ke domain eksternal,
      rule yang menghapus/memindahkan email ber-keyword "invoice/
      payment" — event New-InboxRule/Set-InboxRule di audit log
- [ ] kontrol proses yang menutup celah teknis: dual-authorization
      wire transfer, verifikasi out-of-band (callback ke nomor
      TERSIMPAN) untuk perubahan rekening vendor
- [ ] kompromi akun: impossible travel di sign-in log, UA aneh
      (python-requests/PowerShell/curl) di log email, OAuth consent
      grant pihak ketiga mencurigakan
- [ ] sisi AI (#0394): baseline perilaku 30 hari + writing-style
      profile per user — butuh platform/API; intinya: identitas
      pengirim TIDAK cukup, gaya & pola juga bukti

## 50. Cloud threat & kredensial cloud (dari mukul975/detecting-cloud-threats-with-guardduty + detecting-compromised-cloud-credentials)
- [ ] taksonomi finding GuardDuty "ThreatPurpose:ResourceType/
      ThreatName"; yang khas: InstanceCredentialExfiltration.OutsideAWS
      (kredensial instance dipakai DI LUAR AWS — pasti aneh),
      TorIPCaller, ConsoleLoginSuccess.B
- [ ] routing severity eksplisit: >=7 -> otomasi (EventBridge ->
      isolasi via SG), >=9 -> hunt; finding tanpa aksi = noise
- [ ] korelasi deterministik atas log yang diekspor: impossible
      travel = 2 IP beda negara < 1 jam per user; stuffing = >=10
      gagal lalu sukses per user; unique IP console login > 3 / 24 jam
- [ ] containment kredensial: deactivate access key, revoke session,
      disable service account — hentikan pemakaian DULU, cari jejak
      belakangan
- [ ] di cyphron: sisi log AWS offline dilayani cloudtrail_scan
      (#0383, B13) + iam_escalation_scan; Entra/GCP butuh API —
      checklist ini dipakai saat MENGATUR ekspor log dari lab

## 51. Container drift & escape runtime (dari mukul975/detecting-container-drift-at-runtime + detecting-container-escape-attempts + detecting-container-escape-with-falco-rules + detecting-container-runtime-threats-with-falco)
- [ ] drift (T1611): binary DIEKSEKUSI dari upper layer, package
      manager (apt/yum/apk/pip/npm) di runtime, shell yang bukan
      entrypoint — semua = "image tidak lagi sama dengan manifest"
- [ ] vektor escape yang dipantau: privileged container, mount
      docker.sock, /proc/kcore & /proc/sysrq-trigger, write cgroup
      release_agent (CVE-2022-0492), nsenter/unshare/mount dgn argumen
      /host, insmod/modprobe, baca /etc/kubernetes/admin.conf
- [ ] anatomi rule Falco: spawned_process + container + proc.name/
      fd.name, plus list biner + EXCEPTION list utk FP + priority —
      rule tanpa exception = alarm massal hari pertama
- [ ] integritas image: pin digest @sha256: (bukan tag mutable);
      readOnlyRootFilesystem = mitigasi drift termurah
- [ ] runtime detection butuh sensor kernel (eBPF/Falco) — di cyphron
      jejak API-side dilayani k8s_audit_triage/k8s_rbac_audit;
      checklist ini utk AUDIT aturan milik lab, bukan eksekusi

## 52. Credential dumping Windows (dari mukul975/detecting-credential-dumping-techniques)
- [ ] Sysmon EID 10 (ProcessAccess) ke lsasse: GrantedAccess
      mencurigakan umum 0x1010 (query+read VM), 0x1FFFFF (semua) —
      proses biasa TIDAK membaca lsasse; pola yang sama diterapkan ke
      proses tak dikenal dgn bit read
- [ ] dump alternatif di cmdline (4688/Sysmon EID 1): rundll32
      comsvcs.dll MiniDump, procdump -ma, reg save SAM/SYSTEM,
      ntdsutil "ifm", vssadmin create shadow -> salin NTDS.dit
- [ ] disiplin: satu akses lsasse = LEAD; konfirmasi butuh konteks
      (EDR/backup agent sah memang kerap berhak membaca)

## 53. Cryptomining di cloud (dari mukul975/detecting-cryptomining-in-cloud)
- [ ] empat sinyal independen: cost anomaly (dimensi SERVICE), alarm
      CPU (>=90% x 3 periode), traffic ke pool (port stratum/3333,
      domain pool), proses runtime (xmrig/minerd)
- [ ] pola CloudTrail khas: RunInstances burst di region tak lazim,
      instance GPU, user-data berisi curl|sh miner (T1496) — sisi log
      offline dilayani cloudtrail_scan (#0383)
- [ ] satu sinyal = lead; dua sinyal serentak = eskalasi langsung

## 54. Data & model poisoning (dari mukul975/detecting-data-and-model-poisoning)
- [ ] provenance dulu: dataset per versi disimpan hash + sumber +
      waktu; dataset "muncul sendiri" tanpa provenance = jangan
      dipakai train
- [ ] label noise: distribusi prediksi vs label (mis. Cleanlab) —
      label yang selalu salah pada fitur tertentu = kandidat
      poisoning ATAU kualitas data (dua-duanya temuan sah)
- [ ] deteksi poison: activation clustering (dua cluster jelas di
      lapisan akhir = curiga) + spectral signature (gap eigenvalue
      besar); keduanya sinyal statistik, konfirmasi = review sampel
      manual
- [ ] backdoor: performa normal di distribusi utama + anomali pada
      subset trigger — uji subset terpisah
- [ ] gate: dataset/weight baru masuk pipeline lewat diff-stat +
      quarantine review (analog ci_gate utk kode)

## 55. DCSync (dari mukul975/detecting-dcsync-attack-in-active-directory)
- [ ] Event 4662 di DC dengan GUID replicasi: DS-Replication-Get-
      Changes 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2, -All
      1131f6ad-9c07-11d1-f79f-00c04fc2dcd2, -In-Filtered-Set
      89e95b76-444d-4c62-991a-0facbeda640c
- [ ] pembeda utama: sumber normal GUID itu = DC lain; akun user/
      service biasa = DCSync (Mimikatz lsadump::dcsync, secretsdump)
- [ ] presyarat audit: Advanced Audit Policy 4662 di DC — tanpa itu
      teknik invisible; cek coverage logging dulu sebelum menyimpulkan
      "tidak ada DCSync"

## 56. Deepfake audio di vishing (dari mukul975/detecting-deepfake-audio-in-vishing-attacks)
- [ ] pertahanan termurah = PROSES: permintaan uang/kredensial lewat
      suara WAJIB callback ke nomor tersimpan (bukan nomor penelepon)
      — tak peduli suara asli atau bukan
- [ ] artefak forensik: discontinuity fasa/spektral, prosodi & jeda
      tak wajar, hilangnya napas/transisi fonem, band-limit (energi
      > 8-12 kHz kosong); classifier ML butuh model terlatih — cukup
      checklist inspeksi
- [ ] bukti = gabungan artefak audio + anomali konteks (jam, permintaan,
      identitas); satu artefak = lead

## 57. Dependency confusion — padanan (dari mukul975/detecting-dependency-confusion)
- [ ] padanan cyphron: dep_confusion_check (manifest + konfigurasi
      registry, offline). Entri ini versi deteksi aktif: nama internal
      yang tak terdaftar di registry publik = CLAIMABLE (cek 404
      registry = langkah live ops, bukan tool)
- [ ] remediasi pinning: .npmrc scope->registry privat, pip index-url
      TUNGGAL (jangan extra-index-url — pip menggabungkan & memilih
      versi tertinggi), Maven mirrorOf=*
- [ ] defensif terakhir: pre-register nama internal di registry
      publik sbg placeholder

## 58. DLL side-loading (dari mukul975/detecting-dll-sideloading-attacks)
- [ ] pola T1574.002: EXE signed + DLL tak-signature nama sama di dir
      yang sama (wrapper); phantom DLL (nama tak ada di dir aplikasi,
      dicari di PATH); proxy DLL (export-forward ke DLL asli, payload
      di DllMain)
- [ ] deteksi log: Sysmon EID 7 ImageLoaded — DLL unsigned dimuat EXE
      signed, path Temp/AppData/Public, DLL bukan dari dir aplikasi;
      verifikasi signature + hash ke inventaris
- [ ] statis: pe_mitigation_scan menutup sisi mitigasi biner; ekspor
      Sysmon XML bisa diparse pola sama dgn kerberos_log_triage bila
      kelak dibutuhkan

## 59. UA fingerprint tool ofensif di Entra ID (dari mukul975/detecting-entra-offensive-tools-in-graph-logs)
- [ ] UA yang dikenali: ROADtools/aiohttp, AADInternals, AzureHound di
      SignInLogs/Graph log; python-requests generik dari lingkungan
      tanpa app resmi = lead
- [ ] behavioral: endpoint sweep (banyak GET objek berurutan dalam
      detik) = roadrecon-likes, terpisah dari login manusia sah
- [ ] mitigasi: conditional access menolak UA tak sah + alert saat UA
      resmi muncul di lokasi baru — log Entra = API/jaringan; pola
      "UA + sweep" berlaku juga di log HTTP umum (web_log_intrusion)

## 60. Evasion endpoint — T1070 (dari mukul975/detecting-evasion-techniques-in-endpoint-logs)
- [ ] log clearing: Security 1102, System 104, Sysmon EID 1 cmdline
      `wevtutil cl` / `Clear-EventLog`; juga lonjakan ukuran log turun
      mendadak
- [ ] timestomping: Sysmon EID 2 FileCreationTime changed — file
      ber-isi resen tapi creation time LAMA = anomali; korelasi EID 11
      FileCreate
- [ ] encodedcommand/base64 di cmdline = evasion klasik — decode dulu
      sebelum menilai
- [ ] kegelapan deteksi = insiden itu sendiri: gap log justru area
      dicurigai (cf. seksi 33 timeline)

## 61. Fileless & LOLBins (dari mukul975/detecting-fileless-attacks-on-endpoints + detecting-fileless-malware-techniques)
- [ ] indikator di log proses: office/scripting parent -> powershell/
      wscript/mshta child, cmdline encodedcommand/iex/downloadstring/
      frombase64string, jaringan langsung setelahnya
- [ ] persistence WMI (Sysmon EID 19 Filter / 20 Consumer / 21
      Binding): consumer cmdline mencurigakan + binding ke filter
      timer/event = persistence tanpa file
- [ ] registry-resident: payload base64 di Run keys/HKCU yang
      mengeksekusi encodedcommand = lead
- [ ] sumber kebenaran fileless = script block logging (EID 4104,
      isi SETELAH deobfuscation) — pastikan menyala di lab sebelum uji
- [ ] analisis memori di luar kelas cyphron — checklist utk MEMBACA
      ekspor event XML/EDR lab

## 62. DNS C2/eksfiltrasi — pelengkap (dari mukul975/detecting-command-and-control-over-dns + detecting-dns-exfiltration-with-dns-query-analysis + detecting-exfiltration-over-dns-with-zeek)
- [ ] padanan cyphron: dns_log_triage (entropi, panjang label, volume
      TXT, DGA kelas-karakter, beacon, signature tool; parser Zeek +
      BIND) + zeek_beacon_scan (#0390, B13). Yang tak ada di tool dan
      layak diingat saat triase manual:
- [ ] decode payload TXT: base64 -> header MZ/ELF + regex stager PS
      (IEX/DownloadString/FromBase64String); TXT sah punya whitelist
      (SPF/DKIM/DMARC/verifikasi domain)
- [ ] tabel interval beacon C2 umum (60/120/300/600/900/1800/3600 s,
      toleransi ±10%) sebagai alat pencocokan cepat; CV jitter < 25%
- [ ] rasio NXDOMAIN per client tinggi = kelas DGA yang lolos uji
      entropi; kueri per domain puncak + kekalaan interval = beacon

## 63. Di luar domain blok B14 — catatan bidang (bukan "skip" polos)
- [ ] #0391 BLE (Bluetooth Low Energy): sniffer hardware (Ubertooth/
      nRF52840), enumerasi GATT live (bleak), crackle utk legacy
      pairing (TK=0 Just Works, passkey 6-digit), replay & MITM via
      cloning advertising — butuh radio + alat eksternal, di luar
      web/app/infra. Inti yang layak diingat: characteristic
      write/write-without-response tanpa auth = kandidat; SMP opcode
      0x00/0x01 & L2CAP CID 0x0006 = titik analisis pairing
- [ ] #0409 DNP3 (ICS/OT): anomali protokol industri — deviasi interval
      poling, unsolicited flood, object group/variation tak biasa,
      scan burst ke outstation; jaringan OT berbeda risiko (nyawa/
      produksi) & regulasi — di luar fokus web/app cyphron; konsep
      "deviasi interval poling" berlaku generik (cf. beacon di
      zeek_beacon_scan)

## 64. Siklus uji penetrasi jaringan (dari mukul975/conducting-network-penetration-test) — distilasi B12
- [ ] validasi ruang lingkup SEBELUM scan: kepemilikan IP via WHOIS,
      jendela waktu tertulis, jalur komunikasi darurat — scan IP milik
      pihak lain = insiden, bukan temuan
- [ ] log aktivitas ber-timestamp utk SEMUA perintah (chain of custody);
      percobaan exploit yang GAGAL tetap didokumentasikan (bukti kontrol
      yang bekerja, bukan tanda kemampuan kurang)
- [ ] urutan hemat: host discovery -> port -> enumerasi versi -> korelasi
      CVE -> exploit terkendali -> post-exploit -> cleanup + verifikasi
      cleanup via scan ulang
- [ ] bukti kompromi: hostname+IP+user+privilege, tanpa eksfiltrasi data
      sungguhan (akses didemonstrasikan, tidak dipindahkan)
- padanan cyphron: target_scout, lab_target, exploit_engine + gates,
  session_ledger

## 65. Penjarahan & deteksi tiket Kerberos (dari mukul975/conducting-pass-the-ticket-attack) — distilasi B12
- [ ] sisi serangan (lab): ekstrak TGT/TGS dari LSASS (.kirbi) ->
      konversi ccache -> injeksi -> gerbang hanya di lab berizin;
      NEVER-LIST cyphron tetap di atas segalanya
- [ ] sisi deteksi: 4768/4769 dari host tak lazim, TGT dipakai dari IP
      berbeda dgn saat diterbitkan, tiket sama muncul di beberapa
      workstation berurutan = reuse, bukan reissue
- padanan cyphron: kerberos_log_triage (B14, #0418/#0419) — cek RC4
  downgrade & TGS tanpa TGT di log XML Windows

## 66. Koridor tangani insiden phishing (dari mukul975/conducting-phishing-incident-response) — distilasi B12
- [ ] klasifikasi 4-bin: confirmed / suspicious / spam / false-report —
      jangan campur BEC (pembajakan akun internal) dgn phishing eksternal
- [ ] corong dampak: recipients -> delivered -> opened -> clicked ->
      credentials entered -> attachment executed; tiap tingkat punya sumber
      telemetri berbeda (gateway, proxy, EDR) — jangan klaim tingkat
      tanpa sumbernya
- [ ] remediasi akun: reset password TIDAK cukup — cabut sesi/token aktif
      (cookie AiTM bertahan hidup setelah reset), cek rule forwarding &
      OAuth grant yang dibuat penyerang
- [ ] jerat QR-code phishing (quishing): scanner URL tak membaca QR di
      lampiran — decode dulu
- padanan cyphron: eml_phish_triage (B07 #0199) — header, SPF/DKIM/DMARC,
  Reply-To mismatch; spf_dmarc_posture untuk postur domain

## 67. Post-mortem blameless & metrik respons (dari mukul975/conducting-post-incident-lessons-learned) — distilasi B12
- [ ] fokus pada sistem/proses, bukan individu; asumsi niat baik dgn info
      yang tersedia saat itu
- [ ] 5 Whys berhenti di akar proses ("PAM belum ada"), bukan di orang
      ("passwordnya lemah") — akar = hal yang bisa diganti via kontrol
- [ ] metrik dari timeline event: dwell (compromise->detection), MTTD
      (detection->triage), MTTC (detection->containment), MTTR
      (eradication->recovery) — hitung dari timestamp, bukan ingatan
- [ ] setiap action item punya pemilik + tenggat; ubah playbook & rule
      deteksi sebagai output, bukan pelengkap
- catatan cyphron: pola sama dipakai saat menulis nightrun/report —
  impact_narrative + session_ledger menyimpan timeline

## 68. Uji social-engineering berizin (dari mukul975/conducting-social-engineering-penetration-test, -pretext-call, -spearphishing-simulation-campaign) — distilasi B12
- [ ] autorisasi tertulis utk lingkup SE + tinjauan legal (perekaman
      suara, spoofing caller-ID punya hukumnya sendiri per yurisdiksi)
- [ ] matriks target: kelompok -> pretext -> vektor (phish/vish/physical);
      jangan satu pretext untuk semua kelompok
- [ ] metrik kampanye: delivered/opened/clicked/credentials/reported —
      rasio REPORTED adalah metrik kesehatan, bukan rasio berhasilnya
      tipu (semakin tinggi report = pelatihan mengena)
- [ ] etika: tanpa ancaman/kegregetan nyata, jangan publikasi identitas
      individu yang gagal, debrief target setelah uji
- [ ] prasyarat spoof email = postur auth domain target; cek dulu
- padanan cyphron: spf_dmarc_posture (spoofability), eml_phish_triage

## 69. Uji penetrasi nirkabel (dari mukul975/conducting-wireless-network-penetration-test) — distilasi B12
- [ ] butuh adapter monitor-mode + izin fisik — di luar bentuk tool
      cyphron (software-only); catat sebagai bidang terpisah
- [ ] yang bisa diekstrak: sisi analisis PCAP — handshake/PMKID capture,
      deauth frame, rogue AP vs inventaris BSSID sah, mode transisi WPA3
      downgrade
- padanan cyphron: deauth_pcap_scan (B06 #0159) — frame deauth dari
  pcap; sisanya (crack PSK, evil twin) = bidang radio/HW

## 70. Hardening identitas & infrastruktur (dari mukul975/configuring-active-directory-tiered-model, -host-based-intrusion-detection, -ldap-security-hardening, -microsegmentation-for-zero-trust) — distilasi B12
- [ ] model bertingkat AD (tier 0/1/2): akun admin tier-N TIDAK boleh
      logon ke host tier-N-1; PAW terpisah; audit = daftar anggota grup
      lintas tier
- [ ] HIDS/FIM: baseline dulu 48 jam (noise awal bukan ancaman), sasarkan
      /etc + /usr/bin + System32 + web root, exclude file yang berubah
      sendiri (log/cache/mtab), uji active-response di non-prod sebelum
      dipasang prod
- [ ] LDAP: paksakan LDAPS + signing + channel binding; binding anonim
      ditutup; cek di konfigurasi, bukan dari nama port terbuka
- [ ] microsegmentation: monitor/test-mode 2 minggu -> enforce bertahap
      dari aplikasi paling terisolasi; default-deny; break-glass
      didokumentasikan & diuji
- catatan cyphron: k8s_rbac_audit (B09) & k8s_audit_triage menyentuh
  lintas-tier di klaster; AD/LDAP = infra Windows, catat bidang

## 71. OAuth 2.1 / PKCE checklist (dari mukul975/configuring-oauth2-authorization-flow) — distilasi B12
- [ ] authorization code + PKCE S256 WAJIB utk semua klien (implicit &
      ROPC mati di OAuth 2.1) — verifier 43-128 char unreserved, challenge
      = BASE64URL(SHA256(verifier))
- [ ] state = anti-CSRF: cocokkan persis, satu pakai satu
- [ ] redirect_uri exact-match tanpa wildcard (wildcard = open redirect)
- [ ] refresh token satu-pakai + rotasi + deteksi reuse (reuse = token
      dicuri -> cabut rantai)
- [ ] token di httpOnly cookie (web)/keychain (mobile), BUKAN localStorage
- padanan cyphron: open_redirect_surface, cors_checker, param_probe_checker

## 72. TLS 1.3 (dari mukul975/configuring-tls-1-3-for-secure-communications) — padanan cyphron
- [ ] 3 cipher suite sah TLS 1.3 (AES-256-GCM, AES-128-GCM, ChaCha20-
      Poly1305); kunci = PFS wajib, tidak ada RSA key exchange
- [ ] 0-RTT replayable — hanya utk request idempoten
- [ ] matikan TLS 1.0/1.1; HSTS max-age panjang + includeSubDomains
- [ ] padanan sudah ada di cyphron: ssl_tls_analyzer, tls_cipher_suites_
      checker, tls_heartbeat_overread, http_security_headers (HSTS),
      hsts_preload_checker — skill ini = panduan konfigurasi server,
      tanpa inti deterministik baru

## 73. Mengandung pelanggaran aktif (dari mukul975/containing-active-breach) — distilasi B12
- [ ] map dulu scope (host/akun/C2/lintasan lateral), baru bertindak —
      containment parsial memberi sinyal ke penyerang
- [ ] urutan volatilitas saat menahan: tangkap memori SEBELUM
      remediasi; akun dilumpuhkan (bukan dihapus — jejak audit)
- [ ] Domain Admin kena = reset KRBTGT dua kali, jarak 12 jam
      (tiket golden semua mati)
- [ ] validasi containment: 4625 dari akun yang dilumpuhkan (harus gagal),
      tidak ada callback C2 baru, honeypot tidak disentuh
- [ ] komunikasi status: % aktivitas terhenti, sisa risiko, dampak
      bisnis dari tindakan containment

## 74. Red team LLM berkelanjutan & pola korelasi SIEM (dari mukul975/continuous-llm-red-teaming-with-promptfoo, correlating-security-events-in-qradar) — distilasi B12
- [ ] red team LLM = CI gate: attack-success-rate per kategori OWASP LLM
      dipantau ANTAR rilis — naik di kategori mana pun = regresi yang
      
      memblokir merge (pola sama dgn patch_proof cyphron: bukti sebelum
      dan sesudah)
- [ ] hasil uji disimpan per run utk diff, hanya case gagal yang
      diulang saat verifikasi fix
- [ ] pola korelasi SIEM yang reusable: N gagal dari satu sumber dalam
      window T diikuti sukses dari sumber sama ke tujuan sama = offense;
      join event->flow dalam +-5 menit utk konteks lateral
- [ ] penjaga FP: IP pen-tester di reference-set TTL (polanya = allowlist
      berkedaluwarsa, bukan allowlist abadi)

## 75. Di luar domain + ops produk — catatan bidang blok B12
- [ ] perangkat keras kunci (#0343 HSM/PKCS#11): butuh perangkat/SoftHSM2
      — bidang kriptografi-hardware, di luar bentuk tool cyphron;
      prinsip yang bisa dipinjam: kunci non-extractable, SO-PIN,
      key ceremony dua orang
- [ ] jaringan fisik (#0348 VLAN, #0350 pfSense): konfigurasi switch/
      appliance — akses konsol/SSH perangkat jaringan milik sendiri;
      prinsip: matrix aliran antar-zona + native VLAN tidur
- [ ] produk ZTNA/cloud IAM (#0340 AWS Verified Access, #0344 Google IAP,
      #0347 Duo, #0356 Zscaler ZPA): konsol/gcloud vendor, butuh
      kredensial live — bukan alat audit; pola Cedar/IAP = kebijakan
      per-request, dicatat sebagai konsep seksi 70
- [ ] endpoint vendor (#0354 Defender ASR/Exploit Protection): setting
      EDR Windows via Intune/PowerShell; padanan statis cyphron:
      pe_mitigation_scan (B05 #0131) memverifikasi DEP/ASLR/CFG dari
      binary — versi konfigurasi OS-nya = ops endpoint

---
Blok B15 (#0421-#0450, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Empat entri-grup diekstrak jadi tool: #0421+#0423 ->
tools/insider_baseline_scan.py, #0425+#0426+#0440+#0442 ->
tools/win_auth_triage.py, #0428+#0429+#0431 -> tools/lolbin_scan.py,
#0427 -> tools/zeek_lateral_scan.py; sisanya didistilasi di bawah.
Pembagian ranah dgn tool B16 (sysmon_triage, win_logon_triage) dan
tool lama (kerberos_log_triage, npm_script_audit, k8s_audit_triage,
packer_scan, eml_phish_triage, ids_rule_lint) ditulis eksplisit di
docstring masing-masing tool.

## 76. Baseline perilaku insider / UEBA hemat (dari mukul975/detecting-insider-data-exfiltration-via-dlp, detecting-insider-threat-behaviors, detecting-insider-threat-with-ueba)
- [ ] aturan inti = DEViasi dari BASELINE sendiri, bukan ambang global:
      total upload hari ini > 3x mean harian user adalah sinyal
      utama; rasio tak bermakna utk user bervolume kecil — beri
      lantai minimum baseline sebelum menilai (anti-FP)
- [ ] z-score butuh minimal ~4 hari data & stdev > 0; jumlah hari
      kurang = cek DILEWATI dgn catatan, bukan disimpulkan aman
- [ ] sinyal pelengkap: aktivitas di luar jam kerja (jendela kerja
      eksplisit), mass download per hari, dan peer-group deviation
      (median teman segrup AKTIF hari itu, kecuali user yang
      dievaluasi — user pasif merusak median)
- [ ] skenario insider yang dicari: bulk download menjelang
      pengunduran diri, admin IT mengakses data di luar fungsi
      kerja, service account dipakai query data, kontraktor menyalin
      source code ke cloud pribadi
- [ ] UEBA platform (Elastic/OpenSearch + agregasi) = ops
      infrastruktur; di cyphron inti offline-nya dilayani
      insider_baseline_scan (CSV aktivitas file -> 5 cek); deteksi
      live streaming (watchdog/psutil) tidak di-port

## 77. Lateral movement Windows & NTLM relay (dari mukul975/detecting-lateral-movement-in-network, detecting-lateral-movement-with-splunk, detecting-ntlm-relay-with-event-correlation, detecting-pass-the-hash-attacks, detecting-privilege-escalation-attempts)
- [ ] peta event inti: 4624 LogonType 3 (network)/10 (RDP), 4625
      (gagal), 4648 (kredensial eksplisit — RunAs/PsExec), 4776
      (validasi NTLM), 7045 (service baru — PsExec), 4672 (privilese
      khusus saat logon)
- [ ] pass-the-hash = satu user, logon network NTLM ke BANYAK host
      unik; akun mesin (`$`) dan ANONYMOUS LOGON selalu
      dikecualikan; NTLMv1 di lingkungan NTLMv2 = downgrade
      mencurigakan (alat ofensif memaksa NTLMv1)
- [ ] deteksi relay T1557.001 = 4624 type-3 dgn WorkstationName
      tercatat tapi IP sumber != IP inventory (DHCP/DNS/CMDB) —
      TANPA inventory cek ini TIDAK BOLEH ditebak; audit juga
      enforcement SMB/LDAP signing (relay hanya sukses bila signing
      tidak wajib)
- [ ] privesc generik (T1134 token, T1548.002 UAC, T1574.009 unquoted
      service path): indikatornya di log proses/registry — padanan
      cyphron: lolbin_scan (cmdline) + sysmon_triage (uac-registry-
      hijack, auto-elevate-parent)
- [ ] containment berjenjang saat alert lateral: enrich dulu (peran
      user, admin workstation, hasil scan) -> isolate (port down /
      VLAN karantina / blokir firewall — pilih yang paling kecil
      dampaknya) -> lumpuhkan akun (disable, bukan delete — jejak
      audit) -> reset password -> kumpulkan bukti (Velociraptor)
      SEBELUM tindakan destruktif
- [ ] disiplin investigasi: SATU alert tidak boleh jadi kesimpulan —
      telusuri rantai (host sumber -> semua host tujuan), cek
      persistence tiap host sebelum menyatakan contained, dan
      selalu korelasikan log endpoint dgn network flow (alat yang
      tidak memunculkan event Windows tetap kelihatan di jaringan);
      tanpa baseline pola auth normal, "anomali" tak terdefinisi

## 78. Analisis jaringan pasif & deteksi scan (dari mukul975/detecting-lateral-movement-with-zeek, detecting-network-anomalies-with-zeek, detecting-network-scanning-with-ids-signatures, detecting-port-scanning-with-fail2ban)
- [ ] deployment Zeek/Suricata + konfigurasi sensor (SPAN/TAP,
      node.cfg, offloading NIC) = ops infrastruktur; nilai yang
      diekstrak = analisis POST-HOC file log-nya (conn/smb_mapping/
      smb_files/dce_rpc/ntlm, TSV #fields atau JSONL)
- [ ] signature lateral di Zeek: akses share C$/ADMIN$/IPC$
      (smb_mapping), svcctl/atsvc di dce_rpc = buat service/task
      jarak jauh, satu akun NTLM -> banyak host = spray (ntlm.log
      TIDAK ekspos hash — deteksinya perilaku, bukan isi kredensial)
- [ ] tabel flag scan TCP: SYN-scan (SYN tanpa selesai), FIN/Xmas/
      NULL (flag kombinasi tak sah), ACK (probing firewall),
      SYN+ACK stateless — tiap jenis butuh threshold window per
      sumber; Nmap T0-T5 menentukan keterlihatan (T0 nyaris tak
      terdeteksi, T4/T5 mudah)
- [ ] fail2ban = pertahanan host (jail/filter/iptables recent) —
      konsep yang dipinjam: ambang N kejadian dalam window T ->
      aksi; ignoreip utk jaringan internal; bukan pengganti
      segmentasi
- [ ] padanan cyphron: zeek_lateral_scan (lateral SMB/DCE-RPC/NTLM),
      zeek_beacon_scan + dns_log_triage (beacon/DNS), ids_rule_lint
      (mutu rule IDS) — deteksi scan-port generik = Suricata live,
      di luar kelas tool offline

## 79. Kredensial & tiket — pelengkap deteksi (dari mukul975/detecting-kerberoasting-attacks, detecting-mimikatz-execution-patterns, detecting-pass-the-ticket-attacks)
- [ ] kerberoasting (T1558.003): 4769 RC4 (0x17) padahal domain
      AES-only + VOLUME TGS tinggi per user utk banyak SPN berbeda
      dalam window pendek; AS-REP roasting = 4768 pre-auth tidak
      wajib (accounts dnt-req-preauth); padanan cyphron:
      kerberos_log_triage (RC4/tanpa-TGT/lifetime) — burst-volume
      bisa ditambah di situ bila dibutuhkan
- [ ] mimikatz: cmdline sekurlsa::/lsadump::/Invoke-Mimikatz + EID 10
      akses lsasse (0x1010/0x1FFFFF) — padanan cyphron:
      sysmon_triage (dump-cmdline + lsass-access)
- [ ] pass-the-ticket (T1550.003): tiket dipakai dari host berbeda
      dgn saat diterbitkan, tiket sama muncul di beberapa workstation
      berurutan = REUSE bukan reissue; padanan: kerberos_log_triage
      (indeks user+IP)

## 80. Vetting paket npm (dari mukul975/detecting-malicious-npm-packages)
- [ ] bahaya khas npm: `npm install` MENJALANKAN preinstall/install/
      postinstall sebelum kode aplikasi apa pun — cukup memasang
      untuk terkena; vektor masuk: typosquat, dependency confusion,
      maintainer takeover, worm (Shai-Hulud-style)
- [ ] akuisisi aman: `npm pack` / tarball dgn scripts disabled, di
      VM disposabel tanpa kredensial produksi; detonasi dinamis
      HANYA di sandbox dgn capture egress (tcpdump) bila statis tak
      menyimpulkan
- [ ] heuristik ber-sinyal-tinggi ala GuardDog: install-script,
      serialize-environment (process.env keluar), exec-base64,
      silent-process-execution, obfuscation, shady-links,
      typosquatting
- [ ] cross-check lockfile vs advisory MAL- (OSV) + ekstrak IOC
      (URL/hash) utk blokir; verdict akhir = benign/suspicious/
      malicious DENGAN bukti per baris
- [ ] padanan cyphron: npm_script_audit (lifecycle script offline),
      dep_confusion_check, dependency_cve, supplychain_check —
      GuardDog/OSV sendiri = alat pihak ketiga (ops CI)

## 81. Cloud, AI, mobile, ransomware — pola yang layak diingat (dari mukul975/detecting-misconfigured-azure-storage, detecting-model-extraction-attacks, detecting-oauth-token-theft, detecting-mobile-malware-behavior, detecting-ransomware-encryption-behavior)
- [ ] Azure storage (ops az CLI): yang diaudit — allowBlobPublicAccess,
      networkRuleSet.defaultAction (Allow = terbuka), minimumTlsVersion
      >= 1.2, encryption.requireInfrastructureEncryption, SAS token
      berlebihan, logging disabled; anonymous-blob test = satu curl
      list container; di cyphron belum ada padanan Azure — checklist
      ini utk audit manual/kelak tool JSON-export offline
- [ ] model extraction (AML.T0024): tiga sinyal per principal pada
      log inference API — volume query/window, rasio UNIQUE-input
      (penyerang jarang mengulang), rasio permintaan probabilitas
      penuh; defensinya: rate limit, label-only/rounding, deteksi
      output; uji ekstraktability sendiri (ART) sebelum produksi
- [ ] OAuth token theft Entra (ops API): tabel lifetime — access
      60-90 menit, refresh hingga 90 hari, PRT = SSO penuh, session
      cookie = AitM; vektor: Evilginx (AitM), device-code phishing,
      PRT extraction (sekurlsa::cloudap), infostealer cookie;
      remediasi = cabut sesi/refresh token, bukan reset password
      saja; cf. seksi 50/59
- [ ] mobile malware: triase statis APK (hash, izin, eksport
      komponen) = apk_firebase_scan; analisis dinamis (MobSF/
      Frida/emulator + capture jaringan) = kelas alat lain —
      indikator perilaku: izin SMS/kontak berlebih, API C2 hard-
      coded, lodear dynamis
- [ ] ransomware entropi: baseline entropi PER TIPE file (teks 2-5.5,
      dokumen 3.5-7.2, terenkripsi 7.8-8.0) — teks = kandidat
      terbaik, ZIP/JPEG tak terbedakan (FP); entropi sendirian tak
      cukup: gabung laju I/O + pola rename massal + vssadmin delete
      shadows; padanan cyphron: packer_scan (entropi PE); monitoring
      real-time = out of class

## 82. Quishing — QR-code phishing (dari mukul975/detecting-qr-code-phishing-with-email-security)
- [ ] kenapa lolos: gateway scan URL teks, tidak membaca piksel QR;
      pindai QR terjadi di perangkat pribadi di luar kontrol
      korporat; QR dianggap normal (menu/parkir/pembayaran)
- [ ] taksonomi evasif: SPLIT QR (dua gambar terpisah yang masing-
      masing tampak jinak), NESTED QR (QR dalam QR + halaman antara),
      ASCII QR (teks karakter, lolos analisis gambar), QR artistik
      ber-logo, QR di lampiran PDF
- [ ] lead deterministik di level email: lampiran gambar/PDF + body
      minim URL + konteks pembayaran/kredensial — decode QR butuh
      dependensi non-stdlib (zbar/PIL), jadi di cyphron ditangani
      sebagai prosedur manual pada eml yang sudah ditandai
      eml_phish_triage, bukan tool decode

## 83. Di luar domain — Modbus/OT (dari mukul975/detecting-modbus-command-injection-attacks, detecting-modbus-protocol-anomalies)
- [ ] domain ICS/SCADA (cf. seksi 48/63) — butuh SPAN/TAP jaringan OT
      + parser protokol industri, di luar fokus web/app/infra cyphron
- [ ] inti yang layak diingat: function code Modbus read = 1-4,
      write = 5/6/15/16 (unauthorized write = dampak operasional
      langsung, gaya FrostyGoop), diagnostic = 8/17/43; deteksi =
      baseline master/slamen sah (siapa boleh menulis, rentang
      register, interval poling) -> deviasi + rogue master + frame
      malformed = alert; diagnosis butuh dokumentasi register PLC
      milik lab sendiri
