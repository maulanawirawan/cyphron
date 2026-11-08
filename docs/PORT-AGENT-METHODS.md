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

---
Blok B16 (#0451-#0480, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Enam entri diekstrak jadi tool: #0452 -> tools/
win_logon_triage.py, #0458 -> tools/shadow_api_diff.py, #0461 -> tools/
waf_sqli_triage.py, #0463 -> tools/gha_workflow_audit.py, #0469+#0470
-> tools/pkg_typosquat_check.py, #0466+#0467+#0468+#0471 -> tools/
sysmon_triage.py; sisanya didistilasi di bawah (84-94).

## 84. Koridor ransomware pre-encryption (dari mukul975/detecting-ransomware-precursors-in-network)
- [ ] fokus = window pra-enkripsi (rata-rata 17 menit dari beacon CS
      sampai enkripsi) — deteksi tepat waktu > deteksi cantik
- [ ] fase kill-chain jaringan dgn sumbernya: akses awal (RDP brute
      force/VPN stuffing), C2 (beacon HTTPS/DNS), panen kredensial
      (NTLM relay/Kerberoasting/DCSync), recon internal, lateral
      (PsExec/WMI/WinRM/SMB), staging (arsip + upload)
- [ ] korelasi berantai > satu sinyal: RDP brute force + akses admin
      share dari IP sama = high-confidence; satu sinyal saja = lead
- [ ] pola port-to-port: 445/135/3389/5985 lintas host internal dgn
      volume anomali = lateral movement, bukan noise
- [ ] padanan cyphron: zeek_beacon_scan (beacon), dns_log_triage
      (DGA/TXT), web_log_intrusion (brute force), netflow_parse;
      checklist ini utk MERANGKAI hasilnya jadi narasi insiden

## 85. Rootkit cross-view (dari mukul975/detecting-rootkit-activity)
- [ ] inti metodologi = CROSS-VIEW: enumerasi API (pslist, netstat)
      vs enumerasi mentah (psscan pool scan, raw disk/proc) — objek
      yang ada di view bawah tapi hilang di view atas = hidden
- [ ] SSDT/IRP hook: alamat handler menunjuk di luar modul sah
      (ntoskrnl/win32k) = hook; inline patch = lead
- [ ] alat userland (rkhunter/GMER) = sinyal awal, bukan bukti;
      konfirmasi butuh memori/disk akses rendah
- [ ] di luar kelas alat cyphron (forensik memori Volatility);
      prinsip cross-view muncul generik: ct_baseline_diff (harapan vs
      kenyataan), mft_scan (disk mentah vs API)

## 86. Eksfiltrasi S3 — pelengkap cloudtrail_scan (dari mukul975/detecting-s3-data-exfiltration-attempts)
- [ ] padanan cyphron: cloudtrail_scan (B13) melayani sisi log statis;
      skill ini menambah pola yang layak dicari saat membaca hasil:
- [ ] data event S3: GetObject BULK per identity baru (volume/entitas
      tak lazim), CopyObject lintas akun (dest account != owner) =
      exfil paling bersih
- [ ] presyarat: data event S3 HARUS dinyalakan eksplisit di trail
      (default mati) — "tidak ada temuan" pada trail tanpa data event
      = telemetri kosong, bukan bersih
- [ ] GuardDuty/Macie = pengayaan, bukan sumber kebenaran tunggal;
      skor eksfil = volume x keunikan objek x kelainan identity

## 87. Serverless function injection (dari mukul975/detecting-serverless-function-injection)
- [ ] permukaan: SEMUA event source tidak dipercaya (S3 key, SQS
      body, header API GW, DynamoDB stream) — field event yang
      mengalir ke exec/eval/shell = sink injeksi serverless
- [ ] lapisan audit: (1) statis kode fungsi (sink + sumber event),
      (2) CloudTrail: UpdateFunctionConfiguration/AddLayerVersion/
      AddRoleToInstanceProfile = persistence/eskalasi via fungsi,
      (3) layer pihak ketiga = dependensi supply chain runtime
- [ ] mitigasi runtime: IMDSv2 wajib, env var rahasia jangan di
      plaintext, fungsi = role per-fungsi minimal
- [ ] padanan cyphron: sisi CloudTrail/IAM = cloudtrail_scan +
      iam_escalation_scan; analisis sink kode = belum ada (SAST umum),
      checklist ini dipakai saat review kode handler lab

## 88. Abuse service account (dari mukul975/detecting-service-account-abuse)
- [ ] definisi abuse T1078: akun servis melakukan hal INTERAKTIF —
      logon type 2/10 dari akun servis = anomali hampir pasti
- [ ] pola yang dicari: RDP servis -> DC, akses share di luar scope
      fungsi servis, aktivitas off-hours, servis dgn hak domain-
      luas dipakai DCSync
- [ ] higiene: gMSA/managed identity > password statis; password
      servis = evergreen di log; inventorikan owner+tujuan tiap servis
- [ ] padanan cyphron: win_logon_triage (logon type filter bisa
      dilebarkan), k8s_rbac_audit (serviceaccount cluster); checklist
      ini utk MEMBACA hasilnya

## 89. Shadow IT SaaS (dari mukul975/detecting-shadow-it-cloud-usage)
- [ ] mekanisme: agregasi proxy/DNS log per domain -> volume byte +
      jumlah user unik -> klasifikasi kategori SaaS -> bandingkan
      daftar disetujui organisasi
- [ ] risiko bukan dari kategori saja: volume data + jumlah user +
      kategori (storage/AI = tinggi) -> skor eksfil potensial
- [ ] butuh daftar-putih ORGANISASI — alat generik tidak bisa
      memutuskan "unauthorized"; di cyphron ini proses review log,
      bukan tool (dns_log_triage menyediakan agregasi per-domain)
- [ ] remediasi berjenjang: temukan -> kategorikan -> kebijakan
      (blokir/sanction) -> monitor deviasi

## 90. Spearphishing via email gateway — sisi konfigurasi (dari mukul975/detecting-spearphishing-with-email-gateway)
- [ ] empat lapis SEG yang wajib dinyala: impersonation protection
      (display-name/domain mirip eksekutif), URL rewriting+detonation,
      attachment sandboxing, rule kustom kampanye
- [ ] spearphish lolos spam filter generik karena personal — indikator
      = ketidakcocokan identitas + konteks proses, bukan signature
- [ ] padanan cyphron: eml_phish_triage (header/SPF/DKIM/Reply-To),
      spf_dmarc_posture (spoofability domain); checklist ini utk
      AUDIT konfigurasi gateway lab, bukan analisis email tunggal

## 91. Illicit OAuth consent grant (dari mukul975/detecting-suspicious-oauth-application-consent)
- [ ] serangan: phish halaman consent -> user memberi app pihak
      ketiga scope tinggi (Mail.ReadWrite, Files.ReadWrite.All,
      full_access_as_app) — tanpa password, tanpa MFA
- [ ] yang diaudit (Graph API live): /oauth2PermissionGrants, service
      principal tanpa publisher verification, audit log "Consent to
      application" dgn IP/jam anomali
- [ ] red flag: consent pertama user non-admin utk scope delegated
      tinggi, app baru + langganan inbox rule segera setelahnya
- [ ] butuh kredensial Graph — di cyphron = runbook live ops;
      pola "grant tinggi + tindak lanjut persistence" berlaku juga
      saat membaca cloudtrail_scan (AttachUserPolicy dsb.)

## 92. PowerShell T1059.001 — melengkapi ps_obf_scan (dari mukul975/detecting-suspicious-powershell-execution)
- [ ] padanan cyphron: ps_obf_scan (obfuskasi statis); skill ini
      menambah pola sisi log yang layak dicari:
- [ ] token cmdline: -enc/encodedcommand, -nop -w hidden, iex/
      invoke-expression + downloadstring/downloadfile, frombase64
- [ ] AMSI bypass = patch reflection (AmsiInitialize/AmsiScanBuffer)
      — stringnya di script block log (EID 4104), bukan cmdline
- [ ] constrained language mode evasion = tanda payload runtime;
      proses office/winword sebagai parent powershell = chain fileless
- [ ] EID 4104 = sumber kebenaran isi skrip; tanpa logging skrip,
      "tidak ada temuan" = telemetri kosong

## 93. Eradikasi malware — verifikasi bersih (dari mukul975/eradicating-malware-from-infected-systems)
- [ ] peta persistence SEBELUM menghapus: Run/RunOnce (HKLM+HKCU),
      schtasks, WMI subscription, services BinaryPathName, cron/
      init.d/systemd/rc.local/bashrc — autorunsc -a = daftar lengkap
- [ ] urutan: peta -> identifikasi artefak (hash/YARA/AV multi-engine)
      -> hapus persistence -> hapus binary -> verifikasi
- [ ] verifikasi "bersih" = bukti: autoruns ulang, scan ulang, kred
      direset (kalau tidak, re-infeksi lewat kredensial lama), no
      callback C2 baru window >= 1 minggu
- [ ] jangan bersihkan sebelum forensik selesai (menghancurkan bukti)
- [ ] cyphron: sysmon_triage/win_logon_triage membaca jejak; checklist
      ini = runbook respons lab

## 94. Di luar domain + ops/produk — blok B16
-- [ ] #0455 Secure Boot/bootkit: firmware UEFI — mokutil/dbxtool/
      CHIPSEC butuh akses OS/fisik; inti: dbx harus mutakhir (revokasi
      BlackLotus), EFI binary diverifikasi sbverify, Fail = precondition
      bootkit pra-OS (T1542); bidang hardware-firmware
- [ ] #0462 Stuxnet-style: ICS/OT — integritas logika PLC + anomali
      fisika proses (setpoint vs sensor); butuh sensor OT tersegmentasi;
      bidang OT (cf. seksi 48/83)
- [ ] #0472 Stratus Red Team: emulasi serangan cloud live (warmup-
      detonate-revert) utk uji deteksi — butuh kredensial cloud +
      environment throwaway; padanan statis cyphron: cloudtrail_scan/
      iam_escalation_scan utk MEMBACA telemetrinya
- [ ] #0473 CloudFox: enumerasi read-only AWS/Azure pasca-kredensial
      (role-trust, secrets, endpoints) — alat ofensif live; polanya
      (AssumeRole graph) dicakup iam_escalation_scan
- [ ] #0475 container escape (ofensif): privileged/hostPath/docker
      .sock/release_agent — sisi deteksinya sudah diekstrak seksi 51;
      eksekusi breakout = hanya lab berizin, bukan bentuk tool cyphron
- [ ] #0476 evaluasi TIP: procurement (feed integration, STIX/TAXII,
      TCO) — tata kelola, bukan pengujian teknis (cf. seksi 24)
- [ ] #0477 simulasi serangan AD: BloodHound/Mimikatz/Impacket —
      ofensif infra AD (cf. seksi 42); padanan deteksi statis:
      kerberos_log_triage, sysmon_triage
- [ ] #0478 NIST RMF ATO: proses otorisasi federal (SP 800-37, FIPS
      199/200, 800-53) — kepatuhan dokumen (SSP/SAR/POA&M), bukan
      pengujian; prinsip yang bisa dipinjam: baseline kontrol dari
      kategorisasi dampak, POA&M = temuan dgn owner+tenggat
- [ ] #0479 kampanye phishing simulasi: pelaksanaan (infra harvest,
      kirim) = ops SE berizin (cf. seksi 68); metrik: reported rate >
      click rate sebagai ukuran kesehatan
- [ ] #0480 perencanaan engagement red team: scope/RoE/emergency
      stop/threat profile — padanan cyphron: attack_planner (rencana
      tanpa eksekusi); checklist ini utk MENINJAU rencana, bukan
      menjalankan

---
Blok B18 (#0511-#0540, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Enam entri-grup diekstrak jadi tool: #0511 -> tools/
ssti_engine_id.py, #0514 -> tools/ws_handshake_audit.py, #0517+#0519 ->
tools/rat_config_scan.py, #0526+#0527 -> tools/docker_audit.py,
#0534 -> tools/ps_scriptlog_triage.py, #0540 -> tools/
dcom_lateral_scan.py; sisanya didistilasi di bawah (95-107).

## 95. Type juggling PHP & magic hash (dari mukul975/exploiting-type-juggling-vulnerabilities)
- [ ] akar masalah = perbandingan LONGGAR `==` / `in_array` tanpa
      strict pada kode keamanan-kritis (login, verifikasi token/PIN,
      cek peran); PHP 8 meredakan sebagian, lama tetap relevan
- [ ] matriks mutasi tipe JSON: true, false, null, 0, "", [],
      "0", "0e99999" — json_decode mempertahankan tipe, jadi penyerang
      memilih tipe, bukan string
- [ ] magic hash: hash yang berawalan "0e" + hanya digit dievaluasi
      sbg notasi ilmiah (0) — "0e123" == "0e456" TRUE; tabel seed
      publik (240610708 utk MD5, aaK1STfY utk SHA-1) dipakai sbg
      payload, dan cek `hash_equals()`/`password_verify()` = remediasi
- [ ] strcmp(array, string) -> NULL == 0 TRUE: kirim password[]
      (array) utk mem-bypass perbandingan
- [ ] di cyphron: tidak ada tool PHP-khusus (lab web umumnya bukan
      PHP) — checklist dipakai saat review kode PHP lab; padanan
      lint: grep `==`/`in_array` di file auth lab, bukan tool

## 96. Validasi eksploitabilitas via Metasploit (dari mukul975/exploiting-vulnerabilities-with-metasploit-framework)
- [ ] fungsi kerangka di vuln management: VALIDASI temuan scanner
      (skor != eksploitabel), demonstrasi dampak, prioritas remediasi,
      dan post-patch verification (check ulang setelah patch)
- [ ] disiplin wajib: `check` SEBELUM `exploit` bila modul punya;
      payload minim untuk validasi; workspace per engagement; log
      per aksi dgn timestamp (chain of custody, cf. seksi 40)
- [ ] percobaan exploit GAGAL tetap didokumentasikan = bukti kontrol
      bekerja (cf. seksi 64); CLEANUP + verifikasi scan-ulang setelah
      sesi (sesi meterpreter tertinggal = insiden sendiri)
- [ ] di cyphron: eksekusi exploit live = exploit_engine + gates +
      session_ledger di lab berizin; tidak ada tool baru (msf = alat
      eksternal ops)

## 97. Forensik artefak peramban (dari mukul975/extracting-browser-history-artifacts)
- [ ] peta artefak: Chrome/Edge (Chromium) = History/Cookies/"Login
      Data"/Bookmarks (SQLite + JSON); Firefox = places.sqlite/
      cookies.sqlite/formhistory.sqlite/logins.json — salin dulu
      (read-only), hash sumber sebelum analisis
- [ ] dua epok berbeda: Chromium = µs sejak 1601 (offset 11644473600
      detik ke Unix), Firefox = µs sejak 1970 — konversi salah epok =
      timeline meleset berjam-jam (cf. skew seksi 40)
- [ ] SQLite WAL berisi rekord TERBARU yang belum di-checkpoint —
      salin berkas -wal/-shm bersama DB utk rekord terdekat insiden
- [ ] kredensial/cookie Chromium terenkripsi DPAPI/AES-GCM per profil
      — nilai ter-dekripsi butuh masterkey user (dpapi_blob_scan
      menutup sisi blob masterkey); tanpa itu hanya metadata
- [ ] skenario investigasi: phishing (URL yang dikunjungi + download),
      eksfil cloud pribadi (domain storage + volume), rantai redirect
      drive-by (referrer + downloads)
- [ ] di cyphron: parsing SQLite peramban tidak di-build (skema DB
      berubah antar-versi browser + enkripsi kredensial non-stdlib);
      checklist dipakai saat AKUISISI/penugasan artefak, bukan parse

## 98. Forensik memori — volatilitas (dari mukul975/extracting-credentials-from-memory-dump, extracting-memory-artifacts-with-rekall) — di luar kelas
- [ ] di luar kelas alat cyphron (cf. seksi 42 #0329, seksi 85): butuh
      Volatility/pypykatz + simbol OS; prinsip yang layak diingat:
      cross-view pslist vs psscan (seksi 85), prioritas akun utk reset
      (RID 500/krbtgt = double reset 12 jam, cf. seksi 73)
- [ ] pencarian string di memori utk kredensial cloud (AKIA.../bearer)
      = pola yang sama dgn zeroize_scan/secret scanning — hanya lebih
      liar (FP tinggi, lead saja)

## 99. Di luar domain — AD ofensif & firmware (blok B18)
- [ ] #0515 Zerologon (CVE-2020-1472): eksploit AD ofensif (reset
      mesin akun DC + DCSync) — di luar fokus web/app (cf. seksi 42);
      sisi deteksi yang layak diingat: 4742 beruntun utk akun DC$,
      5805 banjir lalu sukses, Suricata dcerpc opnum 4 challenge
      all-zero; remediasi = patch + enforcement secure RPC
      (FullSecureChannelProtection)
- [ ] #0531 bootkit di ESP: mount ESP + hash boot loader vs golden
      baseline + file non-EFI/ di root ESP = indikator (T1542.003) —
      bidang firmware/hardware (cf. seksi 94 #0455); butuh akses
      elevated + sbsign/UEFITool

## 100. Ekosistem alat eksternal triase — EVTX & Velociraptor (dari mukul975/extracting-windows-event-logs-artifacts, fleet-hunting-with-velociraptor, generating-forensic-timelines-with-hayabusa, hunting-evtx-with-chainsaw)
- [ ] chainsaw/hayabusa = binary eksternal dgn korpus SigmaHQ —
      padanan cyphron: parser XML triase milik sendiri (win_logon_
      triage, win_auth_triage, sysmon_triage, kerberos_log_triage,
      ps_scriptlog_triage); pilih berdasar kebutuhan: korpus Sigma
      luas = alat eksternal, cek deterministik tertarget = parser
      cyphron; alat eksternal = ops, bukan kode repo
- [ ] alur yang layak diingat saat MENGARAHKAN ekspor: prioritaskan
      channel Security, Sysmon, PowerShell/Operational, RDP
      LocalSessionManager, TaskScheduler — ekspor XML (wevtutil /x)
      langsung bisa dibaca parser cyphron
- [ ] Velociraptor: VQL artifact + hunt fleet-wide + offline collector
      = platform ops (cf. seksi 48 produk); konsep yang dipinjam:
      hipotesis -> VQL -> fan-out -> agregasi terpusat (pola sama dgn
      fleet_dispatch cyphron)

## 101. SBOM CycloneDX/SPDX (dari mukul975/generating-and-analyzing-sboms) — padanan ada
- [ ] padanan cyphron: dependency_cve MENGKONSUMSI CycloneDX JSON +
      SPDX JSON langsung (match CVE dari rentang NVD/OSV) — SBOM =
      input, bukan tool baru
- [ ] disiplin yang diambil: SBOM disimpan per rilis lalu DI-SCAN ULANG
      saat DB CVE terbaru (komponen tak berubah bisa jadi rentan) —
      re-scan-on-db-update, bukan scan-on-build saja
- [ ] gate CI: --fail-on severity = pola exploit_ci_gate; hanya-fixed
      = filter temuan tanpa remediasi
- [ ] tanda tangan/attestation (cosign/in-toto) = infra registry, ops
      (cf. seksi 94 provenance)

## 102. Laporan threat intelligence (dari mukul975/generating-threat-intelligence-reports)
- [ ] empat produk dgn audiens berbeda: strategis (C-suite, tren &
      keputusan), operasional (CISO/IR, kampanye & TTP), taktis (SOC,
      IOC/rule), flash (<=1 halaman, <2 jam) — jangan campur audiens
      dalam satu dokumen
- [ ] key judgment DI DEPAN dlm kalimat langsung ("aktor X memanfaatkan
      CVE-Y di produk Z; risiko = W"), bukan "laporan ini mengkaji..."
- [ ] bahasa kepercayaan standar ICD-203: high/medium/low confidence
      ditulis eksplisit per klaim (cf. seksi 35 ACH) — klaim tanpa
      label confidence = red flag metodologi
- [ ] TLP ditentukan SEBELUM distribusi; IOC mentah dibagikan via
      TIP/MISP (mesin), laporan = intel jadi utk manusia
- [ ] di cyphron: impact_narrative + report_pack melayani temuan
      internal; checklist ini utk MENULIS ringkasan, bukan tool

## 103. Hardening endpoint CIS benchmark (dari mukul975/hardening-linux-endpoint-with-cis-benchmark, hardening-windows-endpoint-with-cis-benchmark)
- [ ] runbook live (butuh root/admin per host) — yang layak diingat:
      urutan priorit remediasi = internet-facing dulu, kontrol akun/
      auth sebelum audit-logging, dan SETIAP kontrol punya nomor CIS
      yang dapat direferensikan sbg bukti kepatuhan
- [ ] Linux: partisi tmp/dev/shm dgn noexec,nodev,nosuid, boot
      password GRUB, pam pwquality, sshd PermitRootLogin no +
      PasswordAuthentication no — cek via file konfigurasi saat
      audit manual (sshd_config/fstab), bukan dari nama port
- [ ] Windows: LAPS utk password admin lokal, ASR rules, credential
      guard, SMB signing — sisi konfigurasi OS = ops endpoint (cf.
      seksi 75 #0354); padanan statis cyphron: pe_mitigation_scan
      (biner), win_audit_coverage (cakupan logging)
- [ ] di cyphron: tidak ada tool audit CIS host (butuh akses host
      hidup); konsep gate = docker_audit (B18) utk sisi kontainer

## 104. APT hunting hypothesis (dari mukul975/hunting-advanced-persistent-threats) — duplikat
- [ ] kerangka sama dgn seksi 36 (hipotesis teruji: teknik -> artefak
      -> sumber data) — tidak ada tambahan baru; sumber ekstra yang
      disebut: ATT&CK Groups sbg seeds, ISAC report sbg pemicu sprint

## 105. Credential stuffing vs spray (dari mukul975/hunting-credential-stuffing-attacks)
- [ ] pembeda yang menentukan respons: brute force = satu akun banyak
      percobaan dari sedikit IP; spray = satu password banyak akun;
      stuffing = banyak akun BANYAK IP dgn kredensial bocor (velocity
      per akun rendah tapi IP unik per akun tinggi + UA seragam)
- [ ] indikator stuffing: unique_ip per username gagal tinggi, success
      rate < 1% lintas banyak akun, ASN konsentrasi cloud/proxy,
      geo-impossibility per akun
- [ ] padanan cyphron: web_log_intrusion (ambang POST per window),
      win_logon_triage (4625 spray/enumerasi) — stuffing lintas-IP
      butuh agregasi per-akun lintas window; pola bisa ditambah di
      web_log_intrusion bila dibutuhkan, bukan tool baru
- [ ] defensif: rate limit per identitas+per-IP, deteksi breach
      password (deny-list), MFA — bukan cuma CAPTCHA

## 106. Beacon C2 & Cobalt Strike statis (dari mukul975/hunting-for-beaconing-with-frequency-analysis, hunting-for-cobalt-strike-beacons, hunting-for-command-and-control-beaconing)
- [ ] padanan cyphron: zeek_beacon_scan (interval/CV/jitter per pair),
      dns_log_triage (DGA/TXT/beacon DNS) — entri #0535/#0537 adalah
      metodologi yang sama (CV < 0.20 = periodik, >= 50 koneksi,
      filter known-good: update/AV/NTP/SaaS-heartbeat)
- [ ] sinyal pelengkap yang layak diingat: konsistensi UKURAN payload
      (CV bytes rendah = heartbeat otomatis), JA3/JA3S/JARM utk
      kelompokkan client TLS aneh, IP->host via DHCP -> proses via
      Sysmon EID 1/3 (korelasi jaringan-endpoint)
- [ ] Cobalt Strike statis (bila membaca ssl.log/http.log Zeek):
      sertifikat default CS (serial mencurigakan dikenal publik),
      JA3S default CS, profil malleable (URI tetap berpola + UA
      tua MSIE), URIs yang sama persis berulang — indikator statis
      satu-dua saja = lead; butuh konfirmasi timing (zeek_beacon_scan)
- [ ] aturan escalasi tetap: satu sinyal = lead, dua berangkai =
      eskalasi (pola sama dgn dcom-lateral-chain & seksi 84)

## 107. Eksfiltrasi & staging pra-eksfil (dari mukul975/hunting-for-data-exfiltration-indicators, hunting-for-data-staging-before-exfiltration)
- [ ] kanal eksfil (T1048/T1567): volume anomali per user/host/dest
      vs baseline 30 hari, DNS tunneling (TXT besar/sering —
      dns_log_triage), upload cloud pribadi, email attachment, USB;
      baseline dulu, deviasi sesudah (cf. seksi 76 UEBA)
- [ ] padanan cyphron: insider_baseline_scan (volume per user),
      dns_log_triage (DNS), netflow_parse (volume flow); kanal
      cloud/emails = log gateway, bukan tool offline
- [ ] staging (T1074/T1560): eksekusi archiver (7z/rar/tar/zip dgn
      argumen arsip) di EID 1/4688, tulis ke %TEMP%/ProgramData/
      Recycle Bin/hidden dir, konsolidasi file multi-direktori ->
      satu lokasi, lalu eksfil pelan (T1030 size-limits)
- [ ] kandidat perluasan: cek "archiver-exec + staging-path" cocok
      ditempatkan di lolbin_scan milik pemiliknya (ranah EID 1/11
      sudah dipegang tool itu) — jangan tool paralel dgn parser sama;
      sampai ada, checklist ini dipakai saat MEMBACA hasil
      lolbin_scan/sysmon_triage
- [ ] skor staging eksplisit: ukuran arsip x keunikan sumber (banyak
      dir) x kecurigaan path x jam — satu sinyal saja = lead

---
Blok B17 (#0481-#0510, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Gelombang "exploiting-*" mayoritas = eksploitasi live yang
SUDAH dilayani playbook cyphron; dua entri diekstrak jadi tool:
#0491+#0495 -> tools/mobile_manifest_audit.py (AXML/XML/plist/prefs),
#0498 -> tools/jwt_token_audit.py (konten token); sisanya di bawah.
Ranah playbooks live TIDAK diperluas — tool triase pasif saja.

## 108. Eksekusi red team exercise (dari mukul975/executing-red-team-exercise)
- [ ] rencana eksekusi turun dari threat model (aktor nyata yang
      relevan), bukan daftar exploit yang menarik — padanan cyphron:
      attack_planner + session_ledger
- [ ] fase: plan (objektif + RoE + deconfliction) -> execute (gated)
      -> measure (detection/response ratio per fase) -> report
- [ ] deconfliction eksplisit dengan SOC/biru: jendela, IP sumber
      terdaftar (cf. seksi 74 allowlist berkedaluwarsa), kata kode
      stop — aktivitas tanpa deconfliction = insiden palsu
- [ ] ukur respons, bukan penetrasi: berapa fase terdeteksi, berapa
      lama MTTD/MTTC biru, temuan biru akurat tidak — laporan merah
      yang penting adalah celah DETEKSI, bukan daftar akses
- [ ] kriteria sukses ditulis SEBELUM mulai (apa yang membuktikan
      risiko) — tanpa itu exercise berhenti jadi "kita masuk"

## 109. Taksonomi bypass injeksi API & SSRF (dari mukul975/exploiting-api-injection-vulnerabilities, exploiting-server-side-request-forgery)
- [ ] titik injeksi mencakup HEADER juga (X-Forwarded-For/Referer/UA
      yang ter-log ke DB = injeksi second-order; cf. seksi 41)
- [ ] tabel format bypass SSRF yang portabel: hex 0x7f000001, desimal
      2130706433, oktal 0177.0.0.1, pendek 127.1, IPv6 [::1], DNS
      rebinding (nip.io dst), protokol gopher/dict/file — validator
      URL yang hanya cocok string pasti lolos salah satu
- [ ] target metadata cloud selalu diuji eksplisit: 169.254.169.254
      (AWS/Azure), metadata.google.internal (wajib header
      Metadata-Flavor) — balasan berisi ami-id/instance-id/
      AccessKeyId = bukti langsung
- [ ] cmd injection: indikator time-based (sleep/ping delay) +
      output marker (uid=/root:/bin/bash, "Directory of") — payload
      destruktif TIDAK perlu; padanan cyphron: RceMarkerPlaybook
- [ ] padanan cyphron: SsrfCallbackPlaybook/SsrfChainPlaybook
      (callback eksternal = bukti terkuat), Sqli*/NosqliLogin;
      checklist ini saat MEMBACA hasil & menulis temuan SSRF

## 110. BFLA — pelengkap seksi 41 (dari mukul975/exploiting-broken-function-level-authorization)
- [ ] beda dgn BOLA: BFLA = FUNGSI (endpoint admin utk role rendah),
      BOLA = OBJEK (id milik orang lain); dua kelas, dua tes
- [ ] metode hemat: daftar path admin (admin/manage/internal/system/
      backoffice + /users/role /settings /config /audit) x kelima
      metode (GET/POST/PUT/DELETE/PATCH) dgn kredensial user biasa
- [ ] sinyal "accessible": status BUKAN 401/403/404/405 — 405 atau
      200-kosong perlu dikonfirmasi manual (method override sering
      mengubah hasil; cf. seksi 37)
- [ ] tes fungsi admin juga via endpoint NON-admin: POST /users dgn
      field role/is_admin = jalur MassAssignment yang menaikkan
      role (cf. seksi 41 BFLA/mass-assignment)
- [ ] padanan cyphron: AdminAccessPlaybook (diferensial unauth/auth),
      MassAssignmentPlaybook, k8s_rbac_audit (sisi klaster);
      checklist ini utk menyusun matriks metode x path manual

## 111. HTTP request smuggling (dari mukul975/exploiting-http-request-smuggling)
- [ ] taksonomi: CL.TE (front-end CL, back-end TE), TE.CL kebalikannya,
      TE.TE (obfuscation header TE — duplicate/gagal parse), CL.0
      (back-end abaikan CL sepenuhnya) — penyebab umum: dua processor
      dgn parser framing berbeda
- [ ] deteksi pasif (clue) = tools/smuggling_clue_checker: dua CL
      beda nilai, CL+TE bersamaan, TE non-chunked — clue L1, bukan
      bukti desync
- [ ] uji desync AKTIF = payload bisa mencemari request user lain/
      cache front-end — hanya staging berizin, jangan produksi;
      teknik deteksi: differential/timing (request tidak lengkap
      membuat back-end menunggu)
- [ ] arsitektur rawan dicatat dari header respons (Via/Server/
      x-served-by) — rantai CDN->proxy->app = permukaan utama;
      HTTP/2 downgrade ke HTTP/1.1 di origin = kelas baru (H2.CL)
- [ ] dampak: bypass kontrol front-end (auth/rate-limit di proxy
      yang di-skip back-end) — selalu hubungkan temuan ke kontrol
      yang bisa dilewati, bukan sekadar desync

## 112. Insecure deserialization — taksonomi gadget (dari mukul975/exploiting-insecure-deserialization)
- [ ] peta per runtime: Java (ysoserial + CommonsCollections — cek
      pustaka di classpath), PHP (phpggc — unserialize), .NET
      (ViewState tanpa MAC validation / machineKey bocor), Python
      (pickle.loads pada data tak dipercaya), Node (node-serialize/
      func eval)
- [ ] sinyal statis: endpoint menerima blob terenkode (base64 cookie/
      body) yang berubah panjangnya dgn input; string pustaka gadget
      di dependensi (CommonsCollections 3.x, yaml.load tanpa
      SafeLoader)
- [ ] mitigasi bawaan yang dicari di review: format biner diganti
      JSON, signature/HMAC di atas blob, deserialization filter,
      versi pustaka yang sudah patch (cf. dependency_cve)
- [ ] padanan cyphron: DeserRcePlaybook (uji live lab); eksploitasi
      gadget nyata = alat khusus per-runtime, bukan bentuk tool
      offline

## 113. NoSQL injection melampaui login bypass (dari mukul975/exploiting-nosql-injection-vulnerabilities)
- [ ] tiga kelas: operator injection di JSON body ({"$ne": ""},
      $gt, $regex ".*", $exists), operator di QUERY PARAM (username
      [$ne]=x — parser yang menerima bracket-notation mengangkat
      string jadi objek), $where JS injection (kode JS dieksekusi
      server — kelas RCE-ish)
- [ ] ekstraksi blind: $regex "^a" per karakter = oracle boolean
      dari endpoint login/search; ekstraksi lambat tapi sunyi
      (tanpa error) — deteksinya volume query regex per sumber
- [ ] tanda app rentan: framework menerima array/objek dari form
      (qs/express bracket parsing), peta cek cyphron:
      param_probe_checker + NosqliLoginPlaybook (bypass login)
- [ ] mitigasi: sanitasi operator ($-prefixed key ditolak di body),
      cast tipe eksplisit, disable $where di server, validasi
      skema input (cf. seksi 41 urutan hemat)

## 114. OAuth redirect_uri bypass taxonomy (dari mukul975/exploiting-oauth-misconfiguration)
- [ ] bentuk bypass redirect_uri yang dicoba berurutan: suffix
      (app.example.com.evil.com), userinfo (@evil.com), path
      traversal (/callback/../../evil), case (APP.EXAMPLE.COM),
      percent-encoding, downgrade http, append query/fragment —
      validasi yang benar = EXACT-MATCH string (cf. seksi 71)
- [ ] kebocoran token/code di Referer = implicit flow (response_type
      token) yang dijatuhkan di halaman dgn link keluar — implicit
      mati di OAuth 2.1; state satu-pakai (cf. seksi 71)
- [ ] openid-configuration ekspos grant yang didukung — implicit/
      hybrid terlihat langsung; PKCE S256 wajib
- [ ] padanan cyphron: OauthStatePlaybook, open_redirect_surface,
      cors_checker; checklist ini saat MERANCANG urutan tes OAuth

## 115. Race condition — kelas & teknik (dari mukul975/exploiting-race-condition-vulnerabilities)
- [ ] dua kelas: limit-race (kupon/vote/withdraw sekali-klaim — satu
      endpoint dipanggil paralel) dan multi-step TOCTOU (registrasi/
      reset password/MFA: state "sudah diverifikasi" dicek di langkah
      lain) — multi-step TIDAK butuh paralel, cukup urutan aneh
- [ ] teknik pengiriman: HTTP/2 single-packet (semua request dalam
      satu frame, byte terakhir dikirim bersamaan), koneksi N
      paralel, last-byte sync — kebisingan sisi server (ambang
      toleransi) ditangani jitter
- [ ] sisi deteksi: N sukses pada sumber daya sama dalam window <
      detik dari satu identity (cf. seksi 74 korelasi); padanan
      cyphron: RaceCouponPlaybook/ReplayTransferPlaybook (lab),
      rate-limit-validator (ambang)
- [ ] mitigasi yang dicari di review: locking serializable / unique
      constraint DB (bukan cek-then-write aplikasi), idempotency key

## 116. Di luar domain + padanan — catatan bidang blok B17
- [ ] #0482/#0484 AD CS ESC1/Certipy (cf. seksi 42 AD ofensif):
      inti konsep ESC1 = template dgn ENROLLEE_SUPPLIES_SUBJECT +
      EKU auth = SAN bebas = impersonasi (T1649); sisi audit
      template = data AD live, di luar kelas tool cyphron
- [ ] #0483 BloodHound/SharpHound: graf jalur serangan AD (session/
      ACL/group) — konsep graf dipakai iam_escalation_scan (cloud);
      kolektor = eksekusi di host AD, di luar fokus web/app
- [ ] #0486 Pacu: live AWS creds; modulnya membuat PERUBAHAN DURABLE
      (IAM user/key/policy) — wajib dicatat & direvert; sisi log
      statis dilayani cloudtrail_scan + iam_escalation_scan
- [ ] #0487 BGP hijacking: prefix hijack/route leak/ROA-RPKI —
      infrastruktur routing global (containerlab), di luar domain;
      inti yang layak: monitoring as-paths milik sendiri + ROA
- [ ] #0490 constrained delegation: enumerasi msDS-AllowedToDelegate
      (S4U2Self/S4U2Proxy) — ofensif AD (cf. seksi 42); sisi
      deteksi 4769 dgn forwardable = ranah kerberos_log_triage
- [ ] #0497 IPv6: RA spoofing/ND/DHCPv6 rogue + dual-stack yang
      tak setara kontrolnya — jaringan L2/L3 live, di luar domain;
      prinsip: kontrol v4 tanpa padanan v6 = celah
- [ ] #0499 Kerberoasting w/ Impacket (cf. seksi 79): minta TGS
      RC4 utk SPN lalu crack offline — ofensif AD; deteksi
      volume-TGS/RC4 = kerberos_log_triage
- [ ] #0501 EternalBlue MS17-010 + #0508 SMB Metasploit: exploit
      kernel SMB (WannaCry/NotPetya) — RCE jaringan pada host
      tak diperbarui; NEVER-LIST & kelas read-only cyphron
      melarang; sisi audit = inventaris SMBv1/patch level (ops)
- [ ] #0502 noPac CVE-2021-42278/42287: rename komputer + s4U2self
      = eskalasi ke DC — ofensif AD (cf. seksi 42); patch level =
      kontrol utamanya
- [ ] #0489 broken link hijacking: padanan cyphron SUDAH ADA —
      sri_checker + third_party_script_risk (script eksternal tanpa
      SRI), wayback_history (referensi historis), rdap_whois
      (status domain live); cek CNAME/dig = live DNS ops
- [ ] #0492 excessive data exposure: padanan api_property_scan
      (#0392 B14 — diff skema respons vs dokumentasi) + seksi 41
      PSS; tanpa inti baru
- [ ] #0494 IDOR: padanan IdorOrdersPlaybook/IdorMassPlaybook +
      seksi 41 (dua bukti: respons objek lain + isi tak sesuai
      pemilik)
- [ ] #0505 prototype pollution: padanan ProtoPollutionPlaybook
      (__proto__ merge sink, klien & server); gadget chain =
      riset per-pustaka, bukan tool umum
- [ ] #0509/#0510 SQLi manual & sqlmap: padanan SqliProducts/
      SqliError/SqliTime + waf_sqli_triage (#0461); sqlmap = alat
      eksternal — prinsip yang diambil: injeksi juga di COOKIE/
      header (bukan hanya param) + level/risk bertingkat
test-append

---
Blok B19 (#0541-#0570, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Enam entri-grup diekstrak jadi tool: #0541 -> tools/
dcsync_triage.py, #0542 -> tools/timestomp_triage.py, #0545 -> tools/
zeek_front_scan.py, #0551+#0554+#0555+#0556+#0559+#0561 -> tools/
win_persist_triage.py, #0562 -> tools/account_manip_triage.py,
#0565 -> tools/webshell_triage.py; sisanya didistilasi di bawah
(117-126).

## 117. DNS persistence & tunneling — pelengkap dns_log_triage (dari mukul975/hunting-for-dns-based-persistence, hunting-for-dns-tunneling-with-zeek)
- [ ] #0543 persistence DNS hidup di ZONE, bukan di log query: record
      A/CNAME baru tak sah, wildcard record, delegasi NS yang diganti,
      TXT update — bertahan lintas rotasi kredensial & reimage host;
      audit = diff zona saat ini vs baseline + riwayat pasif-DNS
- [ ] sumber utamanya API pasif-DNS (SecurityTrails) + audit log
      provider (Route53/Azure DNS/Cloudflare) = live ops ber-kunci;
      di cyphron sisi QUERY dilayani dns_log_triage — checklist ini
      utk AUDIT zona milik lab secara manual
- [ ] #0544 tunneling DNS tercakup dns_log_triage (panjang label,
      entropi, subdomain unik, volume TXT, timing); yang layak
      diingat: distribusi panjang query PER DOMAIN (mean+stdev),
      ambang entropi 3.5 bit/karakter, >100 query/jam per sumber,
      korelasi conn.log utk proses asal, iodine/dnscat2/DNS-over-
      HTTPS sebagai kelas ancaman

## 118. Living off the cloud (dari mukul975/hunting-for-living-off-the-cloud-techniques)
- [ ] T1102/T1567/T1537: C2 via webhook (Discord/Telegram), fungsi
      cloud sebagai relay dinamis, staging data di storage/SaaS sah —
      traffic "terlihat normal" karena keluar ke domain reputasi
      tinggi; signature IP tidak berguna
- [ ] deteksi bergantung pada KONTEN & POLA, bukan reputasi: volume
      upload ke satu tenant baru, token bot di header, payload di
      user-agent yang jarang, endpoint webhook dipanggil dari host
      server (bukan browser user)
- [ ] sisi log AWS statis dilayani cloudtrail_scan; egress filtering
      + allowlist per kategori = kontrol utamanya (ops jaringan)

## 119. WMI lateral & service install — pelengkap (dari mukul975/hunting-for-lateral-movement-via-wmi, hunting-for-unusual-service-installations)
- [ ] #0546 tiga sudut deteksi WMI: jaringan (dce_rpc svcctl/wbem =
      zeek_lateral_scan), cmdline (wmic /node: = lolbin_scan), dan
      endpoint PARENT (WmiPrvSE.exe spawning cmd/powershell di EID 1/
      4688) — sudut ketiga belum ada toolnya; saat membaca ekspor
      Sysmon, cari ParentImage=WmiPrvSE.exe dgn child interpreter
      + cmdline /q /c atau redirect output ke share admin
- [ ] WMI-Activity/Operational 5857/5860/5861 = sumber tambahan
      subscription; 5861 mencatat konfigurasi consumer baru
- [ ] #0564: padanan cyphron win_auth_triage (7045 psexec-service +
      suspicious-service UNC/Temp/Public); varian 4697 (Security log)
      diperiksa win_persist_triage — mekanisme sama, log berbeda

## 120. WMI subscription & shadow copy — pelengkap sysmon_triage (dari mukul975/hunting-for-persistence-via-wmi-subscriptions, hunting-for-shadow-copy-deletion)
- [ ] #0552: padanan sysmon_triage wmi-consumer/binding/filter-timer
      (EID 19/20/21); pelengkap saat triase manual: sistem bersih
      nyaris TIDAK punya permanent subscription — anomali mudah
      terlihat; consumer berbahaya = ActiveScriptEventConsumer &
      CommandLineEventConsumer; trigger Win32_ProcessStartTrace /
      logon / timer; mofcomp.exe = kompilasi subscription
      programatik (lead kuat di EID 1)
- [ ] #0557: padanan sysmon_triage dump-cmdline (vssadmin create/
      delete shadows); pola pelengkap yang layak dicari: wmic
      shadowcopy delete, PowerShell Remove-CimInstance / WMI
      Win32_ShadowCopy.Delete(), bcdedit /set recoveryenabled no,
      event 1105 VSS dalam System log

## 121. Koneksi jaringan tak lazim — berbasis baseline (dari mukul975/hunting-for-unusual-network-connections)
- [ ] "unusual" = deviasi dari baseline per host/proses: proses yang
      TIDAK biasa bicara jaringan (cmd.exe/powershell/w3wp), port
      non-standar (T1571), beacon berkala (cf. seksi 62/106)
- [ ] padanan cyphron: netflow_parse (flow statis) + zeek_beacon_scan;
      baseline proses:port milik ORGANISASI — alat generik tidak bisa
      memutuskan; checklist ini dipakai saat MEMBACA ekspor Sysmon
      EID 3/netflow lab
- [ ] pola konkrit: DNS exfil ke nameserver baru (cf. seksi 117),
      scanning internal (banyak host/port per sumber, cf. seksi 78),
      koneksi ke pool mining (port stratum, cf. seksi 53)

## 122. SaaS SSO token abuse (dari mukul975/hunting-saas-sso-token-abuse)
- [ ] T1550.001: MFA diloloskan dgn mencuri artefak SETELAH auth
      sukses — session cookie, access/refresh token, PRT; replay
      mewarisi sesi tanpa menyentuh kredensial
- [ ] identitas kunci: Entra SessionId/UniqueTokenIdentifier
      menyambungkan semua artefak satu root-auth — SATU sesi dipakai
      dari IP/ASN/device berbeda = replay; tabel non-interactive
      (AADNonInteractiveUserSignInLogs) tempat refresh replay
      muncul; Okta: user.session.start dgn deviceToken dari IP
      divergen, ITP "suspected session hijacking"
- [ ] pola: impossible travel DENGAN SATU session id, refresh-token
      reuse (reuse = cabut rantai, cf. seksi 71), ASN hosting/VPS
      sebagai sumber, akses SaaS dari device yang tak pernah dipakai
      user
- [ ] remediasi = cabut sesi/token (revoke session, revoke refresh),
      bukan reset password saja (cf. seksi 50/66/81); sumbernya API
      Entra/Okta = live ops, checklist ini utk MEMBACA ekspor lognya

## 123. Implementasi enkripsi at-rest (dari mukul975/implementing-aes-encryption-for-data-at-rest)
- [ ] panduan implementasi (bukan deteksi) — yang layak diaudit saat
      review kode/enkripsi lab: mode AEAD (GCM) sebagai default, CBC/
      CTR tanpa MAC = jangan, IV/nonce 96-bit UNIK per pesan (reuse
      GCM = fatal), kunci jangan raw password — KDF: PBKDF2 >=600k
      iterasi / Argon2id (memory-hard), AAD dipakai utk menyatukan
      konteks, streaming utk file besar (jangan seluruh file ke RAM)
- [ ] manajemen kunci: rotasi, penyimpanan terpisah dari data
      (KMS/enclave, cf. seksi 75/86), zeroize di memori (padanan
      cyphron zeroize_scan utk artefak)
- [ ] padanan cyphron saat AUDIT: cert_chain_audit (sertifikat),
      secret_history_scan/zeroize_scan (kunci bocor) — pemilihan
      mode/KDF sendiri = review kode manual dgn checklist ini

## 124. Kurasi alert & program anti-phishing (dari mukul975/implementing-alert-fatigue-reduction, implementing-anti-phishing-training-program)
- [ ] #0568 kurasi bekerja pada DATA disposisi 90 hari per rule:
      fp_rate, tp_rate, signal_to_noise, volume per analyst —
      kandidat tuning = fp_rate >70% atau volume >1000; urutan
      tindakan: higiene (hapus duplikat/low-signal) -> tuning
      (threshold/exception) -> agregasi RBA (skor risiko, bukan
      alert per event) -> SUPPRESSION terakhir; melumpuhkan rule
      tanpa analisis = menciptakan blind spot (eksplisit di sumber)
- [ ] #0569 program awareness: baseline -> kurikulum per-role
      (finance=BEC, IT=kredensial, eksekutif=whaling) -> simulasi
      berkala berjenjang -> just-in-time training saat gagal ->
      penghargaan utk pelapor; metrik kesehatan = REPORT RATE
      (cf. seksi 27/68), bukan click rate; maturity SANS L1-L5
      sbg peta program
- [ ] cyphron: keduanya tata kelola program — dipakai saat MENYUSUN
      rekomendasi di laporan, bukan tool

## 125. GPO anti-ransomware — checklist hardening (dari mukul975/implementing-anti-ransomware-group-policy)
- [ ] sasaran GPO (yang diaudit di konfigurasi lab): blokir eksekusi
      di path user-writable (AppLocker/WDAC), ASR rules Defender,
      Controlled Folder Access utk folder kritis, macro diblokir
      dari internet (Office), LSA protection + Credential Guard,
      USB tak di-whitelist ditolak, PowerShell Constrained Language
      + script block logging, RDP dibatasi (NLA + allowlist)
- [ ] sisi T1490: deny vssadmin/shadowcopy via SRP/AppLocker (cf.
      seksi 120), backup offline + immutable + DIUJI restore (cf.
      seksi 28), rbac admin terbatas (cf. seksi 70 tiered model)
- [ ] GPO bukan pertahanan tunggal — melengkapi EDR/segmentasi/
      backup (eksplisit di sumber); verifikasi = baca hasil GPO
      (gpresult) saat audit lab, bukan tool

## 126. Padanan tool ada — catatan blok B19
- [ ] #0548/#0549 LOLBin (living off the land): padanan lolbin_scan
      (EID 1/11, pola certutil/mshta/rundll32/bitsadmin/wmic/schtasks
      + ps-encoded/office-spawn) — daftar LOLBAS terbuka; variabel
      baseline per lingkungan (proses sah) = --allow-parent/
      --allow-path
- [ ] #0550 NTLM relay: padanan win_auth_triage relay-mismatch
      (WorkstationName vs inventory IP) + ntlm-v1-downgrade +
      zeek_lateral_scan ntlm-spray; pelengkap: audit enforcement
      SMB/LDAP signing (relay hanya sukses bila signing longgar),
      EID 5145 named pipe Spoolss/lsarpc/netlogon/samr (cf. seksi 77)
- [ ] #0553 process injection: padanan sysmon_triage cross-process-
      write/remote-thread/process-tampering (EID 8/10/25, T1055)
- [ ] #0558 spearphishing attachment/link/service: padanan
      eml_phish_triage (header/SPF/DKIM/Reply-To) + seksi 49 (BEC
      identitas) & 66 (corong dampak); HTML smuggling/ISO-LNK/QR di
      PDF = prosedur manual pada eml yang sudah ditandai (cf.
      seksi 82 quishing)
- [ ] #0560 supply chain compromise (T1195): padanan supplychain_check
      + gha_workflow_audit + dep_confusion_check + pkg_typosquat_check
      + sekret secret_history_scan (cf. seksi 80); sisi build-server
      tamper = kebijakan CI (cf. seksi 19)

---
Blok B21 (#0601-#0630, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Tiga entri diekstrak jadi tool: #0630 -> tools/
gcp_fw_audit.py, #0629 -> tools/gcp_orgpolicy_audit.py, #0626 ->
tools/aide_change_triage.py; sisanya didistilasi di bawah (127-134).

## 127. Postur firewall & org policy GCP — padanan tool + runbook (dari mukul975/implementing-gcp-vpc-firewall-rules, implementing-gcp-organization-policy-constraints, implementing-gcp-binary-authorization)
- [ ] audit firewall = klasifikasi eksplisit dari ekspor: world
      (0.0.0.0/0 / ::/0) -> port manajemen (22/23/3389/5985/5986) & DB
      (3306/5432/6379/27017/dst.) = critical; entry protokol "all" atau
      tcp-tanpa-ports = semua port; port web 80/443 dari world sering
      DISENGAJA — medium review via flow logs, bukan temuan pasti
- [ ] dua penanda risiko yang sering meleset: rule world-open TANPA
      targetTags/targetServiceAccounts (berlaku utk SEMUA instance) dan
      rule disabled (drift); postur egress: tanpa deny-all EGRESS =
      implied allow-all-egress tetap berlaku; logConfig per rule =
      syarat validasi efektivitas via flow logs
- [ ] org policy = guardrail tertinggi; baseline esensial
      (vmExternalIpAccess list-deny, resourceLocations,
      disableServiceAccountKeyCreation, automaticIamGrants untuk default
      SA, requireOsLogin, disableSerialPortAccess,
      uniformBucketLevelAccess, sql.restrictPublicIp); status: enforced
      / dry-run (Policy Intelligence — rollout sah tapi belum enforce)
      / weak (enforced=false, allValues=ALLOW, restoreDefault) /
      exceptions (daftar nilai = pengecualian sah, wajib ada owner)
- [ ] Binary Authorization: default-admission REQUIRE_ATTESTATION +
      ENFORCED_BLOCK_AND_AUDIT_LOG; staging = ALWAYS_ALLOW + DRYRUN
      AUDIT_LOG_ONLY; break-glass = annotation terdokumentasi (tiket);
      attestor = KMS asymmetric-signing key + Container Analysis note;
      Continuous Validation = monitor pod berjalan
- [ ] ekspor read-only: `firewall-rules list --format=json` &
      `org-policies list --format=json` -> gcp_fw_audit /
      gcp_orgpolicy_audit; firewall-policies hierarkis org/folder &
      violation CV = cek manual gcloud (di luar ekspor)
- [ ] ranah dibagi: IaC Terraform = terraform_audit (B09), IAM
      escalation = iam_escalation_scan (B13), log CloudTrail =
      cloudtrail_scan (B13) — tool ini khusus konfigurasi firewall/policy

## 128. FIM Linux — parser laporan AIDE (dari mukul975/implementing-file-integrity-monitoring-with-aide)
- [ ] padanan cyphron: aide_change_triage (#0626) — parser laporan
      `aide --check` + klasifikasi severity; AIDE sendiri = alat host
      (aide --init baseline, --check banding, cron terjadwal, alert)
- [ ] disiplin baseline (cf. seksi 70): baseline diambil SETELAH
      hardening & SEBELUM exposure; baseline usang = semua temuan
      noise; re-init hanya via change window (update paket massal)
      dgn owner eksplisit
- [ ] parser dua format: klasik "Added/Removed/Changed entries:" dan
      ringkas "added: N"; angka Summary wajib = jumlah ter-parse —
      mismatch = fail-closed (parser melewatkan sesuatu), bukan bersih
- [ ] klasifikasi: attr HASH berubah = perubahan ISI (sinyal terkuat,
      di atas lokasi); path biner/boot/lib+/root/.ssh kritis; /etc =
      config; /tmp & /dev/shm = staging; metadata saja (mtime/perm) =
      low — higiene biasa
- [ ] verifikasi manual sebelum menyebut kompromi: bandingkan hash
      dgn package manager (rpm -V / dpkg --verify); entry berubah
      saat window update sah = allowlist path, dicatat bukan dipendam

## 129. Program DLP (dari mukul975/implementing-data-loss-prevention-with-microsoft-purview, implementing-endpoint-dlp-controls)
- [ ] rollout WAJIB berjenjang: TestWithNotifications (audit) 2-4
      minggu -> review Activity Explorer -> tune SIT/ambang -> baru
      enforce; enforce langsung = mass blocking & produksi lumpuh
- [ ] override rate > ~20% = aturan terlalu agresif ATAU konten tak
      sensitif — koreksi threshold dgn bukti, jangan paksa blokir;
      override justification dianalisis per rule (business requirement
      vs false positive)
- [ ] custom SIT: regex TANPA anchor ^$ (evaluasi per konten, bukan
      per baris), corroboration keyword + proximity (~300 char)
      menaikkan confidence (85 -> 95); MinCount memisahkan blok (5+
      kartu kredit) vs warn (1-4 dgn override)
- [ ] endpoint DLP: aksi per aktivitas (USB / print / clipboard /
      upload cloud / unallowed app) masing-masing audit|warn|block;
      exception USB by vendor/product ID; unallowed apps = browser
      pribadi + sink cloud
- [ ] EDM (exact data match) utk data terstruktur — tanpa FP regex;
      Purview/Graph = live ops ber-kunci; checklist ini utk MENYUSUN
      rekomendasi kebijakan di laporan, bukan tool

## 130. Validasi kontrol berkelanjutan — BAS (dari mukul975/implementing-continuous-security-validation-with-bas)
- [ ] rumus inti: Control Effectiveness = (prevented + detected) /
      total simulasi; prevention rate & detection rate DIPISAH —
      terdeteksi tapi tidak dicegah tetap celah (gabung melembutkan)
- [ ] peta kontrol -> teknik ATT&CK eksplisit (email gateway <- T1566.*,
      EDR <- T1059/T1003/T1547, SIEM <- T1053/T1021, DLP <-
      T1048/T1567, NDR <- T1071/T1021) — skenario tanpa pemetaan tak
      bisa menunjukkan gap per kontrol
- [ ] deconfliction SOC WAJIB sebelum simulasi (cf. seksi 108);
      perubahan kontrol (rule firewall, update EDR policy) = pemicu
      re-run — regresi deteksi terjadi saat perubahan, bukan saat
      jadwal
- [ ] BAS = komplemen pentest, bukan pengganti (emulasi aman, tanpa
      exploit nyata); di cyphron tidak ada platform BAS — rumus skor
      dipakai saat MEMBACA hasil uji purple-team lab & menyusun
      rekomendasi coverage

## 131. Runtime sensor & postur endpoint (dari mukul975/implementing-ebpf-security-monitoring, implementing-cloud-workload-protection, implementing-device-posture-assessment-in-zero-trust, implementing-disk-encryption-with-bitlocker, implementing-container-image-minimal-base-with-distroless)
- [ ] eBPF/Tetragon = sensor kernel (CAP_BPF/CAP_SYS_ADMIN + BTF):
      TracingPolicy = kprobe + selector (matchArgs/matchBinaries) +
      action (Post/Sigkill); reverse-shell = tcp_connect DARI
      interpreter (bash/python/nc/perl); escape = akses /proc/1/root,
      sysrq-trigger, mount; Sigkill enforcement hanya utk daftar
      tertutup — risiko FP produksi
- [ ] CWPP (boto3 SSM) = runbook live: proses miner (xmrig/minerd/
      cryptonight), reverse shell, `ss -tunlp` C2, FIM hash biner,
      CPU anomaly — sisi log statis dilayani cloudtrail_scan (seksi 53)
- [ ] device posture: skor ZTA per tier akses (basic >= 50, sensitive
      >= 80); drift (EDR mati, enkripsi off, OS downgrade) -> revoke
      akses; grace period remediasi eksplisit; BYOD = jalur browser
      terbatas, bukan trust penuh; data stale = false trust (ditulis
      eksplisit di sumber)
- [ ] BitLocker: XTS-AES 256; escrow recovery key SEBELUM enkripsi
      (TPM gagal = data hilang); TPM-only rentan cold-boot/evil-maid
      (laptop = +PIN); used-space-only pada drive bekas = data lama
      tetap plaintext; removable drive = vektor yang sering terlupa
- [ ] distroless: tanpa shell/package-manager/coreutils = vektor exec
      & instal-runtime mati (drift T1611 tertahan, cf. seksi 51);
      debug via image :debug / kubectl debug ephemeral, jangan di
      produksi; pin digest — padanan cyphron: docker_audit (B18)

## 132. Kripto terapan & penandatanganan artefak (dari mukul975/implementing-code-signing-for-artifacts, implementing-digital-signatures-with-ed25519, implementing-end-to-end-encryption-for-messaging, implementing-envelope-encryption-with-aws-kms)
- [ ] pipeline tanda: checksums.sha256 + detached signature; keyless
      Sigstore (cert short-lived dari OIDC) > kunci jangka-panjang di
      CI secrets; verifikasi WAJIB di jalur deployment (reject
      unsigned), bukan hanya di release; SLSA L2 = provenance
      tersigning, L3 = build terisolasi
- [ ] Ed25519: deterministic (tanpa nonce — tak ada kegagalan RNG),
      key 32B / sig 64B; VALIDASI public key (low-order point) sebelum
      pakai; verifikasi pesan penuh (hash internal), bukan hash luar
- [ ] E2EE Signal-style: X3DH (X25519) untuk initial key agreement +
      Double Ratchet (chain HMAC-SHA256 -> per-message key ->
      AES-256-GCM); forward secrecy = hapus message key setelah pakai;
      out-of-order delivery = jendela skip-keys terbatas; safety
      number = verifikasi identitas out-of-band
- [ ] envelope encryption: data di-encrypt DEK lokal (AES-256-GCM),
      DEK di-encrypt KEK di KMS/HSM — KMS langsung max 4KB vs envelope
      unlimited; encryption context = AAD, wajib divalidasi saat
      decrypt; plaintext DEK jangan disimpan & di-zeroize (cf.
      zeroize_scan); key caching = trade-off latensi vs blast radius
- [ ] di cyphron: tidak ada tool kripto-engineer — checklist utk
      REVIEW pilihan mode/kunci di kode lab (cf. seksi 123 AEAD/KDF)

## 133. Email & identitas — konfigurasi gateway/DMARC/CA (dari mukul975/implementing-dmarc-dkim-spf-email-security, implementing-email-sandboxing-with-proofpoint, implementing-conditional-access-policies-azure-ad)
- [ ] rollout DMARC berjenjang: p=none (monitor, rua ke mailbox khusus)
      -> quarantine pct=25 -> reject pct=100; SPF -all (hard fail)
      setelah stabil; DKIM 2048-bit RSA per selector; audit awal =
      dig TXT — padanan cyphron: spf_dmarc_posture + eml_phish_triage
- [ ] SEG sandbox: detonate utk .exe/.doc(m)/.xls(m)/.pdf/.iso/.zip;
      block-langsung utk .bat/.cmd/.ps1/.vbs/.js/.wsf/.hta (eksekusi
      nyata, tak perlu detonasi); dynamic delivery = body dulu,
      attachment ditahan sampai verdict; evasive (archive ter-password,
      time-bomb, VM-detect) — verdict sandbox = SATU sinyal (cf. seksi
      13/90)
- [ ] Conditional Access Entra: sinyal (user, risk, device compliance,
      location) -> grant MFA / compliant-device ATAU block; break-glass
      = grup exclude EKSPLISIT dan dimonitor; sign-in frequency +
      persistent browser never utk app sensitif; named location bukan
      trust abadi (cf. allowlist berkedaluwarsa seksi 74)
- [ ] ketiganya = live-ops portal/API ber-kunci; checklist utk AUDIT
      konfigurasi lab; sisi per-pesan dilayani eml_phish_triage

## 134. Di luar domain + padanan — catatan bidang blok B21
- [ ] OT/ICS (#0604 conduit remote access IEC 62443, #0618 Dragos):
      zone/conduit SL3, jump server + MFA + approval-based access +
      session recording + vendor escort; Dragos = sensor SPAN jaringan
      OT dgn knowledge pack — bidang OT (cf. seksi 48/63/83), butuh
      TAP/SPAN milik sendiri
- [ ] produk identitas/PAM/jaringan (#0611 Delinea Secret Server,
      #0612 device posture CrowdStrike/Intune/Jamf, #0606 Calico
      GlobalNetworkPolicy/HostEndpoint): vaulting, Remote Password
      Changing + heartbeat, dual control, discovery akun; MDM
      compliance -> CA; CNI tier/DNS egress — integrasi produk pihak
      ketiga (konsep di seksi 70/131); audit gMSA vs password statis
      diingat (cf. seksi 88)
- [ ] #0614 Diamond Model: padanan SUDAH ADA — campaign_correlate
      (#0360) menerapkan 4-pivot (infrastruktur/kapabilitas/temporal/
      viktimologi) + FP-guard CDN/hosting; skill ini versi struktur
      data (activity thread chronological linking) — gunakan
      campaign_correlate, thread = urutan waktu event id
- [ ] #0625 EPSS: skor probabilistik eksplloitasi 30 hari + percentile;
      matriks EPSS x CVSS -> P0-P4 (epss>0.7 & cvss>=9 = P0; epss>0.7 &
      cvss>=7 = P1; epss>0.4 & cvss>=7 = P2; epss>0.1 ATAU cvss>=7 =
      P3; sisanya P4); lonjakan >= 0.3 antar hari = emergensi; API &
      dataset harian = jaringan (di luar disiplin repo) — padanan
      offline: vuln_sla_aging + kev_gap + dependency_cve; pola matriks
      dipakai saat MEMPRIORITASKAN backlog manual
- [ ] #0617 DMARC audit: padanan spf_dmarc_posture; #0613 DevSecOps
      pipeline: padanan exploit_ci_gate + secret_history_scan +
      dependency_cve + gha_workflow_audit (seksi 19/101); #0622 Wazuh:
      deteksi endpoint = alat ops (agent/decoder/rule XML) — lint rule
      XML Wazuh tak di-build tanpa korpus (ids_rule_lint = IDS umum)
- [ ] #0621 E2EE messaging & #0627 AFL++: desain kripto messaging dan
      fuzzing C/C++ (harness persistent __AFL_LOOP, build ASAN+CmpLog,
      corpus cache + afl-cmin, triage crash stack-hash) — butuh
      toolchain C/target terkompilasi, di luar bentuk tool cyphron
      (repo stdlib Python); konsep harness & triage = checklist review
      manual bila lab punya target C
- [ ] #0609 Cloudflare DDoS: proxy-all + sembunyikan origin IP +
      authenticated origin pulls (mTLS) + rate-limit per characteristic
      (ip.src/colo) + rule uji dengan Log dulu sebelum Block; #0610
      canarytoken: laporan coverage per tipe token (web/DNS/doc/AWS) &
      lokasi penempatan = baris program deception (cf. seksi 45);
      alert-on-touch = nilai utamanya, bukan alat pembuat token
---
Blok B22 (#0631-#0660, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Tiga entri diekstrak jadi tool: #0653 -> tools/
k8s_podsec_audit.py, #0656 -> tools/log_chain_verify.py, #0660 ->
tools/attack_coverage.py; sisanya didistilasi di bawah (135-141).

## 135. WebAuthn/FIDO2 relying party (dari mukul975/implementing-hardware-security-key-authentication)
- [ ] RP ID = registrable domain suffix dari origin (example.com sah
      untuk auth.example.com; domain lain tidak) — RP ID salah =
      credential terbit dengan scope salah; cek konfigurasi RP dulu
- [ ] sign_count assertion TIDAK naik dari nilai tersimpan = kandidat
      authenticator klon — flag security event, jangan diam-diam pass
- [ ] user verification (PIN/biometrik) = required untuk assurance
      tinggi; attestation AAGUID diverifikasi vs daftar vendor saat
      enterprise deployment (kunci tiruan lolos tanpa itu)
- [ ] recovery yang tidak membatalkan phishing-resistance: dua kunci
      fisik terdaftar + recovery codes saat enrolment; recovery via
      SMS/email saja = jalur bypass yang mengalahkan seluruh FIDO2
- [ ] python-fido2/py_webauthn = dependensi non-stdlib + butuh browser
      & perangkat — checklist ini dipakai saat REVIEW implementasi RP
      di lab, bukan tool

## 136. Vault dynamic secrets (dari mukul975/implementing-hashicorp-vault-dynamic-secrets)
- [ ] prinsip inti: hapus secret statis — kredensial DB/cloud/PKI
      dibuat on-demand dengan lease TTL dan auto-revoke; bocor =
      menunggu kedaluwarsa, bukan rotasi manual selamanya
- [ ] yang diaudit saat review lab: TTL lease pendek, policy
      least-privilege per path (bukan root policy), AppRole utk
      aplikasi (bukan token panjang), audit device MENYALA (semua
      baca secret tercatat — tanpa itu tidak ada jejak pencurian)
- [ ] dynamic ≠ semua: secret yang tak bisa dibuat programatik tetap
      KV — inventaris mana yang dinamis mana yang statis = bagian
      auditnya
- [ ] Vault = infrastruktur ops; sisi artefak cyphron:
      zeroize_scan/secret_history_scan menangkap kredensial yang
      telanjur statis di file/riwayat git

## 137. Provenance image & backup immutable (dari mukul975/implementing-image-provenance-verification-with-cosign, implementing-immutable-backup-with-restic)
- [ ] cosign: tanda/verifikasi image (key-based atau keyless OIDC via
      Fulcio+Rekor); enforcement = admission policy
      verified-images-only — verify SEBELUM deploy, bukan laporan
      pasca (cf. docker_audit base-not-digest-pin utk pin digest)
- [ ] attestasi SLSA = dokumen provenance TERPISAH dari signature;
      subjectRegExp mengikat identitas builder yang sah — tanpa itu
      signature hanya membuktikan "sesuatu pernah ditandatangani"
- [ ] restic + S3 Object Lock (mode governance/compliance) = salinan
      WORM anti-ransomware; compliance mode tak bisa dibatalkan
      bahkan admin — pilih sadar-risiko; restore test berkala =
      bukti, bukan asumsi (cf. seksi 28)
- [ ] keduanya ops infrastruktur (registry/cluster/object store);
      checklist untuk MENILAI konfigurasi lab, bukan tool

## 138. JIT access — zero standing privilege (dari mukul975/implementing-just-in-time-access-provisioning)
- [ ] akses time-bound dengan approval + auto-expire + jejak; angka
      yang ditulis eksplisit: durasi maksimum per role, justifikasi
      wajib, dan siapa approver-nya
- [ ] sinyal penyalahgunaan: window JIT yang di-extend berulang =
      standing privilege terselubung; aktivitas di dalam window
      harus masih diperiksa (JIT bukan absolved)
- [ ] akun break-glass tetap ada, dipantau, dan diuji — JIT yang
      gagal membuka saat insiden = stagnasi respons
- [ ] cf. seksi 70 (tiered model) & iam_escalation_scan (sisi cloud)

## 139. Deception deployment = ops (dari mukul975/implementing-honeypot-for-ransomware-detection, implementing-honeytokens-for-breach-detection)
- [ ] ranah konsep deception = seksi 45 (MITRE Engage); B20 melaporkan
      canarytoken (#0594/#0604/#0610, cf. seksi 134 B21)
      — sisa nilai dari dua skill ini: honeypot ransomware punya FP
      mendekati nol (tidak ada alasan sah menyentuh decoy file/share)
      sehingga jadi deteksi DI ATAS EDR utk varian yang lolos
      signature; penempatan = direktori share/file yang dikenai lebih
      dulu oleh enumerate-then-encrypt
- [ ] eksekusi (Canarytokens API, webhook, appliance) = live ops
      ber-jaringan — tidak di-port

## 140. SaaS & email gateway — konfigurasi produk (dari mukul975/implementing-google-workspace-admin-security, -phishing-protection, -sso-configuration, implementing-mimecast-targeted-attack-protection, implementing-microsegmentation-with-guardicore, implementing-log-forwarding-with-fluentd, implementing-identity-verification-for-zero-trust)
- [ ] semuanya runbook konsol vendor (Admin Console, Mimecast TTP,
      Guardicore, Fluentd, Entra CA) — butuh tenant + kredensial live;
      pola validasi yang reusable lintas produk: uji SPOOF lookalike
      nyata, dry-run/Reveal mode SEBELUM enforce, rollout per-OU
      berjenjang, threshold FP diperiksa setelah tiap gelombang
- [ ] Workspace SSO: Workspace = SP, ACS google.com/a/{domain}/acs;
      sisi audit = rotasi cert signing IdP + penutupan password
      native (cf. seksi 20 SAML)
- [ ] padanan analisis cyphron: eml_phish_triage + spf_dmarc_posture
      (email), seksi 46/59 (anomali identitas), seksi 90 (SEG),
      seksi 70 (disiplin microsegmentation monitor->enforce)

## 141. Di luar domain + padanan — catatan bidang blok B22
- [ ] kepatuhan/privasi (#0631 #0632 #0639 #0649): GDPR controls/
      DSAR, HIPAA Security Rule, ISO 27001 ISMS — tata kelola
      kepatuhan (cf. seksi 42 #0324); inti teknis GDPR Art.32
      (enkripsi at-rest/transit, pseudonymization, retention) =
      review kode manual; PII regex discovery di DSAR = konsep,
      NER = dependensi non-stdlib
- [ ] OT/hardware (#0642 Tofino ICS firewall, #0645 IEC 62443 zones):
      DPI protokol industri + zone/conduit + SL-T assignment (cf.
      seksi 48/63/83); konsep diode: aliran satu arah, REVERSE FLOW =
      bypass dinyatakan sebagai temuan
- [ ] IGA (#0643 SailPoint): joiner-mover-leaver + SOD + certification
      campaign (cf. seksi 34 #0285) — administrasi identitas
- [ ] padanan tool ada: #0633 GHAS code scanning (sarif_ingest +
      gha_workflow_audit + secret_history_scan), #0648 IaC scanning
      checkov/tfsec/KICS (terraform_audit #0270), #0651 JWT
      signing/verification (jwt_token_audit + JwtAlgConfusion/
      JwtWeakSecretPlaybook), #0657 DEP/ASLR (pe_mitigation_scan
      #0131 — skill ini versi konfigurasi OS bcdedit/
      Get-ProcessMitigation = ops endpoint, cf. seksi 75)
- [ ] padanan konsep: #0654 LLM guardrails (seksi 44 + injection_
      guard; NeMo/Guardrails AI = produk runtime), #0652 Calico
      NetworkPolicy (install CNI = ops; AUDIT manifest NetworkPolicy
      = ranah entri #0668 blok lain — sengaja tidak dibangun utk
      anti-tabrakan; disiplin yang diambil: default-deny baseline
      dulu, verifikasi enforcement via dry-run)



---
Blok B20 (#0571-#0600, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Gelombang "implementing-*": panduan implementasi kontrol,
mayoritas konsol vendor. Lima entri-grup diekstrak jadi tool: #0575 ->
tools/openapi_spec_audit.py, #0579 -> tools/applocker_policy_audit.py,
#0583 -> tools/aws_config_audit.py, #0585 -> tools/data_class_scan.py,
#0597+#0599 -> tools/cspm_finding_ingest.py; sisanya didistilasi di
bawah (142-149; nomor seksi lanjutan B21/B22 yang menulis duluan).

## 142. Rate limiting & deteksi abuse API (dari mukul975/implementing-api-abuse-detection-with-rate-limiting, implementing-api-rate-limiting-and-throttling)
- [ ] dua mekanisme limiter inti: token bucket (refill = elapsed x rate,
      cap max_tokens, retry_after = (requested-tokens)/rate) dan sliding
      window (sorted-set, buang entri < window_start, hitung zcard)
- [ ] limiter adaptif = skor ancaman eksplisit: auth_failures >10 -> +3,
      >5 -> +2, >2 -> +1; error_rate >0.8 -> +3, >0.5 -> +2;
      request_rate >50 -> +2, >20 -> +1; unique_endpoints >50 -> +2;
      skor >=7 CRITICAL, >=5 HIGH, >=3 ELEVATED — tabel limit per level
      (100/50/20/5 rpm) ditulis eksplisit, bukan perasaan
- [ ] tiered limits per kelas pelanggan (free/premium/enterprise +
      endpoint sensitif lebih ketat: auth 5/min, export 5/hour) —
      header X-RateLimit-* + Retry-After wajib di respons
- [ ] padanan cyphron: rate-limit-validator (ukur live di lab),
      web_log_intrusion (ambang per window dari log), LockoutCanaryPlaybook;
      checklist ini dipakai saat MENDESAIN ambang & MEMBACA hasilnya

## 143. Gateway & threat protection — audit konfigurasi (dari mukul975/implementing-api-gateway-security-controls, implementing-api-threat-protection-with-apigee)
- [ ] kontrol gateway yang diaudit di konfigurasi lab: throttle eksplisit
      (contoh 50 rps/burst 100), metric filter status 401/403/429/5xx,
      deny-list UA tool ofensif (sqlmap/nikto/nmap/masscan), mTLS
      terverifikasi (bukan hanya port 443)
- [ ] ambang JSON threat protection Apigee layak dipakai sebagai default
      penilaian payload: ContainerDepth 5, ObjectEntryCount 25,
      ArrayElementCount 100, StringValueLength 500,
      ObjectEntryNameLength 50; XML: NodeDepth 5,
      AttributeCountPerElement 5, ChildCount 25; SpikeArrest 30ps
- [ ] payload bomb = bentuk yang mahal diparse, bukan hanya besar —
      cek struktur tangkapan bisa lewat api_property_scan; regex
      injection (SQLi/XSS/CRLF/traversal) = ranah waf_sqli_triage
- [ ] parser YAML multi-vendor (Kong/Apigee XML) tidak stdlib — audit
      konfigurasi gateway = checklist manual di lab, bukan tool

## 144. API key lifecycle (dari mukul975/implementing-api-key-security-controls)
- [ ] format key = prefix semantik (sk_live_/sk_test_/pk_live_) +
      entropy 256-bit (token_urlsafe(32)) — prefix memudahkan deteksi
      leak dan membedakan lingkungan
- [ ] penyimpanan = SHA-256 hash, BUKAN plaintext; revocation list
      dipakai saat validasi; rotasi dgn grace-period ganda (key lama
      tetap sah terbatas waktu) supaya tidak outage
- [ ] leak response deterministik: regex prefix di repo/log/HTML ->
      ekstrak -> revoke segera — deteksinya sudah di cyphron
      (repo_secret_scan/bundle_exposure/js_secret_scanner_v2/
      secret_history_scan); auto-revoke = aksi berdampak, butuh manusia

## 145. Skor postur API komposit (dari mukul975/implementing-api-security-posture-management)
- [ ] rumus skor per endpoint (0-100): kontrol wajib hilang dihitung
      severity x 5 (authentication, HTTPS, header rate-limit, CORS
      non-`*`, security headers, input validation); multiplier
      klasifikasi: shadow 2.0, deprecated 1.8, external 1.5,
      partner 1.3, internal 1.0; +10 tidak terdokumentasi; +5 per
      tipe data sensitif terdeteksi di sampel respons
- [ ] distribusi: skor >=75 CRITICAL, >=50 HIGH, >=25 MEDIUM — laporan
      agregat organisasi + top-20 terburuk dulu
- [ ] di cyphron: klasifikasi shadow = shadow_api_diff; cek header
      per-kontrol = http_security_headers/cors_checker/
      cache_control_posture; rumus ini dipakai saat MENYUSUN skor dari
      evidence yang sudah dikumpulkan (bukan tool baru)

## 146. Container scan gate & Security Hub (dari mukul975/implementing-aqua-security-for-container-scanning, implementing-aws-security-hub, implementing-aws-security-hub-compliance)
- [ ] gate container scan yang sehat: exit-code gagal pada
      CRITICAL + HIGH yang punya FIX (fixable), bukan semua temuan;
      .trivyignore dgn tanggal kedaluwarsa — ignore abadi = celah;
      re-scan saat DB CVE terbaru (komponen tak berubah bisa jadi
      rentan — pola sama dgn seksi 101 SBOM)
- [ ] padanan cyphron: docker_audit (misconfig statis),
      dependency_cve (CVE dari lockfile/SBOM), gha_workflow_audit (gate)
- [ ] Security Hub x2 = dedup fungsional (standards CIS/FSBP/PCI/NIST,
      delegated admin, insight = preset filter); jalur hasil vendor ->
      ingest: SARIF = sarif_ingest, ASFF = pola ingest yang sama bila
      kelak dibutuhkan; temuan tanpa aksi = noise

## 147. IAM permission boundaries & attack path (dari mukul975/implementing-aws-iam-permission-boundaries, implementing-attack-path-analysis-with-xm-cyber)
- [ ] boundary policy yang benar punya Deny eksplisit utk
      iam:DeleteUserPermissionsBoundary / DeleteRolePermissionsBoundary /
      CreatePolicyVersion pada boundary itu sendiri (jika tidak, boundary
      bisa dilepas oleh principal yang dibatasi)
- [ ] delegation policy wajib mensyaratkan Condition StringEquals
      iam:PermissionsBoundary pada iam:CreateRole — role baru tanpa
      boundary = jalur keluar dari batas
- [ ] effective permission = irisan identity ∩ boundary (expand
      wildcard dgn cek eksplisit); cek ini cocok ditambahkan di
      iam_escalation_scan milik pemiliknya bila dibutuhkan
- [ ] choke point attack path (XM Cyber): prioritas = f(paths_blocked x
      assets_protected) — node dgn banyak jalur masuk/keluar; pada
      temuan cyphron: jalur eskalasi IAM = versi mikro konsep itu
      (iam_escalation_scan); platform sensor = OPS vendor

## 148. OPS & kerangka — catatan bidang blok B20 (bukan "skip" polos)
- [ ] #0577 42Crunch: platform audit OpenAPI (300+ check) + conformance
      scan live — hasilnya SARIF -> sarif_ingest; checklist statisnya
      menyatu dgn openapi_spec_audit (#0575)
- [ ] #0586 Nitro Enclave: attestation doc = COSE_Sign1/CBOR (PCR0-4,
      nonce), validasi PCR vs build + verifikasi chain ke root
      aws.nitro-enclaves; KMS policy wajib Condition
      kms:RecipientAttestation:ImageSha512 — parent role yang bisa
      Decrypt TANPA attestation = FAIL; pustaka cbor2/cose non-stdlib
      -> di luar disiplin cyphron
- [ ] #0589/#0590 Azure PIM + Defender for Cloud: PIM = konversi
      standing -> eligible + MFA-on-activation + access review berkala
      + alert (>5 Global Admin, assignment stale 90 hari); Defender =
      secure score + regulatory dashboard + JIT VM access — keduanya
      konsol/Graph live; konsep inti: standing access = permukaan,
      eligible+JIT = pengecilan
- [ ] #0591/#0593/#0595 BeyondCorp + browser isolation + CISA ZTMM:
      migrasi VPN->ZTNA berfase (inventory -> pilot -> coexist ->
      decommission); access level = atribut device+user+context;
      RBI = matrix mode per kategori URL + CDR strip active-content
      (sisi OOXML padanan maldoc_triage); ZTMM = kerangka maturity
      5 pillar x 4 stage, assessment manual per kapabilitas
- [ ] #0594 canary tokens: prinsip = token TIDAK PERNAH diakses sah ->
      alert-on-touch high-confidence; placement menentukan vektor
      (.aws/credentials, config, wiki); vendor live = OPS; normalisasi
      alert webhook (memo/src/channel/time) = pola triase eml/log
- [ ] #0596 cloud DLP: sisi identifikasi custom = data_class_scan
      (#0585); platform (Macie job, GCP DLP inspect/de-identify,
      Purview labeling) = OPS; gate DLP = scan -> findings -> BLOCK/
      ALLOW eksplisit (jangan silent-allow)

## 149. Di luar domain — routing global RPKI (dari mukul975/implementing-bgp-security-with-rpki)
- [ ] preseden #0487 (B17): infrastruktur routing global (ROA di RIR,
      validator Routinator/FORT, route-map router) di luar fokus
      web/app/infra cyphron
- [ ] inti konsep yang layak diingat — Route Origin Validation RFC 6811:
      pasangkan (origin ASN, prefix) terhadap VRP (prefix, ASN,
      max-length): cocok penuh = VALID; ROA ada tapi ASN/prefix-length
      mismatch = INVALID (indikasi hijack / sub-prefix route leak);
      tanpa ROA = NOT-FOUND (bukan aman, hanya belum terlindungi)
- [ ] monitoring milik sendiri: coverage ROA prefix publik + alarm saat
      VALIDITY announce sendiri turun menjadi INVALID — bisa dievaluasi
      offline dari dump `routinator vrps --format json` bila kelak
      dibutuhkan; tanpa data VRP tidak ada yang bisa disimpulkan

---
Blok B23 (#0661-#0690, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Dua entri diekstrak jadi tool: #0668 -> tools/
netpol_audit.py, #0683 -> tools/psa_ns_audit.py; sisanya didistilasi
di bawah (150-161).

## 150. Policy-as-code OPA/Gatekeeper (dari mukul975/implementing-opa-gatekeeper-for-policy-enforcement, implementing-policy-as-code-with-open-policy-agent)
- [ ] lifecycle constraint yang sehat: ConstraintTemplate (blueprint
      Rego + CRD) -> Constraint instansiasi (match + parameters) —
      rollout WAJIB enforcementAction: dryrun dulu, review .status
      .violations, baru deny; constraint "dryrun" yang tersisa berminggu-
      minggu = kebijakan teater (audit: grep enforcementAction)
- [ ] pairing eksplisit: kind Constraint harus punya ConstraintTemplate
      dgn crd.spec.names.kind sama; tanpa itu constraint tidak pernah
      aktif (silent no-op)
- [ ] higiene match/excludedNamespaces: kube-system & gatekeeper-system
      exclude eksplisit; match kinds per apiGroups — constraint Pod
      saja TIDAK mengenai Deployment template (evaluasi expanded pod,
      baca dulu bentuk match sebelum menilai cakupan)
- [ ] policy disimpan di Git + diuji: opa test utk unit Rego, conftest
      utk lint IaC di CI — gate gagal = temuan critical (fail-closed,
      cf. seksi 19); library resmi gatekeeper-library sbg titik awal,
      jangan tulis ulang
- [ ] Gatekeeper = lapisan DI ATAS PSA (bukan pengganti): PSS bawaan
      utk baseline, Gatekeeper utk kebijakan kustom (label wajib,
      registry allowlist, latest-tag blokir) — padanan cyphron:
      k8s_podsec_audit/psa_ns_audit/netpol_audit; evaluasi Rego live =
      admission webhook cluster (di luar tool)

## 151. Baselining traffic & alat NTA (dari mukul975/implementing-network-traffic-baselining, implementing-network-traffic-analysis-with-arkime)
- [ ] disiplin baseline flow (cf. seksi 76 UEBA & 107 eksfil): minimum
      7 hari data, profil per sumber (mean/median/stdev), z-score +
      IQR ganda (z-score utk lonjakan, IQR utk distribusi miring),
      lantai minimum volume sebelum menilai (host kecil = rasio bohong)
- [ ] profil yang dibangun: distribusi jam/hari (jam kerja eksplisit),
      rasio protokol/port, top-N talkers — anomali dinilai TERHADAP
      profil itu, bukan ambang global
- [ ] beacon butuh interval+jitter (cf. zeek_beacon_scan): avg interval
      stabil + jitter < 5% = high confidence; Arkime/Moloch = alat
      query sesi (deploy + API live = ops) — pola deteksinya sudah
      dilayani zeek_beacon_scan/dns_log_triage/netflow_parse
- [ ] "tidak ada baseline" bukan status netral: tanpa profil 7 hari,
      z-score tak bisa dihitung — catat telemetri kurang (fail-closed),
      jangan menyimpulkan normal

## 152. mTLS antar-servis (dari mukul975/implementing-mtls-for-zero-trust-services)
- [ ] arsitektur: internal CA terpisah dari CA publik, sertifikat
      servis berumur pendek (<= 1 tahun, idealnya rotasi otomatis
      ala mesh), verify_mode CERT_REQUIRED DI KEDUA arah — "TLS dgn
      sertifikat" satu arah bukan mTLS
- [ ] yang diaudit saat review: CA cert BasicConstraints ca=true
      eksplisit, key 4096 utk CA root, SAN dipakai (bukan CN saja),
      tanggal not-before/not-after dihitung UTC (utcnow deprecated —
      timezone-aware), CA key di luar host servis
- [ ] implementasi python sumber = pustaka cryptography (non-stdlib)
      — di cyphron: cert_chain_audit memverifikasi rantai/validity
      dari luar; ssl_tls_analyzer melihat negosiasi endpoint; pembuatan
      CA/sertifikat = ops PKI lab
- [ ] zero-trust service-to-service: identitas workload (SAN/spiffe)
      bukan IP — IP berpindah, identitas tidak; rotasi kunci servis =
      konsumen cert_chain_audit

## 153. NAC 802.1X & RADIUS (dari mukul975/implementing-network-access-control, implementing-network-access-control-with-cisco-ise)
- [ ] tiga pemeran: supplicant (endpoint) -> authenticator (switch/
      WLC) -> auth server (RADIUS/ISE); urutan kekuatan metode:
      EAP-TLS (cert) > PEAP-MSCHAPv2 (password via AD) > MAB (MAC =
      identitas yang MENIRU, bukan yang diautentikasi — MAB terakhir
      dan selalu dianggap jalur lemah)
- [ ] kegagalan harus FAIL-CLOSED: authentication event fail -> VLAN
      karantina (bukan VLAN akses); critical VLAN saat RADIUS mati =
      trade-off availability eksplisit — device fallback VLAN yang
      sama dgn VLAN produksi = kebijakan mati
- [ ] port kontrol: dot1x pae authenticator + order dot1x mab + host-
      mode multi-auth; PRE-AUTH ACL hanya DHCP/DNS/portal — sisanya
      deny; CoA (Change of Authorization) = mekanisme re-authorization
      saat posture berubah (quarantine/uncarantine tanpa re-auth fisik)
- [ ] dACL + SGT (TrustSec) = segmentasi mengikuti identitas, bukan
      port; posture non-compliant -> VLAN remediasi terpisah — konsep
      identitas-mengikuti-perangkat ini yang dipinjam, konfigurasi
      switch/ISE = jaringan fisik (cf. seksi 75 #0348/#0350)

## 154. Deception honeypot ops (dari mukul975/implementing-network-deception-with-honeypots) — cf. seksi 45 & 139
- [ ] kelas: low-interaction (OpenCanary/Cowrie — emulasi protokol,
      aman) vs high-interaction (T-Pot/full OS — tangkap TTP, risiko
      pivot); honeypot = deteksi DI ATAS EDR karena TIDAK ADA alasan
      sah menyentuh (FP ~ nol, cf. seksi 139)
- [ ] placement: VLAN terpisah, "nilai bohong" (file kredensial decoy,
      share, token DNS); setiap interaksi = insiden kandidat, bukan
      statistik — format alert berstandar (service, source, creds
      dipakai, command dieksekusi) menentukan triase
- [ ] integrasi SIEM (syslog/webhook) wajib SEBELUM go-live — honeypot
      tanpa jalur alert = dekorasi; eksekusi deployment = live ops
      (cf. seksi 45 MITRE Engage utk desain goal-nya)

## 155. Suricata IPS deployment (dari mukul975/implementing-network-intrusion-prevention-with-suricata) — cf. seksi 78
- [ ] mode: IDS pasif (TAP/SPAN) vs IPS inline (NFQUEUE/AF-PACKET
      bridge) — inline = pilihan FAIL-CLOSED vs FAIL-OPEN eksplisit:
      `--queue-bypass` dan `fail-open: yes` menjamin traffic lewat saat
      engine mati (availability) tapi berarti IPS bisa diam-diam
      dimatikan; catat pilihan itu saat audit
- [ ] vars yang menentukan validitas rule: HOME_NET/EXTERNAL_NET salah
      = rule melayang (EXTERNAL_NET "!$HOME_NET"); EVE JSON = sumber
      kebenaran (alert/http/dns/tls/files dgn hash) — padanan analisis
      post-hoc cyphron: parser log zeek/web_log
- [ ] anatomi rule: action proto src -> dst (options) — action drop/
      reject aktif; mutu rule = ids_rule_lint (B12); ruleset ET-open/
      ET-pro via suricata-update = ops
- [ ] deployment sensor = ops infrastruktur (cf. seksi 78); nilai
      ekstrak untuk cyphron: kategori rule, EVE-log schema, pilihan
      fail-open/fail-closed sebagai temuan konfigurasi

## 156. Passwordless FIDO2/Entra rollout (dari mukul975/implementing-passwordless-auth-with-microsoft-entra, implementing-passwordless-authentication-with-fido2) — cf. seksi 135
- [ ] ruang konfigurasi enterprise yang diaudit: key restrictions
      AAGUID allowlist (hanya kunci vendor terdaftar), isAttestation-
      Enforced (kunci tiruan lolos tanpa itu), authentication strengths
      CA (phishing-resistant wajib utk admin), migrasi keluar SMS/voice
      (T1111 — interceptable)
- [ ] hybrid: Windows Hello for Business/passkey — registrasi self-
      service dijalankan DGN approval; legacy auth (NTLM/basic) harus
      mati dulu — passwordless di atas jalur legacy = pintu tetap
      terbuka
- [ ] recovery = penentu assurance (cf. seksi 135): dua kunci fisik +
      recovery codes enrolment; jalur recovery SMS/email = bypass
      phishing-resistance; Graph API live = ops ber-kunci — checklist
      ini utk REVIEW kebijakan metode autentikasi lab

## 157. Program PAM: vault, session proxy, PAW (dari mukul975/implementing-pam-for-database-access, implementing-privileged-access-management-with-cyberark, implementing-privileged-access-workstation, implementing-privileged-session-monitoring) — cf. seksi 70, 136, 138
- [ ] arsitektur PAM inti: vault (kredensial TIDAK pernah dilihat
      admin), CPM (rotasi+verifikasi otomatis), PSM (proxy session —
      kredensial tak ekspos, sesi terekam), reconciliation (re-sync
      saat vault vs target beda) — target "zero standing credential"
      (cf. seksi 138 JIT)
- [ ] jaminan arsitektural PSM: firewall MENOLAK RDP/SSH langsung ke
      target, hanya dari IP PSM; bypass jalur = temuan kebijakan, bukan
      preferensi — storage rekaman dihitung (RDP 50-250 KB/menit)
      sebelum go-live
- [ ] PAW (cf. seksi 70 tiered): workstation khusus admin, tanpa
      email/browser, tier-N admin TIDAK logon ke tier-N-1; hardening:
      AppLocker, Credential Guard, VBS; compliance PAW dinilai per
      device, bukan per user
- [ ] database PAM: proxy query (bukan hanya vault koneksi), akun DB
      dinamis on-demand (cf. seksi 136 lease TTL), least-privilege per
      role; vendor PAM (CyberArk/BeyondTrust/Delinea) = live ops ber-
      kunci — yang dipinjam: model routing+rekam+rotasi sbg checklist
      audit lab

## 158. SEG Proofpoint & MAM Intune (dari mukul975/implementing-proofpoint-email-security-gateway, implementing-mobile-application-management) — cf. seksi 49, 90, 133, 140
- [ ] SEG tiga model deploy: MX-based (semua mail lewat gateway), API
      (integrasi M365/Workspace tanpa MX, cepat), hybrid — pola
      validasi lintas produk: uji lookalike/spoof nyata sebelum
      produksi (cf. seksi 140), time-of-click URL rewrite, TRAP/
      retraction pasca-delivery
- [ ] BEC = kelas tanpa URL/lampiran: impostor classifier (ML) + label
      reputasi pengirim — deteksi sisi isi per-pesan di cyphron tetap
      eml_phish_triage (Reply-To/Return-Path/homoglyph, cf. seksi 49)
- [ ] MAM (BYOD tanpa MDM): proteksi per-APLIKASI (Intune App
      Protection Policy) — transfer antar app dibatasi managed-only,
      clipboard level, selective wipe (data korporat hilang, personal
      tetap), offline grace period eksplisit, CA "require app protection
      policy" sbg gate
- [ ] matriks uji MAM deterministik: copy dari managed -> paste di
      unmanaged (harus gagal), save-as (harus gagal), backup OS (harus
      gagal), wipe (data korporat hilang dgn cepat) — rollout per-tier
      data (email < finansial < PII/legal); konsol Intune = live ops;
      cyphron: apk_firebase_scan sisi statis APK

## 159. Firewall zone & NGFW design (dari mukul975/implementing-network-segmentation-with-firewall-zones, implementing-next-generation-firewall-with-palo-alto) — cf. seksi 75
- [ ] tabel zone standar dgn trust level eksplisit (Internet/DMZ/Guest/
      Corporate/Servers/PCI-CDE/Management/OT): kebijakan ditulis PER
      PASANGAN zone, deny-by-default antar-zone; intra-zone deny utk
      zone besar (lateral movement dalam zone sering dilupakan);
      rule default-deny any-any LOG di paling bawah wajib ada
- [ ] yang diaudit dari konfigurasi firewall: rule permissive any-to-
      any tanpa log, management zone tercapai dari user zone (harusnya
      jump-box saja), PCI-CDE dikejar dari zone umum, native VLAN dipakai
      production + trunk tanpa nonegotiate (VLAN hopping)
- [ ] NGFW di atas port: App-ID (klasifikasi aplikasi, bukan port) +
      User-ID (mapping IP->user dari event 4624/4768/syslog) + Content-
      ID (IPS/AV/URL) — Policy Optimizer migrasi port-based ->
      app-based; SSL decrypt = keputusan privasi eksplisit (exclude
      banking/health)
- [ ] zone protection profile: SYN flood (alert/activate/maximal rate +
      SYN cookies), scan detection threshold — konfigurasi appliance =
      jaringan fisik (di luar bentuk tool cyphron; cf. seksi 75
      #0350); checklist ini utk REVIEW desain zone di lab

## 160. Backup tahan-ransomware 3-2-1-1-0 (dari mukul975/implementing-ransomware-backup-strategy) — cf. seksi 28, 137
- [ ] 3-2-1-1-0 didefinisikan eksplisit: 3 salinan, 2 media, 1 offsite,
      1 immutable/air-gapped, 0 error restore-test — salinan immutable
      (Object Lock compliance/hardened repo chattr +i) TIDAK BISA
      dihapus bahkan admin; ransomware modern mencari infrastruktur
      backup DULU (del VSS + hapus job)
- [ ] tiering RPO/RTO per tingkat bisnis (Tier1 1 jam/4 jam — DC, ERP,
      DB; Tier2 4/12; Tier3 24/48) + urutan pemulihan dependensi (DNS/
      DC sebelum app); RPO target vs frekuensi job backup dicocokkan
      eksplisit — target tanpa cadensi job = klaim bohong
- [ ] isolasi kredensial backup: akun admin backup DI LUAR AD produksi
      (domain terpisah / lokal), MFA hardware di konsol, RDP mati,
      repo hardened = SSH password off + kredensial single-use —
      kompromi AD tidak boleh menghapus jalur pemulihan
- [ ] bukti = restore test: SureBackup/restore berkala (Tier1 mingguan,
      Tier2/3 bulanan), verifikasi boot+app health; "backup sukses"
      (job hijau) TIDAK sama dgn "bisa restore" (cf. seksi 28 & 137);
      di cyphron: checklist utk AUDIT strategi backup lab, eksekusi
      infrastruktur = ops

## 161. Di luar domain — OT/ICS & kepatuhan blok B23 (cf. seksi 48, 63, 83, 134, 141)
- [ ] #0663 NERC CIP: regulasi kelistrikan BES — kategorisasi CIP-002
      Attachment 1 (control center RC/BA/TOP = high; >= 3000 MW = high;
      >= 1500 MW generation = medium), ESP + EAP (CIP-005), patch 35
      hari (CIP-007), supply chain (CIP-013) — kepatuhan regulasi +
      bidang grid, bukan pengujian teknis; kategorisasi dampak ->
      kontrol bertingkat cf. seksi 70/104
- [ ] #0669/#0689 segmentasi OT & Purdue model: klasifikasi level 0-5 +
      DMZ IT/OT (3.5) wajib — TIDAK ADA jalur langsung Level 4 ->
      Level 1; konduitor melalui DMZ (historian mirror, jump server,
      patch server), quarantine VLAN, SIS (safety) diisolasi dari
      BPCS; aturan allow DIBANGUN dari baseline traffic 2-4 minggu
      (default-deny per pasangan zone) — bidang OT (butuh TAP/SPAN
      milik sendiri)
- [ ] #0675 OT IR playbook: severity OT berbeda (SEV1-SAFETY = kompromi
      safety system), containment DILARANG power-off tanpa approval
      ops (isolasi di firewall industri), PLC ke mode LOCAL/MANUAL saat
      manipulasi jarak jauh dicurigai, eradikasi = diff program PLC
      berjalan vs backup known-good — PICERL-nya sama (cf. seksi 22/
      28), ranah OT-nya di luar domain
- [ ] #0676 Nozomi (+Dragos seksi 134): sensor pasif SPAN utk visibilitas
      asset OT tanpa scan aktif; korpus alert/asset = produk vendor
      (API live ber-kunci) — pola yang layak: validasi coverage sensor
      per segment, asset baru di jaringan OT = lead
- [ ] #0680 patch OT: lifecycle dgn deadline regulasi (CIP-007 evaluasi
      35 hari), test/staging meniru produksi, window maintenance
      mengikuti shutdown proses, compensating controls EKSPLISIT utk
      sistem tak bisa di-patch (virtual patching via firewall DPI) —
      cf. seksi 26 (ring IT), bidang OT
- [ ] #0682 PCI DSS 4.0.1: 12 requirement / 6 objektif — CDE scoping
      (segmentasi mengecilkan scope), MFA semua akses CDE (8.4.2),
      authenticated internal scan (11.3.1.1), anti-phishing teknis
      (5.4.1), automated log review (10.4.1.1), customized approach =
      validasi alternatif dgn Targeted Risk Analysis — tata kelola
      kepatuhan (cf. seksi 42 #0324); kontrol teknisnya sudah dilayani
      tool cyphron (waf/ssl/log)
