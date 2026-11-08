# PORT-AGENT-METHODS — distilasi metodologi dari skill antrean yang di-skip

Beberapa skill di SKILL-PORT-QUEUE di-SKIP sebagai tool (tanpa inti yang
bisa dieksekusi kode), tapi inti metodologinya tetap berguna untuk
AGENT yang bekerja di repo ini. Dokumen ini mendistilasinya dari
trailofbits/skills (CC-BY-SA-4.0 — konsep, bukan teks) ke checklist
yang dipakai saat review/audit di secai. Kontrak repo tetap di atas
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
Catatan secai: repo fokus web/app — checklist ini dipakai hanya bila
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
SecAI tidak memasang gh CLI; protokol yang setara via REST API:
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
- [ ] di secai: suite 1584+ test — mutasi manual ini dipakai saat
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
      tandai partial (prinsip fail-closed secai)
- [ ] skor otomatis tidak pernah memicu blokir sendiri — manusia yang
      konfirmasi (keputusan berdampak butuh persetujuan)

## 10. Benchmark Kubernetes (dari mukul975/benchmarking-kubernetes-with-kube-bench)
- [ ] runbook eksternal (kube-bench butuh node/cluster) — secai mengaudit
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
- [ ] sumber pasif-DNS/SecurityTrails = jaringan+API key — di secai cukup
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
- [ ] lab secai: verifikasi header/UA-filtering bisa diuji via playbook
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
      belum ada konsumen sigma di secai — disiplinnya saja yang diambil
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
- [ ] padanan secai: tools/exploit_ci_gate.py + diff_risk_scan untuk
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
- [ ] padanan secai: rdap-enrichment + intel_sync (KEV/nuclei) sudah
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
      inti deterministik utk secai

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
- [ ] di secai konsep ini muncul sebagai korelasi multi-sumber di
      dns_log_triage/netflow_parse — timeline = pertanyaan, bukan alat

## 34. Di luar domain — catatan bidang (bukan "skip" polos)
- [ ] #0272 auditing-uefi-firmware-with-chipsec: firmware/UEFI hardware —
      butuh akses fisik+driver kernel, di luar web/app/infra secai.
      Inti yang layak diingat: bios_wp (BIOS_CNTL+PRR), spi_lock (FLOCKDN),
      smrr/smm, secureboot variables, s3bootscript — FAIL = precondition
      implant firmware (T1542.001); bukti = dump SPI vs image OEM
- [ ] #0285 identity governance lifecycle: proses IGA enterprise (JML:
      joiner-mover-leaver, status PRE_HIRE->ACTIVE->TERMINATED, orphan
      account) — administrasi identitas, bukan pengujian keamanan
- [ ] #0296 role mining RBAC: optimasi peran dari matriks user-permission
      (clustering Jaccard / Formal Concept Analysis, metrik WSC & coverage)
      — data-mining utk admin IAM, bukan temuan keamanan; padanan secai
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
- [ ] di secai: tidak ada tool atribusi (bagian API OSINT butuh kunci +
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
      cek secai: file-exposure-checker, directory-listing-detector,
      cached-sensitive-files
- [ ] enforcement kadang hanya ditegakkan pada METODE tertentu: HEAD/
      OPTIONS/PATCH atau method-override header bisa lolos sementara GET
      diblok — tes varian metode pada endpoint yang sama
- [ ] 403 bukan "aman": bandingkan isi respons 403 vs 404 vs 200 untuk
      membedakan "ada tapi dilindungi" vs "ada dan bocor"
- [ ] di secai: differential unauth-vs-auth sudah ada di
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
- [ ] di secai: permukaan pasif sudah luas (rdap-whois, ct-inventory,
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
      serangan — di secai dipakai untuk menyempitkan scope audit sah
- [ ] padanan secai: program_discovery/target_scout + permukaan pasif
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
- [ ] di secai: mft_scan/dpapi_blob_scan membaca artefak statis; checklist
      ini dipakai saat MEMINTA/MENCATAT bukti, bukan saat memparse-nya

## 41. OWASP API Top 10 dipetakan secai (dari mukul975/conducting-api-security-testing) — distilasi B11
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
      web/app secai dan bertentangan dengan kelas read-only
- [ ] IR/response ops (#0318 #0327): cloud IR + malware IR — proses
      respons insiden organisasi; triase statisnya sudah dilayani
      maldoc_triage/pdf_triage/packer_scan/ioc_defang
- [ ] pentest ofensif jaringan/cloud/mobile (#0319 #0323 #0325 #0328
      #0330): metodologi engagement ofensif penuh (MITM, internal network,
      cloud, MASTG) — pelaksanaan butuh izin per-engagement dan alat aktif;
      padanan statis secai: attack_planner (rencana, tanpa eksekusi),
      apk_firebase_scan (triase APK)
- [ ] forensik memori (#0329): parsing RAM dump (Volatility) — di luar
      kelas alat secai (artefak statis: mft_scan, dpapi_blob_scan)
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
- [ ] padanan secai: tools/injection_guard.py melayani lapis 1-2 untuk
      bukti/teks yang masuk repo; lapis 3 (model klasifikasi) = butuh
      unduhan model + jaringan — di luar disiplin secai
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
- [ ] secai: tidak ada alat engagement — checklist ini dipakai saat
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
- [ ] padanan secai: brute force web = web_log_intrusion (ambang POST
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
      id berurutan, rate limit per identity — cek secai: IdorOrders/
      AdminAccessPlaybook (aktif), rate-limit-validator
- [ ] di secai: parser CLF sudah ada di web_log_intrusion — pola
      enumerasi bisa ditambahkan di situ bila dibutuhkan, jangan tool baru

## 48. Di luar domain + ops produk — catatan bidang blok B13
- [ ] OT/ICS/SCADA (#0377 #0381 #0382): deteksi anomali proses ICS,
      historian, aturan Suricata Modbus/S7comm/DNP3 — domain teknologi
      operasional, di luar fokus web/app/infra secai; butuh jaringan
      OT tersegmentasi + sensor SPAN milik sendiri
- [ ] deployment deception (#0364 #0365 #0367 #0369 #0372): runbook
      membuat honeytoken/canary/decoy (AD, cloud, file) + alert-on-touch
      — konsepnya dicakup seksi 45; pelaksanaan = ops infrastruktur
- [ ] produk zero-trust/EDR (#0366 #0368 #0370 #0371 #0373 #0374):
      Cloudflare Access, CrowdStrike, osquery/Fleet, Prisma Access, SDP,
      Tailscale — integrasi produk pihak ketiga, bukan alat audit
- [ ] ops deteksi cloud (#0385 #0387 #0388 #0389): automation GuardDuty
      (EventBridge/Lambda), KQL Azure, query Graph utk service principal,
      az CLI storage — butuh kredensial live; padanan statis secai:
      cloudtrail_scan + iam_escalation_scan
- [ ] alat eksternal (#0384): TruffleHog = scanner secret pihak ketiga;
      padanan secai: secret_history_scan (riwayat git) + zeroize_scan

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
- [ ] di secai: sisi log AWS offline dilayani cloudtrail_scan
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
- [ ] runtime detection butuh sensor kernel (eBPF/Falco) — di secai
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
- [ ] padanan secai: dep_confusion_check (manifest + konfigurasi
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
- [ ] analisis memori di luar kelas secai — checklist utk MEMBACA
      ekspor event XML/EDR lab

## 62. DNS C2/eksfiltrasi — pelengkap (dari mukul975/detecting-command-and-control-over-dns + detecting-dns-exfiltration-with-dns-query-analysis + detecting-exfiltration-over-dns-with-zeek)
- [ ] padanan secai: dns_log_triage (entropi, panjang label, volume
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
      produksi) & regulasi — di luar fokus web/app secai; konsep
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
- padanan secai: target_scout, lab_target, exploit_engine + gates,
  session_ledger

## 65. Penjarahan & deteksi tiket Kerberos (dari mukul975/conducting-pass-the-ticket-attack) — distilasi B12
- [ ] sisi serangan (lab): ekstrak TGT/TGS dari LSASS (.kirbi) ->
      konversi ccache -> injeksi -> gerbang hanya di lab berizin;
      NEVER-LIST secai tetap di atas segalanya
- [ ] sisi deteksi: 4768/4769 dari host tak lazim, TGT dipakai dari IP
      berbeda dgn saat diterbitkan, tiket sama muncul di beberapa
      workstation berurutan = reuse, bukan reissue
- padanan secai: kerberos_log_triage (B14, #0418/#0419) — cek RC4
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
- padanan secai: eml_phish_triage (B07 #0199) — header, SPF/DKIM/DMARC,
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
- catatan secai: pola sama dipakai saat menulis nightrun/report —
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
- padanan secai: spf_dmarc_posture (spoofability), eml_phish_triage

## 69. Uji penetrasi nirkabel (dari mukul975/conducting-wireless-network-penetration-test) — distilasi B12
- [ ] butuh adapter monitor-mode + izin fisik — di luar bentuk tool
      secai (software-only); catat sebagai bidang terpisah
- [ ] yang bisa diekstrak: sisi analisis PCAP — handshake/PMKID capture,
      deauth frame, rogue AP vs inventaris BSSID sah, mode transisi WPA3
      downgrade
- padanan secai: deauth_pcap_scan (B06 #0159) — frame deauth dari
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
- catatan secai: k8s_rbac_audit (B09) & k8s_audit_triage menyentuh
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
- padanan secai: open_redirect_surface, cors_checker, param_probe_checker

## 72. TLS 1.3 (dari mukul975/configuring-tls-1-3-for-secure-communications) — padanan secai
- [ ] 3 cipher suite sah TLS 1.3 (AES-256-GCM, AES-128-GCM, ChaCha20-
      Poly1305); kunci = PFS wajib, tidak ada RSA key exchange
- [ ] 0-RTT replayable — hanya utk request idempoten
- [ ] matikan TLS 1.0/1.1; HSTS max-age panjang + includeSubDomains
- [ ] padanan sudah ada di secai: ssl_tls_analyzer, tls_cipher_suites_
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
      
      memblokir merge (pola sama dgn patch_proof secai: bukti sebelum
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
      — bidang kriptografi-hardware, di luar bentuk tool secai;
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
      EDR Windows via Intune/PowerShell; padanan statis secai:
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
      infrastruktur; di secai inti offline-nya dilayani
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
      secai: lolbin_scan (cmdline) + sysmon_triage (uac-registry-
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
- [ ] padanan secai: zeek_lateral_scan (lateral SMB/DCE-RPC/NTLM),
      zeek_beacon_scan + dns_log_triage (beacon/DNS), ids_rule_lint
      (mutu rule IDS) — deteksi scan-port generik = Suricata live,
      di luar kelas tool offline

## 79. Kredensial & tiket — pelengkap deteksi (dari mukul975/detecting-kerberoasting-attacks, detecting-mimikatz-execution-patterns, detecting-pass-the-ticket-attacks)
- [ ] kerberoasting (T1558.003): 4769 RC4 (0x17) padahal domain
      AES-only + VOLUME TGS tinggi per user utk banyak SPN berbeda
      dalam window pendek; AS-REP roasting = 4768 pre-auth tidak
      wajib (accounts dnt-req-preauth); padanan secai:
      kerberos_log_triage (RC4/tanpa-TGT/lifetime) — burst-volume
      bisa ditambah di situ bila dibutuhkan
- [ ] mimikatz: cmdline sekurlsa::/lsadump::/Invoke-Mimikatz + EID 10
      akses lsasse (0x1010/0x1FFFFF) — padanan secai:
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
- [ ] padanan secai: npm_script_audit (lifecycle script offline),
      dep_confusion_check, dependency_cve, supplychain_check —
      GuardDog/OSV sendiri = alat pihak ketiga (ops CI)

## 81. Cloud, AI, mobile, ransomware — pola yang layak diingat (dari mukul975/detecting-misconfigured-azure-storage, detecting-model-extraction-attacks, detecting-oauth-token-theft, detecting-mobile-malware-behavior, detecting-ransomware-encryption-behavior)
- [ ] Azure storage (ops az CLI): yang diaudit — allowBlobPublicAccess,
      networkRuleSet.defaultAction (Allow = terbuka), minimumTlsVersion
      >= 1.2, encryption.requireInfrastructureEncryption, SAS token
      berlebihan, logging disabled; anonymous-blob test = satu curl
      list container; di secai belum ada padanan Azure — checklist
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
      shadows; padanan secai: packer_scan (entropi PE); monitoring
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
      dependensi non-stdlib (zbar/PIL), jadi di secai ditangani
      sebagai prosedur manual pada eml yang sudah ditandai
      eml_phish_triage, bukan tool decode

## 83. Di luar domain — Modbus/OT (dari mukul975/detecting-modbus-command-injection-attacks, detecting-modbus-protocol-anomalies)
- [ ] domain ICS/SCADA (cf. seksi 48/63) — butuh SPAN/TAP jaringan OT
      + parser protokol industri, di luar fokus web/app/infra secai
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
- [ ] padanan secai: zeek_beacon_scan (beacon), dns_log_triage
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
- [ ] di luar kelas alat secai (forensik memori Volatility);
      prinsip cross-view muncul generik: ct_baseline_diff (harapan vs
      kenyataan), mft_scan (disk mentah vs API)

## 86. Eksfiltrasi S3 — pelengkap cloudtrail_scan (dari mukul975/detecting-s3-data-exfiltration-attempts)
- [ ] padanan secai: cloudtrail_scan (B13) melayani sisi log statis;
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
- [ ] padanan secai: sisi CloudTrail/IAM = cloudtrail_scan +
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
- [ ] padanan secai: win_logon_triage (logon type filter bisa
      dilebarkan), k8s_rbac_audit (serviceaccount cluster); checklist
      ini utk MEMBACA hasilnya

## 89. Shadow IT SaaS (dari mukul975/detecting-shadow-it-cloud-usage)
- [ ] mekanisme: agregasi proxy/DNS log per domain -> volume byte +
      jumlah user unik -> klasifikasi kategori SaaS -> bandingkan
      daftar disetujui organisasi
- [ ] risiko bukan dari kategori saja: volume data + jumlah user +
      kategori (storage/AI = tinggi) -> skor eksfil potensial
- [ ] butuh daftar-putih ORGANISASI — alat generik tidak bisa
      memutuskan "unauthorized"; di secai ini proses review log,
      bukan tool (dns_log_triage menyediakan agregasi per-domain)
- [ ] remediasi berjenjang: temukan -> kategorikan -> kebijakan
      (blokir/sanction) -> monitor deviasi

## 90. Spearphishing via email gateway — sisi konfigurasi (dari mukul975/detecting-spearphishing-with-email-gateway)
- [ ] empat lapis SEG yang wajib dinyala: impersonation protection
      (display-name/domain mirip eksekutif), URL rewriting+detonation,
      attachment sandboxing, rule kustom kampanye
- [ ] spearphish lolos spam filter generik karena personal — indikator
      = ketidakcocokan identitas + konteks proses, bukan signature
- [ ] padanan secai: eml_phish_triage (header/SPF/DKIM/Reply-To),
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
- [ ] butuh kredensial Graph — di secai = runbook live ops;
      pola "grant tinggi + tindak lanjut persistence" berlaku juga
      saat membaca cloudtrail_scan (AttachUserPolicy dsb.)

## 92. PowerShell T1059.001 — melengkapi ps_obf_scan (dari mukul975/detecting-suspicious-powershell-execution)
- [ ] padanan secai: ps_obf_scan (obfuskasi statis); skill ini
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
- [ ] secai: sysmon_triage/win_logon_triage membaca jejak; checklist
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
      environment throwaway; padanan statis secai: cloudtrail_scan/
      iam_escalation_scan utk MEMBACA telemetrinya
- [ ] #0473 CloudFox: enumerasi read-only AWS/Azure pasca-kredensial
      (role-trust, secrets, endpoints) — alat ofensif live; polanya
      (AssumeRole graph) dicakup iam_escalation_scan
- [ ] #0475 container escape (ofensif): privileged/hostPath/docker
      .sock/release_agent — sisi deteksinya sudah diekstrak seksi 51;
      eksekusi breakout = hanya lab berizin, bukan bentuk tool secai
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
      stop/threat profile — padanan secai: attack_planner (rencana
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
- [ ] di secai: tidak ada tool PHP-khusus (lab web umumnya bukan
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
- [ ] di secai: eksekusi exploit live = exploit_engine + gates +
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
- [ ] di secai: parsing SQLite peramban tidak di-build (skema DB
      berubah antar-versi browser + enkripsi kredensial non-stdlib);
      checklist dipakai saat AKUISISI/penugasan artefak, bukan parse

## 98. Forensik memori — volatilitas (dari mukul975/extracting-credentials-from-memory-dump, extracting-memory-artifacts-with-rekall) — di luar kelas
- [ ] di luar kelas alat secai (cf. seksi 42 #0329, seksi 85): butuh
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
      padanan secai: parser XML triase milik sendiri (win_logon_
      triage, win_auth_triage, sysmon_triage, kerberos_log_triage,
      ps_scriptlog_triage); pilih berdasar kebutuhan: korpus Sigma
      luas = alat eksternal, cek deterministik tertarget = parser
      secai; alat eksternal = ops, bukan kode repo
- [ ] alur yang layak diingat saat MENGARAHKAN ekspor: prioritaskan
      channel Security, Sysmon, PowerShell/Operational, RDP
      LocalSessionManager, TaskScheduler — ekspor XML (wevtutil /x)
      langsung bisa dibaca parser secai
- [ ] Velociraptor: VQL artifact + hunt fleet-wide + offline collector
      = platform ops (cf. seksi 48 produk); konsep yang dipinjam:
      hipotesis -> VQL -> fan-out -> agregasi terpusat (pola sama dgn
      fleet_dispatch secai)

## 101. SBOM CycloneDX/SPDX (dari mukul975/generating-and-analyzing-sboms) — padanan ada
- [ ] padanan secai: dependency_cve MENGKONSUMSI CycloneDX JSON +
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
- [ ] di secai: impact_narrative + report_pack melayani temuan
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
      seksi 75 #0354); padanan statis secai: pe_mitigation_scan
      (biner), win_audit_coverage (cakupan logging)
- [ ] di secai: tidak ada tool audit CIS host (butuh akses host
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
- [ ] padanan secai: web_log_intrusion (ambang POST per window),
      win_logon_triage (4625 spray/enumerasi) — stuffing lintas-IP
      butuh agregasi per-akun lintas window; pola bisa ditambah di
      web_log_intrusion bila dibutuhkan, bukan tool baru
- [ ] defensif: rate limit per identitas+per-IP, deteksi breach
      password (deny-list), MFA — bukan cuma CAPTCHA

## 106. Beacon C2 & Cobalt Strike statis (dari mukul975/hunting-for-beaconing-with-frequency-analysis, hunting-for-cobalt-strike-beacons, hunting-for-command-and-control-beaconing)
- [ ] padanan secai: zeek_beacon_scan (interval/CV/jitter per pair),
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
- [ ] padanan secai: insider_baseline_scan (volume per user),
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
SUDAH dilayani playbook secai; dua entri diekstrak jadi tool:
#0491+#0495 -> tools/mobile_manifest_audit.py (AXML/XML/plist/prefs),
#0498 -> tools/jwt_token_audit.py (konten token); sisanya di bawah.
Ranah playbooks live TIDAK diperluas — tool triase pasif saja.

## 108. Eksekusi red team exercise (dari mukul975/executing-red-team-exercise)
- [ ] rencana eksekusi turun dari threat model (aktor nyata yang
      relevan), bukan daftar exploit yang menarik — padanan secai:
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
      destruktif TIDAK perlu; padanan secai: RceMarkerPlaybook
- [ ] padanan secai: SsrfCallbackPlaybook/SsrfChainPlaybook
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
- [ ] padanan secai: AdminAccessPlaybook (diferensial unauth/auth),
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
- [ ] padanan secai: DeserRcePlaybook (uji live lab); eksploitasi
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
      (qs/express bracket parsing), peta cek secai:
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
- [ ] padanan secai: OauthStatePlaybook, open_redirect_surface,
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
      secai: RaceCouponPlaybook/ReplayTransferPlaybook (lab),
      rate-limit-validator (ambang)
- [ ] mitigasi yang dicari di review: locking serializable / unique
      constraint DB (bukan cek-then-write aplikasi), idempotency key

## 116. Di luar domain + padanan — catatan bidang blok B17
- [ ] #0482/#0484 AD CS ESC1/Certipy (cf. seksi 42 AD ofensif):
      inti konsep ESC1 = template dgn ENROLLEE_SUPPLIES_SUBJECT +
      EKU auth = SAN bebas = impersonasi (T1649); sisi audit
      template = data AD live, di luar kelas tool secai
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
      tak diperbarui; NEVER-LIST & kelas read-only secai
      melarang; sisi audit = inventaris SMBv1/patch level (ops)
- [ ] #0502 noPac CVE-2021-42278/42287: rename komputer + s4U2self
      = eskalasi ke DC — ofensif AD (cf. seksi 42); patch level =
      kontrol utamanya
- [ ] #0489 broken link hijacking: padanan secai SUDAH ADA —
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
      di secai sisi QUERY dilayani dns_log_triage — checklist ini
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
- [ ] #0564: padanan secai win_auth_triage (7045 psexec-service +
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
- [ ] padanan secai: netflow_parse (flow statis) + zeek_beacon_scan;
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
      secai zeroize_scan utk artefak)
- [ ] padanan secai saat AUDIT: cert_chain_audit (sertifikat),
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
- [ ] secai: keduanya tata kelola program — dipakai saat MENYUSUN
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
- [ ] padanan secai: aide_change_triage (#0626) — parser laporan
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
      exploit nyata); di secai tidak ada platform BAS — rumus skor
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
      produksi; pin digest — padanan secai: docker_audit (B18)

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
- [ ] di secai: tidak ada tool kripto-engineer — checklist utk
      REVIEW pilihan mode/kunci di kode lab (cf. seksi 123 AEAD/KDF)

## 133. Email & identitas — konfigurasi gateway/DMARC/CA (dari mukul975/implementing-dmarc-dkim-spf-email-security, implementing-email-sandboxing-with-proofpoint, implementing-conditional-access-policies-azure-ad)
- [ ] rollout DMARC berjenjang: p=none (monitor, rua ke mailbox khusus)
      -> quarantine pct=25 -> reject pct=100; SPF -all (hard fail)
      setelah stabil; DKIM 2048-bit RSA per selector; audit awal =
      dig TXT — padanan secai: spf_dmarc_posture + eml_phish_triage
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
      toolchain C/target terkompilasi, di luar bentuk tool secai
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
- [ ] Vault = infrastruktur ops; sisi artefak secai:
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
- [ ] padanan analisis secai: eml_phish_triage + spf_dmarc_posture
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
- [ ] padanan secai: rate-limit-validator (ukur live di lab),
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
      ekstrak -> revoke segera — deteksinya sudah di secai
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
- [ ] di secai: klasifikasi shadow = shadow_api_diff; cek header
      per-kontrol = http_security_headers/cors_checker/
      cache_control_posture; rumus ini dipakai saat MENYUSUN skor dari
      evidence yang sudah dikumpulkan (bukan tool baru)

## 146. Container scan gate & Security Hub (dari mukul975/implementing-aqua-security-for-container-scanning, implementing-aws-security-hub, implementing-aws-security-hub-compliance)
- [ ] gate container scan yang sehat: exit-code gagal pada
      CRITICAL + HIGH yang punya FIX (fixable), bukan semua temuan;
      .trivyignore dgn tanggal kedaluwarsa — ignore abadi = celah;
      re-scan saat DB CVE terbaru (komponen tak berubah bisa jadi
      rentan — pola sama dgn seksi 101 SBOM)
- [ ] padanan secai: docker_audit (misconfig statis),
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
      temuan secai: jalur eskalasi IAM = versi mikro konsep itu
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
      -> di luar disiplin secai
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
      web/app/infra secai
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
      registry allowlist, latest-tag blokir) — padanan secai:
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
      — di secai: cert_chain_audit memverifikasi rantai/validity
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
      post-hoc secai: parser log zeek/web_log
- [ ] anatomi rule: action proto src -> dst (options) — action drop/
      reject aktif; mutu rule = ids_rule_lint (B12); ruleset ET-open/
      ET-pro via suricata-update = ops
- [ ] deployment sensor = ops infrastruktur (cf. seksi 78); nilai
      ekstrak untuk secai: kategori rule, EVE-log schema, pilihan
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
      reputasi pengirim — deteksi sisi isi per-pesan di secai tetap
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
      secai: apk_firebase_scan sisi statis APK

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
      jaringan fisik (di luar bentuk tool secai; cf. seksi 75
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
      di secai: checklist utk AUDIT strategi backup lab, eksekusi
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
      tool secai (waf/ssl/log)

---
Blok B25 (#0721-#0750, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Dua entri diekstrak jadi tool: #0740 -> tools/
ransom_artifact_triage.py, #0746 -> tools/crypto_inventory_scan.py;
sisanya didistilasi di bawah (162-175). Gelombang "implementing/
integrating/managing" mayoritas = panduan kontrol + konsol vendor;
keluarga zero-trust (#0727-#0734) distilasi jadi satu seksi (166).

## 162. VQL artifact inventory — Velociraptor (dari mukul975/implementing-velociraptor-for-ir-collection) — cf. seksi 100
- [ ] nilai yang layak dipinjam dari skill ini = PETA "artefak mana
      menjawab pertanyaan mana" di endpoint Windows: EvtxHunter
      (IDRegex 4624/4625/4648/4672/4688/4698/4769/7045) utk autentikasi,
      Prefetch utk bukti eksekusi, AppCompatCache/Shimcache + Amcache
      utk riwayat program, UserAssist utk aktivitas GUI, NTFS.MFT dgn
      FileRegex .(exe|dll|ps1|bat|cmd) utk timeline file — kumpulkan
      dari artefak paling murah yang menjawab hipotesis
- [ ] tiga mode koleksi: hunt fleet-wide (pola hipotesis->VQL->fan-out
      ->agregasi = fleet_dispatch), per-client targeted, dan OFFLINE
      collector utk host terisolasi (hasil tetap diimpor server)
- [ ] deployment (server config generate, repack MSI client, port
      8000/8001/8889) = platform ops; di secai sisi artefak statis
      dilayani mft_scan/dpapi_blob_scan/browser_history_triage/
      ransom_artifact_triage (#0740); runbook live tetap milik sumber

## 163. Program SLA remediasi — pelengkap vuln_sla_aging (dari mukul975/implementing-vulnerability-remediation-sla, implementing-vulnerability-sla-breach-alerting)
- [ ] padanan secai: vuln_sla_aging (#0307) sudah memegang matriks
      severity->hari, modifier internet-facing, override KEV, umur/
      overdue, dan tangga eskalasi 50/75/100% — dua skill ini versi
      PROGRAM-nya; tambahan yang layak diingat saat menyetel kebijakan:
- [ ] matriks dgn ASSET TIER (Tier1 24-48 jam utk critical; Tier3 7
      hari) — tier dari criticality bisnis+eksposur, bukan perasaan;
      accelerator: EPSS > 0.5, exploit publik, riwayat breach tipe
      serupa (potong SLA 50% — pola sama dgn modifier x0.5 tool)
- [ ] exception process yang sehat: justifikasi tertulis + dampak
      bisnis, compensating controls TERDOKUMENTASI, approval asset
      owner DAN security, durasi maksimum 90 hari (renewable dgn
      re-approval) — exception tanpa tanggal kedaluwarsa = celah
- [ ] KPI target eksplisit: SLA compliance > 90%, backlog overdue <
      5%, exception rate < 10%, recurrence < 5%, MTTR per severity —
      metrik tanpa target = pajangan
- [ ] breach alerting (DB schema, dispatch SMTP/Slack/PagerDuty,
      runner cron) = ops infrastruktur; logika deteksinya (umur vs
      SLA + grace period) sudah dieksekusi vuln_sla_aging

## 164. ZKP autentikasi — Schnorr (dari mukul975/implementing-zero-knowledge-proof-for-authentication) — cf. seksi 132
- [ ] protokol inti (logaritma diskrit): publik y = g^x mod p;
      commitment t = g^r (r acak); verifier kirim challenge c acak;
      respons s = r + c*x mod q; verifikasi g^s == t * y^c mod p —
      server TIDAK PERNAH menerima x
- [ ] non-interactive = Fiat-Shamir: c = H(t, konteks) — hash
      collision-resistant, konteks disertakan agar proof tak
      dipindahkan antar-sesi (replay)
- [ ] validasi implementasi: completeness (honest prover lolos
      selalu), soundness (respons acak tanpa rahasia ditolak), ZK
      (transkrip berbeda tiap sesi — verifikator tak belajar x),
      challenge dari CSPRNG, ZKP bukan pengganti TLS (cf. seksi 132
      "review pilihan mode/kunci", bukan tool)
- [ ] padanan secai: tidak ada tool kripto-engineer — checklist ini
      dipakai saat REVIEW implementasi autentikasi lab; cek sederhana
      yang bisa dieksekusi: server tidak mengirim/menyimpan hash
      eksplisit kredensial (ranah zeroize_scan/secret scanning)

## 165. Koridor ModSecurity/CRS (dari mukul975/implementing-web-application-logging-with-modsecurity)
- [ ] rollout yang benar: SecRuleEngine DetectionOnly dulu -> tune FP
      (SecRuleRemoveById per rule-id dgn alasan, exclusions per
      aplikasi) -> On; SecAuditEngine RelevantOnly (bukan On penuh —
      volume, bukan Off — kehilangan bukti); audit log serial vs
      parallel dipilih konsisten utk parser downstream
- [ ] CRS paranoia level PL1-PL4 = knob FP-vs-coverage eksplisit:
      naik bertahap, tiap kenaikan disertai review FP window tetap;
      response body limit & inspect sesuaikan ukuran app
- [ ] sisi log di secai = waf_sqli_triage (#0461 mem-parse audit log
      ModSecurity); audit konfigurasi modsec.conf milik lab = checklist
      manual (pola nilai-eksplisit ala linux_cis_audit bila kelak
      dibutuhkan — tanpa ekspor konfig, tak ada yang bisa disimpulkan)

## 166. Keluarga zero-trust — pola lintas vendor (dari mukul975/implementing-zero-standing-privilege-with-cyberark, -zero-trust-dns-with-nextdns, -zero-trust-for-saas-applications, -zero-trust-in-cloud, -zero-trust-network-access, -zero-trust-network-access-with-zscaler, -zero-trust-with-beyondcorp, -zero-trust-with-hashicorp-boundary) — cf. seksi 70/131/138/148/157
- [ ] delapan skill ini = SATU pola berulang: akses per-aplikasi
      diperantarai identitas (GCP IAP, AWS Verified Access, Zscaler
      ZPA app segments, HashiCorp Boundary) — user TIDAK masuk
      jaringan; access level = atribut user + device posture +
      konteks (lokasi/jam), bukan IP tepercaya (cf. allowlist
      berkedaluwarsa seksi 74)
- [ ] zero standing privilege: TEA framework CyberArk SCA (Time/
      Entitlements/Approvals) = bentuk vendor dari JIT seksi 138 —
      role ephemeral scoped per sesi, approval gate, auto-expire;
      sesi terekam (cf. PSM seksi 157)
- [ ] Boundary tambahan yang layak diingat: hierarchy org/project/
      host-set, credential brokering via Vault (kredensial tak pernah
      ke client), session recording di worker; OIDC/LDAP di auth
      method, bukan di target
- [ ] SaaS (#0729): federasi IdP + conditional access + CASB shadow-IT
      discovery + OAuth app governance (cf. seksi 91) + session DLP
      (block download di device unmanaged) — konsol tenant = live ops
- [ ] NextDNS (#0728): DoH/DoT + blokir kategori/threat feed + deteksi
      DNS rebinding (jawaban private-IP utk domain publik) & CNAME
      cloaking (first-party domain mengarah ke tracker) — sisi query
      offline di secai = dns_log_triage; resolusi live = ops
      (cf. seksi 117 audit zona)
- [ ] semua = konsol/tenant ber-kredensial — bukan tool audit;
      checklist dipakai saat MENDESAIN/meninjau arsitektur lab

## 167. Pipeline CI: DAST ZAP & SAST CodeQL/Semgrep (dari mukul975/integrating-dast-with-owasp-zap-in-pipeline, integrating-sast-into-github-actions-pipeline) — padanan seksi 19/101/146
- [ ] ZAP tiga mode sesuai tujuan: baseline (passive-scan, cepat,
      cocok tiap PR), full scan (aktif — hanya staging stabil), API
      scan (dari OpenAPI spec — padanan openapi_spec_audit sbg sumber
      path); jangan full-scan produksi
- [ ] mekanisme rules.tsv (rule-id + IGNORE/WARN/FAIL + alasan) =
      penyesuaian yang AUDITABLE — pola sama dgn .trivyignore
      berkedaluwarsa (seksi 146): pengecualian harus punya pemilik
      dan alasan, bukan silent
- [ ] gate: FAIL menolak merge (branch protection) — gate yang tidak
      memblokir = pelaporan, bukan gating (fail-closed, cf. seksi 19)
- [ ] SAST: CodeQL default GHA + Semgrep custom rules (pola
      organisasi) + SARIF upload (padanan sarif_ingest); tuning FP:
      suppression inline harus ber-alasan — tumpukan "exclude"
      tanpa konteks = celah yang disembunyikan rapi
- [ ] padanan secai: exploit_ci_gate + gha_workflow_audit (#0463)
      + sarif_ingest (#0289); ZAP/Semgrep/CodeQL live = alat
      eksternal ops CI


## 168. MITM trafik mobile (dari mukul975/intercepting-mobile-traffic-with-burpsuite) — live ops
- [ ] inti teknis: proxy listener + instal CA Burp; Android 7+ TIDAK
      mempercayai CA user utk app default — butuh
      network_security_config.xml (debug-overrides/trust anchors)
      yang butuh rebuild APK, ATAU app target yang tak set
      certificate pinning; iOS = profile trust manual
- [ ] yang dianalisis: API plaintext, token di header, respons
      berisi data berlebih (cf. api_property_scan), TLS bypass via
      pinning yang lemah — pembuktian butuh sesi live
- [ ] di secai: sisi statis APK dilayani apk_firebase_scan +
      mobile_manifest_audit (#0491/#0495); intersepsi live = lab
      berizin, bukan bentuk tool

## 169. Koridor IR: insider, phishing, ransomware (dari mukul975/investigating-insider-threat-indicators, investigating-phishing-email-incident, investigating-ransomware-attack-artifacts) — cf. seksi 49/66/76/28/84
- [ ] insider (#0738): legal/HR authorization DULU (investigasi
      insider = ranah hukum), timeline lintas sumber (SIEM + DLP +
      proxy), korelasi fisik-logis: badge access vs logon remote —
      "di dua tempat sekaligus" = lead kuat; event HR (resign,
      review buruk) = pemicu window pengawasan (cf. seksi 76
      pre-departure); chain of custody per bukti (seksi 40) —
      padanan: insider_baseline_scan
- [ ] phishing (#0739): header bottom-up Received + SPF/DKIM/DMARC
      (eml_phish_triage), detonasi URL/lampiran via layanan (live),
      scope: cari penerima lain by subject/sender (message trace),
      siapa klik = proxy log, siapa submit kredensial = POST ke
      domain phishing; containment: purge mailbox + REVOKE SESSION
      (cf. seksi 66: reset password saja tidak cukup)
- [ ] ransomware (#0740): JANGAN restart — kunci enkripsi masih di
      memori (urutan volatilitas seksi 40); identifikasi varian dari
      ekstensi + isi note + sampel (offline: ransom_artifact_triage
      — tabel ekstensi keluarga, IOC note BTC/XMR/onion, window
      waktu enkripsi dari mtime); cek VSS selamat/terhapus (T1490 =
      ranah sysmon_triage/lolbin_scan); decryptor cek No More
      Ransom (live); cek eksfiltrasi sebelum keputusan pembayaran
      (double extortion, cf. seksi 28)
- [ ] ketiganya = koridor IR; pelaksanaan live (EDR, mail purge,
      memory capture) = ops, tool secai melayani sisi artefak
      statis yang dibawa pulang

## 170. Identitas Okta & lifecycle intel & OpenCTI (dari mukul975/managing-cloud-identity-with-okta, managing-intelligence-lifecycle, modeling-threats-with-opencti) — cf. seksi 24/122/135/156
- [ ] Okta: IdP pusat lintas cloud (OIDC/SAML/Workforce Identity),
      phishing-resistant MFA (FIDO2 — cf. seksi 135/156; SMS =
      T1111), lifecycle otomatis (joiner-mover-leaver cf. seksi 34),
      ThreatInsight + system log streaming ke SIEM — tenant live;
      pola MEMBACA lognya = seksi 122 (session token abuse,
      deviceToken divergen)
- [ ] intel lifecycle (#0742): direction (collection requirement
      eksplisit — seksi 38) -> collection -> processing/normalisasi
      -> analysis -> dissemination per audiens (seksi 102) ->
      feedback (bila laporan tak dipakai, matikan koleksinya) —
      siklus tanpa feedback = arsip tumbuh tanpa arah
- [ ] OpenCTI (#0747): docker stack + pycti; model STIX 2.1 SDO/SRO
      (threat-actor/intrusion-set/campaign/indicator + uses/
      attributed-to/targets) — graph relationship = konsep
      campaign_correlate (#0360); platform = TIP ops (seksi 24)

## 171. TPRM — risiko vendor pihak ketiga (dari mukul975/managing-third-party-vendor-risk)
- [ ] koridor program: inventaris -> tier inherent risk (data yang
      dipegang + integrasi + kritisnya layanan) -> due diligence per
      tier (SOC 2/ISO cert, pentest summary, DPA) -> review bukti
      KRITIS (lingkup sertifikat penuh atau satu DC saja? tanggal
      kedaluwarsa? temuan diperbaiki?) -> codify di kontrak (breach
      notification SLA, audit right, sub-processor) -> monitoring
      berkala + nth-party & concentration risk -> offboard (akun,
      data, integrasi dicabut TERVERIFIKASI)
- [ ] tata kelola, bukan pengujian teknis (cf. seksi 42 #0324) —
      checklist dipakai saat MENYUSUN rekomendasi kebijakan di
      laporan; padanan teknis secai utk permukaan vendor web:
      third_party_script_risk + sri_checker

## 172. BloodHound CE & NetExec — AD ofensif (dari mukul975/mapping-attack-paths-with-bloodhound-ce, moving-laterally-with-netexec) — di luar domain, cf. seksi 42/116
- [ ] BloodHound CE: SharpHound (LDAP-only utk stealth; loop session
      collection utk menangkap Tier-0 logon) / AzureHound -> ingest
      -> cypher attack paths (shortest-path ke Domain Admin/tenant)
      — kolektor = eksekusi di infra AD live; konsep graf jalur
      versi cloud sudah di iam_escalation_scan
- [ ] NetExec (nxc): validasi kredensial/hash lintas protokol (SMB/
      WinRM/LDAP/MSSQL/SSH), enum share/user/policy, password spray
      dgn DISIPLIN: baca lockout policy DULU (--pass-pol), satu
      password per window di bawah ambang lockout, catat hit lalu
      tunggu — spray tanpa baca policy = lockout massal = insiden
      sendiri; dump SAM/LSA/NTDS = post-exploit berizin
- [ ] sisi deteksi yang menyertai: 4624/4625 volume per sumber
      (win_logon_triage), 4769 volume/RC4 (kerberos_log_triage),
      7045 service install (win_auth_triage) — eksekusi ofensifnya
      di luar fokus web/app secai

## 173. ATT&CK coverage mapping — padanan attack_coverage (dari mukul975/mapping-mitre-attack-techniques) — cf. seksi 150
- [ ] padanan secai: attack_coverage (#0660) — rule export ->
      matriks teknik x state (covered/partial/gap) -> prioritas gap;
      skill ini menambah dua konsep utk MENYUSUN prioritas: gap
      dinilai terhadap teknik yang AKTIF dipakai aktor relevan ke
      sektor kita (intel-driven, bukan angka besar) dan output
      eksekutif = layer Navigator + persentase coverage per tactic,
      bukan daftar rule
- [ ] disiplin: data ATT&CK enterprise-attack STIX diunduh resmi
      (versi eksplisit — mapping lintas versi = drift); mapping
      rule->teknik disimpan sbg DATA yang bisa diaudit, bukan di
      kepala analis

## 174. Darkweb monitoring (dari mukul975/monitoring-darkweb-sources)
- [ ] mekanisme: keyword monitoring (brand/domain/email/eksekutif)
      via layanan komersial + manual ber-OPSEC (Tor + VM disposabel);
      target: forum/marketplace, paste sites (API), ransom leak
      sites (cari nama organisasi di blog korban), credential dumps
      (korelasi domain email)
- [ ] respons berjenjang: kredensial bocor = reset + revoke session
      SEKARANG (cf. seksi 50); data internal muncul di leak site =
      insiden aktif, bukan sekadar intel
- [ ] butuh jaringan/Tor/layanan berbayar = ops; permukaan pasif
      secai (rdap-whois/ct-inventory/wayback/github-leak-checker,
      cf. seksi 38) menutup sisi publik — checklist ini utk MENYUSUN
      keyword list & SOP eskalasinya

## 175. Di luar domain — Modbus/SCADA monitor (dari mukul975/monitoring-scada-modbus-traffic-anomalies) — cf. seksi 48/63/83/161
- [ ] domain OT (SPAN/TAP jaringan industri milik sendiri) — di luar
      fokus web/app/infra secai; inti teknis yang layak diingat:
      MBAP header TCP/502 (transaction 2B, protocol-id 2B=0, length
      2B, unit-id 1B, function-code 1B) — parser protokol industri =
      kelas alat lain
- [ ] baseline per pasangan master/slave yang sah: daftar function
      code yang boleh (read 1-4 vs write 5/6/15/16 — cf. seksi 83),
      rentang register, interval poling; anomali = tulisan tanpa
      wewenang, enumerasi register/read burst, deviasi interval,
      unit-id/MAC/slave baru — pola "baseline sah -> deviasi"
      berlaku generik (cf. seksi 76/151)
- [ ] skenario dampak (manipulasi parameter water treatment,
      enumerasi dari engineering workstation) = motivasi segmentasi
      + monitoring OT terpisah — bukan tool secai

---
Blok B26 (#0751-#0780, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Dua entri diekstrak jadi tool: #0773 -> tools/
asset_criticality_score.py (model kritikalitas aset -> modifier SLA),
#0780 -> tools/elf_checksec.py (inti deterministik checksec ELF,
analog pe_mitigation_scan); sisanya didistilasi di bawah (176-181) +
catatan bidang (182). CATATAN PENOMORAN: seksi 162-175 milik blok B25
(yang menulis duluan di tree bersama) — nomor B26 lanjut dari 176.

## 176. LLM red team multi-turn (dari mukul975/orchestrating-llm-attacks-with-pyrit) — distilasi B26
- [ ] primitives yang dipisah eksplisit: TARGET (yang diuji) vs
      adversarial chat (penyerang LLM) vs scorer (penilai objektif);
      orchestrator = strategi, converter = mutasi payload (base64/
      ROT13), memory = bukti percakapan utuh — semuanya butuh API LLM
      live, jadi secai hanya mengambil TAXONOMI-nya
- [ ] tiga strategi multi-turn: RedTeaming (loop generik dgn scorer),
      Crescendo (eskalasi bertahap — TIAP turn tampak jinak sendirian,
      guardrail per-turn lolos tapi kumulatif jahat), TAP (branching +
      pruning by skor — eksploitasi jalur yang "memanas")
- [ ] implikasi defensif: uji guardrail PER-RESPONSE saja tidak cukup —
      uji juga KONSISTENSI lintas turn (state percakapan = permukaan);
      single-shot scanner dulu (murah), multi-turn hanya utk yang tahan
- [ ] bukti kampanye = percakapan utuh tersimpan per run, tiap
      keberhasilan ditandai orchestrator + jumlah turn + verdict scorer
      (pola sama dgn session_ledger secai: aksi + jejak)
- [ ] mapping ATLAS AML.T0051 (prompt injection) / AML.T0054
      (jailbreak) + OWASP LLM Top 10 — secai: injection_guard
      (lapis 1-2, seksi 44) + CI-gate regresi promptfoo (seksi 74);
      checklist ini dipakai saat MENGUJI chatbot/agent lab sendiri

## 177. MISP feed curation & IOC -> deteksi (dari mukul975/operationalizing-misp-threat-feeds) — distilasi B26
- [ ] "instance jalan" != teroperasionalkan: pilih feed bereputasi
      saja (CIRCL/abuse.ch/Feodo) — mengaktifkan semua feed publik =
      noise; cache feed utk lookup real-time; TLP + tag scoping
      sebelum ekspor
- [ ] warninglist = kontrol FP di SISU TIP: RFC1918, top-sites, public
      DNS resolver ditandai non-actionable SEBELUM nilai keluar ke
      SIEM/IDS — query wajib to_ids + published + window + enforce_
      warninglist = himpunan "actionable" yang eksplisit
- [ ] ekspor IOC -> deteksi punya tiga bentuk: NIDS rule (Suricata/
      Snort via REST), Sigma (script), lookup list (Wazuh CDB) — SEMUA
      wajib lolos validasi load (suricata -T) sebelum deploy + pipeline
      terjadwal dgn log (bukan manual saat ingat)
- [ ] secai: TIP = ops produk (cf. seksi 42/24); intel_sync sudah
      menutup freshness/delta KEV/nuclei; mutu rule = ids_rule_lint;
      checklist ini dipakai saat MENYETEL feed lab

## 178. Korelasi artefak Windows (dari mukul975/parsing-artifacts-with-eric-zimmerman-tools) — distilasi B26
- [ ] EZ Tools (MFTECmd/PECmd/RECmd/SBECmd/AmcacheParser) = binary
      eksternal (cf. seksi 100); secai sudah punya parser sisi-nya:
      mft_scan (MFT/$J), timestomp_triage, sysmon_triage,
      win_persist_triage, browser_history_triage — parser registry/
      prefetch/shellbags tidak di-build (format proprietary + ranah
      forensik Windows, bukan web/app)
- [ ] nilai metodologinya = ORDE korelasi lintas artefak: eksekusi
      (prefetch/amcache/shimcache) x pembuatan file (MFT) x akses
      (shellbags/LNK), SEMUA dijangkarkan kolom waktu UTC yang
      konsisten antar-parser — teori kasus dibangun dari irisan,
      bukan satu artefak
- [ ] jebakan klasik saat membaca hasil: shimcache = KEHADIRAN
      program, BUKAN bukti eksekusi; prefetch = bukti eksekusi
      berapa-kali + terakhir-jalan; amcache = instalasi/metadata —
      campur aduk = laporan salah muat
- [ ] akuisisi KAPE/forensic copy dulu (cf. seksi 40 chain of
      custody); Timeline Explorer = viewer CSV, bukan bagian analisis

## 179. AD kompromi — peta event IR (dari mukul975/performing-active-directory-compromise-investigation, -forest-trust-attack) — distilasi B26
- [ ] eksfil NTDS.dit: 4662 GUID replikasi (dcsync_triage), 4742
      perubahan akun DC$, vssadmin/ntdsutil di cmdline (lolbin_scan/
      sysmon_triage), VSS 8222 pada DC — kombinasi = rantai, satu = lead
- [ ] Kerberos: golden ticket = TGT lifetime > default 10 jam + 4769
      RC4 + TGT tanpa 4768 (kerberos_log_triage); silver ticket = TGS
      tanpa TGT + service name aneh; kerberoasting = volume 4769 per
      SPN (seksi 79)
- [ ] abuse GPO: event 5136 (perubahan directory object) untuk
      deployment scheduled task / login script / software policy via
      GPO — persistence domain-wide dari satu titik; perubahan grup
      istimewa (Domain Admins, DnsAdmins [DLL pada DC!], Backup
      Operators) = ranah account_manip_triage
- [ ] trust: 4706 trust baru + SID filtering mati + SID history lintas
      forest = jalur pivot lintas domain — audit atribut trust bisa
      offline bila ada ekspor; ofensif impacket TIDAK di-port (cf.
      seksi 42)
- [ ] narasi IR AD selalu: vektor akses awal + scope akun/host +
      persistence yang terpasang + reset KRBTGT dua kali (seksi 73) —
      peta event di atas = urutan MEMBACA log, bukan tool baru

## 180. AiTM reverse-proxy phishing (dari mukul975/performing-adversary-in-the-middle-phishing-detection) — distilasi B26
- [ ] model serangan: reverse proxy mencerminkan halaman login ASLI,
      korban menyelesaikan MFA di halaman proxy, attacker menangkap
      SESSION COOKIE yang diterbitkan layanan sah — MFA tidak
      "diloloskan", ia DILEWATI (cookie di-replay tanpa MFA)
- [ ] kit 2025: Tycoon 2FA/EvilProxy/Evilginx/Sneaky 2FA; distribusi
      bergeser QR -> lampiran HTML/SVG — eml_phish_triage menandai
      lampiran HTML/SVG + body minim URL sebagai lead quishing/aitm
- [ ] indikator deterministik saat membaca log identitas: cookie sesi
      dipakai dari IP/device BEDA dari waktu auth (satu SessionId,
      cf. seksi 122), impossible travel auth->pemakaian, halaman login
      tersaji dari infra non-corp, request CDN auth-provider dari
      domain phishing
- [ ] remediasi = cabut sesi + refresh token (reset password SAJA
      tidak membunuh cookie AiTM — cf. seksi 50/66); pencegahan
      satu-satunya yang menutup kelas ini = MFA phishing-resistant
      (FIDO2 origin-bound — tidak bisa di-proxy)
- [ ] secai: eml_phish_triage (sisi email) + seksi 66 (corong
      dampak); log Entra/Okta = API live — checklist ini dipakai saat
      MENULIS playbook deteksi lab

## 181. Fuzzing API stateful & taxonomy rate-limit bypass (dari mukul975/performing-api-fuzzing-with-restler, performing-api-rate-limiting-bypass) — distilasi B26
- [ ] inti stateful fuzzing RESTler = producer-consumer dependency:
      id dari respons POST menjadi parameter request BERIKUTNYA — bug
      "hanya muncul pada urutan tertentu" tidak akan ditemukan fuzzer
      stateless; mode bertingkat test -> fuzz-lean -> fuzz (biaya &
      dampak data naik); payload dict kustom per path (injection/
      boundary/overflow) dikelola eksplisit
- [ ] sinyal temuan fuzzing: 500 = unhandled exception (selalu
      temuan), akses yang seharusnya ditolak, resource leak (create
      tanpa delete) — semua butuh API live staging berizin; padanan
      statis secai: openapi_spec_audit + param_probe_checker;
      playbook injeksi live = ranah playbook (seksi 41)
- [ ] checklist bypass rate-limit (dipakai saat MENG-AUDIT desain
      limiter & membaca hasil rate-limit-validator): ~17 header IP-
      spoof (X-Forwarded-For/True-Client-IP/CF-Connecting-IP/
      X-Real-IP dst.) yang dipercaya limiter di belakang proxy;
      variasi path (case/encoding/trailing-slash/double-slash),
      variasi metode (HEAD/OPTIONS/override), versi API lama yang
      belum kena limit, endpoint setara yang lupa dikunci
- [ ] limiter yang benar mengunci pada identitas + IP INTERNAL (bukan
      header yang bisa di-craft) + tetap mengirim X-RateLimit-* +
      Retry-After (seksi 142); bypass berhasil = temuan API4 OWASP,
      bukan catatan kaki

## 182. Di luar domain + padanan — catatan bidang blok B26
- [ ] C2 ops (#0751 #0752): Havoc (Yaotl profile, Demon indirect
      syscall/Ekko sleep obf) & Sliver (mTLS/HTTP/DNS/WG, beacon
      jitter, armory BOF/.NET) = runbook ops merah live — padanan
      distilasi seksi 30/14; sisi biru: deteksi = deviasi profil
      (UA/URI/jitter) + JA3/JA3S, bukan signature; cleanup = revoke
      operator + hapus artefak + verifikasi scan-ulang
- [ ] IGA & sertifikasi akses (#0756 #0757): Saviynt EIC + access
      review generik = administrasi identitas (cf. seksi 34 #0285,
      seksi 141 #0643); konsep yang layak: lifecycle CONFIGURATION->
      PREVIEW->ACTIVE->REMEDIATION, auto-revoke bila certifier tak
      merespons, completion >95% sebelum tutup, revoke DI-VERIFIKASI
      (re-check entitlement) — jangan "tiket dibuat" = selesai
- [ ] AD ofensif & asesmen (#0758 #0761 #0762): BloodHound graf jalur
      serangan, pentest AD end-to-end (NetExec/Impacket/Certipy/
      Rubeus), PingCastle/Purple Knight = alat/kredensial live domain
      (cf. seksi 42/116); padanan deteksi statis secai:
      kerberos_log_triage, dcsync_triage, account_manip_triage; peta
      event IR-nya di seksi 179
- [ ] scanner vuln live (#0764 #0774 #0775): agentless SSH/WMI/SNMP/
      snapshot-cloud, OpenVAS-GVM, authenticated scan Nessus/Qualys =
      alat eksternal live; padanan statis: dependency_cve (CVE dari
      lockfile/SBOM), cspm_finding_ingest; disiplin yang dipinjam:
      akun scan khusus read-only + kredensial di vault (seksi 136),
      authenticated scan menemukan 45-60% lebih banyak temuan ->
      "tidak ada temuan" dari scan unauthenticated = telemetri kosong
      (fail-closed, cf. seksi 86)
- [ ] sandbox malware CAPE (#0776): deploy Windows guest + API = ops
      (cf. seksi 13: pre-screen hash dulu, verdict sandbox = SATU
      sinyal); padanan statis secai: maldoc_triage, pdf_triage,
      packer_scan, rat_config_scan (ekstraksi konfigurasi RAT dari
      artefak statis)
- [ ] cloud audit & privesc (#0777 #0778): ScoutSuite (read-only
      SecurityAudit) = alat eksternal; padanan: cspm_finding_ingest
      (eksplisit mengkonsumsi keluaran ScoutSuite/Prowler) +
      aws_config_audit (snapshot); AWS privesc Pacu/CloudFox/PMapper =
      padanan iam_escalation_scan (#0386) + seksi 147 (permission
      boundary); aws iam simulate-principal-policy = cara RESMI cek
      effective permission tanpa menyentuh data
- [ ] alat eksternal & jaringan fisik lain: Postman/Newman (#0771 —
      metodologi multi-role OWASP API Top 10 = seksi 41); MobSF
      (#0767 — padanan apk_firebase_scan + mobile_manifest_audit);
      Elastic SIEM triage (#0766 — Kibana/ES|QL = ops produk SOC,
      pola konteks = cluster by host+user + alert terkait by
      source.ip); OSINT correlation (#0765 — Sherlock/theHarvester/
      SpiderFoot + LLM = jaringan, cf. seksi 35/38/39); ARP spoofing
      live (#0772 — padanan analisis arp_pcap_scan #0380); bandwidth
      throttling tc/netem/iperf3 (#0779 — manipulasi jaringan hidup,
      di luar bentuk tool; baseline SEBELUM degradasi + rollback
      plan, cf. seksi 69)

---
Blok B24 (#0691-#0720, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Empat entri diekstrak jadi tool: #0691 -> tools/
killswitch_triage.py, #0694 -> tools/rsa_key_audit.py, #0699+#0701 ->
tools/secret_report_ingest.py, #0703+#0713 -> tools/stix_bundle_audit
.py; sisanya didistilasi di bawah. Entri #0693 = padanan k8s_rbac_audit
(B09); #0705 = padanan sarif_ingest + SAST eksternal (semgrep = tool
pihak ketiga, SARIF-nya masuk lewat sarif_ingest).

## 183. Program vulnerability scanning & remediasi (dari mukul975/implementing-rapid7-insightvm-for-scanning) — distilasi B24
- [ ] scan unauthenticated melewatkan 60-80% vuln lokal — authenticated
      scan (SSH key > password, sudo elevation, WMI/db cred) = standar;
      UJI kredensial dulu sebelum full scan (scan gagal-auth = "bersih"
      palsu, bukan bersih)
- [ ] urutan hemat: discovery (inventaris) -> full audit -> template
      khusus (web spider terpisah dari infra); safe-checks ON untuk
      perangkat rentan (printer/ICS/medis) — scan agresif matikan
      perangkat = insiden operasional sendiri
- [ ] scan engine ditempatkan DEKAT segmen target (lintas-firewall =
      bottleneck + false scope); agent untuk endpoint berpindah; dua
      sumber digabung, bukan diganti
- [ ] blackout window jam kerja + batas durasi scan (runaway scan =
      resource habis diam-diam)
- [ ] remediasi project = scope eksplisit (severity >= 7 / CVSS >= 7),
      owner, due date, auto-verify via re-scan, eskalasi di 75% SLA —
      tabel SLA sama dengan seksi 26; padanan secai: vuln_sla_aging +
      kev_gap + cve_sweep
- [ ] catatan secai: InsightVM/konsol = produk komersial (ops); yang
      diport = disiplin program di atas

## 184. Runtime protection: RASP & eBPF Tetragon (dari mukul975/implementing-runtime-application-self-protection, implementing-runtime-security-with-tetragon) — cf. seksi 51
- [ ] RASP: pasang dalam mode MONITOR dulu (baseline, ukur FP), baru
      BLOCK — membalik urutan = aplikasi produksi mati; deteksinya di
      konteks eksekusi (fungsi SQL/exec/deserialisasi), bukan traffic —
      itu sebabnya FP-nya rendah, dan itu juga sebabnya agent-nya
      berat (in-process)
- [ ] Tetragon (eBPF, <1% overhead): TracingPolicy = kprobe (security_
      bprm_check, setns, security_file_open) + selector (matchBinaries/
      matchNamespaces) + aksi (Post/Sigkill/Override/Signal)
- [ ] kebijakan yang layak diingat utk audit kebijakan lab: Sigkill pada
      sys_setns di luar host_ns (escape), Post pada open prefix /etc/
      shadow | /etc/kubernetes/pki | /var/run/secrets (kredensial),
      Sigkill matchBinaries xmrig/minerd (miner)
- [ ] metrik kesehatan sensor: tetragon_missed_events_total > 0
      sustained = blind spot terukur (bukan "aman"); spike events > 3x
      baseline = insiden
- [ ] sisi secai: jejak API-side k8s = k8s_audit_triage/k8s_rbac_audit;
      sensor kernel = ops infrastruktur — checklist ini utk AUDIT
      kebijakan TracingPolicy milik lab, bukan eksekusi

## 185. SAML SP-side validation & SCIM lifecycle (dari mukul975/implementing-saml-sso-with-okta, implementing-scim-provisioning-with-okta) — cf. seksi 20, 34
- [ ] lima validasi SP yang tidak boleh bolong: (1) signature SHA-256
      (tolak SHA-1), (2) assertion encryption (AES-256) bila atribut
      sensitif, (3) Audience restriction (assertion dipinjam SP lain =
      replay), (4) NotBefore/NotOnOrAfter + toleransi clock skew
      eksplisit, (5) InResponseTo dicocokkan AuthnRequest (IdP-initiated
      unsolicited = jalur terpisah yang dikelola, bukan dimatikan)
- [ ] kegagalan umum produksi: sertifikat signing kedaluwarsa tanpa
      rotasi = outage massal — rotasi dual-cert sebelum expiry, uji
      tanpa downtime
- [ ] SCIM (RFC 7644): deprovision = active:false, BUKAN hard delete
      (jejak audit + reaktivasi); PATCH = ops add/replace/remove;
      filter "userName eq" wajib didukung (Okta dedup); error schema
      scimType (uniqueness) = kontrak, bukan 500 generik
- [ ] provisioning hooks = T1098/F1005 — akun baru/grup baru yang dibuat
      otomatis HARUS masuk audit yang sama dgn akun manual; tool secai:
      belum ada (end-to-end butuh IdP live) — checklist utk review
      konfigurasi IdP di lab

## 186. Secret scanning lifecycle & baseline (dari mukul975/implementing-secret-scanning-with-gitleaks, implementing-secrets-scanning-in-ci-cd) — inti diekstrak tools/secret_report_ingest.py
- [ ] tiga lapisan waktu: pre-commit (blok SEBELUM masuk riwayat),
      CI per-commit, dan riwayat penuh (audit legacy) — padanan
      secai: secret_history_scan + repo-secret-scan; ingest laporan
      scanner eksternal + baseline diff = secret_report_ingest
- [ ] baseline = BUKAN allowlist abadi: tiap entri ditriase (aktif/
      sudah-rotasi/FP), dikurangi tiap rotasi; "asumsi sudah mati" tanpa
      verifikasi provider = kebocoran yang dianggap aman
- [ ] remediasi = ROTASI DULU, bersihkan riwayat kemudian (git-filter-
      repo koordinasi tim); sebaliknya = secret masih valid di cache/
      fork/laporan lama
- [ ] custom rule organisasi: regex + ENTROPY + keywords + allowlist
      path (test/vendor/fixtures) — pola generik tanpa entropi = alarm
      massal hari pertama (cf. kosakata repo-secret-scan: pola kuat +
      generik berentropi + penekan placeholder)

## 187. Korelasi multi-event SIEM & tuning FP (dari mukul975/implementing-siem-correlation-rules-for-apt, implementing-siem-use-case-tuning, implementing-security-monitoring-with-datadog) — cf. seksi 17, 74, 77
- [ ] pola SEQUENCE (A lalu B pada host sama dalam window): RDP logon
      (4624 type-10) -> service baru (7045) <= 15 menit; NTLM logon
      type-3 -> proses admin tool; named pipe PSEXESVC + service
      install <= 5 menit — tiap pola tulis: sumber log, agregasi per
      host/principal, window, severity, mapping ATT&CK (format seksi 17)
- [ ] tuning = siklus data, bukan selera: FP rate per rule dari
      disposition analyst, ambang baru = baseline (mean + N*stdev,
      minimum data 30 hari), whitelist known-good BERKEDALUWARSA (TTL,
      cf. seksi 74), hasil diukur dgn alert-to-incident conversion —
      rule yang tidak pernah jadi insiden = kandidat matikan/merge
- [ ] suppression per POLA entity (mis. @usr.id:service-account-*),
      bukan per kejadian; keep-alive signal (10-30 menit) supaya
      aktivitas bertahap tidak pecah jadi N alert
- [ ] contoh agent-rule kernel-level yang reusable (Datadog CSM): write
      ke authorized_keys oleh proses non-sshd = T1098.004 — pola
      "subjek tak sah menyentuh file kebijakan" dipakai ulang untuk
      FIM apa pun (cf. seksi 51/70)

## 188. STIX/TAXII — disiplin konsumen offline (dari mukul975/implementing-security-information-sharing-with-stix2, implementing-stix-taxii-feed-integration, implementing-taxii-server-with-opentaxii) — inti diekstrak tools/stix_bundle_audit.py
- [ ] bundle = unit pertukaran; nilai intel = GRAF (relationship
      indicates/uses antar SDO), bukan daftar IOC datar — simpan graf,
      render datar saat butuh (padanan secai: campaign_correlate)
- [ ] feed tak patuh spec = temuan: id bukan UUIDv4 (SDO/SRO), modified
      < created, ref menggantung, pattern tanpa grammar — SIEM/TIP yang
      membaca tanpa validasi = data hilang diam-diam; sba menghitung
      semuanya (fail-closed)
- [ ] indicator: valid_until aktif (expired = jangan diblokir otomatis),
      TLP marking dihormati saat re-share, provenance created_by_ref +
      external_references (mitre-attack id) wajib ada utk attribution
- [ ] TAXII: added_after = incremental polling (konsep freshness cf.
      intel_sync); pagination per-request; collection readonly utk
      konsumen — transport/server (Medallion/OpenTAXII) = ops produk
      TIP, bukan alat audit

## 189. Ops produk & di luar domain — catatan bidang blok B24 (cf. seksi 42, 48, 136, 137, 130)
- [ ] #0700 Vault secrets m
---
Blok B27 (#0781-#0810, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Satu entri diekstrak jadi tool: #0783 -> tools/
brand_lookalike_scan.py; sisanya didistilasi di bawah (4 seksi) +
catatan bidang. Web-offense cluster (#0781 #0784 #0797 #0800 #0804)
jadi seksi 190; cluster cloud-forensics/IR (#0785-#0789 #0791 #0793)
jadi seksi 191-192; container cluster (#0790 #0794-#0796 #0809) seksi
193; sisanya seksi 194.

## 190. Taksonomi bypass web — SSRF, CSP, CSRF, traversal, clickjacking (dari mukul975/performing-blind-ssrf-exploitation, -clickjacking-attack-test, -content-security-policy-bypass, -csrf-attack-simulation, -directory-traversal-testing) — distilasi B27
- [ ] blind SSRF: OOB callback (Collaborator/interact.sh) = bukti lebih
      kuat daripada timing; bypass filter = tabela representasi IP
      (hex 0x7f000001, desimal 2130706433, oktal 0177.0.0.1, short
      127.1, IPv6 [::1], @-auth confusion target.com@127.0.0.1,
      fragment #), DNS rebinding utk metadata 169.254.169.254 —
      padanan secai: SsrfCallbackPlaybook + SsrfChainPlaybook +
      payload_lab (kelas ssrf); remediasi: allowlist + blok RFC1918 +
      IMDSv2 + matikan scheme gopher/file/dict
- [ ] CSP bypass kelas: 'unsafe-inline'/'unsafe-eval' = kekalahan
      langsung; script-src whitelists host dgn endpoint JSONP/Angular
      = sandbox escape via host sah; base-uri tak dibatasi = <base>
      injeksi; form-action tak dibatasi = eksfil via form; CSP
      report-only = TIDAK ditegakkan; nonce membuat 'unsafe-inline'
      diabaikan (CSP3) — padanan secai: csp_analyzer (unsafe-
      inline/wildcard); checklist di atas utk review manual header
- [ ] CSRF token-enforcement matriks diferensial: token dihapus ->
      kosong -> acak -> kadaluarsa -> milik sesi lain — semua varian
      DITERIMA = enforcement cacat; cek juga SameSite cookie, Origin/
      Referer validation, method override (HEAD/OPTIONS lolos) —
      padanan secai: form_csrf_checker (keberadaan token), 
      OauthStatePlaybook (state anti-CSRF); tanpa playbook CSRF penuh,
      matriks ini = panduan uji manual lab
- [ ] traversal: matriks encoding (URL-encode, double-encode %252f,
      ....//, ..;\ utk IIS, overlong UTF-8, null byte lama) — target
      file kanonik: /etc/passwd, win.ini, boot.ini; marker respons
      "root:" — padanan secai: LfiTraversalPlaybook + payload_lab
      (kelas traversal + rantai encoder); filter stripping ".." dua
      kali = "....//" lolos (sisi remediasi)
- [ ] clickjacking: XFO DENY/SAMEORIGIN + CSP frame-ancestors
      'none'/'self'; ALLOW-FROM deprecated; frame-busting JS = lemah;
      dites per halaman-sensitif (transfer/delete/change-password),
      bukan hanya beranda — padanan secai: 
      clickjacking_protection_checker

## 191. Program monitoring impersonasi merek (dari mukul975/performing-brand-monitoring-for-impersonation) — inti diekstrak brand_lookalike_scan
- [ ] kanal impersonasi: domain (typosquat/homoglyph/TLD-variasi),
      situs kloning, profil medsos eksekutif, app store palsu, spoof
      email, darkweb — tiap kanal sumber dan tempo berbeda
- [ ] klasifikasi nama (diekstrak -> tools/brand_lookalike_scan):
      permutasi ala dnstwist + skel confusable + jarak edit + token
      curiga + embed-subdomain; faktor risiko: konten aktif, sertifikat
      ada, MX terpasang, registrasi baru — di tool: hanya metadata dari
      input, TIDAK diquery live (kepemilikan = rdap lanjutan)
- [ ] kanal LIVE yang tak diport: dnstwist --registered (query DNS
      massal), Safe Browsing API, scraping Play Store, Twitter API —
      semuanya butuh jaringan/kunci; pipeline secai: generator
      kandidat (typoswat_watch) -> klasifikasi (brand_lookalike_scan)
      -> verifikasi kepemilikan (rdap-whois/rdap_enrichment)
- [ ] takedown: laporan abuse butuh bukti (teknik klasifikasi, IP,
      tanggal deteksi) dan jalur registrar/hosting — alat ini menyediakan
      bukti klasifikasi, keputusan takedown = manusia

## 192. Cluster forensik & IR cloud (dari mukul975/performing-cloud-forensics-investigation, -cloud-forensics-with-aws-cloudtrail, -cloud-incident-containment-procedures, -cloud-log-forensics-with-athena, -cloud-asset-inventory-with-cartography, -cloud-native-threat-hunting-with-aws-detective, -cloud-storage-forensic-acquisition) — runbook ops, distilasi B27
- [ ] urutan preservasi cloud: snapshot EBS/disk/VM SEBELUM isolate;
      isolate via security-group forensik (bukan terminate — jejak
      hilang); kumpulkan metadata instance/SG/ENI + ekspor log window
      insiden (CloudTrail lookup-events 90 hari, S3 utk lebih lama)
- [ ] containment kredensial cloud: deactivate access key -> deny-all
      policy -> revoke sesi (RevokeOldSessions dgn aws:TokenIssueTime)
      -> invalidate assume-role policy — hentikan PEMAKAIAN dulu, cari
      jejak kemudian (cf. seksi 50/73)
- [ ] pola query forensik CloudTrail/Athena yang reusable: filter
      sourceIPAddress di luar CIDR internal, userAgent tak lazim
      (tool ofensif), massal DeleteItem/GetObject, CreateUser/
      CreateAccessKey/AssumeRole = persistence — padanan offline
      secai: cloudtrail_scan (parser + pola), iam_escalation_scan
- [ ] tabel Athena partition-projection = pola "log besar": partisi
      per tanggal menghindari full-scan biaya; bukti-grade = query
      deterministik + hasil diarsipkan (cf. seksi 17 pola SIEM)
- [ ] graf aset (Cartography/Neo4j, Detective behavior-graph): nilai
      konseptual = relasi (IAM chain, trust antar-akun, jalur network)
      bukan inventaris datar; query khas: bucket publik, prinsipal
      dgn akses admin lintas akun, EC2 dgn IAM role sensitif —
      secai: aws_config_audit + cspm_finding_ingest + 
      asset_criticality_score melayani potongan statisnya
- [ ] cloud storage personal (Drive/OneDrive/Dropbox): artefak sinkron
      endpoint (cache DB, log) vs API akuisisi; chain of custody cf.
      seksi 40; butuh otorisasi legal eksplisit — forensik-ops, bukan
      kelas tool secai

## 193. Container cluster — Falco, escape, hardening, scanner, docker-bench (dari mukul975/performing-cloud-native-forensics-with-falco, -container-escape-detection, -container-image-hardening, -container-security-scanning-with-trivy, -docker-bench-security-assessment) — padanan ada, distilasi B27
- [ ] Falco = sensor runtime (eBPF); yang dipakai = anatomi rule-nya
      (spawned_process + container + exception list, cf. seksi 51);
      JSONL alert-nya trivial diparse — tidak layak tool terpisah
- [ ] escape vector pod: privileged, CAP_SYS_ADMIN, hostPID/Network/
      IPC, hostPath writable ke / atau /etc, mount docker.sock —
      padanan secai: k8s_podsec_audit (16 cek vector) + k8s_audit_
      triage; runtime-side (nsenter/cgroup/release_agent) = seksi 51
- [ ] image hardening: multi-stage, distroless/slim, purge package
      manager, USER nonroot, pin digest, HEALTHCHECK — padanan:
      docker_audit (cek Dockerfile/daemon/compose) + seksi 131
- [ ] Trivy/dockle = scanner eksternal (ops CI): SARIF-nya masuk via
      sarif_ingest; gate severity = pola exploit_ci_gate; SBOM cf.
      seksi 101
- [ ] docker-bench = CIS benchmark LIVE host+daemon; kategori PASS/
      FAIL/WARN + remediasi utama (icc=false, no-new-privileges,
      cap-drop, read-only rootfs) sudah dicakup cek statis
      docker_audit; menjalankan bench = ops host

## 194. Di luar domain + ops — catatan bidang blok B27
- [ ] #0782 BLE/Bluetooth: enumerasi GATT live (bleak) butuh adapter
      radio + perangkat fisik — di luar web/app/infra (cf. seksi 63
      BLE #0391); inti yang layak diingat: characteristic read/write
      tanpa auth pada UUID sensitif (heart-rate 0x2A37, device info)
      = kandidat; pairing Just Works/TK=0 = lemah
- [ ] #0792 Pacu: framework ofensif cloud live (butuh kredensial
      target berizin, CloudTrail utk post-review) — pelaksanaan =
  
      engagement ofensif penuh (cf. seksi 42); padanan statis:
      iam_escalation_scan + cloudtrail_scan
- [ ] #0798 LaZagne: credential harvesting post-exploitation (T1555)
      — NEVER-LIST adjacent; sisi deteksi: cmdline lazagne.exe di
      lolbin_scan/sysmon_triage; prinsip defensif: credential manager
      terenkripsi + least-privilege di endpoint
- [ ] #0810 dynamic analysis Android: Frida/objection/emulator = kelas
      alat lain (cf. seksi 81); padanan statis secai: apk_firebase_
      scan + mobile_manifest_audit; indikator yang dicari saat hook:
      root-detection bypass, crypto hook, pinning bypass
- [ ] #0802 darkweb monitoring: Tor SOCKS5 + vendor API (Flare/
      SpyCloud) = ops jaringan + persona OPSEC (VM terpisah, tanpa
      identitas) — distilasi program sudah ada di seksi 174
- [ ] #0803 deception deployment: platform produk (Thinkst/Attivo),
      peta penempatan per segmen, honeytoken AD — konsep cf. seksi
      45/139/154; "interaksi = suspicious by definition" tetap prinsip
      kunci
- [ ] #0805 disk forensics: imaging E01/dcfldd + chain of custody +
      Autopsy = forensik-ops hardware (cf. seksi 40); padanan parsing
      artefak statis secai: mft_scan; hash ganda + write blocker =
      disiplin yang tak berubah
- [ ] #0801 KEV prioritization: matriks KEV/EPSS/CVSS/aset -> P1-P5
      SLA — padanan secai: kev_gap + vuln_sla_aging +
      asset_criticality_score (+ intel_sync feed); tabel SLA cf.
      seksi 26/163 (KEV = 24-48 jam); EPSS = API jaringan (ops)
- [ ] #0806 DMARC rollout: fase p=none -> quarantine (pct naik
      bertahap) -> reject; inventory pengirim sah dulu; alignment
      adkim/aspf relaxed vs strict — padanan: spf_dmarc_posture;
      distilasi config cf. seksi 133
- [ ] #0807 DNS enumeration/AXFR: dig record-types + AXFR per NS —
      padanan: dns_axfr_check (live AXFR) + subdomain_enum_surface +
      dns_light; IXFR incremental jarang dites — tambahan runbook saja
- [ ] #0808 DNS tunneling: entropi label >3.5, panjang >50, volume TXT
      per domain, unique-subdomain count — padanan penuh:
      dns_log_triage (+ seksi 62/117); scapy pcap = parser lain,
      polanya sama

---
Blok B29 (#0841-#0870, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Lima entri diekstrak jadi tool: #0844 -> tools/
linux_auth_triage.py, #0849 (sisi Linux; Windows = win_persist_triage)
-> tools/linux_persist_scan.py, #0855 + #0856 + #0857 -> tools/
pcap_triage.py, #0860 -> tools/oauth_grant_audit.py, #0868 -> tools/
paste_triage.py; sisanya didistilasi di bawah (seksi 195-201).

## 195. Kubernetes penetration testing — permukaan serangan & peta fase (dari mukul975/performing-kubernetes-penetration-testing) — distilasi B29
- [ ] permukaan serangan per komponen: API server 6443 (anonymous auth,
      RBAC abuse), kubelet 10250/10255 (unauthenticated /pods, exec),
      etcd 2379 (read tanpa auth = semua Secret), dashboard 8443
      (default cred), NodePort 30000-32767, CoreDNS 53 — tiap port =
      cek berbeda, jangan scan satu port lalu simpulkan
- [ ] peta fase ATT&CK-for-Kubernetes: akses awal (dashboard terekspos/
      kubeconfig dicuri) -> eksekusi (exec container, CronJob, pod
      privileged) -> persistensi (container backdoor, mutating webhook)
      -> eskalasi (privileged pod, RBAC abuse) -> kredensial (SA token,
      Secret) -> lateral (container escape, service internal)
- [ ] cek RBAC ofensif yang valid: kubectl auth can-i create pods /
      get secrets / create clusterrolebindings / '*' '*'; binding dgn
      subjek system:anonymous/system:unauthenticated = red flag
- [ ] ranah secai: sisi API/hardening = k8s_rbac_audit,
      k8s_audit_triage, k8s_podsec_audit, netpol_audit, psa_ns_audit,
      kube-bench = kubebench_ingest (B28), etcd config =
      etcd_config_audit (B28); EKSEKUSI pentest live (kube-hunter,
      peirates, deploy pod pentest) = ops cluster berizin — runbook,
      bukan tool audit
- [ ] higiene uji: pod uji diberi nama jelas + dihapus setelah uji;
      uji network policy dgn probe wget timeout pendek, JANGAN sweep
      metadata 169.254.169.254 tanpa persetujuan eksplisit (kredensial
      cloud)

## 196. Deteksi lateral movement Windows & WMI (#0842 + #0843) — distilasi B29
- [ ] pola deteksi inti per teknik: PtH = 4624 LogonType-3 NTLM ke >3
      host oleh user sama; overpass-the-hash = 4769 encryption RC4
      (0x17) volume tinggi; golden ticket = 4769 lifetime > 10 jam +
      TicketOptions anomali; PsExec = 7045 PSEXESVC + pipe
      \PSEXESVC* (Sysmon 17); WMI = WmiPrvSE.exe mem-lahirkan
      cmd/powershell + WMI-Activity 5857/5860/5861; WinRM =
      wsmprovhost parent; RDP = 4624 LogonType-10 fan-out; admin
      share = 5140 ShareName C$/ADMIN$/IPC$ fan-out; remote task =
      4698 dari non-SYSTEM dgn isi XML http/powershell/temp
- [ ] korrelasi graf: edge = (src_ip -> host, user, logon_type)
      agregat 24 jam; NetFlow port 445/135/3389/5985 memperkuat jejak
      host-to-host yang di log terlihat terputus
- [ ] WMIExec (offense): Win32_Process.Create via DCOM/WinRM TIDAK
      menciptakan service (lebih senyap dari PsExec), output via file
      temp di ADMIN$ — sisi deteksinya justru file temp di share
      admin + proses anak WmiPrvSE; persistensi WMI = pasangan
      __EventFilter + CommandLineEventConsumer + FilterToConsumerBinding
      di root\subscription (OBJECTS.DATA bisa dipindai regex offline)
- [ ] ranah secai: kerberos_log_triage (4769 RC4/golden),
      win_logon_triage (4624/4625), dcom_lateral_scan (DCOM),
      zeek_lateral_scan (fan-out jaringan), account_manip_triage,
      win_persist_triage (4698/4697); koridor eksekusi live =
      ops red team berizin

## 197. Forensik log lintas sumber & onboarding SIEM (#0845 + #0846) — distilasi B29
- [ ] disiplin koleksi forensik: struktur direktori kasus per sumber,
      HASH semua log yang dikumpulkan (sha256sum) SEBELUM analisis;
      Event ID prioritas Windows: 4624/4625/4648/4672/4688/4697/4698/
      4720/4732/1102 (log cleared = anti-forensik, selalu temuan);
      Linux: auth.log/secure + auditd EXECVE/USER_AUTH
- [ ] korrelasi = normalisasi timestamp + urutkan + window: brute
      force (4625 beruntun) -> 4624 sukses dari sumber sama -> 4688/
      4697 sesudahnya; log tanpa NTP sinkron = korrelasi palsu — cek
      dulu konsistensi jam antar sumber
- [ ] onboarding SIEM ber-tier: Tier-1 dulu (AD, firewall, EDR, VPN,
      DNS, email gateway) karena nilai-deteksi per GB paling tinggi;
      tiap sumber: format + EPS estimasi + parser + pemetaan CIM
      (src->src_ip dst->dest_ip) + coverage field target >= 80-90%
- [ ] validasi kualitas ingest: event datang (count per sourcetype/
      host), coverage field (count(src)/count total), LAG timestamp
      (_indextime - _time) > 300s = masalah jam/parsing — jangan
      onboarding lalu tinggal
- [ ] ranah secai: triase log = win_logon_triage/sysmon_triage/
      linux_auth_triage; integritas jalur = log_chain_verify;
      keputusan onboarding = proses SOC (checklist ini), bukan tool

## 198. Triage malware & enrichment intel (#0847 + #0848 + #0850 + #0851 + #0852) — distilasi B29
- [ ] VT hash enrichment (jaringan): verdict dari last_analysis_stats
      — ratio malicious: >70% engine = critical, >40% high, >10%
      medium; JANGAN hanya andalkan ratio: lihat popular_threat_
      classification, crowdsourced YARA, sandbox behavior (proses/
      file/registry/mutex/dns); pivot: hash -> contacted_ips/domains/
      urls -> IOC; free tier 4 req/menit = batch wajib throttle;
      kirim hash aman, JANGAN kirim sample sensitif ke scanner publik
- [ ] ekstraksi IOC dari sample: hash file (md5/sha1/sha256) + imphash
      + string ASCII/UTF-16LE + pola (url/ip/domain/registry path/
      mutex Global\|Local\, PDB path, BTC address, user-agent);
      FILTER IP privat (10/8, 172.16/12, 192.168/16, 127/8) dari IOC
      C2; render STIX indicator [file:hashes.'SHA-256' = '...']
- [ ] ranah secai: string+offset = binary_strings_surface;
      klasifikasi/defang IOC teks = ioc_defang; konsumsi/validasi
      STIX = stix_bundle_audit; mutex = killswitch_triage; entropi
      section = packer_scan — ekstraksi terfragmentasi BUKAN hilang;
      YARA: menulis/menjalankan rule = runtime yara pihak ketiga,
      yang diport = yara_rule_lint (lint statis rule); disiplin
      authoring: uji dulu di korpus BERSIH (FP test), hindari string
      generik (OpenSSL/mozilla), batasi filesize, hex wildcard utk
      varian — rule terlalu spesifik = lewatkan varian, terlalu
      generik = alarm massal
- [ ] Volatility 3 (ops, pip install + symbol ISF): urutan triase
      memori: info/banners -> pslist+pstree -> psscan CROSS-VIEW
      (PID di psscan tapi tidak di pslist = hidden/unlinked) ->
      malfind (VAD RWX + kode) -> netscan (C2) -> cmdline/envars ->
      dumpfiles; modscan vs modules = driver tersembunyi; credential
      dump (hashdump/lsadump) hanya di lab/berizin; YARA-in-memory
      dgn rule keluarga = klasifikasi cepat
- [ ] ranah secai: config RAT dari sample = rat_config_scan; triase
      dokumen = maldoc_triage/pdf_triage; artefak ransom =
      ransom_artifact_triage; dump memori = kerangka ops (tool eksternal)

## 199. Mobile assessment — pinning bypass & forensik perangkat (#0853 + #0854) — distilasi B29
- [ ] sisi STATIS pinning (audit): Android network_security_config.xml
      <pin-set> + trust anchors + cleartextTrafficPermitted; OkHttp
      CertificatePinner; iOS ATS + plist; ranah secai:
      mobile_manifest_audit membaca AXML/XML/plist/prefs — cek
      pinning di sana dulu SEBELUM uji dinamis
- [ ] sisi DINAMIS (ops, berizin): Frida/Objection hook TrustManagerImpl/
      OkHttp check/SecTrustEvaluate; multi-layer pinning = bypass
      SEMUA layer (OkHttp + custom TrustManager + CT check); binary-
      level pinning (C/C++) butuh Interceptor native — hati-hati
      klaim "sudah bypass" saat satu layer belum tersentuh
- [ ] forensik mobile: urutan akuisisi logical -> file system ->
      physical; Faraday bag / airplane mode SEBELUM apa pun (remote
      wipe); dokumentasi IMEI/OS/lock state + hash akuisisi = chain
      of custody; UFED/Cellebrite = hardware+lisensi (ops); alternatif
      open: ALEAPP/iLEAPP/libimobiledevice; WAL SQLite = sumber
      pesan terhapus
- [ ] ranah secai: apk_firebase_scan, mobile_manifest_audit (statik);
      ekstraksi pesan/location = kerangka ops perangkat fisik

## 200. Monitoring jaringan & program social-engineering (#0858 + #0862 + #0863 + #0867 + #0869) — distilasi B29
- [ ] Zeek deployment: TAP > SPAN (packet loss), 1 worker per 1 Gbps,
      AF_PACKET lb untuk multi-core, pantau capture_loss.log (loss =
      blind spot terukur), JSON logs utk SIEM, intel framework
      (indicator -> notice) refresh harian; log yang dibaca triage:
      conn/dns/http/ssl (JA3)/files/notice/weird
- [ ] OSINT (jaringan): 6 kategori — domain (CT log, subdomain),
      personel (LinkedIn, pola email), kredensial (breach db,
      paste, GitHub), teknologi (job posting, Wappalyzer, Shodan),
      fisik (Maps), dokumen (metadata); SpiderFoot modes: footprint
      (peta aset), investigate (IOC tertentu), passive (tanpa sentuh
      target) — pilih mode sesuai izin; cf. seksi 35/38/39
- [ ] packet injection (live, lab saja): Scapy SYN/XMAS/NULL utk uji
      IDS/firewall + anti-spoofing (BCP38/uRPF); verifikasi sisi
      penerima dgn capture; NEVER-LIST: bukan DoS; sisi secai =
      deteksi offline artefaknya (pcap_triage: SYN-only anomali,
      flag aneh)
- [ ] phishing simulation (GoPhish, ops): komponen = sending profile/
      template {{.URL}}/{{.Tracker}}/landing/group/campaign; metrik =
      delivered/open/click/submit rate + time-to-click; etika: izin
      tertulis, halaman redirect ke training, JANGAN kredensial
      nyata tersimpan tanpa rotasi; cf. seksi 66 (playbook phishing)
- [ ] ranah secai: analisis hasil = lewat ingest log/triase
      eml_phish_triage (sisi email), eksekusi campaign = ops

## 201. Kepatuhan & di luar domain — catatan bidang blok B29 (#0859 + #0861 + #0864-#0866 + #0870)
- [ ] NIST CSF 2.0 (#0859): 6 fungsi (GV baru: Organizational Context/
      Risk Mgmt/Roles/Policy/Oversight/Supply Chain) x 4 tier (Partial/
      Risk-Informed/Repeatable/Adaptive); metodologi: profil-saat-ini
      -> profil-target -> gap -> roadmap 0-3/3-12/12-24 bulan;
      jebakan: menilai teknologi saja tanpa govern, target tier
      tanpa resource, CSF tidak sinkron ISO 27001/SOC 2 yang sudah ada
      — governance methodology, bukan tool audit
- [ ] Di luar domain secai (fokus web/app/infra):
      #0861 oil & gas (API 1164/TSA SD-02/IEC 62443 — konsep layak
      dicatat: custody transfer metering tanpa auth = fraud finansial
      langsung; remote site tanpa IDS fisik), #0864 OT network
      (Purdue L0-L4, safety exclusion SIS/ESD dulu baru scan),
      #0865 Claroty xDome (produk komersial), #0866 Tenable OT
      (passive-first: pindai native protocol yang aman, aktif hanya
      window maintenance + profil teruji lab), #0870 physical
      intrusion (tailgating/RFID/lock — bukan ranah cyber tool;
      izin tertulis + alat dokumentasi = prasyarat mutlak)
- [ ] pola lintas-blok: produk OT komersial (Claroty/Tenable/Dragos)
      = ops; yang bisa diport dari OT = lapisan ingest/parse laporan
      (cf. kubebench_ingest utk kube-bench) bila kelak ada keluaran
      format teks yang stabil

---
Blok B28 (#0811-#0840, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Lima entri diekstrak jadi tool: #0817+#0818 -> tools/
carve_scan.py, #0823+#0825 -> tools/graphql_depth_audit.py, #0830+#0833
-> tools/ioc_lifecycle_score.py, #0839 -> tools/kubebench_ingest.py,
#0840 -> tools/etcd_config_audit.py; sisanya didistilasi di bawah
(seksi 208-220). CATATAN PENOMORAN: nomor 195-207 bertabrakan dgn
apendiks blok B29 (195-201) yang terlanjur terbit terpisah — seksi B28
direnumber 208-220 mengikuti preseden renumber B24; menyusul 195-201
blok B29.

## 208. Sandbox analisis dinamis interaktif (dari #0811 performing-dynamic-analysis-with-any-run) — distilasi B28
- [ ] sandbox interaktif dipilih bila perilaku sample TERGANTUNG klik
      (macro "Enable Content", installer, UAC) — sandbox pasif buta
      terhadap jalur ini; interaksi = variabel analisis, dicatat apa
      yang diklik agar reprodusibel
- [ ] sebelum detonasi: timeout 2-5x dugaan (malware slow-acting),
      MITM proxy ON bila butuh isi HTTPS C2, fake-net bila sample cek
      konektivitas — konfigurasi salah = hasil "bersih" palsu
- [ ] sampel sensitif/organisasi TIDAK ke sandbox awan publik —
      on-prem saja (privasi task URL publik vs privat)
- [ ] artefak yang WAJIB diekspor per analisis: process tree (parent-
      child abnormal), IOC (file/domain/mutex/registry), PCAP, ATT&CK
      mapping — feed ke kampanye (cf. campaign_correlate, ioc_defang)
- [ ] ranah secai: triase statis offline dulu (maldoc_triage,
      pdf_triage, packer_scan) — detonasi live = ops sandbox, bukan
      tool repo

## 209. Forensik endpoint — order of volatility & rantai bukti (dari #0812 performing-endpoint-forensics-investigation) — cf. seksi 100/169/178
- [ ] urutan pengambilan TIDAK bisa ditawar: memori dulu (fileless
      tidak menyisakan artefak disk), lalu koneksi/proses, disk,
      removable, log — yang paling volatil paling dulu
- [ ] IMAGING sebelum analisis (alat di sistem hidup mengubah
      timestamp & memori); hash MD5+SHA256 saat akuisisi; write
      blocker utk disk sumber; chain of custody per artefak — tanpa
      itu bukti tak terpakai di forum hukum
- [ ] peta artefak Windows (cf. seksi 178): prefetch = eksekusi,
      shimcache = keberadaan (JEBAKAN: hadiran != eksekusi), amcache =
      SHA1 + instalasi, $MFT/UsnJrnl = filesystem, EVTX = event
- [ ] super-timeline (plaso) lalu filter jendela insiden — tunnel
      vision satu artefak = cerita bocor; padanan parsing statis
      secai: mft_scan, sysmon_triage, win_persist_triage,
      timestomp_triage; analisis memori (volatility) = ops live

## 210. Remediasi endpoint & prioritas EPSS (dari #0813 performing-endpoint-vulnerability-remediation) — cf. seksi 183, padanan vuln_sla_aging/kev_gap/asset_criticality_score
- [ ] matriks prioritas P1-P4: P1 = CVSS>=9 ATAU KEV ATAU exploit-
      in-the-wild + CVSS>=7 (SLA 14 hari); P2 = CVSS 7-8.9 + EPSS>0.5
      (30); P3 = CVSS 4-6.9 (60); P4 = sisanya (90) — EPSS & KEV
      MEMBALIK urutan CVSS: 9.8 dgn EPSS 0.01 kalah urgensinya dari
      7.5 dgn EPSS 0.95
- [ ] kelas remediasi berurutan: patch > config-change (mis. matikan
      SMBv1/Spooler/LLMNR) > upgrade > workaround ber-tanggal-kedalu-
      warsa > compensating control > accept-risk ber-sign-off —
      workaround TANPA tanggal kedaluwarsa = exception abadi
- [ ] patch tanpa uji ring = BSOD massal; group uji dulu, jendela
      maintenance utk server "tak boleh reboot" (stok vuln kritis
      menumpuk di server itu)
- [ ] verifikasi = re-scan/konfirmasi KB terpasang, BUKAN "patch sudah
      didistribusikan"; metrik program: MTTR + %SLA + overdue (cf.
      vuln_sla_aging; kev_gap utk KEV; asset_criticality_score utk
      bobot aset)

## 211. Reduksi false-positive SIEM — disiplin tuning (dari #0816 performing-false-positive-reduction-in-siem) — cf. seksi 187
- [ ] ukur dulu: FP-rate per rule = FP/(FP+TP) dari status closure —
      target <20%, prioritaskan rule >30%; sampling 20 FP per rule
      utk kategori akar-masalah sebelum menyentuh logika
- [ ] desain ulang ambang, bukan hanya naikkan: single-event "5 failed
      logins" -> multi-sinyal "20+ kegagalan, >=3 akun unik, 10 menit"
      — ambang naik MURNI membunuh deteksi, korelasi mempertahankannya
- [ ] allowlist ber-disiplin: field (src_ip/proses), ALASAN, APPROVER,
      TANGGAL KEDALUWARSA — allowlist tanpa kedaluwarsa = celah abadi
      (spirit baseline secret_report_ingest: bukan allowlist abadi)
- [ ] eksklusi waktu (window maintenance, jadwal batch) + baseline
      perilaku (mean+3*stdev per pengguna) + intel enrichment dgn
      ambang confidence — jangan tambat ke satu sumber
- [ ] validasi PASCA-tuning wajib: atomic test (red team) masih
      memicu rule yang dituning — tuning yang membunuh TP = blind spot
      terukur; siklus: mingguan identifikasi, dua-mingguan tuning,
      bulanan validasi, kuartalan laporan

## 212. Triage filesystem firmware ter-embed (dari #0819 performing-firmware-malware-analysis) — padanan carve_scan + binary_strings_surface
- [ ] ekstraksi dulu (intinya di carve_scan #0817/#0818: signature +
      entropi), lalu triase isi: skrip startup (/etc/init.d/rcS,
      inittab), cron, authorized_keys, iptables rule asing, SUID
      di luar baseline, file .so lebih baru dari busybox (flag
      modifikasi)
- [ ] pencarian kredensial keras: passwd/shadow, grep "password|secret
      |token|key" di /etc — padanan: binary_strings_surface utk
      string+offset, repo-secret-scan utk pola layanan
- [ ] diff hash terhadap firmware baseline resmi (sha256 per binari)
      — yang berbeda = kandidat backdoor, analisis RE terpisah
      (ghidra = ops RE, di luar tool)
- [ ] verifikasi versi komponen (busybox/dropbear/dnsmasq) vs CVE —
      cf. cve_matcher; patch vendor firmware biasanya datang sebagai
      image utuh, bukan patch per-paket

## 213. Fuzzing coverage-guided AFL++ (dari #0820 performing-fuzzing-with-aflplusplus) — live ops
- [ ] rantai kerja: instrumentasi (afl-clang-fast; QEMU mode utk
      binary-only) -> seed corpus MINIMAL valid -> afl-cmin (buang
      seed redundan) -> afl-fuzz paralel (-M/-S per core) -> triase
      crash (afl-tmin + dedup)
- [ ] persistent mode utk target hot-loop (throughput naik orde
      magnitude); build ASAN/UBSAN = crashnya bug nyata, bukan noise
- [ ] disiplin: fuzz HANYA target berizin/lab; crash unik dilaporkan
      dgn langkah reproduksi, bukan klaim CVE dini; map density rendah
      = corpus/entry-point salah, bukan target aman
- [ ] ranah secai: hasil fuzz (crash + input pemicu) jadi EVIDENCE
      tersimpan, dianalisis tool lain — fuzzing live = infrastruktur
      lab terpisah

## 214. Audit GCP: sisi offline secai vs alat live (dari #0821 gcpbucketbrute, #0822 forseti) — padanan cloud_bucket_exposure/gcp_fw_audit/gcp_orgpolicy_audit
- [ ] enumerasi bucket = tebakan nama + GET status; sisi secai:
      cloud_bucket_exposure (pola sama, S3); permutations keyword
      (org-nama, produk, lingkungan) = daftar kandidat, bukan temuan
- [ ] TestIamPermissions / get-iam-policy = opsi live berotorisasi;
      yang terport ke secai = AUDIT FILE konfigurasi: gcp_fw_audit
      (0.0.0.0/0, SSH/RDP terbuka, flow log mati) & gcp_orgpolicy_
      audit — ekspor gcloud -> triase offline di sini, cf.
      aws_config_audit
- [ ] Forseti = produk terdeprekasi; SCC = real-time vendor — bukan
      target port; checklist CIS GCP yang relevan: SA key >90 hari,
      primitive role owner/editor, binding allUsers (cf.
      iam_escalation_scan utk pola eskalasi IAM)

## 215. Audit kata sandi berotorisasi — hashcat (dari #0827 performing-hash-cracking-with-hashcat) — live ops
- [ ] JANGAN crack tanpa surat tugas eksplisit; hash dari ekspor
      audit/lab sendiri; laporan = distribusi kelas sandi (kosong/
      default/kamus/kebijakan-putus), bukan daftar sandi plaintext —
      nilai sandi TIDAK PERNAH di-output (redaksi, spirit secret
      tools)
- [ ] mode serangan naik bertahap: kamus -> kamus+rule (best64) ->
      mask (dari pola kebijakan) -> kombinasi; mulai dgn hash type
      SALAH = kampanye sia-sia (identifikasi format dulu)
- [ ] anti-lockout: cracking OFFLINE atas hash TIDAK menyentuh domain
      — validasi kredensial hasil = spray pelan dgn lockout-awareness
      (cf. disiplin spray seksi 172)
- [ ] hasil -> temuan kebijakan sandi (panjang/entropy), bukan
      penghukuman pengguna; rotasi wajib utk yang tercrack

## 216. HPP — peta parser & lintas-lapis (dari #0828 performing-http-parameter-pollution-attack) — padanan hpp_differential
- [ ] akar masalah: front-end (WAF/proxy) dan back-end mem-parse
      parameter duplikat BERBEDA (PHP last, ASP concat koma, Tomcat
      first, Express array) — uji perilaku server dulu dgn probe
      netral sebelum eksploitasi; padanan secai: hpp_differential
- [ ] kelas dampak: bypass validasi (payload terbelah dua parameter),
      override parameter keamanan (price/role), client-side (query
      yang direfleksikan ke href dgn %26) — yang terakhir = inject
      link, bukan hanya input
- [ ] WAF-split buktinya harus END-TO-END: respons menunjukkan polusi
      diterapkan back-end, bukan sekadar WAF tidak menolak request
- [ ] perbaikan: satu kebijakan parse di semua lapis (reject duplikat
      / gabung eksplisit) + validasi server-side final

## 217. Investigasi ancaman insider — bukti kovert & otorisasi (dari #0832 performing-insider-threat-investigation) — cf. seksi 169, padanan insider_baseline_scan
- [ ] GATE otorisasi sebelum koleksi: kasus terdokumentasi, legal
      sign-off, HR liaison, SCOPE eksplisit (sistem + rentang waktu) —
      investigasi insider menyentuh privasi karyawan; tanpa gate =
      risiko hukum sendiri
- [ ] koleksi kovert dulu (log server-side, DLP, proxy) — jangan
      gelisahkan subjek sebelum bukti cukup; forensik endpoint baru
      kalau log mengarah ke sana
- [ ] analisis = baseline vs anomali: jam akses, volume, pola
      perangkat, USB/cloud-upload — padanan secai: insider_baseline
      _scan; perbandingan kuartal, bukan momen tunggal
- [ ] motive-samping (notice period, embargo saham/kinerja) = konteks
      kasus, bukan bukti; kesimpulan digariskan bukti digital + rantai
      custodi (cf. seksi 209)

## 218. Statis iOS — apa yang terbaca dari IPA (dari #0834 performing-ios-app-security-assessment) — padanan mobile_manifest_audit + binary_strings_surface
- [ ] IPA = ZIP; lapis statis yang bisa diaudit offline: Info.plist
      (CFBundleURLSchemes custom, ATS exception NSAllowsArbitraryLoads,
      associated domains), entitlements, embedded.mobileprovision
      (expired? devices?), daftar framework tertaut — padanan:
      mobile_manifest_audit (jalur plist)
- [ ] strings binary + pola rahasia (api_key/secret/firebase) —
      padanan: binary_strings_surface; LC_ENCRYPTION ada = FairPlay
      (binary app-store terenkripsi — analisis statis terbatas,
      catat, bukan gagal senyap)
- [ ] Frida/objection/SSL-pinning-bypass/keychain dump = dinamis
      ber-perangkat jailbreak — di luar bentuk tool repo (lab
      terpisah); perbedaan dgn Android: secai punya apk_firebase_
      scan, iOS tercakup jalur plist di mobile_manifest_audit

## 219. Reputasi IP — konteks bukan vonis (dari #0836 performing-ip-reputation-analysis-with-shodan) — cf. intel_sync
- [ ] reputasi = KOMPOSIT: port tidak lazim terbuka, layanan rentan
      (CVE dari banner), tipe hosting (residential/VPN/bulletproof),
      tag riwayat — bukan angka tunggal dari satu API
- [ ] InternetDB (tanpa kunci) utk volume tinggi, API penuh utk
      detail; rate limit = antre, bukan naikkan laju
- [ ] skor reputasi = PRIORITAS triase, bukan vonis blokir — CDN/
      pemindai sah bisa "gudang port"; konteks jaringan sumber
      (asset owner?) menimbang; hasil enrichment disimpan sbg evidence
      ber-timestamp (usia intel, cf. intel_sync freshness,
      ioc_lifecycle_score utk peluruhan)
- [ ] live API lookup = ops jaringan; secai memakai HASIL tersimpan

## 220. Di luar domain + padanan — catatan bidang blok B28 (cf. seksi 141/161/172/180)
- [ ] #0814 SailPoint IIQ entitlement review = IGA-ops (cf. seksi 141):
      konsep lintas-produk yang layak diingat — kampanye ber-default-
      revoke (tak direview = dicabut), SOD constraint dua sisi, dan
      VERIFIKASI cabut-akses benar-benar ter-provision ke target
      (approve di kertas = akses masih hidup)
- [ ] #0824 GraphQL introspection live = padanan secai graphql_
      schema_map (1-request inventory) + graphql_surface_detector
      (0-request); endpoint discovery & clairvoyance = probing live
      (target berizin); sisi statis skema = graphql_depth_audit
      (#0823/#0825)
- [ ] #0826 HSM PKCS#11 = operasi perangkat keras/FIPS (SoftHSM/
      CloudHSM/YubiHSM) — di luar bentuk tool; konsep: keygen & sign
      DI-DEVICE, audit mechanism list, kunci tak pernah keluar
- [ ] #0829 Claroty xDome ICS asset discovery = OT (cf. seksi 161):
      pasif dulu (SPAN), aktif butuh izin vendor PLC — bukan ranah IT
- [ ] #0831 EvilGinx3 AiTM = operasi ofensif phishing (di luar domain);
      sisi deteksi & remediasinya sudah didistilasi seksi 180 (B26):
      MFA-dilewati-bukan-diloloskan + cabut-sesi
- [ ] #0835 IoT assessment = lapis perangkat keras (UART/JTAG/SPI/
      flashrom) di luar domain; sisi firmware-nya = seksi 212 +
      carve_scan; default-cred & command-injection = pola web biasa
- [ ] #0837 JWT alg=none live = padanan jwt_token_audit (varian none,
      jwk/jku/x5u/kid sudah dicek offline dari token tersimpan);
      forging+replay = uji hidup target berizin
- [ ] #0838 Kerberoasting = AD ofensif (cf. seksi 172): SPN enum +
      TGS + crack offline; sisi deteksi = padanan kerberos_log_triage
      (RC4 0x17 pada 4769, tgs-tanpa-tgt); mitigasi = gMSA/panjang
      sandi >25 + audit RC4

---
Blok B30 (#0871-#0900, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Tiga entri diekstrak jadi tool: #0876 -> tools/
linux_privesc_audit.py, #0890 -> tools/lambda_config_audit.py, #0896 ->
tools/sqlite_forensics.py; sisanya didistilasi di bawah (seksi 221-232).

## 221. Privesc lintas-OS — pelengkap linux_privesc_audit (dari mukul975/performing-privilege-escalation-assessment + performing-privilege-escalation-on-linux)
- [ ] sisi Linux deterministik diekstrak jadi linux_privesc_audit
      (#0876); yang tinggal live-ops: kernel exploit (Dirty Cow CVE-
      2016-5195, Dirty Pipe CVE-2022-0847, PwnKit CVE-2021-4034,
      GameOver(lay)) — patch level = kontrol utamanya, bukan tool;
      lookup GTFOBins = referensi live, tabel lokal tool = kurasi sendiri
- [ ] sisi Windows (cf. seksi 77/104): unquoted service path + service
      binary writable (ops service config — pola bisa masuk
      win_audit_coverage bila kelak dibutuhkan), AlwaysInstallElevated
      (2 registry HKLM/HKCU), AutoRun registry writable
      (win_persist_triage), token privilege SeImpersonate/
      SeAssignPrimaryToken (potato-class = live lab), UAC
      (sysmon_triage uac-registry-hijack)
- [ ] disiplin laporan: vektor yang DITEMUKAN != vektor yang BERHASIL
      dieksekusi — dua kategori berbeda; klaim eskalasi butuh bukti
      shell root/SYSTEM (session_ledger)
- [ ] padanan secai: linux_privesc_audit (misconfig), lolbin_scan +
      sysmon_triage (cmdline/uac), kev_gap (kernel CVE prioritas)

## 222. PQC migration — padanan crypto_inventory_scan + program (dari mukul975/performing-post-quantum-cryptography-migration)
- [ ] padanan secai: crypto_inventory_scan (#0746 — CBOM-lite,
      klasifikasi quantum-vulnerable/weak-legacy/post-quantum + Mosca);
      skill ini = versi PROGRAM-nya, delta yang layak diingat:
- [ ] FIPS 203 (ML-KEM/Kyber — key exchange), FIPS 204 (ML-DSA/
      Dilithium — signature), FIPS 205 (SLH-DSA/SPHINCS+ — fallback
      hash-based); output inventaris harus memetakan usage -> tiga
      peran itu
- [ ] hybrid TLS = jalur transisi (X25519MLKEM768 di handshake):
      hybrid sah diterima; downgrade ke klasik-murni di endpoint
      sensitif = temuan program
- [ ] validasi kesiapan = uji LIVE (oqs-provider OpenSSL) — paket
      "terpasang" != negosiasi PQC berhasil; sertifikat PQC & jalur
      HSM = risiko tersendiri (infra crypto, cf. seksi 132)
- [ ] urutan migrasi: data jangka-panjang / harvest-now-decrypt-later
      DULU (backup, arsip, log terenkripsi), lalu transit TLS, terakhir
      signature internal — klaim selesai tanpa data-at-rest = salah
      prioritas

## 223. Gubernansi akun privilese & service account (dari mukul975/performing-privileged-account-access-review, -privileged-account-discovery, -service-account-audit, -service-account-credential-rotation)
- [ ] discovery dulu, review kemudian: inventaris dari SEMUA sumber —
      grup AD (Domain Admins/Enterprise Admins), role Entra, IAM AWS
      (admin policy), cluster-admin k8s, local admin per host, DBA,
      akun aplikasi; inventaris parsial = sisi buta (fail-closed)
- [ ] tiering by blast radius (tier-0 = kontrol domain/forest) ->
      cadensi review berbeda per tier; akun tanpa owner = orphan,
      disable BUKAN delete (jejak audit, cf. seksi 73)
- [ ] review = bukti JUSTIFIKASI, bukan daftar: pemilik, tujuan,
      terakhir-dipakai (lastLogon/servicePrincipalName), status MFA;
      privilese tinggi + tak dipakai > 90 hari = kandidat cabut
- [ ] service account (cf. seksi 88): gMSA/managed identity > password
      statis; rotasi otomatis WAJIB dgn peta dependensi dulu (rotasi
      tanpa peta = outage massal — urutan: inventaris konsumen ->
      window -> rotasi -> verifikasi service hidup); password servis
      evergreen di log = ranah linux_auth_triage/win_logon_triage
- [ ] padanan secai: k8s_rbac_audit (cluster), iam_escalation_scan
      (AWS), oauth_grant_audit (Entra); checklist ini utk MENYUSUN
      program recertification lab, bukan tool

## 224. Purple team — emulasi terkendali & validasi deteksi (dari mukul975/performing-purple-team-atomic-testing, -purple-team-exercise) — cf. seksi 108/130
- [ ] Atomic Red Team = eksekusi uji per-teknik ATT&CK (Invoke-
      AtomicRedTeam) = ops ber-izin di host lab; nilai yang dipinjam:
      uji SATU teknik, deterministik, prasyarat eksplisit
- [ ] loop validasi deteksi: jalankan uji -> rule deteksi memicu?
      -> tidak = GAP -> tulis/tuning rule -> uji ulang; hasil disimpan
      per-teknik (covered/detected/missed) — pola sama dgn
      attack_coverage; validasi pasca-tuning wajib atomic test masih
      memicu (cf. seksi 211)
- [ ] output eksekutif = layer ATT&CK Navigator + persentase deteksi
      per tactic (cf. seksi 173), bukan log eksekusi mentah
- [ ] korelasi Sigma: tiap atomic test memetakan rule Sigma terkait —
      mapping disimpan sbg DATA yang bisa diaudit (cf. seksi 18/173)
- [ ] exercise (bukan testing tunggal): objective -> scenario ->
      deconfliction SOC (seksi 108) -> ukur MTTD/MTTC per fase -> AAR;
      kegagalan deteksi = temuan biru, bukan kegagalan merah

## 225. Koridor ransomware: respons, negosiasi, tabletop (dari mukul975/performing-ransomware-response, -ransomware-tabletop-exercise, -soc-tabletop-exercise) — cf. seksi 28/29/66/84/125/160/169
- [ ] respons: koridor CISA sudah di seksi 28; delta keputusan yang
      layak diingat: pembayaran = keputusan BISNIS/HUKUM (konsultasi
      legal + penegak hukum + cek sanksi OFAC sebelum kontak; decryptor
      keluarga lama cek No More Ransom dulu — cf. seksi 169); notifikasi
      regulator punya tenggat per-yurisdiksi (GDPR 72 jam — timeline
      dihitung dari KETAHUAN, bukan dari kontain)
- [ ] verifikasi backup SEBELUM percaya restore: hash/scan sampel
      cadangan + boot test terisolasi — cadangan yang terjangkit =
      jalur re-infeksi (cf. seksi 160 3-2-1-1-0)
- [ ] tabletop ransomware: skenario dari aktor NYATA (injects LockBit/
      ALPHV: double extortion, penghapusan backup, tekanan deadline),
      cadensi inject terjadwal (jangan semua di menit pertama),
      evaluasi vs NIST CSF/CISA; keputusan yang diuji: bayar/tidak,
      isolate/tidak, notifikasi siapa-kapan
- [ ] tabletop SOC generik: tujuan terukur (uji playbook X), fasilitator
      + scribe terpisah, peserta = yang BAKAL menangani insiden (bukan
      manajemen saja), diskusi > teori; AAR = action item ber-owner +
      tenggat yang mengubah playbook (cf. seksi 67)
- [ ] secai: ransom_artifact_triage (artefak), sysmon_triage/
      lolbin_scan (T1490 vssadmin), win_persist_triage; eksekusi
      respons live = ops IR

## 226. Infrastruktur red team — kampanye phishing & C2 (dari mukul975/performing-red-team-phishing-with-gophish, -red-team-with-covenant) — cf. seksi 14/30/68/182/200
- [ ] GoPhish = platform kampanye ber-izin (sending profile/template/
      group/campaign + metrik delivered/open/click/submit) — runbook
      ops; etika & metrik kesehatan (report rate > click rate) cf.
      seksi 200; padanan analisis sisi email: eml_phish_triage +
      spf_dmarc_posture
- [ ] Covenant = C2 .NET (listeners, grunts, lateral tracking) —
      padanan distilasi C2 lain (seksi 14/30/182): deteksi = deviasi
      profil + artefak in-memory, bukan signature; tanpa inti
      deterministik baru utk secai

## 227. SCA — program di atas padanan dependency_cve (dari mukul975/performing-sca-dependency-scanning-with-snyk) — cf. seksi 19/80/101/146
- [ ] padanan secai: dependency_cve (lockfile/SBOM -> CVE),
      supplychain_check, dep_confusion_check, pkg_typosquat_check,
      exploit_ci_gate; Snyk = produk SCA (ops CI)
- [ ] delta program yang layak diingat: fix-PR otomatis tetap WAJIB
      review (patch versi bisa pecah behavior — gate test tetap
      jalan); license compliance = gate TERPISAH dari gate CVE
      (GPL/SSPL di produk komersial = temuan kebijakan); continuous
      monitoring = re-scan saat DB CVE terbaru (cf. seksi 101
      re-scan-on-db-update)

## 228. Second-order SQL injection — metodologi stored payload (dari mukul975/performing-second-order-sql-injection)
- [ ] mekanisme: payload disimpan TANPA error (diterima validasi
      input), lalu DIGUNAKAN lagi di operasi/query BERBEDA yang tak
      meng-escape konten — tidak ada respons langsung di titik injeksi;
      uji = dua fase (simpan -> picu)
- [ ] titik simpan: registrasi/profil (username, nama, alamat), email,
      header UA/referer yang tersimpan (cf. seksi 109); titik picu:
      query admin/listing, pencarian, ekspor CSV, laporan
- [ ] payload: quote-break dgn konteks escaping ASIMETRIS (tersimpan
      ter-escape lalu di-unescape tak sengaja saat dipakai ulang);
      fase simpan 200-normal adalah ciri, bukan ketenangan
- [ ] disiplin uji: payload unik ber-marker per titik (atribusi hasil),
      uji juga update-profile (read-modify-write merusak escaping
      kedua), bandingkan data tersimpan (dump DB bila sah) vs tampilan
- [ ] padanan secai: SqliProducts/SqliError/SqliTimePlaybook (fase-1
      live), waf_sqli_triage (sisi log); fase-2 = urutan playbook
      manual dua-langkah di lab, bukan tool

## 229. Postur headers & SSL/TLS — padanan + program lifecycle (dari mukul975/performing-security-headers-audit, -ssl-certificate-lifecycle-management, -ssl-stripping-attack, -ssl-tls-inspection-configuration, -ssl-tls-security-assessment)
- [ ] #0889 padanan SUDAH ADA: http-security-headers, csp-analyzer,
      clickjacking-protection-checker, hsts-preload-checker, xss-
      protection-header-checker (registry) — skill ini checklist yang
      sama; tambahan evaluasi: atribut cookie Secure/HttpOnly/SameSite
      per kelas (session vs preferensi), dan header di SEMUA respons
      (404/error kerap tanpa headers — audit per-halaman, bukan
      beranda saja)
- [ ] #0897 lifecycle sertifikat: issuance/renewal OTOMATIS via ACME
      (jendela renewal 30 hari sebelum expiry), monitoring expiry di
      SEMUA endpoint (internal/mTLS ikut, bukan publik saja), revokasi
      + OCSP stapling, private key di HSM/vault (cf. seksi 75/136);
      padanan: cert_chain_audit (validasi rantai dari artefak) +
      ssl-tls-analyzer (live)
- [ ] #0898 SSL stripping = MITM live (sslstrip/bettercap) — lab
      berizin saja; yang dipakai secai = sisi pencegahan: HSTS
      max-age panjang + includeSubDomains + preload (padanan
      hsts-preload-checker), redirect http->https server-side bukan
      client-side
- [ ] #0899 TLS inspection: break-and-inspect punya BIAYA eksplisit —
      bypass list wajib (app certificate-pinned, banking/health utk
      privasi, update binary yang gagal pin), fail-open vs fail-closed
      saat engine mati = keputusan tercatat (cf. seksi 155), CA
      inspeksi di trust store TERKENDALI (tidak disebar luas)
- [ ] #0900 padanan: ssl-tls-analyzer + tls-cipher-suites-checker
      (registry) + sslyze/testssl = alat eksternal; tambahan checklist:
      OCSP must-staple, versi minimum TLS 1.2/1.3 (cf. seksi 72),
      monitoring certificate transparency utk wildcard bocor
      (ct-inventory)

## 230. SOAP/WSDL — urutan uji (dari mukul975/performing-soap-web-service-security-testing)
- [ ] recon: ?wsdl -> parse operations/bindings/soap:address (XML
      stdlib), versi (SOAP 1.1 vs 1.2 namespace), operasi sensitif;
      WSDL yang mengekspos operasi internal tak terpakai = lead
      shadow-API (cf. shadow_api_diff)
- [ ] kelas uji: XXE di envelope (padanan XxeCallbackPlaybook), XML/
      SOAP injection di parameter (CDATA/escape), SOAPAction spoofing
      (action tak divalidasi = panggil operasi admin via action lain),
      XPath injection di parameter yang diinterpolasi ke query XML,
      WS-SecurityPolicy ABSEN = lead (tanpa signature/encryption
      meski transport TLS)
- [ ] idempotensi & replay: tanpa WS-Addressing/timestamp = replay
      sah; SOAP fault bocor stack/class (faultstring detail) = temuan
- [ ] pustaka sumber (zeep/requests) = non-stdlib; di secai: uji
      manual dgn template XML di lab berizin — checklist ini
      urutannya, bukan tool

## 231. Di luar domain — OT/energi cluster (dari mukul975/performing-plc-firmware-security-analysis, -power-grid-cybersecurity-assessment, -s7comm-protocol-security-analysis, -scada-hmi-security-assessment) — cf. seksi 48/63/83/161/175
- [ ] #0871 firmware PLC: ekstraksi butuh akses fisik (UART/JTAG/
      vendor tool) — bidang hardware; yang bersinggungan dgn secai:
      hardcoded kredensial & string di image = carve_scan +
      binary_strings_surface; diff vs firmware resmi = hash baseline
      (seksi 212); mekanisme update tak bertanda tangan = temuan
      proses vendor
- [ ] #0873 power grid: NERC CIP (cf. seksi 161), IEC 61850 GOOSE/MMS
      (publish-subscribe tanpa auth native), PMU C37.118,
      Industroyer/CrashOverride (destructive protokol-native) — butuh
      jaringan substation tersegmentasi milik sendiri
- [ ] #0885 S7comm: stack TPKT(102) -> COTP -> S7 (function 0xf0
      handshake, 0x1a/0x1b program download, 0x28/0x29 read/write
      var, PUD/CPU-STOP berbahaya); S7CommPlus (S7-1200/1500) punya
      integritas tapi sudah direverse publik; deteksi = baseline per
      fungsi + alert tulisan/stop — parser protokol = kelas alat lain
- [ ] #0887 SCADA HMI: HMI web-based = permukaan web biasa (default
      cred, auth lemah, upload tak tervalidasi — padanan playbook
      secai) tapi konteks OT (dampak fisik); IEC 62443 zone/conduit
      + thin-client session hijack — bidang OT (cf. seksi 161);
      yang bisa diport = lapisan audit konfigurasi web-nya bila kelak
      ada ekspor

## 232. Kepatuhan & privasi (dari mukul975/performing-privacy-impact-assessment, -soc2-type2-audit-preparation) — cf. seksi 42/141
- [ ] PIA/DPIA (GDPR Art. 35): pemicu = pemrosesan besar/sensitif/
      profiling; metode NIST PRAM: map data flow -> identifikasi
      risiko -> keputusan (avoid/transfer/mitigate/accept) ->
      dokumentasi; tata kelola, bukan pengujian teknis; padanan
      teknis: data_class_scan (temuan PII), retensi = review kode
- [ ] SOC 2 Type II: TSC CC1-CC9 (Security wajib; A/PI/C/P
      opsional); bukti = SAMPEL PERIODE (log kontrol berjalan 3-12
      bulan, bukan snapshot); gap assessment -> POA&M ber-owner (cf.
      seksi 94 #0478 NIST RMF); otomatisasi bukti (AWS/Okta/GitHub
      API) = live ops ber-kunci — bukan tool audit

---
Blok B33 (#0961-#0990, 8 Nov) — sumber mukul975/Anthropic-Cybersecurity-
Skills (Apache-2.0 — konsep, bukan teks). Dua entri diekstrak jadi tool
(#0976 -> tools/prompt_leak_probe.py, #0983 -> tools/oauth_redirect_audit.py);
sisanya didistilasi di bawah / padanan eksisting / luar domain (addendum).

## 233. OWASP API Top-10 2023 — peta cakupan secai (dari mukul975/testing-api-security-with-owasp-top-10, -testing-api-authentication-weaknesses, -testing-for-broken-access-control)
Checklist peta API1-API10 -> alat secai yang sudah ada (jangan bangun ulang):
- [ ] API1 BOLA: playbook idor-orders/idor-mass (live L3) + api_property_scan
      (offline API3) — differential dua-sesi tetap baku emas: objek milik
      user lain harus dibaca TANPA sesi pemilik; satu temuan = idor, bukan
      "akses kontrol rusak" generik
- [ ] API2 Broken auth: playbook api-version-auth (regresi antar versi —
      endpoint lama terbuka saat baru ditutup), jwt_token_audit + playbook
      jwt-weak-secret/jwt-alg-confusion, lockout-canary (brute force)
- [ ] API3 BOPLA: api_property_scan — properti respons yang tak didefinisi
      spesifikasi = kandidat bocor; request mass-assignment live = playbook
      mass-assignment
- [ ] API4/6 unrestricted resource/flow: rate-limit-validator + dasar
      anti-klaim: tekanan rate TIDAK boleh dilakukan tanpa budget eksplisit
- [ ] API5 BFLA: playbook admin-access (fungsi admin dipanggil tanpa role)
- [ ] API7 SSRF: playbook ssrf-callback/ssrf-chain (canary OOB milik sendiri)
- [ ] API8 misconfig: registry checkers (debug-page, directory-listing,
      http-method-allow) + error-oracle
- [ ] API9 inventory: api-docs-surface, api-version-surface, shadow_api_diff
- [ ] API10 unsafe consumption: ssrf-chain + validasi respons pihak-ketiga
- [ ] Autentikasi API lemah (dari skill auth-weaknesses): default cred,
      token di URL (bocor ke log/Referer), lifetime token panjang,
      missing rotation — jwt_token_audit menutup higiene klaim; yang
      tersisa = disiplin review, bukan scanner

## 234. Business logic — metodologi uji (dari mukul975/testing-for-business-logic-vulnerabilities)
Kelas bisnis-logika tidak punya signature — yang bisa diotomasi adalah
DIFFERENTIAL keadaan, sisanya disiplin pemetaan:
- [ ] peta dulu alur uang/entitlement (state machine: order->pay->deliver)
      sebelum menguji; lompat langkah = bandingkan state akhir vs sah
- [ ] harga/kuantitas: nilai negatif, nol, desimal ganda, integer overflow,
      currency mismatch — uji via replay transfer (playbook replay-transfer)
- [ ] race: dua request paralel klaim resource sekali-pakai (playbook
      race-coupon); butuh jendela nyata — target flaky = catat, jangan klaim
- [ ] referral/reward: self-referral, loop pendaftaran, batas per-identitas
      (email+device+payment) — differential identitas, bukan payload
- [ ] role logic: aksi lintas-tenant (cf. API1) + abai batas kuota
- [ ] anti-FP: temuan bisnis-logika WAJIB bawa state-before/state-after;
      tanpa itu = lead L0-L1 (cf. brocards_triage utk disiplin bukti)

## 235. Mobile API authentication (dari mukul975/testing-mobile-api-authentication)
- [ ] token di shared_prefs/UserDefaults = plaintext storage (padanan
      mobile_manifest_audit export shared_prefs) — di iOS cek juga keychain
      accessibility class
- [ ] debuggable/cleartext di manifest = precondition transport lemah
      (padanan mobile_manifest_audit)
- [ ] certificate pinning: BYPASS runtime (Frida) = luar jangkauan statis;
      yang bisa diaudit = ADA/TIDAKnya pinning di manifest/network config
      (network_security_config) — absen pinning + handle kredensial = lead
- [ ] flow OAuth mobile (custom scheme callback): scheme hijackable =
      code interception (padanan seksi deep link mobile_manifest_audit;
      redirect/PKCE = oauth_redirect_audit)
- [ ] uji IDOR sama dengan web (API1) — jangan perlakukan beda hanya karena
      client mobile

## 236. RAG indirect prompt injection — permukaan retrieval (dari mukul975/testing-prompt-injection-in-rag-pipelines)
Retriever = kanal injeksi tak langsung: teks yang di-chunk lalu dikutip
diperlakukan otoritatif oleh model. Playbook rag-poisoning menutup jalur
ingest; checklist program:
- [ ] peta SUMBER corpus: dokumen user-upload, tiket, wiki, email — tiap
      sumber = trust boundary; jalur tanpa review = kandidat poisoning
- [ ] payload canary di dokumen (instruksi benign "sebut <marker>") ->
      jawaban retrieval yang mengutip marker = jalur terbukti L3 (determinis);
      jawaban non-deterministik = pola F59 (trials>=3, cap L2)
- [ ] delimiter/format: chunk yang memecah template sistem (markdown,
      code fence) = lead; uji dengan dokumen ber-format ekstrem
- [ ] mitigasi yang bisa diverifikasi: quote-attribution (kutipan dijawab
      dgn sumber), pemisahan konteks (instruksi vs data), filter pola
      instruksi pada chunk — padanan injection_guard utk sisi bukti
- [ ] cleanup WAJIB: dokumen canary dihapus + diverifikasi tak lagi
      ter-retrieve (cf. disiplin cleanup playbook rag-poisoning)

## 237. Triage insiden & IR playbook (dari mukul975/triaging-security-incident, -triaging-security-incident-with-ir-playbook, cf. triage_advisor, -triaging-security-alerts-in-splunk [ops produk])
Checklist triase yang menyatukan alert -> keputusan -> serah terima:
- [ ] prioritas antrian = dampak x urgensi (severity matrix: pengaruh
      bisnis + sebaran + tahap kill-chain), BUKAN urutan kedatangan
- [ ] klasifikasi tipe dulu (malware/phishing/akun/DoS/insider) — tiap
      tipe punya bukti minimum berbeda; alert tanpa klasifikasi = tidak
      bisa dieskalasi
- [ ] enrichment minimum sebelum keputusan: identitas pemilik aset,
      kepekaan data, keberadaan IOC di intel lokal (cf. ioc_defang,
      campaign_correlate untuk pivot infrastruktur)
- [ ] containment HOLD terpisah dari eradication: tahan dulu (isolasi,
      disable akun) — dokumentasikan justifikasi; aksi destruktif butuh
      approval eksplisit (cf. killswitch_triage utk sisi jaringan)
- [ ] playbook IR = struktur pilihan, bukan naskah: deteksi -> containment
      -> eradication -> recovery -> lessons; tiap fase punya OWNER dan
      exit-criteria tertulis
- [ ] serah terima: temuan triase wajib bawa timeline, bukti mentah
      (tak disanitasi untuk internal), dan keputusan+alasan (cf.
      verdict_audit); metrik triase (MTTA/MTTD) dipakai utk tuning
      deteksi, bukan target performa individu
- [ ] #0988 Splunk = ops produk (notable event, risk-based alerting) —
      konsep di atas dipakai apa pun SIEM-nya

---
Blok B32 (#0931-#0960, 8 Nov) — sumber mukul975/Anthropic-Cybersecurity-
Skills (Apache-2.0 — konsep, bukan teks). Dua entri diekstrak jadi tool
(#0941 + konsep FindCrypt #0940 -> tools/crypto_constant_scan.py,
#0942 -> tools/rust_binary_triage.py); 28 entri sisanya didistilasi di
bawah (nomor seksi sengaja mulai 241 — buffer 238-240 utk hindari
tabrakan penomoran live dgn blok tetangga, celah dijaga mengikuti
preseden koordinator).

## 241. Profil aktor & gap deteksi sebagai prioritas (dari mukul975/profiling-threat-actor-groups) — cf. seksi 35
- [ ] dimensi profil standar: identitas (ATT&CK G-ID + alias lintas
      vendor — BEAR/PANDA/KITTEN/CHOLLIMA = penamaan negara, BUKAN
      organisasi yang sama), motivasi, targeting (sektor/geografi/
      teknologi), kapabilitas, riwayat kampanye, TTP per fase
- [ ] profil ber-TTP, bukan ber-IOC: infrastruktur rotasi dalam
      minggu; TTP bertahan kuartal — profil ber-IOC basi sebelum
      dibaca (cf. seksi 35 ACH)
- [ ] nilai praktis profil = LANGKAH 4-nya: bandingkan daftar teknik
      aktor vs matriks cakupan deteksi sendiri -> teknik tanpa deteksi
      = gap kritis, logging-tanpa-alerting = parsial, kontrol
      kompensasi dicatat bila deteksi tak layak
- [ ] padanan secai: attack_coverage (#0660) melayani sisi gap;
      checklist ini dipakai saat MENULIS profil/briefing dari bukti
      (confidence eksplisit, tidak pernah atribusi tunggal-bukti)
- [ ] higiene umur: profil tidak diperbarui kuartal = aset intel yang
      menipu; klasifikasi distribusi TLP ditulis di dokumen

## 242. Pemulihan data & ransomware — padanan, bukan tool baru (dari mukul975/recovering-deleted-files-with-photorec, -recovering-from-ransomware-attack) — cf. seksi 28/29/66/225
- [ ] #0932 PhotoRec/foremost/scalpel = alat carving eksternal; inti
      signature+entropi sudah diekstrak carve_scan (#0817/#0818) dan
      pemulihan sadar-struktur SQLite = sqlite_forensics (#0896);
      katalog hasil carving (hash, tipe-vs-ekstensi mismatch, NSRL
      filter) = disiplin chain-of-custody seksi 40
- [ ] #0933 runbook recovery: fasa pemulihan bergantung-dependensi
      (identitas dulu — AD/DC sebelum domain member), validasi backup
      PRA-kompromi (timestamp backup vs tanggal kompromi terawal),
      krbtgt reset 2x interval 12 jam (cf. seksi 73), validasi
      persistence pada sistem pulih sebelum reconnect bertahap
- [ ] padanan secai: ransom_artifact_triage (triase manifest+note),
      win_persist_triage/sysmon_triage (cek persistence hasil pulih);
      eksekusi restore (Veeam/wbadmin) = ops di luar kelas tool

## 243. Red team LLM — taksonomi probe & hit-rate (dari mukul975/red-teaming-llms-with-garak) — cf. seksi 74
- [ ] anatomi scanner LLM: probe (payload adversarial per keluarga) ->
      generator (konektor target) -> detector (penilai sukses/gagal)
      per percobaan; hasil per baris = laporan mesin (jsonl), ringkasan
      per probe = hit-rate ok/N
- [ ] keluarga probe inti -> OWASP LLM: promptinject (LLM01), latent
      injection (indirekt via konten, LLM01), dan jailbreak (bypass
      guardrail), leakreplay (memorisasi/system-prompt, LLM02/07),
      encoding (bypass filter ber-enkode), xss (eksfil markdown/HTML)
- [ ] disiplin pengukuran: --generations menaikkan keyakinan statistik
      dan biaya; baseline SEBELUM kontrol vs re-run IDENTIK sesudah =
      bukti reduksi risiko (pola two-arm patch_proof); hit-string
      sukses disimpan sbg bukti PoC
- [ ] di secai: eksekusi probe = live ops ber-token (di luar kelas
      offline); lapisan deteksi statisnya = injection_guard (seksi 44),
      gate programnya = seksi 74 (CI per kategori, regresi = blokir)

## 244. Metodologi RE malware — triase statis Android/.NET/Ghidra (dari mukul975/reverse-engineering-android-malware-with-jadx, -reverse-engineering-dotnet-malware-with-dnspy, -reverse-engineering-malware-with-ghidra) — inti diekstrak crypto_constant_scan (#0941) + rust_binary_triage (#0942)
- [ ] urutan triase selalu: identifikasi format/packer DULU (packer_
      scan, binary_strings_surface, crypto_constant_scan) -> dekompilasi
      (JADX/dnSpy/Ghidra = alat eksternal live, di luar kelas secai)
      -> ekstraksi konfigurasi/IOC -> rule deteksi (YARA)
- [ ] Android (#0937): izin berbahaya dipetakan perilaku (SMS=intersep
      2FA, SYSTEM_ALERT_WINDOW=overlay banking, BIND_ACCESSIBILITY=
      kontrol penuh, BIND_DEVICE_ADMIN=anti-uninstall); penanda kode:
      DexClassLoader (muat DEX runtime = sembunyikan inti), string
      ter-enkode dgn dekriptor, daftar package bank di aset; jebakan:
      logic asli sering di .so native — jangan berhenti di DEX
- [ ] .NET (#0938): kenali obfuscator dulu (ConfuserEx/SmartAssembly/
      Reactor) -> de4dot sebelum analisis manual; konfigurasi C2 pola
      tetap: kelas Config statis (host/port/key/mutex), string XOR
      runtime, resource ter-enkripsi; breakpoint pada fungsi dekriptor
      = semua string terbuka sekaligus (dinamis, di VM lab)
- [ ] Ghidra (#0940): alur hemat — auto-analysis dulu -> entry point ->
      XREF API berbahaya (VirtualAlloc/CreateRemoteThread/Crypt*/
      InternetOpen) -> dekompilasi fungsi terkait -> konstanta kripto
      via FindCrypt — konsep FindCrypt inilah yang diekstrak jadi
      crypto_constant_scan (S-box/sigma/init-state/API import) sehingga
      lapisan pertama identifikasi algoritma jalan TANPA buka Ghidra
- [ ] keluaran RE standar: peta fungsi, protokol C2 (metode/endpoint/
      enkripsi/komando), kebutuhan-eva (anti-VM/anti-debug), IOC +
      kandidat rule — dgn atribusi konsep (Apache-2.0) tanpa salin kode

## 245. Di luar domain — catatan bidang blok B32 (cf. seksi 42/48/63/161/175/231)
- [ ] #0935 NTLM relay -> AD CS ESC8: serangan AD ofensif (coercion
      MS-EFSRPC/MS-RPRN + relay ke /certsrv/ tanpa EPA -> cert DC ->
      PKINIT -> DCSync) — di luar fokus web/app secai dan kelas
      read-only; sisi defensif yang layak diingat: EPA+HTTPS wajib di
      endpoint enrollment, matikan Web Enrollment tak terpakai,
      monitor enrollment sertifikat machine-account anomali (T1649)
- [ ] #0939 Frida iOS: butuh perangkat jailbroken/gadget + hooking
      runtime (ObjC.classes, CCCrypt hook, FairPlay dump) — bidang
      perangkat keras/mobile dinamis, di luar kelas tool offline; cf.
      seksi 199 (pinning) & 218 (statis iOS)
- [ ] #0959 historian OT (OSIsoft PI/PHD): hardening server + DMZ
      replikasi — domain OT, di luar fokus web/app; prinsip generik:
      kredensial bawaan, layanan tak terpakai, jalur replikasi
      satu-arah ke DMZ

## 246. Scanner eksternal & CI gate — padanan ada, jangan bangun ulang (dari mukul975/scanning-container-images-with-grype, -scanning-containers-with-trivy-in-cicd, -scanning-docker-images-with-trivy, -scanning-iac-and-images-with-trivy, -scanning-infrastructure-with-nessus, -scanning-kubernetes-manifests-with-kubesec, -scanning-network-with-nmap-advanced)
- [ ] grype/trivy (keluarga #0943-#0946): scanner CVE/misconfig pihak
      ketiga ber-DB; padanan secai: dependency_cve (paket), docker_
      audit (konfigurasi image), terraform_audit (IaC), exploit_ci_gate
      (gate), sarif_ingest (hasil SARIF) — pola yang dipinjam: gate
      severity cutoff fail-closed, --ignore dgn ALASAN terdokumentasi,
      scan ulang berkala (temuan CVE berubah tanpa kode berubah)
- [ ] #0947 Nessus: runbook scanner live ber-lisensi; padanan keluarga
      ingest offline = cspm_finding_ingest/sarif_ingest; disiplin
      prioritasnya (VPR/EPSS di atas CVSS mentah) sudah di seksi 210
- [ ] #0948 kubesec: scoring manifest (privileged/hostPID/hostNetwork/
      SYS_ADMIN negatif; readOnlyRootFilesystem/runAsNonRoot/seccomp
      positif) — padanan k8s_podsec_audit (#0653) mengaudit spec pod
      vs PSS dengan aturan sendiri; skor numerik = komunikasi, bukan
      vonis keamanan
- [ ] #0949 nmap advanced: pemindaian aktif = kelas lain (izin per-
      engagement, seksi 64); yang layak diingat: simpan output XML/-oA
      selalu (struktur = bahan triase), UDP jangan terlewat (SNMP/
      DNS/TFTP), timing agresif di produksi = risiko sendiri

## 247. Kontrol pemanggilan tool agentic (dari mukul975/securing-agentic-ai-tool-invocation) — padanan mcp_tool_vet/agent_tool_audit
- [ ] lima lapis pada boundary tool-call: allowlist deny-by-default ->
      validasi skema argumen (field ekstra ditolak) -> identitas
      scoped-berumur-pendek per sesi (bukan service-account tuhan) ->
      gerbang keputusan allow/require-approval/deny -> audit log
      (aktor, tool, HASH argumen, keputusan, alasan)
- [ ] HITL fail-closed: aksi berdampak tinggi menunggu persetujuan;
      timeout/non-approval = DENY, bukan lolos
- [ ] sinyal deteksi: lonjakan deny/require-approval = kandidat
      injection berjalan (AML.T0053/0051)
- [ ] di secai: mcp_tool_vet mem-vet tool SEBELUM dipasang, agent_
      tool_audit memindai kode pemanggil; checklist ini = kebijakan
      runtime saat DESAIN agent lab (session_ledger mewadahi jejak)

## 248. Cloud, WAF, registry, helm, k8s-cloud — padanan & konsep (dari mukul975/remediating-s3-bucket-misconfiguration, -securing-api-gateway-with-aws-waf, -securing-aws-iam-permissions, -securing-aws-lambda-execution-roles, -securing-azure-with-microsoft-defender, -securing-container-registry-images, -securing-container-registry-with-harbor, -securing-github-actions-workflows, -securing-helm-chart-deployments, -securing-kubernetes-on-cloud) — cf. seksi 182/193/223
- [ ] #0936 S3: urutan remediasi = stop-exposure dulu (Block Public
      Access) -> BucketOwnerEnforced (matikan ACL legacy) -> enkripsi
      default -> logging; kunci preventif = SCP yang menolak
      put-public-access-block; padanan cloud_bucket_exposure +
      aws_config_audit; jangan remediasi sebelum ambil log akses
      (bukti kebocoran hilang setelah ditutup)
- [ ] #0951 WAF: konsep yang pinjam-lapis — rate-based rule per ident,
      managed rule group + custom rule, logging ke tujuan tunggal;
      padanan registry: waf_fingerprint + rate-limit-validator
- [ ] #0952/#0953 IAM & lambda roles: least-privilege berbasis
      AKTIVITAS (CloudTrail 90 hari -> policy generated), permission
      boundary + SCP sebagai pagar; padanan iam_escalation_scan +
      lambda_config_audit (wildcard role) — cf. seksi 223
- [ ] #0954 Defender for Cloud / #0956 Harbor / #0955 ECR-ACR-GCR:
      CNAPP & registry = produk ops; konsep yang bertahan: scan-on-
      push, tag immutability, digest-pin (bukan tag mutable), verifikasi
      tanda tangan sebelum deploy (cf. seksi 193)
- [ ] #0957 GHA workflows: padanan gha_workflow_audit (#0463 — pin
      SHA, token permission minimal, script injection, fork PR)
- [ ] #0958 helm: yang statis-layar — values.yaml BUKAN tempat secret
      (secret di values = temuan keluarga secret-scan), default
      securityContext di values, pin chart versi + verifikasi provenance
      (.prov) = live-ops; manifest TER-RENDER diaudit k8s_podsec_audit
- [ ] #0960 k8s managed cloud: PSS (k8s_podsec_audit), netpol
      (netpol_audit), RBAC (k8s_rbac_audit), PSA namespace
      (psa_ns_audit); workload identity (IRSA/Workload Identity/
      Managed Identity) = eliminasi kredensial statis di pod — konfigur
      cloud-side = ops, prinsipnya: SA pod tanpa rahasia tertanam


---
Blok B31 (#0901-#0930, 8 Nov) — sumber mukul975 (Apache-2.0 — konsep,
bukan teks). Tiga entri diekstrak jadi tool: #0902 -> tools/
pe_import_scan.py, #0903 -> tools/stego_triage.py, #0920 -> tools/
owasp_risk_rating.py; sisanya didistilasi di bawah. Penomoran: 238-240
= buffer tetangga yang dijaga B32 (preseden koordinator), lanjut 249
setelah 248 milik B32.

## 238. Metodologi thick-client pentest (dari mukul975/performing-thick-client-application-penetration-test) — distilasi B31
- [ ] statis dulu: identifikasi teknologi (.NET -> dnSpy, Java -> JD-GUI/
      JADX, C/C++ -> Ghidra, Electron -> ekstrak asar), string ber-
      keyword kredensial (password/secret/api_key/jdbc/connection), file
      konfigurasi (app.config, settings.xml, %APPDATA% config.json)
- [ ] penyimpanan lokal = permukaan utama: registry Run HKCU, SQLite
      lokal (cek sqlite_forensics), Credential Manager, file di AppData/
      Temp — kredensial plaintext di disk = temuan
- [ ] DLL hijacking versi statis: Procmon NAME NOT FOUND .dll di dir
      writable; di secai: linux_privesc_audit menutup sisi Linux
      (writable-dir + PATH), sisi Windows hanya parsial (lolbin_scan/
      pe_mitigation_scan) — catat celah, jangan klaim tercakup
- [ ] memory dump: string password/token/bearer dari dump proses; zero-
      memory-after-use = remediasi (cf. zeroize_scan utk sisi kode)
- [ ] lapisan API thick-client tetap diuji seperti web: IDOR ubah id
      antar-prinsip, mass assignment field isAdmin, lockout bypass —
      playbook secai sudah ada (IdorOrders/MassAssignment/
      LockoutCanary)
- [ ] auth lokal (patch dnSpy/breakpoint) = kelas ofensif lab-berizin —
      di luar kelas alat read-only secai

## 239. Pola hunt KQL/EQL Elastic (dari mukul975/performing-threat-hunting-with-elastic-siem) — cf. seksi 17/74, distilasi B31
- [ ] hipotesis dulu (seksi 36), sumber data disebut SEBELUM query:
      logs-endpoint.events.process vs sysmon_operational — hunt tanpa
      sumber = celah telemetri, bukan hasil kosong
- [ ] pola KQL LOLBin: nama proses + daftar argumen khas (certutil
      -urlcache/-decode; powershell -enc/iex/frombase64string) + EKSKLUSI
      parent sah (sccm/svchost) — bentuk "proses+args+exclusion" portabel
      (cf. lolbin_scan utk sisi offline)
- [ ] pola EQL sequence yang dipakai ulang: parent-child anomali
      (explorer.exe -> cmd/powershell/rundll32, maxspan), dumping
      kredensial (procdump/rundll32 *lsass* -> file .dmp, maxspan 2m),
      lateral (auth sukses type-3 -> psexesvc, maxspan 1m) — bentuk
      [A] lalu [B] dalam window = pola generik lintas SIEM
- [ ] loop wajib: hunt terkonfirmasi -> detection rule (mapping ATT&CK +
      severity + interval) -> Navigator layer update — hunt yang tidak
      menghasilkan rule/gap-tercatat = borongan

## 240. Threat landscape per sektor (dari mukul975/performing-threat-landscape-assessment-for-sector) — distilasi B31
- [ ] peta aktor-per-sektor dikelola TABEL eksplisit (financial: FIN7/
      Lazarus; healthcare: Ryuk/Conti; energy: Sandworm/Dragonfly;
      government: APT29/28/Turla) — pembaruan dari laporan ISAC/vendor,
      bukan ingatan (cf. seksi 240-B32 profil aktor)
- [ ] teknik umum = hitung frekuensi lintas aktor -> top-10 teknik
      sektor = prioritas deteksi; jangan klaim "aktor X memakai Y"
      tanpa sumber ATT&CK
- [ ] vektor awal dipisah primary vs emerging per sektor (quishing, MFA
      fatigue, API key theft) — emerging wajib bawa tanggal-sumber
- [ ] output = ringkasan eksekutif + tabel + rekomendasi investasi
      (deteksi top-10, red team berbasis aktor, keanggotaan ISAC) —
      dokumen strategis; cf. campaign_correlate utk sisi kampanye
- [ ] di secai: tidak ada sumber ATT&CK live (jaringan/API) —
      checklist dipakai saat MENYUSUN laporan dari intel yang sudah
      terkumpul (intel_sync + seksi 35)

## 249. Triase output scanner klasik — Nessus/Nikto (dari mukul975/performing-vulnerability-scanning-with-nessus + performing-web-application-scanning-with-nikto) — distilasi B31
- [ ] validasi scan terotentikasi SEBELUM percaya hasil: plugin 19506
      "Credentialed checks: yes" per host — scan tanpa kredensial meleset
      mayoritas temuan lokal (hasil incomplete, bukan "bersih")
- [ ] FP kelas scanner: backported-patch (versi lama tapi sudah diperbaiki
      di RHEL/CentOS — verifikasi rpm changelog), custom 404 memicu
      generic-checks, anti-CSRF token dianggap form-vuln, respons CDN/WAF
      salah dikenali sebagai app, health-check page load balancer
- [ ] grouping by remediation (satu patch, 47 host) — laporan per-
      temuan-per-host = noise
- [ ] prioritas: CVSS mulai, naik utk exploit publik + internet-facing +
      asset criticality, TURUN utk compensating control terdokumentasi
      (segmentasi/WAF/EDR) — cf. cvss_score/kev_gap/vuln_sla_aging/
      asset_criticality_score; versi scanner-alat-eksternal = seksi 246
      (B32) + 245 (B32 di-luar-domain Nessus runbook)
- [ ] Nikto = scanner server/config (bukan app-logic): hasilnya pasangan
      registry secai (http-method-allow, server-version-disclosure,
      file-exposure-checker, security headers); DAST temuan -> triase
      owasp_risk_rating (#0920) + brocards_triage
- [ ] ingest ekspor scanner eksternal -> findings.json mengikuti pola
      sarif_ingest/cspm_finding_ingest bila kelak ada konsumen — jangan
      bangun tool tanpa pemakai

## 250. Taksonomi bypass WAF + checklist WSTG yang belum tercakup (dari mukul975/performing-web-application-firewall-bypass + performing-web-application-penetration-test) — distilasi B31
- [ ] fingerprint dulu: header vendor (cf-ray/incap_ses/AkamaiGHost),
      respons terhadap payload pasti-blok (403/custom page/CAPTCHA) —
      padanan waf-fingerprint
- [ ] taksonomi evasi: encoding berlapis (double URL-encode, unicode
      %u0027, HTML entity, charset ibm037), variasi kasus + komentar
      inline /*!50000UNION*/, substitusi spasi (%09/%0A), metode &
      protokol (PUT/PATCH, chunked, HTTP/0.9), lokasi parameter
      (X-Forwarded-For/Referer), body yang tak diinspeksi (JSON/XML/
      multipart), HPP (id=1' UNION&id=SELECT) — padanan hpp_differential
- [ ] XSS evasi: event handler alternatif (onpageshow/onstart),
      svg/onload, javascript: URI, template literal, escape \u0065 —
      pasang di xss-reflect-check + waf_sqli_triage saat WAF aktif
- [ ] WSTG sisa belum ada cek otomatis secai: session fixation (token
      TIDAK berubah pre/post login), MFA bypass akses-langsung halaman
      pasca-auth, reset password (prediktabilitas token + enumerasi akun
      + host-header injection), concurrent session limit, remember-me
      predictability — catat sbg lead manual saat engagement
- [ ] disiplin: bypass = di ATAS vuln terkonfirmasi (bukan cara menemukan
      vuln); uji dgn cache-buster bila cache terlibat (cf. seksi 190)

## 251. Deteksi post-exploit Microsoft Graph + CVSS v4.0 awareness (dari mukul975/post-exploiting-microsoft-graph-with-graphrunner + prioritizing-vulnerabilities-with-cvss-scoring) — distilasi B31
- [ ] GraphRunner = ops merah live (butuh token Graph) — yang diport:
      tabel telemetri sisi biru: device-code grant dari client Azure
      CLI (04b07795) di IP/device tak lazim; audit event "Add
      application" + "Consent to application" scope delegated luas (cf.
      oauth_grant_audit); "Add member to group" pada grup role-assignable;
      inbox rule forward eksternal (T1114.003, cf. seksi 49); volume
      $search tinggi ke /messages di MicrosoftGraphActivityLogs
- [ ] remediasi pencurian token Graph: cabut sesi/refresh token + hapus
      OAuth app injected + hapus inbox rule — reset password saja TIDAK
      cukup (cf. seksi 66/81)
- [ ] CVSS v4.0 = kesadaran, bukan tool: metric group baru (AT, UI
      pasif/aktif, VC/SC terpisah vulnerable/subsequent system, E:
      attacked/POC/unreported); alat secai tetap CVSS v3.1 (cvss_score)
      sampai konsumen v4 ada; prioritas program tetap EPSS/KEV di atas
      skor mentah (cf. seksi 210, kev_gap)

## 252. Peta artefak forensik Windows — EZ tools (dari mukul975/performing-windows-artifact-analysis-with-eric-zimmerman-tools) — cf. seksi 40/52/70/100/209, distilasi B31
- [ ] peta artefak -> pertanyaan: $MFT (mft_scan) = riwayat file + dua
      set timestamp; $J USN = operasi rename/delete cepat; Prefetch =
      bukti eksekusi + run count; Amcache = hash SHA1 exe; LNK/jumplist
      = dokumen dibuka; shellbags = direktori pernah dijelajahi; event
      log = win_logon_triage/win_auth_triage
- [ ] timestomping utama: bandingkan Created0x10 (SI) vs Created0x30
      (FN) — SI < FN = indikasi (padanan timestomp_triage #0542)
- [ ] EZ tools/KAPE = runbook ops Windows (.NET) — secai memparse
      artefak STATIS yang diekspor; onboarding KAPE = ops lab, bukan
      alat audit
- [ ] korelasi eksekusi: Prefetch + Amcache + 4688 + MFT creation —
      satu sumber bukan kesimpulan (cf. seksi 77 disiplin investigasi)

## 253. Di luar domain + padanan — catatan bidang blok B31 (cf. seksi 42/48/63/69/75/188)
- [ ] #0901 SSRF exploitation: padanan SsrfCallbackPlaybook/
      SsrfChainPlaybook + taksonomi bypass seksi 190; varian enkode IP
      (desimal/hex/oktal) masuk ranah playbook bila dibutuhkan
- [ ] #0904 subfinder: padanan subdomain-enum-surface + ct-inventory +
      program_discovery; subfinder/httpx/dnsx = alat pipeline live
- [ ] #0905 supply-chain simulation: padanan pkg_typosquat_check
      (Levenshtein), dep_confusion_check, supplychain_check,
      dependency_cve — hash-verify + pip-audit = ops CI
- [ ] #0907 atomic red team: eksekusi live (atomic-operator) = ops
      purple-team; padanan konsep attack_coverage + seksi 224
- [ ] #0909 YARA hunting: padanan yara_rule_lint (mutu rule); scanning
      live yara-python + watchdog = ops; dedup sha256 + clean-corpus
      FP-test sudah jadi disiplin yara_rule_lint
- [ ] #0910 MISP: ops produk TIP (PyMISP); padanan intel_sync
      (freshness/delta/TTL) + stix_bundle_audit + seksi 24/42; TLP +
      distribution level = kebijakan berbagi, bukan alat
- [ ] #0913 plaso super-timeline: padanan seksi 33 (B11) + log_chain_
      verify; log2timeline/psort/Timesketch = runbook ops
- [ ] #0914 UEBA: padanan insider_baseline_scan + seksi 46/76 (baseline
      deviasi, impossible travel, peer-group, lantai anti-FP)
- [ ] #0915 VLAN hopping: di luar domain (akses fisik switch, DTP/VTP
      live); prinsip hardening yang dicatat: switchport nonegotiate,
      native VLAN tak-terpakai != VLAN 1, VTP transparent, port unused
      di-shutdown; sisi PCAP L2-wired belum ada padanan (deauth_pcap_
      scan = radio) — catat celah
- [ ] #0921/#0922 cache deception/poisoning: padanan CacheDeception
      Playbook + CachePoisonPlaybook (cache-buster, unkeyed header
      X-Forwarded-Host/Proto, delimiter discrepancy) — WCVScanner/
      Param Miner = alat live
- [ ] #0923 aircrack / #0925 wireless pentest / #0926 kismet: di luar
      domain radio/HW (monitor mode adapter, deauth, evil twin, WIDS) —
      cf. seksi 69; sisi PCAP = deauth_pcap_scan/pcap_triage
- [ ] #0927 YARA rule development: padanan yara_rule_lint (anatomi rule,
      filter FP, ambang) — strategi authoring (stack string, C2 URI,
      private rules) sudah diterjemahkan di lint-nya
- [ ] #0930 STIX/TAXII feeds: padanan stix_bundle_audit + seksi 188
      (validasi bundle offline); taxii2-client = jaringan/live ops

---
Blok B34 (#0991-#0995, 8 Nov) — blok PENUTUP program (antrean tuntas
995 entri). Sumber mukul975 (Apache-2.0 — konsep, bukan teks). Dua entri
diekstrak jadi tool: #0991 -> tools/ssvc_triage.py (tabel keputusan
resmi SSVC v2.0 deployer CERT/CC + map kosakata CISA Guide),
#0995 -> tools/slsa_provenance_audit.py (ikatan digest subjek + kebijakan
builder/sumber); tiga entri di bawah didistilasi. Catatan penomoran:
seksi 249-253 ternyata sudah dipakai B31 (19675ef) — seksi B34
dilanjutkan 254-256.

## 254. Triage Windows dengan KAPE — runbook koleksi, parsing sudah ada (dari mukul975/triaging-windows-with-kape) — distilasi B34
- [ ] KAPE = dua fase terpisah: TARGETS (.tkape = APA yang dikumpulkan:
      hive registry, $MFT, event log, prefetch, browser, LNK via akses
      NTFS mentah — file terkunci ikut) dan MODULES (.mkape = BAGAIMANA
      diparse via EZ Tools PECmd/MFTECmd/RECmd); compound target
      KapeTriage = set triage siap-pakai — cf. seksi 252
- [ ] urutan disiplin: sync config dulu (parser match format artefak
      terbaru) -> inventory --tlist/--mlist sebelum menentukan scope ->
      koleksi --tflush ke tujuan write-protected -> VSS (--vss) bila
      butuh state HISTORIS artefak -> kemas VHDX/ZIP + hashing utk
      chain of custody -> parse (!EZParser) -> periksa CopyLog/
      ConsoleLog/SkipLog (yang GAGAL disalin = celah bukti, dicatat)
- [ ] fleet: _kape.cli satu baris = satu run penuh (%%d dir KAPE, %%m
      nama mesin) — pola yang dipinjam: koleksi ulang-ulang harus
      IDENTIS dan bernama-host agar bisa didiff antar waktu
- [ ] padanan secai: parsing artefak statisnya sudah dimiliki —
      mft_scan ($MFT), sqlite_forensics, sysmon_triage, win_auth_triage,
      win_logon_triage, win_persist_triage, dpapi_blob_scan,
      browser_history_triage, timestomp_triage; yang di luar kelas =
      akses volume mentah live (admin, Windows-native, .NET) = ops
      koleksi DFIR, bukan alat audit offline

## 255. Integritas backup untuk recovery — padanan ada, disiplinnya yang dibawa (dari mukul975/validating-backup-integrity-for-recovery) — distilasi B34
- [ ] tiga bukti berbeda, JANGAN dicampur: (1) integritas ARSIP
      (gzip -t / restic check) — tar.gz valid bisa berisi isi rusak;
      (2) integritas ISI per-file (hash manifest sha256 baseline vs
      hasil restore); (3) KETERPULIHAN (restore test ke lingkungan
      terisolasi — satu-satunya bukti backup benar-benar bisa dipakai)
- [ ] manifest hash: sha256 BUKAN MD5 (broken); bandingkan SETELAH
      sort — diff manifest vs manifest, bukan diff direktori; file
      hilang/tambahan = temuan sejajar dgn hash mismatch
- [ ] backup bisa BERISI ransomware (infeksi pra-date backup): scan
      hasil restore SEBELUM dipercaya — ekstensi ransom, nama note,
      entropi tinggi; padanan secai: ransom_artifact_triage +
      packer_scan (entropi)
- [ ] rantai inkremental: SATU inkremental rusak memutus seluruh
      restore chain — verifikasi berantai, bukan hanya full terakhir
- [ ] konsep proses: 3-2-1 (3 salinan, 2 media, 1 offsite), immutable/
      air-gap utk anti-T1485+T1490, validasi jadwal + alert kegagalan
      (validasi senyap = tidak ada), NIST CSF RC.RP-03 — cf. seksi 28
- [ ] padanan secai: aide_change_triage (perbandingan manifest hash
      baseline vs state), log_chain_verify (rantai hash),
      ransom_artifact_triage (scan ransom), carve_scan/
      sqlite_forensics (artefak); restore test sendiri = runbook ops
      infrastruktur backup

## 256. Di luar domain — TPM measured boot attestation (dari mukul975/validating-tpm-measured-boot-attestation) — cf. seksi 42 UEFI #0272, distilasi B34
- [ ] domain hardware-firmware-security (subdomain skill sumber juga
      menyebutnya): butuh TPM 2.0 fisik (/dev/tpm0), root, tpm2-tools
      — di luar fokus web/app/infra secai, preseden seksi 42
- [ ] inti yang layak diingat utk membaca bukti boot: PCR hanya bisa
      DI-EXTEND (new = H(old || measurement)) — nilai akhir = ringkasan
      tamper-evident seluruh boot chain; peta PCR TCG: 0-7 firmware
      (7 = kebijakan Secure Boot), 8-9 bootloader/kernel, 10 IMA
- [ ] dua verifikasi berbeda: lokal = replay event log
      (binary_bios_measurements) harus mereproduksi PCR live (log
      autentik; mismatch = tampering ATAU log basi); remote attestation
      = quote AK signed + nonce fresh (anti-replay) diverifikasi
      verifier + dibandingkan golden baseline (drift PCR = T1542
      bootkit/firmware)
- [ ] penyegelan secret ke PCR policy = unseal hanya saat boot
      terpercaya — konsepnya mirip DPAPI gating (dpapi_blob_scan
      membaca artefaknya, bukan menilai boot-nya)

## 257. Kluster eksploitasi AD red-team — di luar domain AD (dari mukul975/executing-active-directory-attack-simulation, -exploiting-active-directory-certificate-services-esc1, -exploiting-active-directory-with-bloodhound, -exploiting-adcs-with-certipy, -exploiting-constrained-delegation-abuse, -exploiting-kerberoasting-with-impacket, -exploiting-nopac-cve-2021-42278-42287) — distilasi G6-delta-1 — cf. seksi 253 ESC8 (B32)
- [ ] domain red-team AD aktif (impacket/certipy/bloodhound/mimikatz);
      preseden seksi 253 (ESC8) & B17 "di luar domain AD" — secai
      fokus web/app/infra, bukan eksploitasi domain aktif
- [ ] inti ESC1 yang layak diingat utk AUDIT defensif: template AD CS
      berbahaya = msPKI-Certificate-Name-Flag mengizinkan
      ENROLLEE_SUPPLIES_SUBJECT + EKU client-auth/any-purpose +
      enrollee bukan pemilik template (ACL lemah) → siapa pun bisa
      minta sertifikat ATAS NAMA principal lain; audit-nya = baca
      flag template, bukan jalankan certipy (eksploitasi)
- [ ] kerberoasting T1558.003: minta TGS utk SPN akun servis lalu
      crack RC4 offline; sisi biru = password akun servis panjang/
      gMSA + deteksi burst TGS-request (padanan kerberos_log_triage
      B14, win_auth_triage B15)
- [ ] constrained delegation S4U2Self/S4U2Proxy: akun dengan
      msDS-AllowedToDelegateTo bisa impersonate ke layanan target;
      audit = inventaris atribut delegasi + larang unconstrained
- [ ] noPac (CVE-2021-42278 sAMAccountName spoof + CVE-2021-42287
      KDC PAC confusion) = rantai user→Domain Admin; sisi biru =
      patch KB5008102/KB5008380 + monitor machine-account-quota
- [ ] bloodhound = analisis graf path ACL (ShortestPath objektif);
      konsep graf-privilege bisa dipetakan ke audit konfigurasi,
      bukan penyerangan

## 258. Alat ofensif cloud — runbook enum & privesc (dari mukul975/enumerating-cloud-with-cloudfox, -exploiting-aws-with-pacu) — distilasi G6-delta-1
- [ ] di luar kontrak: keduanya alat eksploitasi pasca-kredensial
      (cloudfox = enum read-only Describe/List/Get + role-trust
      mapping; pacu = framework privesc + modul PERSISTENCE
      iam__backdoor_users_keys = NEVER-LIST adjacent — tidak
      dibangun dan tidak akan dibangun)
- [ ] sisi defensif yang bisa dipindai offline sudah ada: deteksi
      enumerasi = cloudtrail_scan (burst GetCallerIdentity/
      LookupEvents, denied-burst per identity), jalur privesc IAM =
      iam_escalation_scan (passrole-combo, trust-wildcard,
      policy-version-swap), postur = aws_config_audit
- [ ] inti metodologi yang dibawa: pemetaan role-trust lintas akun
      (AssumeRole graph) = permukaan lateral cloud; versi auditnya
      (siapa bisa assume siapa) kandidat ekstensi iam_escalation_scan

## 259. Serangan jaringan aktif & eksploitasi jarak jauh — di luar domain (dari mukul975/exploiting-bgp-hijacking-vulnerabilities, -exploiting-ipv6-vulnerabilities, -exploiting-ms17-010-eternalblue-vulnerability, -exploiting-smb-vulnerabilities-with-metasploit) — distilasi G6-delta-1 — cf. seksi 48/63/231, preseden RPKI B20
- [ ] BGP hijack/RPKI: origin validation ROA + monitoring route-leak
      = infrastruktur routing internet (preseden B20: RPKI di luar
      domain); inti yang dibawa: ROA max-length ketat menutup
      sub-prefix hijack
- [ ] IPv6 (SLAAC spoofing, RA flood, tunnel): mitigasi = RA Guard/
      DHCPv6-Shield di switch — konfigurasi jaringan, bukan alat
      audit secai; pcap defensif tetap domain deauth_pcap_scan
- [ ] MS17-010/EternalBlue + SMB metasploit: eksploitasi RCE aktif
      (di luar kontrak); deteksi SMBv1 = patch level + disabled
      binding — ops scanner; tidak ada gap vs playbook secai

## 260. Metodologi hunt rantai pasok T1195 (dari mukul975/hunting-for-supply-chain-compromise) — distilasi G6-delta-1 — padanan secret_history_scan/slsa_provenance_audit/dep_confusion_check/npm_script_audit/supplychain_check
- [ ] pola hunt hypothesis-driven: (1) hipotesis dari intel vendor/
      dependency terkompromi; (2) scope = build pipeline + artifact
      update channel; (3) verifikasi integritas = provenance/digest
      (slsa_provenance_audit mengikat sha256 subjek); (4) bandingkan
      baseline dependency vs rilis (dep_confusion_check,
      npm_script_audit utk vektor script lifecycle)
- [ ] yang TIDAK dibawa: query SIEM/EDR live (proses trojanized
      updater di endpoint) = ops runtime; secai memilih artefak
      offline (riwayat git, manifest, dokumen provenance)
- [ ] tanda trojanized-update utk membaca bukti: update yang jarang
      dipakai tapi baru di-patch, signer berubah antar versi,
      postinstall baru di manifest

## 261. Kepatuhan federal & ops produk keamanan (dari mukul975/executing-nist-rmf-authorization-to-operate, -evaluating-threat-intelligence-platforms, -implementing-github-advanced-security-for-code-scanning) — distilasi G6-delta-1 — cf. seksi 42/141/227/232
- [ ] NIST RMF 800-37 Rev.2 = 7 langkah ATO (Prepare → Categorize
      FIPS 199 low/moderate/high → Select baseline FIPS 200/800-53 →
      Implement → Assess 800-53A → Authorize (ATO/cATO) → Monitor
      ConMon); paket SSP/SAR/POA&M = dokumen kepatuhan federal —
      di luar fokus bounty (preseden seksi 232)
- [ ] evaluasi TIP (ThreatConnect/MISP/OpenCTI/Anomali) = procurement:
      kriteria feed-integration, STIX/TAXII support, workflow
      automation, analyst UX, TCO — keputusan organisasi, bukan alat
- [ ] GitHub Advanced Security = konfigurasi produk (code scanning,
      secret scanning, dependabot); sisi workflow-security sudah
      dipadankan gha_workflow_audit (B16); enablement = runbook

## 262. Padanan eksplisit kluster eksploitasi web & hunt endpoint (dari mukul975/exploiting-excessive-data-exposure-in-api, -exploiting-idor-vulnerabilities, -exploiting-mass-assignment-in-rest-apis, -exploiting-prototype-pollution-in-javascript, -exploiting-sql-injection-vulnerabilities, -exploiting-sql-injection-with-sqlmap, -hunting-for-living-off-the-land-binaries, -hunting-for-lolbins-execution-in-endpoint-logs, -hunting-for-ntlm-relay-attacks, -hunting-for-process-injection-techniques, -hunting-for-registry-run-key-persistence, -hunting-for-spearphishing-indicators) — distilasi G6-delta-1
- [ ] excessive data exposure (API3:2023) → api_property_scan (B14,
      BOPLA statis) + owasp_risk_rating; langkah manual skill sumber
      (bandingkan respons API vs field yang dirender UI) tetap
      metodologi manual utk verifier
- [ ] IDOR → playbook idor (14 rujukan di exploit_playbooks.py);
      mass assignment → playbook mass-assignment + arjun-style
      param discovery = metodologi manual
- [ ] prototype pollution → playbook proto-pollution tier-1 (unsafe
      merge __proto__ + gadget); SQLi (manual & sqlmap) → playbook
      sqli + waf_sqli_triage (B16) + seksi 250 (bypass WAF);
      sqlmap = alat eksternal non-stdlib
- [ ] LOLBins (2 skill, T1218) → lolbin_scan (B15: EID 1/11 Sysmon
      XML offline); EID 8/10/25 sengaja ranah sysmon_triage (B16:
      cross-process-write, granted_access, lsass-access)
- [ ] NTLM relay hunt (T1557.001, EID 4624 logon type 3) →
      win_auth_triage (23 rujukan NTLM/4624) + zeek_lateral_scan;
      registry run key (T1547.001, EID 13) → win_persist_triage
      (check run-key-write, +Policies\Explorer\Run)
- [ ] spearphishing hunt (T1566) → eml_phish_triage (artefak .eml
      offline); hunt lintas SIEM live = ops
- [ ] catatan BUILD satu-satunya blok ini: broken link hijacking
      (#1010) → tools/broken_link_scan.py — ceruk mulai-dari-isi-
      halaman (bukan mulai-dari-hostname spt takeover-cname-hygiene),
      liveness dari resolusi operator, nol jaringan

