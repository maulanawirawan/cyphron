# GAP-MATRIX — Pemetaan Kapabilitas vs Referensi Komunitas 2026

> **[DIKONSOLIDASIKAN 21-09-2026] Status terkini seluruh item ada di [STATUS-MASTER.md](STATUS-MASTER.md) — dokumen ini jadi arsip rincian.**

> Hasil studi B7: 818 skill keamanan komunitas (46 subdomain) dicocokkan
> dengan registry Cyphron (74 skill `.cyphron` + ~145 engine terdaftar).
> Status per subdomain: **ADA** (skill + engine/motor nyata), **PARSIAL**
> (skill metodologi ada, workflow/engine spesifik belum), **GAP** (belum
> ada sama sekali).
>
> Metode: pemahaman konsep → tulis ulang total dalam format `.kimchi`
> Cyphron (Bahasa Indonesia). Tidak ada salinan teks/kode dari referensi.

## 1. Matriks (46 subdomain)

| # | Subdomain | Skill ref. | Status | Bukti di Cyphron | Keputusan |
|---|---|---|---|---|---|
| 1 | cloud-security | 66 | PARSIAL | skill 17 + `cloud_bucket_probe` | port skill 79 (audit IAM read-only) |
| 2 | threat-hunting | 58 | GAP | — (skill 09/45 hanya deteksi/SIEM) | port skill 77 |
| 3 | threat-intelligence | 52 | ADA | skill 44 + skill 83 (pivot graf) | selesai (B10) |
| 4 | network-security | 43 | ADA | skill 21 + skill 87 (analisis traffic) | selesai (B11) |
| 5 | web-application-security | 42 | ADA | puluhan engine tools/ | — |
| 6 | digital-forensics | 41 | PARSIAL | skill 14 generik | port skill 75, 76 |
| 7 | malware-analysis | 39 | ADA | skill 40, 74 + `deobf` + apk_kit | — |
| 8 | identity-access-management | 40 | PARSIAL | skill 36 metodologi | port skill 79 (bagian IAM) |
| 9 | soc-operations | 35 | PARSIAL | skill 45, 58 | parkir |
| 10 | red-teaming | 35 | ADA | skill 51 + redteam + redteam_lab | — |
| 11 | container-security | 33 | PARSIAL | skill 18 + `iac.py` (Dockerfile/compose/k8s) | cukup |
| 12 | security-operations | 28 | PARSIAL | skill 45, 58 | parkir |
| 13 | ot-ics-security | 29 | ADA | skill 85 (pasif-first, staging-only) | selesai (B10) |
| 14 | api-security | 28 | ADA | skill 16 + api_* engines | — |
| 15 | incident-response | 26 | ADA | skill 10 + skill 14 | — |
| 16 | vulnerability-management | 25 | ADA | skill 34 + kb NVD/EDB | — |
| 17 | penetration-testing | 21 | ADA | inti Cyphron | — |
| 18 | devsecops | 18 | ADA | skill 42 + sast/iac/sbom + CI-* | — |
| 19 | zero-trust-architecture | 18 | ADA | skill 49 | — |
| 20 | endpoint-security | 17 | PARSIAL | skill 36 + `privesc_scan` (read-only) | parkir |
| 21 | cryptography | 16 | ADA | skill 05 + crypto_web_engines | — |
| 22 | phishing-defense | 15 | PARSIAL | skill 46 + phishing_kit_extract | port skill 78 + engine `email_intel` |
| 23 | ai-security | 14 | PARSIAL | skill 65 | parkir |
| 24 | mobile-security | 13 | ADA | skill 23 + apk_kit | — |
| 25 | ransomware-defense | 13 | ADA | skill 40 + skill 84 (playbook) | selesai (B10) |
| 26 | compliance-governance | 11 | ADA | skill 32, 33 | — |
| 27 | supply-chain-security | 8 | ADA | skill 19 + SBOM | — |
| 28 | threat-detection | 7 | ADA | skill 09 | — |
| 29 | deception-technology | 6 | ADA | skill 86 (canary & umpan) | selesai (B11) |
| 30 | hardware-firmware-security | 6 | GAP | — | parkir |
| 31 | application-security | 4 | ADA | inti | — |
| 32 | blockchain-security | 2 | ADA | skill 25 + wallet_fp_guard | — |
| 33 | wireless-security | 2 | GAP | — | parkir |
| 34 | offensive-security | 2 | ADA | inti | — |
| 35 | privacy-compliance | 2 | ADA | skill 29 | — |
| 36 | social-engineering-defense | 1 | ADA | skill 47 | — |
| 37 | data-protection | 1 | ADA | skill 28 | — |
| 38 | purple-team | 1 | PARSIAL | redteam detection_coverage | parkir |

Rekap: **ADA 26 · PARSIAL 9 · GAP 3** dari 38 subdomain unik setelah
normalisasi duplikat nama (identity-* dan red-team-* digabung).

## 2. Gap prioritas yang di-port (batch ini)

Dipilih karena (a) nilai jual konsultan terbesar, (b) sinergi langsung
dengan engine/fitur yang sudah ada, (c) bisa dilayani tanpa melanggar
garis etis (semua pasif/read-only):

1. **Forensik memori** (skill 75) — workflow akuisisi → analisis proses →
   injeksi → jaringan → bukti pencurian kredensial; pelengkap skill 74
   (statis) dengan sisi volatile.
2. **Analisis event log** (skill 76) — triage log Windows/Linux: ID event
   yang penting, timeline, korelasi; jalur ke threat hunting.
3. **Threat hunting hipotesis** (skill 77) — kerangka hipotesis → sumber
   data → kueri → analisis → dokumentasi; menutup GAP #2.
4. **Deteksi phishing/BEC** (skill 78) — triage header email (Received,
   Return-Path, Message-ID, hasil SPF/DKIM/DMARC), spoofing display-name,
   domain lookalike; ditopang **engine `email_intel`** (stdlib `email`,
   tanpa jaringan, semua hasil = LEAD).
5. **Audit cloud/IAM read-only** (skill 79) — checklist misconfig IAM:
   aksi wildcard, MFA absen, usia kunci, bucket publik, jalur eskalasi.
6. **Rekomendasi pertahanan terpetakan** (skill 80) — dari temuan →
   kontrol defensif terprioritaskan (informed oleh kerangka D3FEND),
   melengkapi remediate.py yang berhenti di "perbaiki celahnya".
7. **Playbook penanganan fraud** (skill 81) — per vektor (rekkening,
   phishing, social engineering, app fraud); informed kerangka MITRE F3;
   sinergi dengan `fraudintel.py` + jalur pengaduan resmi.

## 3. Yang sengaja TIDAK di-port

- Flood/volumetrik/connection-exhaustion: garis tetap Cyphron (uji beban =
  `resilience` bounded).
- Resolusi identitas orang dari nomor/rekening: tidak ada jalur legal;
  tetap di jalur registry resmi + dossier pengaduan (skill 81 + fraudintel).
- Deception/wireless/OT-ICS/firmware: gap diakui jujur, parkir sampai ada
  permintaan nyata (zero-FP doctrine: tidak menambah katalog yang tak
  bisa dibuktikan di uji).
