"""skillgen — generator skill dedup + progressive-disclosure.

Format: FRONTMATTER ringkas (untuk indeks/scanning) + BODY berat lengkap
(metodologi penuh) — dua-duanya bisa, di satu file.
Sebelum menulis: DEDUP terhadap seluruh skill Cyphron (74 core + tier packs)
berdasarkan nama + kata kunci teknik. Yang mirip -> ditolak dengan alasan."""

from __future__ import annotations

import re
from pathlib import Path

WORD = re.compile(r"[a-z0-9]+")

# Kurasi skill BARU (belum ada di pack 74+220 Cyphron)
NEW_SKILLS = [
    ("memory-forensics-volatility", "forensics", "Analisis memori (RAM dump) untuk mencari proses tersembunyi, injeksi kode, dan kredensial di memori", "Dump RAM (winpmem/AVML) -> profil OS -> proses anomali -> string yara -> laporan"),
    ("credential-dumping-defense", "endpoint", "Deteksi & mitigasi dumping LSASS/SAM (mimikatz-class)", "Audit event 4656/4624 + perlindungan LSASS PPL + deteksi akses membaca lsass"),
    ("bec-detection", "phishing", "Deteksi Business Email Compromise: domain mirip, display-name spoof, thread hijack", "Bandingkan domain pengirim vs daftar resmi (levenshtein) + cek SPF/DKIM/DMARC + pola thread"),
    ("malware-network-traffic-analysis", "forensics", "Analisis trafik jaringan malwar: beaconing, DNS aneh, eksfiltrasi", "PCAP -> jadwal beacon (interval reguler) -> reputasi domain -> volume keluar tak wajar"),
    ("ot-ics-hardening", "ot", "Pengerasan jaringan OT/ICS (Purdue model, unidirectional gateway)", "Petakan zona Purdue -> konduits -> blok IT->OT langsung -> monitoring pasif"),
    ("ad-attack-path-audit", "iam", "Audit jalur serangan Active Directory (Kerberoast, DCSync, delegation)", "BloodHound-style graph: jalur user->admin, kerberoastable SPN, ACL berbahaya"),
    ("k8s-escape-audit", "container", "Audit jalur keluar container: privileged, hostMount, capabilities", "Review spec: privileged/hostPID/hostPath/cap-add; blok kombinasi berbahaya"),
    ("cicd-pipeline-audit", "cicd", "Audit pipeline CI/CD: secret exposure, injeksi pada PR, runner abuse", "Review workflow: pull_request_target, secret di log, runner self-hosted ekspos"),
    ("ransomware-readiness", "ir", "Kesiapan ransomware: backup imutabel, deteksi massal-encrypt, playbook", "Uji restore -> deteksi renam massal/entropi -> playbook isolasi"),
    ("mobile-hardening-review", "mobile", "Review keamanan aplikasi mobile: storage, certificate pinning, IPC", "Decompile statis -> data di storage -> pinning -> exported component"),
    ("windows-event-hunting", "soc", "Berburu di Windows Event Log: logon anomaly, proses berbahaya", "4624/4625/4688/7045 -> korelasikan anomali waktu & host"),
    ("linux-forensics-triage", "forensics", "Triage Linux: auth.log, cron, SUID, persistence mechanism", "auth.log -> crontab -> SUID -> systemd unit -> modul kernel"),
    ("phishing-simulation-defense", "phishing", "Rancang simulasi phishing UNTUK PELATIHAN internal (authorized)", "Domain simulasi terdaftar jelas -> email training -> ukur klik -> edukasi"),
    ("cloud-trail-anomaly", "cloud", "Deteksi anomali CloudTrail/Azure Activity: akses aneh, privilege berubah", "Event -> baseline -> alerts pada iam:PassRole, key expose, unusual region"),
    ("wireless-rogue-detect", "wireless", "Deteksi rogue AP / evil twin di lingkungan kantor (authorized survey)", "Scan beacon -> bandingkan BSSID whitelist -> alert SSID mirip"),
    ("data-protection-audit", "governance", "Audit klasifikasi & perlindungan data PII per sistem", "Inventaris data -> klasifikasi -> kontrol (enkripsi/akses/retensi) -> gap"),
    ("blockchain-contract-review", "blockchain", "Review smart contract: reentrancy, overflow, access control", "Static review -> pola reentrancy/tx.origin/overflow -> rekomendasi"),
    ("deception-canary-deploy", "deception", "Pasang canary (dummy service/token) untuk deteksi dini intrusi", "Canary token/service -> alert saat disentuh -> dokumentasi penempatan"),
    ("purple-team-replay", "purple", "Replay teknik ATT&CK dan ukur deteksi tiap teknik", "Pilih teknik ATT&CK -> jalur aman -> ukur apakah SIEM memicu -> gap"),
    ("threat-intel-feed-fusion", "intel", "Fusi feed threat intel: dedup, skor, mapping ke aset", "Feed -> normalisasi STIX -> dedup -> skor relevansi -> blokir/deteksi"),
    ("api-inventory-discovery", "api", "Inventaris API: REST/GraphQL/gRPC terdokumentasi vs nyata", "Spec vs traffic vs code -> gap endpoint tak terdokumentasi"),
    ("vuln-management-sla", "vulnmgmt", "Bangun SLA remediasi berbasis risiko + kebijakan pengecualian", "Skor risiko kontekstual -> SLA per band -> pengecualian berkedaluwarsa"),
    ("mitre-atlas-ai-audit", "ai", "Audit risiko AI (ATLAS): prompt injection, data poisoning, model theft", "Petakan permukaan AI -> uji injection/guardrail -> mitigasi"),
    ("supply-chain-sbom-diff", "supplychain", "SBOM diff antar rilis: paket baru mencurigakan", "SBOM lama vs baru -> paket baru -> reputasi -> alert"),
    ("zero-day-fuzz-hunt", "offensive", "Zero-day hunting di sistem sendiri: differential fuzzing input", "Fuzz input -> bandingkan respons/crash -> reproduksi -> laporan internal"),
]

FRONT_KEYS = ["domain", "severity_hint"]


def _dedup_check(name: str, technique: str, existing_dir: Path) -> tuple[bool, str]:
    """TRUE (lolos) jika tidak ada skill existing dengan overlap kata kunci dominan."""
    kws = set(WORD.findall(name.lower()))
    for md in existing_dir.glob("*.md"):
        title = md.stem.lower()
        t_words = set(WORD.findall(title))
        overlap = kws & t_words
        if len(overlap) >= 2:
            return False, f"mirip dengan {md.name} (kata sama: {sorted(overlap)})"
    body_sample = ""
    first = existing_dir / "01-secure-code-review.md"
    if first.exists():
        body_sample = first.read_text(encoding="utf-8")[:400].lower()
        for kw in list(kws)[:4]:
            if len(kw) > 5 and kw in body_sample:
                return False, f"kata teknik {kw!r} sudah di 01-secure-code-review"
    return True, "unique"


def build(kimchi_dir: Path) -> dict:
    src_dir = kimchi_dir / "skills"
    out_dir = kimchi_dir / "skills-gen"
    out_dir.mkdir(parents=True, exist_ok=True)
    written, skipped = [], []
    for name, domain, technique, workflow in NEW_SKILLS:
        ok, reason = _dedup_check(name, technique, src_dir)
        if not ok:
            skipped.append(f"{name}: {reason}")
            continue
        body = "\n".join([
            "---",
            f"name: {name}",
            f"domain: {domain}",
            "version: 1.0",
            "format: progressive-disclosure",
            "---",
            "",
            f"# Skill GEN — {name.replace('-', ' ').title()}",
            "",
            f"> Domain: **{domain}**. Ditambahkan lewat generator dedup (bukan duplikat",
            f"> skill inti — lolos cek kata kunci terhadap 74 skill + tier packs).",
            "",
            "## WHEN TO USE",
            technique,
            "",
            "## WORKFLOW (ringkas — load detail on-demand)",
            workflow,
            "",
            "## VERIFICATION",
            "- Hasil analisis wajib punya bukti (file/log/dns/response) yang bisa direplay.",
            "- Temuan tanpa bukti = unconfirmed (aturan yang sama dengan engine).",
            "",
            "## ETHICS",
            "- Defender-side only. Teknik dipakai pada sistem milik sendiri / berotorisasi.",
        ])
        (out_dir / f"GEN-{name}.md").write_text(body, encoding="utf-8")
        written.append(name)
    return {"root": str(out_dir), "written": written, "skipped": skipped}
