"""tierpack3 - HARVEST 3 repo GitHub raksasa (anthropic-skills 32.2k,
CyberStrike 2.6k, CAI 9.8k, Security-101): domain BARU di luar pack lama."""

from __future__ import annotations

from pathlib import Path

from .tierpack import CVSS

TIERS = {
    "low": [
        ("sbom-coverage-audit", "Cakupan SBOM per artefak diukur", "laporan cakupan persen", "road:sbom_cov"),
        ("sec101-fundamentals", "Baseline 8 pilar Security-101 diuji ke sistem sendiri", "checklist lulus", "road:sec101"),
        ("cert-transparency-watch", "Pemantauan CT log berkala", "alert subdomain tak dikenal", "road:ct_watch"),
        ("asset-inventory-diff", "Inventaris aset vs temuan scan", "hit = aset tak terpetakan", "road:asset_diff"),
        ("backup-restore-drill", "Latihan restore backup terjadwal", "hit = restore sukses terukur", "road:backup_drill"),
    ],
    "medium": [
        ("finding-dedup-retest", "Retester: temuan lama diuji ulang, dedup lintas run", "hit = duplikat terdeteksi", "road:retester"),
        ("oauth-pkce-missing", "PKCE tidak dipakai pada public client", "hit = login tanpa PKCE sukses", "road:pkce"),
        ("session-replay-window", "Jendela replay token sesi diukur", "hit = replay valid melewati ambang", "road:replay_win"),
        ("password-policy-audit", "Kebijakan password lemah", "hit = password pendek diterima", "auth_probe"),
        ("rate-limit-per-key", "Rate limit per API key diuji", "hit = tanpa 429 sampai N", "road:rl_key"),
        ("jwt-audience-check", "aud/iss tidak divalidasi lintas service", "hit = token lintas aud diterima", "road:jwt_aud"),
        ("webhook-replay-across-env", "Callback staging diputar ke produksi", "hit = produksi memproses", "road:wh_env"),
        ("backup-exposure-cloud", "Snapshot backup cloud publik", "hit = snapshot anonim terbaca", "road:bak_cloud"),
        ("api-surface-drift", "Endpoint live tidak ada di spec", "hit = endpoint tanpa docs", "road:drift"),
        ("http-desc-leak", "Deskripsi endpoint bocorkan perilaku internal", "hit = teks sensitif", "crawler"),
        ("cookie-domain-wide", "Cookie di-set domain terlalu luas", "definitif: atribut Domain", "security_headers"),
        ("security-quiz-gap", "Gap security questionnaire dipetakan", "checklist gap", "road:quiz"),
    ],
    "high": [
        ("mqtt-unauth-subscribe", "MQTT topic langganan tanpa auth (kasus CAI)", "hit = pesan topic terbaca", "road:mqtt"),
        ("ros-msg-injection", "Injeksi pesan ROS robotik (lab authorized)", "hit = canary diterima robot", "road:ros_inj"),
        ("apt-ttp-replay-lite", "Replay TTP APT versi aman canary", "hit = deteksi/lolos terukur", "road:apt_lite"),
        ("prompt-injection-defense", "Uji 4 lapis prompt-injection defense agen AI", "hit = injeksi lolos lapis", "road:pinj_def"),
        ("fleet-agent-audit", "Audit agen AI security lain yang ter-expose", "hit = panel agen terbaca", "road:agent_audit"),
        ("kerberoast-audit", "SPN kerberoastable di AD (lab)", "hit = hash TGS diperoleh", "road:kerberoast"),
        ("pivot-path-audit", "Jalur pivot internal terpetakan", "hit = rute lintas segmen", "road:pivot"),
        ("grpc-web-exposed", "gRPC-Web endpoint publik", "hit = reflection via web", "road:grpc_web"),
        ("imds-v2-bypass-audit", "IMDSv2 dipaksa turun ke v1", "hit = token v1 terbaca", "road:imds2b"),
        ("ci-cache-poisoning", "Poisoning cache CI memicu build beracun", "hit = build pakai cache canary", "road:ci_cache"),
        ("dependency-confusion", "Nama paket internal diambil alih di registry publik", "hit = registry menerima nama internal", "road:depconf"),
        ("email-thread-hijack", "Thread hijack pada template email", "hit = In-Reply-to dipalsukan", "road:thread_hij"),
    ],
    "critical": [
        ("race-upload-webshell", "Race upload -> webshell (pola CAI, lab)", "hit = canary dieksekusi via paralel", "road:race_up"),
        ("mqtt-command-injection", "Injeksi perintah via pesan MQTT (kasus Grafana CAI)", "hit = perangkat bereaksi canary", "road:mqtt_cmd"),
        ("apt-full-emulation", "Emulasi TTP 5 kelompok APT (lab, izin tertulis)", "hit = gap deteksi terukur", "road:apt_full"),
        ("ctf-coverage-matrix", "Matriks kategori CTF jeopardy teruji", "matriks kategori", "road:ctf_cov"),
        ("robot-vuln-sweep", "Sweep kerentanan robotik/IoT (authorized)", "hit = kelas kerentanan ditemukan", "road:robot"),
        ("agent-tool-pinj", "Prompt injection ke tool AI security itu sendiri", "hit = agen jalan perintah canary", "road:agent_pinj"),
        ("benchmark-cybench-mode", "Mode benchmark Cybench untuk agent", "skor per run terekam", "road:bench"),
        ("cve-workflow-disclosure", "Workflow pengajuan CVE (90 hari, CISA ICS)", "CVE ID terbit", "road:cve_wf"),
        ("game-theory-ctr", "G-CTR: reasoning Nash untuk alokasi defense", "strategi terdokumentasi", "road:gctr"),
        ("multi-scaffold-blackboard", "Orkestrasi blackboard multi-scaffold (Cybench)", "skor di atas single harness", "road:blackboard"),
        ("zero-day-hunt-fuzz", "Zero-day hunting: differential fuzzing di sistem sendiri", "hit = crash/anomali direproduksi", "live:fuzz_engine"),
    ],
}


def build3(kimchi_dir: Path) -> dict:
    from .tierpack import _render
    out_root = kimchi_dir / "skills-tiers3"
    stats, live, total = {}, 0, 0
    index = ["# Cyphron Tier Pack 3 - HARVEST 3 repo GitHub raksasa", "",
             "Sumber: Anthropic-Cybersecurity-Skills (32.2k) + CyberStrike (2.6k) +",
             "CAI (9.8k) + Microsoft Security-101. Domain BARU di luar pack lama.",
             "FP-guard wajib per skill.", ""]
    for tier, rows in TIERS.items():
        tdir = out_root / tier
        tdir.mkdir(parents=True, exist_ok=True)
        for i, (name, technique, guard, engine) in enumerate(rows, start=1):
            (tdir / f"{tier}-{i:02d}-{name}.md").write_text(
                _render(tier, i, name, technique, guard, engine), encoding="utf-8")
            total += 1
            if engine.startswith("live"):
                live += 1
        stats[tier] = len(rows)
        index.append(f"## {tier.upper()} - {len(rows)} skills (CVSS {CVSS[tier]})")
        for i, (name, _t, _g, engine) in enumerate(rows, start=1):
            tag = "LIVE" if engine.startswith("live") else "ROADMAP"
            index.append(f"- {tier}-{i:02d} [{tag}] {name}")
        index.append("")
    (out_root / "INDEX.md").write_text(chr(10).join(index), encoding="utf-8")
    return {"root": str(out_root), "stats": stats, "total": total, "live": live}
