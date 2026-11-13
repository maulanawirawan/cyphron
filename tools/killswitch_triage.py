r"""[AUDIT: read-only] killswitch_triage — triase OFFLINE telemetri
terkumpul vs database indikator kill-switch ransomware
(mutex/named-pipe, domain kill-switch), plus render manifest "vaksinasi"
mutex & kandidat sinkhole.

Premis sumber yang diekstrak: sebagian keluarga ransomware MEMERIKSA
kondisi luar sebelum mengenkripsi (kill switch) — mutex bernama sudah
ada, domain tertentu TERRESOLV (WannaCry-style), key/berkas penanda
ada. Sisi deteksi: kemunculan indikator itu di telemetri terkumpul
adalah lead kuat "ransomware X sedang/bubar mencoba jalan"; sisi
defensi: pre-create mutex (vaksinasi) dan register/sinkhole domain
mengaktifkan kill switch-nya. Keduanya deterministik dan OFFLINE
(bukan alat detonasi malware — sandbox dinamis tetap di luar kelas).

Ranah dibagi eksplisit:
  - dns_log_triage   : DGA/entropi/beacon/volume DNS (analisis pola);
    tool ini HANYA pencocokan DOMAIN EXACT dari DB (zero-FP) — pola
    generik tetap ranah dns_log_triage.
  - sysmon_triage    : triase EID proses/akses umum; tool ini fokus
    EID 17/18 (PipeCreated/Connected) + cmdline/scriptblock utk
    indikator mutex/pipe bernama dari DB.
  - packer_scan/win_persist_triage: sisi biner/persistensi, bukan
    kill-switch.

Input -> mekanisme -> output:
  - Input : --events FILE  — ekspor Windows Event XML (Sysmon/
            PowerShell; satu file boleh banyak blok <Event>). Field
            yang dibaca: EventID 17/18 -> PipeName; EventID 1 ->
            CommandLine; EventID 4104 -> ScriptBlockText.
            --dns FILE    — log kueri DNS teks (baris bebas; token
            domain diekstrak dari tiap baris, qname=xxx juga didukung).
            --db FILE     — DB indikator tambahan (JSON), APPEND ke
            benih bawaan; dedup (family,type,value).
  - Mekanisme: pencocokan EXACT/substring-eksotik — nama mutex/pipe
    dicocokkan exact (normalisasi prefix \??\ dan case-insensitive)
    pada PipeName, dan substring pada CommandLine/ScriptBlockText
    (string DB eksotis; FP praktis nol); domain kill-switch dicocokkan
    EXACT case-insensitive (tanpa trailing dot) pada token DNS.
            Indikator bertipe registry/file dihitung sebagai
    "tanpa-kanal" (dilaporkan, TIDAK pernah dianggap bersih).
  - Output: findings.json (kontrak secai) + vaccination_manifest
    (mutex utk di-pre-create per keluarga) + sinkhole_candidates
    (domain); meta menghitung event/baris ter-parse, indikator
    tanpa-kanal, DB bawaan vs tambahan.

Verdict: kecocokan = bukti string ADA di artefak terkumpul ->
status confirmed, verdict L2 REPRODUCED (bukti baris/event; klaim
"serangan aktif" butuh konteks, bukan L3). Nilai tak pernah dicetak
penuh bila terlihat seperti kredensial (semua indikator DB publik).

Fail-closed: file tidak ada / XML & log tak ter-parse sama sekali ->
exit 2; blok event rusak dihitun di meta, tidak dibuang diam-diam;
tanpa --events dan --dns -> exit 2 (tidak ada telemetri = tidak ada
kesimpulan).

Pemakaian:
  python tools/killswitch_triage.py --events sysmon.xml --out f.json
  python tools/killswitch_triage.py --dns queries.log --db ext.json
Exit: 0 bersih (dengan catatan), 1 ada kecocokan, 2 error input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.killswitch-triage/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

# Benih bawaan — konstanta IOC publik (atribusi konsep #0691, skill
# sumber Apache-2.0; string mutex/domain = fakta teknis publik yang
# dikutip skill + malware-mutex albertzsigovits). MINIMAL, bukan
# komprehensif.
SEED_DB = {
    "families": [
        {"family": "WannaCry", "indicators": [
            {"type": "mutex", "value": "Global\\MsWinZonesCacheCounterMutexA"},
            {"type": "mutex", "value": "Global\\MsWinZonesCacheCounterMutexB"},
            {"type": "domain",
             "value": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"},
            {"type": "domain",
             "value": "fferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"},
        ]},
        {"family": "Conti", "indicators": [
            {"type": "mutex", "value": "Global\\kasKDJSAFJauisiudUASIIQWUA82"},
        ]},
        {"family": "Ryuk", "indicators": [
            {"type": "mutex", "value": "Global\\YOURPRODUCT_MUTEX"},
        ]},
        {"family": "Maze", "indicators": [
            {"type": "mutex", "value": "Global\\JhbGjhBsSQjz"},
        ]},
    ]
}

IND_TYPES = ("mutex", "pipe", "domain", "registry", "file")
CHANNEL_TYPES = ("mutex", "pipe", "domain")

RE_DOMAIN_TOKEN = re.compile(
    r"(?=.{4,253}\b)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]"
    r"(?:[a-z0-9-]*[a-z0-9])?)+\b",
    re.I,
)
RE_QNAME = re.compile(r"qname=([a-z0-9.\-]+)", re.I)

RE_EVENT_BLOCK = re.compile(r"<Event\b.*?</Event>", re.S | re.I)
RE_XML_UNESCAPE = re.compile(r"&(lt|gt|quot|apos);")


def _xml_unescape(text: str) -> str:
    """Unescape entitas XML dasar (amp terakhir, urutan aman)."""
    table = {"lt": "<", "gt": ">", "quot": '"', "apos": "'"}
    out = RE_XML_UNESCAPE.sub(lambda m: table[m.group(1)], text)
    return out.replace("&amp;", "&")


def _data_field(xml: str, name: str) -> str:
    """Ambil nilai <Data Name="name">...</Data> (konvensi Windows Event
    XML); self-closing = string kosong."""
    m = re.search(
        r"<Data\s+Name=[\"']" + re.escape(name) + r"[\"']\s*/?>"
        r"(?:(.*?)</Data>)?", xml, re.S | re.I)
    if not m:
        return ""
    return _xml_unescape(m.group(1) or "").strip()


def _tag_text(xml: str, tag: str) -> str:
    """Ambil teks <Tag> pertama (tanpa dependensi xml.etree agar blok
    event semi-rusak tetap bisa dipindai per-regex)."""
    pat = re.compile(
        r"<" + tag + r"(?:\s[^>]*)?>(.*?)</" + tag + r">", re.S | re.I)
    m = pat.search(xml)
    if not m:
        return ""
    return _xml_unescape(m.group(1)).strip()


def _norm_obj_name(value: str) -> str:
    """Normalisasi nama objek kernel: buang prefix device-path Windows."""
    v = value.strip().strip('"')
    for pref in ("\\??\\", "\\\\.\\", "\\Device\\"):
        if v.lower().startswith(pref.lower()):
            v = v[len(pref):]
    return v.lower()


def load_db(extra_path: str | None) -> tuple[list[dict], dict]:
    """Gabungkan benih + DB ekstra; keluarga sama = menimpa (replace).
    Return (entries, meta). Entry: {family, type, value}."""
    families: dict[str, list[dict]] = {}
    meta = {"seed_families": 0, "extra_families": 0,
            "extra_invalid": 0, "dup_dropped": 0}
    for fam in SEED_DB["families"]:
        families[fam["family"]] = list(fam["indicators"])
        meta["seed_families"] += 1
    if extra_path:
        raw = Path(extra_path).read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise SystemExit(2)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise SystemExit(2)
        if not isinstance(data, dict) or not isinstance(
                data.get("families"), list):
            raise SystemExit(2)
        for fam in data["families"]:
            if (not isinstance(fam, dict) or not fam.get("family")
                    or not isinstance(fam.get("indicators"), list)):
                meta["extra_invalid"] += 1
                continue
            families[fam["family"]] = [
                ind for ind in fam["indicators"]
                if isinstance(ind, dict) and ind.get("type") in IND_TYPES
                and isinstance(ind.get("value"), str) and ind["value"]
            ]
            meta["extra_families"] += 1
    entries: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for family, inds in families.items():
        for ind in inds:
            # dedup per (type, value) lintas famili — nilai sama dua kali
            # = dua temuan noise untuk satu kejadian; famili pertama
            # (benih) menang
            key = (ind["type"], ind["value"].lower())
            if key in seen:
                meta["dup_dropped"] += 1
                continue
            seen.add(key)
            entries.append({
                "family": family,
                "type": ind["type"],
                "value": ind["value"],
            })
    return entries, meta


def parse_dns_file(path: str) -> tuple[list[str], dict]:
    """Ekstrak token domain dari baris log DNS bebas (deterministik)."""
    raw = Path(path).read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise SystemExit(2)
    text = raw.decode("utf-8", "replace")
    domains: list[str] = []
    meta = {"lines": 0, "binary": False}
    if "\x00" in text[:8192]:
        meta["binary"] = True
        return [], meta
    for line in text.splitlines():
        meta["lines"] += 1
        if not line.strip():
            continue
        hit = ""
        m = RE_QNAME.search(line)
        if m:
            hit = m.group(1)
        else:
            for tok in RE_DOMAIN_TOKEN.findall(line):
                # token domain terpanjang di baris = kandidat qname
                if len(tok) > len(hit):
                    hit = tok
        if hit:
            hit = hit.strip(".").lower()
            if "." in hit:
                domains.append(hit)
    return domains, meta


def parse_events_file(path: str) -> tuple[list[dict], dict]:
    """Parse blok <Event> XML Windows; kembalikan observasi per event."""
    raw = Path(path).read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise SystemExit(2)
    text = raw.decode("utf-8", "replace")
    events: list[dict] = []
    meta = {"blocks": 0, "events_parsed": 0, "unparsed": 0,
            "binary": False}
    if "\x00" in text[:8192]:
        meta["binary"] = True
        return [], meta
    for block in RE_EVENT_BLOCK.finditer(text):
        meta["blocks"] += 1
        xml = block.group(0)
        eid_raw = _tag_text(xml, "EventID")
        try:
            eid = int(eid_raw)
        except ValueError:
            meta["unparsed"] += 1
            continue
        ev: dict = {"eid": eid, "idx": meta["blocks"] - 1}
        if eid in (17, 18):
            ev["pipe_name"] = _data_field(xml, "PipeName")
        elif eid in (1, 4688):
            ev["command_line"] = _data_field(xml, "CommandLine") or \
                _data_field(xml, "NewProcessName")
        elif eid == 4104:
            ev["script_block"] = _data_field(xml, "ScriptBlockText")
        else:
            continue
        meta["events_parsed"] += 1
        events.append(ev)
    if meta["blocks"] == 0:
        # bukan ekspor XML Windows sama sekali -> input error (fail-closed)
        raise SystemExit(2)
    return events, meta


def match(events: list[dict], domains: list[str],
          entries: list[dict]) -> tuple[list[dict], dict]:
    """Cocokkan DB vs telemetri. Return (matches, notes_meta)."""
    matches: list[dict] = []
    no_channel = []
    domain_set = set(domains)
    for ent in entries:
        typ, val = ent["type"], ent["value"]
        if typ not in CHANNEL_TYPES:
            no_channel.append(ent)
            continue
        if typ == "domain":
            want = val.strip(".").lower()
            if want in domain_set:
                matches.append({"channel": "dns", "type": typ,
                                "family": ent["family"], "value": val,
                                "mode": "exact"})
            continue
        # mutex/pipe: PipeName exact; cmdline/scriptblock substring
        want = _norm_obj_name(val)
        for ev in events:
            if ev.get("pipe_name"):
                if _norm_obj_name(ev["pipe_name"]) == want:
                    matches.append({"channel": "event", "type": typ,
                                    "family": ent["family"], "value": val,
                                    "mode": "pipe-exact",
                                    "event_idx": ev["idx"],
                                    "eid": ev["eid"]})
            hay = ev.get("command_line") or ev.get("script_block") or ""
            if hay and want in _norm_obj_name(hay):
                matches.append({"channel": "event", "type": typ,
                                "family": ent["family"], "value": val,
                                "mode": "cmd-substring",
                                "event_idx": ev["idx"],
                                "eid": ev["eid"]})
    return matches, {"indicators_without_channel": len(no_channel),
                     "no_channel_types": sorted({e["type"] for e in no_channel})}


def build_output(matches: list[dict], entries: list[dict],
                 dns_meta: dict, ev_meta: dict, db_meta: dict,
                 db_extra: str | None) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    for m in matches:
        where = (f"domain exact-match di log DNS"
                 if m["channel"] == "dns"
                 else f"EID {m.get('eid')} event#{m.get('event_idx')} "
                      f"mode {m['mode']}")
        findings.append(make_finding(
            tool="killswitch_triage",
            title=f"kill-switch {m['type']} keluarga {m['family']}",
            severity="high",
            description=(
                f"Indikator kill-switch ransomware {m['family']} "
                f"({m['type']}: {m['value']}) ditemukan di telemetri "
                f"({where}). Kecocokan exact/eksotik vs DB — lead kuat "
                f"'keluarga ini berjalan/mencoba'; verifikasi konteks "
                f"(proses, host, waktu) sebelum respons."),
            recommendation=(
                "Konfirmasi host/proses sumber; bila benar: isolasi "
                "sebelum enkripsi massal. Sisi defensi: mutex tipe ini "
                "bisa di-pre-create (vaksinasi), domain tipe ini bisa "
                "disinkhole — lihat vaccination_manifest."),
            file_path=None,
            param=m["value"],
            status="confirmed",
            evidence_kind="artifact-match",
            verdict=2,
            confidence=0.85,
            finding_class="detection",
            extra={"family": m["family"], "type": m["type"],
                   "channel": m["channel"], "mode": m["mode"]},
        ))
    manifest = {
        "mutexes_to_precreate": sorted({
            e["value"] for e in entries
            if e["type"] in ("mutex", "pipe")
        }),
        "sinkhole_candidates": sorted({
            e["value"] for e in entries if e["type"] == "domain"
        }),
        "note": ("mutex tak bertahan reboot — re-apply saat startup; "
                 "vaksinasi = lapisan SUPLEMEN, bukan pertahanan utama "
                 "(tidak semua keluarga punya kill switch)"),
    }
    meta = {
        "schema": SCHEMA,
        "db_seed_families": db_meta["seed_families"],
        "db_extra_families": db_meta["extra_families"],
        "db_extra_invalid": db_meta["extra_invalid"],
        "db_dup_dropped": db_meta["dup_dropped"],
        "db_source": "seed+extra" if db_extra else "seed",
        "events_meta": ev_meta,
        "dns_meta": dns_meta,
        "db_indicators": len(entries),
        "indicators_without_channel": None,  # diisi pemanggil
        "no_channel_types": None,
        "matches": len(matches),
        "verdict_note": "L2 REPRODUCED — string terbukti ada di artefak",
    }
    meta["vaccination_manifest"] = manifest
    return findings, meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="triase kill-switch ransomware (offline, DB-based)")
    ap.add_argument("--events", help="ekspor XML Windows (Sysmon/PS)")
    ap.add_argument("--dns", help="log kueri DNS (teks)")
    ap.add_argument("--db", help="JSON DB indikator tambahan (append)")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args(argv)

    if not args.events and not args.dns:
        print("[killswitch_triage] tanpa --events/--dns: tidak ada "
              "telemetri -> tidak ada kesimpulan (fail-closed)",
              file=sys.stderr)
        return 2

    try:
        entries, db_meta = load_db(args.db)
    except SystemExit:
        print("[killswitch_triage] --db tidak valid (bukan JSON DB "
              "families/indicators atau terlalu besar)", file=sys.stderr)
        return 2

    events: list[dict] = []
    ev_meta: dict = {}
    domains: list[str] = []
    dns_meta: dict = {}
    ok = False
    if args.events:
        try:
            events, ev_meta = parse_events_file(args.events)
            ok = True
        except SystemExit:
            print(f"[killswitch_triage] --events {args.events} tidak "
                  "ter-parse sebagai XML Windows (fail-closed)",
                  file=sys.stderr)
            return 2
    if args.dns:
        try:
            domains, dns_meta = parse_dns_file(args.dns)
            ok = True
        except SystemExit:
            print(f"[killswitch_triage] --dns {args.dns} terlalu besar",
                  file=sys.stderr)
            return 2
    if not ok:
        return 2

    matches, nc_meta = match(events, domains, entries)
    findings, meta = build_output(matches, entries, dns_meta, ev_meta,
                                  db_meta, args.db)
    meta["indicators_without_channel"] = nc_meta["indicators_without_channel"]
    meta["no_channel_types"] = nc_meta["no_channel_types"]
    write_findings(args.out, findings, meta)
    if matches:
        print(f"[killswitch_triage] {len(matches)} kecocokan kill-switch "
              f"-> {args.out}")
        return 1
    print(f"[killswitch_triage] bersih ({len(entries)} indikator DB, "
          f"{ev_meta.get('events_parsed', 0)} event + "
          f"{len(domains)} kueri DNS dipindai) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
