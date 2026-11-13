"""[SAFETY: read-only] mcp_tool_vet — vetting server MCP & tool-nya
SEBELUM/jangan-sampai dipasang ke agen.

Tiga permukaan yang diperiksa:
  1. CONFIG (mcpServers di .mcp.json / claude_desktop_config.json /
     mcp.json): perintah server berbahaya (curl|sh, base64|sh,
     rm -rf /), env yang menyimpan secret;
  2. DESKRIPSI TOOL (dump JSON {tools:[{name,description}...]}):
     poisoning — instruksi ke model di deskripsi ("ignore previous
     instructions", "do not tell the user", arahan membaca kredensial,
     karakter zero-width) + shadowing (nama tool sama dari >1 server);
  3. RUG-PULL: hash SHA-256 deskripsi vs file pin (--pin pin.json,
     ditulis dengan --write-pin). Deskripsi berubah setelah approval =
     rug-pull-suspected (critical); tool tanpa pin = unpinned
     (tercatat — fail-closed, tidak pernah dianggap aman).

Fail-closed:
  - file tidak ada / tidak terbaca                    -> exit 2
  - tidak ada config server MCP DAN tidak ada dump    -> exit 2
    (bukti kosong tidak boleh dilaporkan "bersih")
  - JSON tidak ter-parse                              -> tercatat
    unparsed; exit 2 bila SEMUA input gagal
  - critical (poisoning/rug-pull) -> exit 1; sisanya exit 0

Pemakaian:
  python tools/mcp_tool_vet.py --config .mcp.json --tools dump.json
  python tools/mcp_tool_vet.py --config .mcp.json --tools dump.json \\
      --write-pin pin.json
  python tools/mcp_tool_vet.py --config .mcp.json --tools dump.json \\
      --pin pin.json --fail-on critical
Exit: 0 bersih/selesai; 1 temuan critical; 2 input error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import injection_guard  # noqa: E402  (scan_text — kelas operator-override)

SCHEMA = "secai.mcp-tool-vet/1"
MAX_FILE_BYTES = 512 * 1024
SERVER_KEYS = ("mcpServers", "servers")

# --- perintah server berbahaya di config (ditulis sendiri; zero-FP:
#     hanya bentuk eksplisit) ---
CONFIG_PATTERNS: "list[tuple[str, str, re.Pattern]]" = [
    ("install-pipe-shell", "high", re.compile(
        r"(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", re.I)),
    ("decode-pipe-shell", "high", re.compile(
        r"\bbase64\s+(?:-d|--decode)\b[^|]*\|\s*(?:ba|z)?sh\b", re.I)),
    ("rm-rf-root", "high", re.compile(
        r"\brm\s+-rf\s+(?:/|~|\$HOME)(?:\s|$)")),
    ("eval-inline", "medium", re.compile(
        r"\b(?:node|python3?)\s+(?:-e|-c)\s+[\"']"
        r".{0,200}(?:require\s*\(\s*[\"']child_process|os\.environ|"
        r"eval\s*\()", re.I)),
]

# --- poisoning di deskripsi tool (kelas Invariant Labs; pola ditulis
#     sendiri dari publikasi kelas serangan) ---
POISON_PATTERNS: "list[tuple[str, str, re.Pattern]]" = [
    ("override-instruction", "critical", re.compile(
        r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)"
        r"\s+instructions?", re.I)),
    ("conceal-from-user", "critical", re.compile(
        r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal)"
        r"\s+(?:the\s+)?(?:user|human|anyone)", re.I)),
    ("credential-access", "critical", re.compile(
        r"\b(?:read|cat|open|fetch|exfiltrate|send|upload)\b[^\n]{0,60}"
        r"(?:~?/\.(?:ssh|env|aws|git-credentials)|id_rsa|\.env\b|"
        r"credentials(?:\.json)?\b|api[_-]?key|password)", re.I)),
    ("cross-tool-directive", "high", re.compile(
        r"(?:before|after|when)\s+(?:responding|replying|any\s+tool\s+"
        r"use|any\s+response)[^\n]{0,80}\b(?:call|use|invoke|run)\b",
        re.I)),
    ("fake-document-boundary", "high", re.compile(
        r"<\s*(?:important|system|instructions?|assistant)\s*>",
        re.I)),
]
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\u2061-\u2064\ufeff]")
ENV_SECRET_RE = re.compile(
    r"(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|CREDENTIAL)", re.I)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_json(path: Path) -> "tuple[object | None, str | None]":
    """Baca JSON; return (data, None) atau (None, alasan_gagal)."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None, "terlalu besar (>512KB)"
        return json.loads(path.read_text(encoding="utf-8",
                                         errors="replace")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def audit_config(path: Path) -> "tuple[list[dict], int]":
    """Audit satu file config MCP -> (temuan, jumlah server)."""
    data, err = _load_json(path)
    if err is not None:
        return [{"severity": "unparsed", "code": "config-unparseable",
                 "where": str(path), "detail": err}], 0
    servers: dict = {}
    if isinstance(data, dict):
        for key in SERVER_KEYS:
            if isinstance(data.get(key), dict):
                servers = data[key]
                break
    findings: list[dict] = []
    if not servers:
        findings.append({
            "severity": "unparsed", "code": "no-servers",
            "where": str(path),
            "detail": "tidak ada key mcpServers/servers berisi objek",
        })
        return findings, 0
    for name, spec in sorted(servers.items()):
        if not isinstance(spec, dict):
            findings.append({
                "severity": "unparsed", "code": "server-spec-invalid",
                "where": f"{path}:{name}",
                "detail": "nilai server bukan objek",
            })
            continue
        command = str(spec.get("command") or "")
        args = [str(a) for a in spec.get("args") or []]
        cmdline = " ".join([command] + args)
        for code, sev, rx in CONFIG_PATTERNS:
            m = rx.search(cmdline)
            if m:
                findings.append({
                    "severity": sev, "code": code,
                    "where": f"{path}:{name}", "detail":
                        f"perintah server mengandung pola '{code}': "
                        f"...{m.group(0)[:120]}...",
                })
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        for ekey, evalue in sorted(env.items()):
            if ENV_SECRET_RE.search(str(ekey)) and str(evalue).strip():
                findings.append({
                    "severity": "low", "code": "env-secret",
                    "where": f"{path}:{name}",
                    "detail": f"env '{ekey}' tampak menyimpan secret "
                              f"(nilai tidak ditampilkan)",
                })
    return findings, len(servers)


def _extract_tools(dump: object) -> "list[tuple[str, str, str]]":
    """Ekstrak (server, tool_name, description) dari dump JSON.

    Bentuk diterima (fail-closed ke []):
      {"server": "n", "tools": [{"name","description"}...]}
      {"tools": [...]}                        (server = nama file)
      {"tools/list": {"tools": [...]}}        (bentuk JSON-RPC dump)
      [{"name","description"}...]             (array polos)
    """
    out: "list[tuple[str, str, str]]" = []

    def add(server: str, tools: object) -> None:
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, dict) and t.get("name"):
                    out.append((server, str(t["name"]),
                                str(t.get("description") or "")))

    if isinstance(dump, list):
        add("array", dump)
    elif isinstance(dump, dict):
        server = str(dump.get("server") or dump.get("serverName") or "")
        if isinstance(dump.get("tools"), list):
            add(server or "unnamed", dump["tools"])
        rpc = dump.get("tools/list")
        if isinstance(rpc, dict) and isinstance(rpc.get("tools"), list):
            add(server or "unnamed", rpc["tools"])
        result = dump.get("result") if isinstance(
            dump.get("result"), dict) else None
        if result and isinstance(result.get("tools"), list):
            add(server or "unnamed", result["tools"])
    return out


def audit_tool_dump(path: Path) -> "tuple[list[dict], int]":
    """Audit satu dump tool-list -> (temuan, jumlah tool)."""
    data, err = _load_json(path)
    if err is not None:
        return [{"severity": "unparsed", "code": "dump-unparseable",
                 "where": str(path), "detail": err}], 0
    tools = _extract_tools(data)
    findings: list[dict] = []
    if not tools:
        findings.append({
            "severity": "unparsed", "code": "no-tools",
            "where": str(path),
            "detail": "tidak ada tool dikenali di dump (bentuk tak "
                      "didukung — fail-closed)",
        })
        return findings, 0
    for server, name, desc in tools:
        hits = injection_guard.scan_text(desc)
        for label, sev, rx in POISON_PATTERNS:
            m = rx.search(desc)
            if m:
                hits.append({"label": f"mcp:{label}", "snippet":
                             desc[max(0, m.start() - 30):
                                  m.end() + 30][:120],
                             "start": m.start()})
        if ZERO_WIDTH_RE.search(desc):
            hits.append({"label": "mcp:zero-width-chars",
                         "snippet": "(karakter tak terlihat di "
                                    "deskripsi)", "start": 0})
        for h in hits:
            sev = "critical" if h["label"].startswith("mcp:") \
                or "override" in h["label"] or "exfiltrat" in h["label"] \
                else "high"
            findings.append({
                "severity": sev, "code": "description-poisoning",
                "where": f"{path}:{server}/{name}",
                "detail": f"[{h['label']}] {h['snippet']}",
            })
    return findings, len(tools)


def shadowing_findings(all_tools: "list[tuple[str, str, str]]") \
        -> "list[dict]":
    """Nama tool yang sama diiklankan >1 server (tool shadowing)."""
    by_name: dict[str, list[str]] = {}
    for server, name, _ in all_tools:
        by_name.setdefault(name.lower(), []).append(server)
    out: list[dict] = []
    for lname, servers in sorted(by_name.items()):
        uniq = sorted(set(servers))
        if len(uniq) > 1:
            out.append({
                "severity": "high", "code": "tool-shadowing",
                "where": lname,
                "detail": f"tool '{lname}' diiklankan oleh "
                          f"{len(uniq)} server: {', '.join(uniq)} — "
                          f"resolusi nama bisa dibajak",
            })
    return out


def pin_findings(all_tools: "list[tuple[str, str, str]]",
                 pin_path: Path) -> "list[dict]":
    """Bandingkan hash deskripsi vs pin — deteksi rug-pull."""
    data, err = _load_json(pin_path)
    if err is not None:
        return [{"severity": "unparsed", "code": "pin-unparseable",
                 "where": str(pin_path), "detail": err}]
    pins = data if isinstance(data, dict) else {}
    out: list[dict] = []
    pinned_seen: set[tuple] = set()
    for server, name, desc in all_tools:
        server_pins = pins.get(server) if isinstance(
            pins.get(server), dict) else None
        if server_pins is None or name not in server_pins:
            out.append({
                "severity": "medium", "code": "tool-unpinned",
                "where": f"{server}/{name}",
                "detail": "belum ada pin hash — jalankan --write-pin "
                          "setelah review",
            })
            continue
        expected = str(server_pins[name])
        pinned_seen.add((server, name))
        if expected != _sha256(desc):
            out.append({
                "severity": "critical", "code": "rug-pull-suspected",
                "where": f"{server}/{name}",
                "detail": "hash deskripsi berubah dari pin — deskripsi "
                          "tool berubah SETELAH approval",
            })
    for server, tool_pins in sorted(pins.items()):
        if not isinstance(tool_pins, dict):
            continue
        for name in sorted(tool_pins):
            if (str(server), str(name)) not in pinned_seen:
                if any(s == str(server) for s, _, _ in all_tools):
                    out.append({
                        "severity": "medium", "code": "pin-missing-tool",
                        "where": f"{server}/{name}",
                        "detail": "tool ter-pin tidak ada di dump "
                                  "sekarang",
                    })
    return out


def write_pin(all_tools: "list[tuple[str, str, str]]",
              pin_path: Path) -> dict:
    """Tulis/mutakhirkan pin hash deskripsi per server/tool."""
    pins: dict[str, dict[str, str]] = {}
    if pin_path.exists():
        old, err = _load_json(pin_path)
        if err is None and isinstance(old, dict):
            pins = {k: v for k, v in old.items()
                    if isinstance(v, dict)}
    for server, name, desc in all_tools:
        pins.setdefault(server, {})[name] = _sha256(desc)
    pin_path.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    return pins


def _collect(paths: "list[Path]", kind: str) -> "list[Path]":
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(f for f in p.rglob("*") if f.is_file()
                              and f.suffix.lower() == ".json"))
        else:
            out.append(p)
    return out


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="mcp_tool_vet — vetting config + tool MCP "
                    "(statis, nol jaringan, fail-closed).")
    ap.add_argument("--config", action="append", default=[],
                    help="file/dir config MCP (.mcp.json, "
                         "claude_desktop_config.json); boleh berulang")
    ap.add_argument("--tools", action="append", default=[],
                    help="file/dir dump tool-list JSON; boleh berulang")
    ap.add_argument("--pin", help="file pin hash utk deteksi rug-pull")
    ap.add_argument("--write-pin", dest="write_pin",
                    help="tulis/mutakhirkan pin hash ke file ini, lalu "
                         "selesai tanpa penilaian rug-pull")
    ap.add_argument("--fail-on", choices=("critical", "high"),
                    default="critical",
                    help="ambang exit 1 (default critical)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    if not args.config and not args.tools:
        print("[mcp-tool-vet] berikan --config dan/atau --tools",
              file=sys.stderr)
        return 2

    findings: list[dict] = []
    n_servers = n_tools = 0
    unparsed = 0
    all_tools: "list[tuple[str, str, str]]" = []

    for p in _collect([Path(x) for x in args.config], "config"):
        if not p.exists():
            print(f"[mcp-tool-vet] config tidak ada: {p}",
                  file=sys.stderr)
            return 2
        f, n = audit_config(p)
        findings.extend(f)
        unparsed += sum(1 for x in f if x["severity"] == "unparsed")
        n_servers += n
    for p in _collect([Path(x) for x in args.tools], "tools"):
        if not p.exists():
            print(f"[mcp-tool-vet] tools tidak ada: {p}",
                  file=sys.stderr)
            return 2
        f, n = audit_tool_dump(p)
        findings.extend(f)
        unparsed += sum(1 for x in f if x["severity"] == "unparsed")
        n_tools += n
        all_tools.extend(_extract_tools(
            _load_json(p)[0] or {}))

    findings.extend(shadowing_findings(all_tools))

    if args.write_pin:
        pins = write_pin(all_tools, Path(args.write_pin))
        total = sum(len(v) for v in pins.values())
        print(f"[mcp-tool-vet] pin ditulis: {args.write_pin} "
              f"({total} tool, {len(pins)} server)")
        return 0

    if args.pin:
        findings.extend(pin_findings(all_tools, Path(args.pin)))

    if n_servers == 0 and n_tools == 0:
        print("[mcp-tool-vet] tidak ada server MCP / tool yang "
              "dikenali — bukti kosong tidak boleh jadi 'bersih' "
              "(fail-closed)", file=sys.stderr)
        return 2

    real = [f for f in findings if f["severity"] != "unparsed"]
    real.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                             f["where"], f["code"]))
    by_sev: dict[str, int] = {}
    for f in real:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    result = {
        "schema": SCHEMA,
        "servers": n_servers,
        "tools": n_tools,
        "unparsed_count": unparsed,
        "summary": {"findings_total": len(real),
                    "by_severity": {k: by_sev[k] for k in sorted(
                        by_sev, key=lambda s: SEV_ORDER.get(s, 9))}},
        "findings": real,
        "note": "statis & offline: poisoning dinilai dari deskripsi di "
                "dump/config; runtime SSRF/auth masih butuh uji manual "
                "berizin (lihat sumber #0269)",
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(f"[mcp-tool-vet] {n_servers} server + {n_tools} tool "
          f"diperiksa ({unparsed} input unparsed)")
    print(f"[mcp-tool-vet] temuan: {len(real)} "
          f"({', '.join(f'{k}={v}' for k, v in result['summary']['by_severity'].items()) or '-'})")
    for f in real[:10]:
        print(f"  [{f['severity']:8}] {f['code']:22} {f['where']}")
    crit = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    if args.fail_on == "critical" and crit:
        return 1
    if args.fail_on == "high" and (crit or high):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
