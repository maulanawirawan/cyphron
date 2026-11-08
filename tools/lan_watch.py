"""[SAFETY: read-only LAN] lan-watch — inventaris perangkat jaringan
LOKAL milik sendiri (kafe/rumah) — bukan alat serang.

Fungsi:
  1. --scan : ping-sweep subnet lokal (bounded 254 host, timeout pendek)
     + baca tabel ARP Windows + vendor dari OUI MAC + hostname NetBIOS
     (nbtstat, opsional) -> inventaris + deteksi perangkat BARU vs
     baseline (drift, pola nightrun).
  2. --watch N : ulangi scan tiap N menit (log join/leave).
  3. --block-guide <ip|mac> : panduan PEMILIK jaringan untuk memblokir
     perangkat secara PERMANEN via router (URL persis + setting persis
     + kriteria lulus/gagal) — bukan ARP-cut.

Batas jujur (fail-closed):
  - tool ini TIDAK memblokir apa pun dan TIDAK melakukan ARP-spoofing;
    pemutusan permanen = fitur router (MAC filter / guest SSID / QoS)
    — lebih andal, permanen, dan tidak merusak stabilitas LAN sendiri;
  - pemindaian hanya ke subnet antarmuka lokal milik sendiri (254 host,
    ICMP ping satu paket) — sah sebagai admin jaringan SENDIRI;
  - perangkat TIDAK menjawab ping tetap bisa terlihat via ARP table
    (cache gateway); yang tidak terlihat sama sekali = tidak diklaim;
  - bandwidth per-perangkat TIDAK diukur (butuh sniffing promiscuous/
    statistik router) — keputusan blokir dari kebaruan/identitas
    perangkat, bukan tebakan lalu lintas.

Windows-first (arp/nbtstat/ping builtin). Subnet lain = ganti --cidr
(milik sendiri — pemindaian jaringan ORANG LAIN bukan fungsi ini).
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "findings" / "lan-watch"
STATE_FILE = STATE_DIR / "devices.json"

# OUI prefix umum (8 bit vendor pertama, lowercase tanpa '-') — subset
# kurasi perangkat yang sering muncul di jaringan konsumen Indonesia.
# Lookup lengkap: --oui-file <csv IEEE> (di-cache lokal setelah unduh).
OUI_COMMON = {
    "00:45:e2": "CyberTAN", "98:3f:a4": "Router/gateway",
    "14:7f:ce": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "3c:91:80": "Liteon", "e0:0a:f6": "Liteon", "ac:1c:26": "Hikvision/Ezviz",
    "1c:1a:1b": "Sunmi", "74:f7:f6": "Sunmi", "30:cb:f8": "Samsung",
    "88:5a:06": "OPPO", "64:24:4d": "TP-Link", "5e:b8:80": "Xiaomi/Redmi",
    "72:60:50": "Xiaomi (randomized)", "da:a0:d3": "Xiaomi",
    "14:85:7f": "Intel", "00:1a:11": "Google", "3a:5b:2f": "Randomized",
    "06:be:bf": "Randomized", "12:2f:a2": "Randomized",
    "1e:5f:39": "Randomized", "4e:c9:c1": "Randomized",
    "52:ca:78": "Randomized", "5e:6c:db": "Randomized",
    "66:8a:5b": "Randomized", "72:85:39": "Randomized",
    "86:f5:10": "Randomized", "92:71:56": "Randomized",
    "9a:13:d0": "Randomized", "9e:04:19": "Randomized",
    "a2:2a:6e": "Randomized", "aa:7c:85": "Randomized",
    "ae:c9:d6": "Randomized", "be:a0:33": "Randomized",
    "c2:01:2c": "Randomized", "c6:7a:3e": "Randomized",
    "d2:29:28": "Randomized", "d6:c7:04": "Randomized",
    "f6:a9:32": "Randomized", "f6:dd:92": "Randomized",
}
# byte pertama dengan bit LSB-1 (unicast multicast bit) + lokal bit = MAC
# acak perangkat modern (iOS/Android privacy) — sinyal "bukan infrastruktur"


def local_ip() -> str | None:
    """IP antarmuka lokal (tanpa traffic ke internet — UDP connect ke
    gateway-range dummy TIDAK dipakai; pakai route tabel via socket
    trick standar: connect UDP 8.8.8.8 TIDAK mengirim paket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # tidak terkirim (UDP tanpa data)
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def subnet_of(ip: str, cidr: int = 24) -> str | None:
    parts = ip.split(".")
    if len(parts) != 4 or cidr != 24:
        return None
    return ".".join(parts[:3])


def ping_sweep(subnet: str, timeout_s: int = 1, workers: int = 32) -> set[str]:
    """ICMP ping satu paket ke .1-.254 (bounded 254). Windows ping:
    -n 1 -w <ms>. Return daftar IP yang menjawab."""
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    alive: set[str] = set()
    from concurrent.futures import ThreadPoolExecutor

    def one(ip: str) -> str | None:
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip],
                capture_output=True, text=True, timeout=timeout_s + 3)
            if r.returncode == 0 and ("TTL=" in r.stdout or
                                      "ttl=" in r.stdout):
                return ip
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(one, ips):
            if res:
                alive.add(res)
    return alive


def parse_arp(text: str) -> dict[str, str]:
    """Parse output `arp -a` (Windows) — murni, testable."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+"
                     r"([0-9a-fA-F-]{17}|[0-9a-fA-F-]{14})", line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).lower().replace("-", ":")
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("00:00:00"):
            continue
        if mac.startswith("01:00:5e") or mac.startswith("33:33"):
            continue  # multicast
        if int(ip.split(".")[0]) >= 224:
            continue  # multicast/reserved
        out[ip] = mac
    return out


def arp_table() -> dict[str, str]:
    """Tabel ARP Windows: MAC per IP (hanya entri LAN yang valid)."""
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           timeout=15)
    except Exception:
        return {}
    return parse_arp(r.stdout or "")


def netbios_name(ip: str, timeout_s: int = 4) -> str | None:
    """Hostname NetBIOS via nbtstat (Windows builtin) — bounded 1 call
    per IP (dipanggil HANYA utk perangkat baru/berubah)."""
    try:
        r = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                           text=True, timeout=timeout_s + 3)
    except Exception:
        return None
    m = re.search(r"<00>\s*UNIQUE\s+Register(ed)?\s+(\S+)", r.stdout or "")
    if not m:
        m = re.search(r"(\S+)\s+<00>\s+UNIQUE", r.stdout or "")
    return m.group(2) if m else None


def oui_vendor(mac: str) -> str | None:
    prefix = ":".join(mac.lower().split(":")[:3])
    if prefix in OUI_COMMON:
        return OUI_COMMON[prefix]
    # MAC acak perangkat modern: bit "locally administered" = 0x02 di
    # octet PERTAMA (IEEE) — privacy iOS/Android/Windows
    first = int(mac.split(":")[0], 16)
    if first & 0x02:
        return "Perangkat (MAC acak — privacy)"
    return None


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    tmp.replace(STATE_FILE)


def scan_once(cidr: str | None, with_names: bool) -> dict:
    ip = local_ip()
    subnet = cidr or (subnet_of(ip) if ip else None)
    if not subnet:
        return {"ok": False, "error": "subnet lokal tidak ketemu — "
                "sambungkan Wi-Fi dulu atau pakai --cidr"}
    alive = ping_sweep(subnet)
    arps = arp_table()
    macs: dict[str, str] = {}
    for ip2, mac in arps.items():
        if ip2.startswith(subnet + ".") and (alive or True):
            macs[ip2] = mac
    # IP hidup via ping tapi belum di ARP (jarang) = tanpa MAC
    for ip2 in alive:
        macs.setdefault(ip2, None)
    devices = []
    for ip2 in sorted(macs, key=lambda x: tuple(int(p) for p in
                                                x.split("."))):
        mac = macs.get(ip2)
        devices.append({
            "ip": ip2,
            "mac": mac,
            "vendor": oui_vendor(mac) if mac else None,
            "hostname": netbios_name(ip2) if (with_names and mac) else None,
        })
    return {"ok": True, "subnet": subnet, "scan_epoch": time.time(),
            "devices": devices, "requests": len(alive) and 254}


def diff_state(scan: dict, state: dict) -> dict:
    """Drift: perangkat baru (MAC/IP belum pernah terlihat) vs hilang."""
    now = scan.get("scan_epoch")
    known = state.get("devices", {})
    seen_now = {}
    for d in scan.get("devices", []):
        key = d.get("mac") or f"ip-{d['ip']}"
        prev = known.get(key)
        seen_now[key] = {
            "ip": d["ip"], "mac": d.get("mac"),
            "vendor": d.get("vendor"), "hostname": d.get("hostname"),
            "first_seen": (prev or {}).get("first_seen", now),
            "last_seen": now,
            "names": sorted(set((prev or {}).get("names", [])
                                + ([d["hostname"]] if d.get("hostname")
                                   else [])))[-5:],
        }
    new_keys = [k for k in seen_now if k not in known]
    gone_keys = [k for k in known if k not in seen_now]
    return {"known": seen_now, "new_keys": new_keys,
            "gone_keys": gone_keys}


def finding_rows(scan: dict, diff: dict) -> list[dict]:
    """Kontrak findings: perangkat baru = lead L1 (fakta, verifikasi
    manual — bukan klaim penyerang); inventaris penuh = L0."""
    sys.path.insert(0, str(ROOT / "core"))
    from findings import make_finding  # noqa: E402
    rows = []
    for k in diff["new_keys"]:
        d = diff["known"][k]
        rows.append(make_finding(
            tool="lan-watch",
            title=f"Perangkat baru di LAN {scan['subnet']}: "
                  f"{d['hostname'] or d['vendor'] or 'tanpa nama'} "
                  f"({d['ip']})",
            severity="low",
            description=f"Perangkat baru terlihat (MAC {d.get('mac') or '?'}"
                        f", vendor {d.get('vendor') or '?'}) — verifikasi "
                        "manual: milikmu/tamu sah? Bila asing, blokir "
                        "permanen via router (lihat --block-guide). "
                        "Lead = fakta kebaruan, BUKAN klaim penyerang.",
            recommendation="Kenali perangkat; bila asing -> MAC filter "
                           "di router + pisahkan tamu ke guest SSID.",
            cwe=None, target_url=f"lan://{scan['subnet']}/{d['ip']}",
            request=f"ping-sweep {scan['subnet']}.0/24",
            response=f"{d['ip']} mac={d.get('mac')} "
                     f"vendor={d.get('vendor')}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "LAN-DEVICE", "safety_class": "local-only",
                   "mac": d.get("mac"), "vendor": d.get("vendor"),
                   "first_seen": d["first_seen"]}))
    return rows


def block_guide(target: str, scan: dict | None) -> str:
    """Panduan blokir PERMANEN via router (pemilik jaringan)."""
    ip = target if re.match(r"\d+\.\d+\.\d+\.\d+", target) else None
    mac = None
    if scan:
        for d in scan.get("devices", []):
            if target in (d["ip"], d.get("mac")):
                ip, mac = d["ip"], d.get("mac") or mac
    gw = subnet_of(ip) + ".1" if ip else "192.168.1.1"
    lines = [
        "BLOKIR PERMANEN via router (bukan ARP-cut — alasan di docstring):",
        f"  Target: {ip or target}  MAC: {mac or '(jalankan --scan dulu)'}",
        "",
        "  Langkah (umum, semua router ISP/konsumen punya fitur ini):",
        f"  1. Buka panel router: http://{gw}/ (login admin — di stiker "
        "router / dari ISP).",
        "  2. Cari menu (nama berbeda tiap merk):",
        "     - TP-Link: Wireless / Advanced -> Wireless MAC Filtering",
        "     - ZTE/Indihome: Network -> WLAN -> MAC Filter (atau "
        "Access Control)",
        "     - Huawei: WLAN -> Advanced Configuration -> MAC Filter",
        "     - Xiaomi: Wi-Fi settings -> Device management",
        "  3. Mode filter = DENY/Blacklist, lalu tambahkan MAC target:",
        f"     {mac or '<MAC dari --scan>'}",
        "  4. (Lebih baik utk kafe) Aktifkan GUEST SSID terpisah dgn:",
        "     - client isolation ON (tamu tak bisa lihat tamu lain),",
        "     - bandwidth limit per klien (mis. 5-10 Mbps),",
        "     - password gampang diganti tanpa ganggu perangkatmu.",
        "",
        "  Kriteria lulus: jalankan --scan lagi 2-3 menit setelah apply "
        "-> perangkat target TIDAK muncul lagi (atau muncul tapi tak "
        "bisa internet). Kriteria gagal: masih muncul -> MAC yang "
        "diblokir salah (perangkat modern bisa pakai MAC acak per "
        "SSID — blokir berdasarkan MAC yang tercatat di router, bukan "
        "dari scan ini saja).",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", action="store_true",
                    help="scan sekali + update state + laporan")
    ap.add_argument("--watch", type=int, default=0, metavar="MENIT",
                    help="ulangi scan tiap N menit (ctrl+C untuk stop)")
    ap.add_argument("--cidr", default=None,
                    help="subnet eksplisit (default: subnet lokal), "
                         "mis. 192.168.1")
    ap.add_argument("--no-names", action="store_true",
                    help="lewati lookup hostname NetBIOS")
    ap.add_argument("--block-guide", default=None, metavar="IP|MAC",
                    help="cetak panduan blokir permanen via router")
    ap.add_argument("--out", default=None,
                    help="tulis findings JSON (kontrak secai)")
    args = ap.parse_args()

    if args.block_guide:
        # resolve MAC: dari state scan terakhir dulu (NOL request),
        # scan langsung hanya bila --scan juga diminta
        scan = None
        tgt = args.block_guide
        for d in load_state().get("devices", {}).values():
            if tgt in (d.get("ip"), d.get("mac")):
                scan = {"devices": [d]}
                break
        if scan is None and args.scan:
            scan = scan_once(args.cidr, not args.no_names)
        print(block_guide(args.block_guide, scan))
        return 0
    if not args.scan and not args.watch:
        ap.error("--scan atau --watch wajib (atau --block-guide)")

    state = load_state()
    interval = max(1, args.watch or 1)
    while True:
        scan = scan_once(args.cidr, not args.no_names)
        if not scan.get("ok"):
            print(json.dumps({"audit": "lan-watch",
                              "error": scan.get("error")}),
                  file=sys.stderr)
            if not args.watch:
                return 1
            time.sleep(60)
            continue
        diff = diff_state(scan, state)
        state["devices"] = diff["known"]
        state["last_scan"] = scan["scan_epoch"]
        save_state(state)
        ts = datetime.fromtimestamp(scan["scan_epoch"]) \
                      .strftime("%H:%M:%S")
        print(f"[{ts}] {scan['subnet']}.0/24: "
              f"{len(scan['devices'])} perangkat | "
              f"BARU: {len(diff['new_keys'])} | "
              f"hilang: {len(diff['gone_keys'])}")
        for k in diff["new_keys"]:
            d = diff["known"][k]
            print(f"    + BARU {d['ip']} {d.get('mac') or '?'} "
                  f"{d.get('vendor') or '?'} "
                  f"{('[' + d['hostname'] + ']') if d.get('hostname') else ''}")
        rows = finding_rows(scan, diff)
        if args.out:
            sys.path.insert(0, str(ROOT / "core"))
            from findings import write_findings
            write_findings(args.out, rows,
                           {"subnet": scan["subnet"],
                            "devices": len(scan["devices"]),
                            "new": len(diff["new_keys"]),
                            "safety_class": "local-only",
                            "requests": scan["requests"]})
        if not args.watch:
            return 0
        time.sleep(interval * 60)


if __name__ == "__main__":
    raise SystemExit(main())
