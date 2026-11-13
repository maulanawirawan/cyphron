"""[SAFETY: read-only] scope_gate — gerbang cek scope aset SEBELUM ada
request.

Pertanyaan yang dijawab: "bolehkah aset ini diuji menurut kebijakan program?"
Aset yang keliru diuji = laporan ditutup / bisa kena ban program. Cek scope
wajib dilakukan SEBELUM request pertama.

Konsep dari awarexone/Agentic-Bug-Hunter (MIT) — scope checker deterministik
yang menegaskan "out-of-scope traffic executed = 0". Dibangun from scratch
TANPA menyalin kode dari repo itu: parser kanonik, pencocokan wildcard
terjangkar (anchored suffix), dan CIDR via stdlib ditulis sendiri di sini.

Read-only, NOL jaringan: input = ekspor kebijakan JSON + daftar aset.

Bentuk kebijakan (JSON):
  {
    "program": "nama-program",                  // opsional
    "in_scope":  ["target.com",
                  {"asset": "*.target.com", "type": "wildcard"},
                  {"asset": "10.0.0.0/24", "type": "cidr"}],
    "out_of_scope": [{"asset": "staging.target.com"}]
  }
  - entri boleh string polos atau object ber-field aset dikenali
    (asset/identifier/asset_identifier/name/endpoint/target/uri/host)
    + tipe opsional (type/asset_type/category).
  - bentuk/entri/tipe yang TAK dikenali -> exit 2 (fail-closed): kebijakan
    yang tidak bisa dinilai tidak boleh menebak. in_scope boleh absen di
    parser (klaim out_of_scope-only tetap berarti untuk aggregate), tapi
    GERBANG menolak jalan tanpa satu pun aturan in-scope (exit 2) — tidak
    bisa mengizinkan apa pun bukan berarti menolak semua diam-diam.

Semantik pencocokan (deterministik, fail-closed):
  - "*.target.com"  -> subdomain saja: BUKAN apex, BUKAN evil-target.com
  - "target.com"    -> host persis itu saja
  - out-of-scope eksak menutup host DAN subdomennya (melarang itu melarang
    cabangnya); out-of-scope wildcard tetap terjangkar (*.staging.tld tidak
    menutup apex staging.tld)
  - "api.target.com:8443"  -> aturan dengan batasan port (mempersempit)
  - "target.com/api/"      -> aturan dengan batasan path (mempersempit,
                               batas segmen: /api tidak cocok /apixyz)
  - "10.0.0.0/24", "2001:db8::/32" -> CIDR via stdlib ipaddress; single IP
                               = /32. Encoding IP ambigu (desimal/heks/oktal)
                               ditolak stdlib -> fail-closed.
  - hostname non-ASCII/ber karakter aneh/backslash/trailing-URL-trick,
    skema non-http(s), label kosong, label "0x..." -> aset INVALID.
  - wildcard di atas public suffix ("*.com") -> POLICY ERROR, bukan diabaikan.
  - deny menang: aturan out-of-scope dinilai SEBELUM in-scope.

Verdict per aset:
  IN-SCOPE      : ada aturan in-scope yang cocok (dan tidak kena OOS).
  OUT-OF-SCOPE  : kena aturan out-of-scope -> temuan HIGH (jangan diuji!).
  NOT-IN-SCOPE  : parsable tapi tidak ada aturan in-scope yang cocok ->
                  temuan MEDIUM fail-closed (belum terbukti boleh).
  INVALID       : bentuk aset tidak bisa diparse -> temuan HIGH (jangan diuji).

Pemakaian:
  python tools/scope_gate.py --policy policy.json --check dev.target.com
  python tools/scope_gate.py --policy policy.json --explain https://api.target.com/v2
  python tools/scope_gate.py --policy policy.json --check-file urls.txt --out gate.json
Exit: 0 = semua aset in-scope; 1 = ada temuan (sesuai --fail-on); 2 = error
kebijakan/input (fail-closed).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlsplit

SCHEMA = "secai.scope-gate/1"
TOOL = "scope_gate"

# --- eksepsi fail-closed -----------------------------------------------------


class PolicyError(ValueError):
    """Kebijakan/input tak bisa dinilai — ditolak keras (exit 2), bukan ditebak."""


class DangerousPatternError(PolicyError):
    """Pola yang BERBAHAYA bila salah tafsir (wildcard di atas public
    suffix, ber-label tunggal, atau penempatan liar) — selalu naik meski
    entri tak bertipe: menolak seluruh kebijakan lebih aman daripada
    melewatinya tercatat dan berisiko memperluas scope."""


# --- tabel normalisasi kebijakan ---------------------------------------------

# Field object entri yang mungkin membawa identifier aset (urutan = prioritas).
ASSET_FIELDS = ("asset", "identifier", "asset_identifier", "name",
                "endpoint", "target", "uri", "host")
# Field yang mungkin membawa deklarasi tipe aset.
TYPE_FIELDS = ("type", "asset_type", "category")
# Tipe aset JARINGAN yang dikenali (dinormalisasi lowercase). Entri dgn
# tipe ini diharapkan berbentuk host/URL/IP yang bisa diparse; yang gagal
# parse = anomali ekspor -> PolicyError (manusia harus menilai).
NETWORK_TYPES = {
    "url", "domain", "hostname", "host", "wildcard", "api", "web", "ip",
    "ipv4", "ipv6", "cidr", "range",
}
# Tipe aset NON-JARINGAN yang dikenali (id aplikasi toko, biner, hardware,
# kontrak pintar, dsb. — bentuk umum ekspor platform bug bounty). String
# asetnya BUKAN host: "com.wolt.android" mirip domain tapi bukan hostname,
# jadi TIDAK PERNAH dijadikan rule — dilewati TERCATAT (skipped), bukan
# senyap dan bukan error. Tipe lain yang gagal parse (prosa "All other
# assets") juga dilewati tercatat.
NON_NETWORK_TYPES = {
    "apple_store_app_id", "google_play_app_id", "windows_app_store_app_id",
    "testflight", "other_apk", "other_ipa", "downloadable_executables",
    "hardware", "source_code", "smart_contract", "ai_model",
    "android", "ios", "app", "application",
}
# "other" = lenteng: parse bila bentuknya jaringan, kalau tidak dilewati
# tercatat. Nilai di luar ketiga set ini = bentuk tak dikenal -> PolicyError.
LENIENT_TYPES = {"other"}
KNOWN_TYPES = NETWORK_TYPES | NON_NETWORK_TYPES | LENIENT_TYPES

# Charset ASCII hostname pasca-lowercase. Di luar ini (unicode homoglyph,
# %, spasi, underscore, '*') = bukan hostname yang bisa dinilai -> ditolak.
_HOSTNAME_CHARS = re.compile(r"^[a-z0-9._-]+$")
# Karakter URL terlarang: kontrol (NUL/CR/LF/TAB), spasi, DEL/C1, backslash.
# Backslash penting: browser/curl memperlakukan "\" sebagai "/" sementara
# urlsplit tidak — "https://target.com\\@evil.com" bisa meloloskan host salah.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f\\]")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_ALLOWED_SCHEMES = {"http", "https"}

# Public suffix pragmatis yang ditolak untuk wildcard (bukan PSL penuh —
# penangkal footgun umum "*.com"/"*.co.uk" yang memasukkan seluruh TLD).
_PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz",
    "me", "ai", "gov", "edu", "mil", "int", "eu", "us", "uk", "de", "fr",
    "nl", "ru", "cn", "jp", "in", "br", "au", "ca", "es", "it", "se", "no",
    "fi", "pl", "id", "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au",
    "net.au", "org.au", "co.jp", "co.nz", "com.br", "co.in", "com.cn",
    "com.mx", "com.tr", "co.za", "com.sg", "com.hk", "com.tw", "or.id",
    "web.id", "co.id",
}

# Tipe rule: dict kanonik hasil parse.
#   domain: {"kind": "domain", "raw": str, "wild": bool, "base": str,
#            "port": int|None, "path": str|None, "type": str|None}
#   ip:     {"kind": "ip", "raw": str, "network": IPv4Network|IPv6Network,
#            "type": str|None}
Rule = dict


# --- parser kanonik (SATU parser untuk semua keputusan) -----------------------


def _try_ip_network(text: str) -> Optional[Union[ipaddress.IPv4Network,
                                                 ipaddress.IPv6Network]]:
    """ip_network untuk literal IP/CIDR, atau None. Wildcard bukan IP.

    stdlib ipaddress menolak bentuk ambigu (desimal/heks/oktal/pendek),
    jadi "134744072"/"0x7f.0.0.1" otomatis gagal -> None -> fail-closed.
    """
    if not text or "*" in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _clean_host(host: str) -> Optional[str]:
    """Normalisasi hostname: trailing FQDN dot, charset ASCII, label valid.

    Mengembalikan host bersih, atau None bila bentuknya tak bisa dinilai
    (label kosong, charset liar, label heks, dsb) — pemanggil fail-closed.
    """
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or not _HOSTNAME_CHARS.match(host):
        return None
    labels = host.split(".")
    if "" in labels:  # label kosong: leading/double dot (trailing sudah distrip)
        return None
    if any(lab.startswith("0x") for lab in labels):  # encoding IP heks
        return None
    return host


def _parse_asset(asset: str) -> Optional[dict]:
    """Parse SATU aset (host/URL/IP) bentuk apa pun jadi target kanonik.

    Mengembalikan:
      {"kind": "domain", "host": str, "port": int|None, "path": str,
       "scheme": str}
      {"kind": "ip", "ip": IPv4Address|IPv6Address, "port": int|None}
    atau None bila aset kosong/malformed/ambigu/tak didukung (fail-closed).
    """
    if not isinstance(asset, str) or not asset.strip():
        return None
    s = asset.strip()
    if _FORBIDDEN_CHARS.search(s):
        return None

    port: Optional[int] = None
    path = "/"
    scheme = "https"

    if "://" in s:
        try:
            parts = urlsplit(s)
            hostname = parts.hostname  # ValueError utk netloc rusak
            p_port = parts.port
        except ValueError:
            return None
        if parts.scheme not in _ALLOWED_SCHEMES or not hostname:
            return None
        if p_port is not None and not 1 <= p_port <= 65535:
            return None  # port 0 / liar -> invalid
        host_raw = hostname
        if p_port is not None:
            port = p_port
        scheme = parts.scheme
        path = parts.path or "/"
    else:
        # Tanpa skema. Kandungan ':' bisa berarti IPv6 telanjang atau host:port.
        if ":" in s:
            try:
                ip = ipaddress.ip_address(s)  # IPv6 telanjang "2001:db8::1"
                return {"kind": "ip", "ip": ip, "port": None}
            except ValueError:
                host_raw, _, port_s = s.rpartition(":")
                if not _PORT_RE.match(port_s) or not (1 <= int(port_s) <= 65535):
                    return None  # bentuk ambigu -> fail-closed
                port = int(port_s)
        elif "/" in s:
            if _try_ip_network(s) is not None:
                return None  # aset CIDR = range, bukan aset konkret -> invalid
            host_raw, _, rest = s.partition("/")
            path = "/" + rest
        else:
            host_raw = s

    # Host IPv6 (dalam URL selalu sudah lepas kurung siku oleh urlsplit).
    if ":" in host_raw:
        try:
            ip = ipaddress.IPv6Address(host_raw)
        except ValueError:
            return None
        return {"kind": "ip", "ip": ip, "port": port}

    # IPv4: label terakhir angka -> harus lolos IPv4Address, else INVALID
    # (menutup bentuk hampir-IP seperti "10.0.0.999" dan encoding ambigu).
    if host_raw.rpartition(".")[2].isdecimal():
        try:
            ip = ipaddress.IPv4Address(host_raw)
        except ValueError:
            return None
        return {"kind": "ip", "ip": ip, "port": port}

    host = _clean_host(host_raw)
    if host is None:
        return None
    return {"kind": "domain", "host": host, "port": port, "path": path,
            "scheme": scheme}


def _parse_path(raw_path: str, raw: str) -> str:
    """Normalisasi batasan path aturan; tolak bentuk liar (PolicyError)."""
    p = raw_path.strip()
    if not p.startswith("/"):
        raise PolicyError(f"path aturan harus mulai '/': {raw!r}")
    # "target.com/help/*" gaya ekspor platform -> ekuivalen "/help/".
    if p.endswith("/*"):
        p = p[:-1]
    if "*" in p:
        raise PolicyError(f"wildcard di tengah path tidak didukung: {raw!r}")
    if not p.endswith("/"):
        p += "/"  # batas segmen: "/api" identik dengan "/api/"
    return p


def _parse_rule(raw: str, side: str, declared_type: Optional[str]) -> Rule:
    """Parse SATU entri kebijakan jadi rule kanonik.

    Semua kegagalan bentuk = PolicyError (exit 2 fail-closed): aturan yang
    tidak bisa dinilai tidak boleh dilewati senyap maupun ditebak.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError(f"entri {side} kosong / bukan string")
    p = raw.strip().lower()
    if _FORBIDDEN_CHARS.search(p):
        raise PolicyError(f"entri {side} memuat karakter terlarang: {raw!r}")

    if "://" in p:
        scheme, _, rest = p.partition("://")
        if scheme not in _ALLOWED_SCHEMES:
            raise PolicyError(
                f"skema aturan {side} harus http/https: {raw!r}")
        p = rest
        if "@" in p:
            raise PolicyError(
                f"aturan {side} tidak boleh membawa userinfo '@': {raw!r}")

    # IP / CIDR dulu — sebelum "/" dianggap pemisah path (CIDR memakai "/").
    net = _try_ip_network(p)
    if net is not None:
        if "/" in p and p.count("/") > 1:
            raise PolicyError(f"bentuk CIDR tidak valid: {raw!r}")
        return {"kind": "ip", "raw": raw.strip(), "network": net,
                "type": declared_type}

    host_port, sep, rest = p.partition("/")
    path = _parse_path("/" + rest, raw) if sep else None

    host = host_port
    port: Optional[int] = None
    if ":" in host:
        host, _, port_s = host.rpartition(":")
        if not _PORT_RE.match(port_s) or not (1 <= int(port_s) <= 65535):
            raise PolicyError(f"port aturan tidak valid: {raw!r}")
        port = int(port_s)
        if not host:
            raise PolicyError(f"aturan {side} tanpa host: {raw!r}")

    # IP yang membawa port/path: bentuk tak didukung -> tolak keras
    # (bukan diam-diam dibuang port/path-nya).
    net = _try_ip_network(host)
    if net is not None:
        if port is not None or path is not None:
            raise PolicyError(
                f"port/path tidak didukung pada aturan IP: {raw!r}")
        return {"kind": "ip", "raw": raw.strip(), "network": net,
                "type": declared_type}

    wild = False
    if host.startswith("*."):
        wild = True
        base = host[2:]
        if not base or "*" in base:
            raise DangerousPatternError(
                f"bentuk wildcard tidak valid: {raw!r}")
        host = base
    elif "*" in host:
        raise DangerousPatternError(
            f"penempatan wildcard hanya diawali '*.' — ditolak: {raw!r}")

    host = _clean_host(host)
    if host is None:
        raise PolicyError(f"bentuk host aturan tidak valid: {raw!r}")
    if wild:
        if "." not in host:
            raise DangerousPatternError(
                f"wildcard ber-label tunggal menolak: {raw!r} — akan "
                f"memasukkan seluruh TLD")
        if host in _PUBLIC_SUFFIXES:
            raise DangerousPatternError(
                f"wildcard di atas public suffix {host!r} ditolak: {raw!r} — "
                f"akan memasukkan seluruh suffix ke scope")
    return {"kind": "domain", "raw": raw.strip(), "wild": wild, "base": host,
            "port": port, "path": path, "type": declared_type}


# --- pembacaan kebijakan ------------------------------------------------------


class ParsedPolicy:
    """Hasil parse kebijakan: identitas program + daftar rule kedua sisi
    + catatan entri yang dilewati (non-jaringan / tak bisa diparse)."""

    def __init__(self, path: str, program: str,
                 in_rules: list, out_rules: list,
                 skipped: Optional[list] = None) -> None:
        self.path = path
        self.program = program
        self.in_rules = in_rules
        self.out_rules = out_rules
        self.skipped = skipped or []


def _entry_asset(entry: object, side: str) -> tuple:
    """Ekstrak (asset, declared_type) dari satu entri kebijakan.

    Entri boleh string polos atau object ber-field dikenali. Selain itu =
    bentuk tak dikenal -> PolicyError (fail-closed, bukan diabaikan).
    """
    if isinstance(entry, str):
        return entry, None
    if isinstance(entry, dict):
        for field in ASSET_FIELDS:
            value = entry.get(field)
            if isinstance(value, str) and value.strip():
                declared = None
                for tfield in TYPE_FIELDS:
                    tv = entry.get(tfield)
                    if isinstance(tv, str) and tv.strip():
                        declared = tv.strip().lower()
                        break
                if declared is not None and declared not in KNOWN_TYPES:
                    raise PolicyError(
                        f"tipe aset tak dikenal {declared!r} pada entri "
                        f"{side}: {entry!r}")
                return value, declared
        raise PolicyError(
            f"entri {side} tanpa field aset yang dikenali "
            f"({', '.join(ASSET_FIELDS)}): {entry!r}")
    raise PolicyError(f"bentuk entri {side} tidak dikenal: {entry!r}")


def parse_policy_file(path: str) -> ParsedPolicy:
    """Baca + validasi ekspor kebijakan JSON. Kegagalan bentuk = PolicyError.

    Entri bertipe non-jaringan dikenali (id aplikasi toko, kontrak pintar,
    dsb.), atau bertipe "other"/tanpa tipe yang tidak berbentuk jaringan,
    DILEWATI TERCATAT (policy.skipped) — bukan dijadikan rule tanpa dasar
    ("com.wolt.android" mirip domain tapi bukan host) dan bukan error.
    Entri bertipe jaringan yang gagal diparse = anomali ekspor -> PolicyError.
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"kebijakan tak bisa dibaca {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"kebijakan bukan JSON valid {path!r}: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError(f"kebijakan harus object JSON, dapat "
                          f"{type(data).__name__}: {path!r}")

    program = data.get("program")
    if program is not None and not isinstance(program, str):
        raise PolicyError(f"field 'program' harus string: {path!r}")

    # Parser memvalidasi BENTUK: in_scope boleh absen/kosong (klaim
    # larangan out_of_scope-only tetap berarti — dipakai aggregate).
    # Kecukupan isi adalah keputusan tiap tool: gate menolak jalan tanpa
    # satu pun aturan in-scope (tidak bisa mengizinkan apa pun).
    in_raw = data.get("in_scope", [])
    if not isinstance(in_raw, list):
        raise PolicyError(f"'in_scope' harus list: {path!r}")
    out_raw = data.get("out_of_scope", [])
    if not isinstance(out_raw, list):
        raise PolicyError(f"'out_of_scope' harus list: {path!r}")

    in_rules: list = []
    out_rules: list = []
    skipped: list = []
    for side, entries, rules in (("in_scope", in_raw, in_rules),
                                 ("out_of_scope", out_raw, out_rules)):
        for entry in entries:
            asset, declared = _entry_asset(entry, side)
            if declared in NON_NETWORK_TYPES:
                skipped.append({"side": side, "asset": asset,
                                "type": declared, "reason": "non_network"})
                continue
            try:
                rule = _parse_rule(asset, side, declared)
            except DangerousPatternError:
                raise  # pola overbroad selalu ditolak, apa pun tipenya
            except PolicyError:
                if declared in NETWORK_TYPES:
                    raise  # klaim aset jaringan yang tak bisa dinilai = anomali
                skipped.append({"side": side, "asset": asset,
                                "type": declared, "reason": "unparseable"})
                continue
            rules.append(rule)

    return ParsedPolicy(str(path), program or p.stem, in_rules, out_rules,
                        skipped)


# --- pencocokan ---------------------------------------------------------------


def _path_matches(url_path: str, pattern_path: Optional[str]) -> bool:
    """Prefix match dgn batas segmen: /api tidak cocok /apixyz.
    Aturan tanpa path (None atau '/') cocok dengan path apa pun."""
    if not pattern_path or pattern_path == "/":
        return True
    up = url_path or "/"
    return up == pattern_path[:-1] or up.startswith(pattern_path)


def _rule_matches(rule: Rule, target: dict) -> bool:
    """Cocokkan rule dengan target kanonik aset (host+port+path / IP)."""
    if rule["kind"] == "ip":
        if target["kind"] != "ip":
            return False
        return target["ip"] in rule["network"]

    if target["kind"] != "domain":
        return False
    host = target["host"]
    if rule["wild"]:
        if not host.endswith("." + rule["base"]):
            return False  # terjangkar: subdomain saja, apex tidak
    elif host != rule["base"]:
        return False
    eff_port = target["port"]
    if eff_port is None:
        eff_port = 443 if target["scheme"] == "https" else 80
    if rule["port"] is not None and rule["port"] != eff_port:
        return False
    if not _path_matches(target["path"], rule["path"]):
        return False
    return True


def _exclusion_matches(rule: Rule, target: dict) -> bool:
    """Cocokkan aturan OUT-OF-SCOPE.

    Eksak melarang host DAN subdomennya (melarang itu melarang cabangnya —
    "blog.target.com" juga memblokir "cdn.blog.target.com" yang sebaliknya
    lolos wildcard in-scope). Wildcard tetap terjangkar (*.staging tidak
    menutup apex staging)."""
    if rule["kind"] == "ip":
        return (target["kind"] == "ip" and target["ip"] in rule["network"])
    if target["kind"] != "domain":
        return False
    host = target["host"]
    if rule["wild"]:
        if not host.endswith("." + rule["base"]):
            return False
    elif host != rule["base"] and not host.endswith("." + rule["base"]):
        return False
    if rule["port"] is not None:
        eff = target["port"]
        if eff is None:
            eff = 443 if target["scheme"] == "https" else 80
        if eff != rule["port"]:
            return False
    if not _path_matches(target["path"], rule["path"]):
        return False
    return True


def evaluate(policy: ParsedPolicy, asset: str) -> dict:
    """Satu keputusan scope deterministik + atribusi aturan.

    Mengembalikan dict: asset, kind (domain/ip/invalid), verdict
    (IN_SCOPE/OUT_OF_SCOPE/NOT_IN_SCOPE/INVALID), matched_rule, rule_side,
    reason, severity (None/high/medium), finding (dict|None).

    Deny menang: out-of-scope dinilai sebelum in-scope. Apa pun yang tidak
    terbukti in-scope = bukan izin (fail-closed).
    """
    target = _parse_asset(asset)
    if target is None:
        return {
            "asset": asset, "kind": "invalid", "verdict": "INVALID",
            "matched_rule": None, "rule_side": None,
            "reason": ("aset kosong/malformed/ambigu (skema aneh, encoding "
                       "IP ambigu, karakter terlarang) — fail-closed, "
                       "jangan diuji"),
            "severity": "high",
            "finding": {"kind": "invalid_asset", "severity": "high"},
        }

    if target["kind"] == "ip":
        kind = "ip"
        desc = str(target["ip"])
    else:
        kind = "domain"
        desc = target["host"] + (
            f":{target['port']}" if target["port"] is not None else "")
        if target["path"] != "/":
            desc += target["path"]

    for rule in policy.out_rules:
        if _exclusion_matches(rule, target):
            return {
                "asset": asset, "kind": kind, "verdict": "OUT_OF_SCOPE",
                "matched_rule": rule["raw"], "rule_side": "out_of_scope",
                "reason": (f"{desc} kena aturan out-of-scope "
                           f"{rule['raw']!r} — JANGAN DIUJI"),
                "severity": "high",
                "finding": {"kind": "out_of_scope", "severity": "high"},
            }

    for rule in policy.in_rules:
        if _rule_matches(rule, target):
            return {
                "asset": asset, "kind": kind, "verdict": "IN_SCOPE",
                "matched_rule": rule["raw"], "rule_side": "in_scope",
                "reason": f"{desc} cocok aturan in-scope {rule['raw']!r}",
                "severity": None, "finding": None,
            }

    return {
        "asset": asset, "kind": kind, "verdict": "NOT_IN_SCOPE",
        "matched_rule": None, "rule_side": None,
        "reason": (f"{desc} tidak cocok aturan in-scope mana pun — "
                   f"belum terbukti boleh (fail-closed), jangan diuji "
                   f"sebelum kebijakan diklarifikasi"),
        "severity": "medium",
        "finding": {"kind": "not_in_scope", "severity": "medium"},
    }


# --- CLI ----------------------------------------------------------------------


def _read_asset_file(path: str) -> list:
    """Baca daftar aset satu-per-baris; baris kosong dilewati."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"file aset tak bisa dibaca {path!r}: {exc}") from exc
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Gerbang scope deterministik: cek aset terhadap "
                     "ekspor kebijakan JSON sebelum ada request. "
                     "NOL jaringan."))
    parser.add_argument("--policy", required=True,
                        help="path ekspor kebijakan JSON (in_scope/out_of_scope)")
    parser.add_argument("--check", nargs="+", metavar="ASET",
                        help="aset yang dicek (domain/URL/IP, boleh banyak)")
    parser.add_argument("--explain", nargs="+", metavar="ASET",
                        help="spt --check + tunjukkan aturan mana yang kena")
    parser.add_argument("--check-file", metavar="FILE",
                        help="file daftar aset satu per baris")
    parser.add_argument("--out", metavar="FILE",
                        help="tulis bukti JSON ke file")
    parser.add_argument("--json", action="store_true",
                        help="cetak JSON ke stdout")
    parser.add_argument("--fail-on", choices=("any", "high"), default="any",
                        help="ambang exit 1: any = semua temuan (default), "
                             "high = hanya temuan high")
    args = parser.parse_args(argv)

    if args.check and args.explain:
        parser.error("--check dan --explain saling eksklusif")
    if not args.check and not args.explain and not args.check_file:
        parser.error("butuh --check ASET / --explain ASET / --check-file FILE")

    try:
        policy = parse_policy_file(args.policy)
        if not policy.in_rules:
            raise PolicyError(
                f"kebijakan {args.policy!r} tanpa satu pun aturan in-scope "
                f"— gerbang tidak bisa mengizinkan apa pun, tolak "
                f"(fail-closed) daripada menolak semua aset diam-diam")
        assets = list(args.explain or args.check or [])
        if args.check_file:
            assets.extend(_read_asset_file(args.check_file))
        if not assets:
            parser.error("tidak ada aset yang dicek")
    except PolicyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    results = [evaluate(policy, a) for a in assets]
    findings = [r["finding"] | {"asset": r["asset"], "verdict": r["verdict"],
                                "matched_rule": r["matched_rule"],
                                "reason": r["reason"]}
                for r in results if r["finding"]]
    in_count = sum(1 for r in results if r["verdict"] == "IN_SCOPE")

    # Entri kebijakan tak terparse DILEWATI — itu keterbatasan penegakan
    # nyata (mis. prosa "All other assets" tidak bisa dimodelkan): angkat
    # jadi temuan policy-level agar wajib direview, bukan hilang senyap.
    suspicious = [s for s in policy.skipped if s["reason"] == "unparseable"]
    if suspicious:
        detail = "; ".join(f"{s['side']}:{s['asset']!r}"
                           for s in suspicious[:5])
        findings.append({
            "kind": "policy_skipped_unparseable", "severity": "medium",
            "asset": f"{len(suspicious)} entri kebijakan tak terparse",
            "verdict": "POLICY_WARNING", "matched_rule": None,
            "reason": (f"entri kebijakan dilewati (tidak bisa diparse) — "
                       f"review ekspor: {detail}"
                       + (" ..." if len(suspicious) > 5 else "")),
        })

    threshold_severities = {"any": {"high", "medium"}, "high": {"high"}}
    breached = any(f["severity"] in threshold_severities[args.fail_on]
                   for f in findings)
    exit_code = 1 if breached else 0

    evidence = {
        "schema": SCHEMA,
        "tool": TOOL,
        "policy": args.policy,
        "program": policy.program,
        "fail_on": args.fail_on,
        "checked": len(results),
        "in_scope_count": in_count,
        "finding_count": len(findings),
        "skipped_count": len(policy.skipped),
        "skipped": policy.skipped,
        "results": results,
        "findings": findings,
        "exit": exit_code,
    }

    if args.out:
        try:
            Path(args.out).write_text(
                json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: bukti tak bisa ditulis {args.out!r}: {exc}",
                  file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(evidence, indent=2, ensure_ascii=False))
    else:
        show_rule = args.explain is not None
        for r in results:
            if r["verdict"] == "IN_SCOPE":
                line = f"IN-SCOPE: {r['asset']}"
            else:
                sev = (r["severity"] or "?").upper()
                label = {"OUT_OF_SCOPE": "OUT-OF-SCOPE",
                         "NOT_IN_SCOPE": "NOT-IN-SCOPE",
                         "INVALID": "INVALID"}[r["verdict"]]
                line = f"{label} ({sev}): {r['asset']}"
            if show_rule and r["matched_rule"]:
                line += f" [rule: {r['matched_rule']}]"
            print(line)
            if show_rule:
                print(f"  reason: {r['reason']}")
        print(f"Ringkasan: {len(results)} dicek, {in_count} in-scope, "
              f"{len(findings)} temuan -> exit {exit_code}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
