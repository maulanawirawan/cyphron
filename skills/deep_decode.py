"""[SAFETY: read-only] Deep decode & deobfuscation — berlapis hingga 8 lapis.

F14 — membongkar payload/secret/teks ter-enkode untuk debugging dan
verifikasi temuan (analisis data yang ada; tidak ada trafik). Mendukung:
base64 (termasuk nested), hex, URL-encode, gzip+base64, unicode escape,
octal escape, charCode array (String.fromCharCode), HTML entity, ROT13,
JWT (header.payload.signature) tanpa verifikasi.

Pemakaian:
  python skills/deep_decode.py --input "aGVsbG8=" --out f.json
  python skills/deep_decode.py --file obfuscated.js --out f.json
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_DEPTH = 8
RE_UNI = re.compile(r"\\u([0-9a-fA-F]{4})")
RE_OCT = re.compile(r"\\([0-3][0-7]{2})")
RE_CC = re.compile(r"String\.fromCharCode\(([\d,\s]+)\)")
RE_JWT = re.compile(r"^ey[A-Za-z0-9_\-]+\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")


def _try_b64(s: str) -> tuple[bool, str, str]:
    t = "".join(s.split())
    if len(t) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", t):
        return False, "", "b64"
    try:
        pad = t + "=" * (-len(t) % 4)
        raw = base64.b64decode(pad, validate=True)
        txt = raw.decode("utf-8")
        if sum(c.isprintable() for c in txt) / max(len(txt), 1) > 0.9:
            return True, txt, "base64"
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return False, "", "b64"


def _try_gzip_b64(s: str) -> tuple[bool, str, str]:
    try:
        pad = "".join(s.split()) + "=" * (-len("".join(s.split())) % 4)
        raw = base64.b64decode(pad, validate=True)
        if raw[:2] == b"\x1f\x8b":
            txt = gzip.decompress(raw).decode("utf-8", errors="replace")
            return True, txt, "gzip+base64"
    except (binascii.Error, OSError, ValueError):
        pass
    return False, "", "gzip"


def _try_hex(s: str) -> tuple[bool, str, str]:
    t = s.strip().replace("0x", "").replace("\\x", "").replace(" ", "")
    if len(t) < 8 or not re.fullmatch(r"[0-9a-fA-F]+", t) or len(t) % 2:
        return False, "", "hex"
    try:
        txt = binascii.unhexlify(t).decode("utf-8")
        if sum(c.isprintable() for c in txt) / max(len(txt), 1) > 0.9:
            return True, txt, "hex"
    except (binascii.Error, UnicodeDecodeError):
        pass
    return False, "", "hex"


def _try_url(s: str) -> tuple[bool, str, str]:
    if "%" not in s:
        return False, "", "url"
    try:
        import urllib.parse
        dec = urllib.parse.unquote_plus(s)
        return (dec != s, dec, "url")
    except Exception:
        return False, "", "url"


def _try_rot13(s: str) -> tuple[bool, str, str]:
    import codecs
    try:
        return True, codecs.decode(s, "rot_13"), "rot13"
    except Exception:
        return False, "", "rot13"


def _layers(s: str, rot13: bool = False) -> list[tuple[bool, str, str]]:
    layers = [
        _try_gzip_b64(s), _try_b64(s), _try_hex(s), _try_url(s),
        (bool(RE_JWT.match(s.strip())),
         json.dumps(decode_jwt(s.strip()), ensure_ascii=False), "jwt"),
        (bool(RE_UNI.search(s)),
         RE_UNI.sub(lambda m: chr(int(m.group(1), 16)), s), "unicode-escape"),
        (bool(RE_OCT.search(s)),
         RE_OCT.sub(lambda m: chr(int(m.group(1), 8)), s), "octal-escape"),
        (bool(RE_CC.search(s)),
         RE_CC.sub(lambda m: "".join(
             chr(int(x)) for x in m.group(1).split(",")), s), "charcode"),
        ("&#" in s or "&x" in s, html.unescape(s), "html-entity"),
    ]
    # rot13 TIDAK bisa dideteksi dari bentuknya (selalu "cocok") —
    # auto-chain rot13 membajak semua lapisan dengan teks sampah.
    # Maka rot13 hanya opt-in via flag.
    if rot13:
        layers.append(_try_rot13(s))
    return layers


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    out = {}
    for name, part in zip(("header", "payload"), parts[:2]):
        try:
            pad = part + "=" * (-len(part) % 4)
            out[name] = json.loads(base64.urlsafe_b64decode(pad))
        except Exception as exc:
            out[name] = f"__decode_error__ {exc}"
    out["signature"] = parts[2] if len(parts) > 2 else ""
    out["_note"] = "TIDAK diverifikasi — hanya didekode (analisis)"
    return out


def deep_decode(data: str, rot13: bool = False) -> dict:
    """Pecahkan berlapis sampai tak ada yang bisa didekode (maks 8 lapis)."""
    layers = []
    current = data.strip()
    for depth in range(MAX_DEPTH):
        hit = None
        for ok, decoded, name in _layers(current, rot13=rot13):
            if ok and decoded and decoded != current:
                hit = (decoded, name)
                break
        if not hit:
            break
        current, name = hit
        layers.append({"depth": depth + 1, "method": name,
                       "preview": current[:200]})
    return {"original_len": len(data), "layers": layers,
            "final": current, "depth_reached": len(layers),
            "max_depth": MAX_DEPTH}


def audit(data: str, source: str, rot13: bool = False) -> tuple[list[dict], dict]:
    result = deep_decode(data, rot13=rot13)
    rows = [make_finding(
        tool="deep-decode",
        title=f"Decoded {result['depth_reached']} layer(s) from {source}",
        severity="info",
        description="Analisis dekode/deobfuscasi berlapis (read-only). "
                    "Lapisan & hasil akhir tersimpan sebagai bukti.",
        response=json.dumps(result["layers"])[:400],
        evidence_kind="arithmetic", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "DEBUG", "safety_class": "read-only",
               "depth_reached": result["depth_reached"],
               "final_preview": result["final"][:300]})]
    return rows, result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", default=None, help="string yang dianalisis")
    ap.add_argument("--file", default=None, help="file yang dianalisis")
    ap.add_argument("--rot13", action="store_true",
                    help="aktifkan rot13 (opt-in — tak terdeteksi otomatis)")
    ap.add_argument("--out", default="decode_findings.json")
    args = ap.parse_args()
    if args.file:
        data = Path(args.file).read_text(encoding="utf-8", errors="replace")
        source = args.file
    elif args.input:
        data, source = args.input, "stdin-arg"
    else:
        print("butuh --input atau --file", file=sys.stderr)
        return 2
    rows, result = audit(data, source, rot13=args.rot13)
    write_findings(args.out, rows, {"source": source,
                                    "safety_class": "read-only",
                                    "result": result})
    print(f"deep-decode: {result['depth_reached']} lapis -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
