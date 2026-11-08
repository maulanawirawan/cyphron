"""Nol jaringan — test rsa_key_audit (audit kunci RSA dari PEM/SSH).

Fixture DER dibangun inline (tanpa lib kripto): PKCS#1 publik/privat,
PKCS#8, SPKI, OpenSSH privat cipher=none, wire kunci publik SSH —
semua struktur ditulis manual sesuai spesifikasi, bukan kunci asli.
Tidak ada request jaringan.
"""
from __future__ import annotations

import base64
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import rsa_key_audit as rka  # noqa: E402
from findings import validate_finding  # noqa: E402


# --------------------------------------------------------------- DER
def der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + der_len(len(b)) + b


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_seq(*items: bytes) -> bytes:
    body = b"".join(items)
    return b"\x30" + der_len(len(body)) + body


def der_oid_rsa() -> bytes:
    return b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


def der_bitstr(data: bytes) -> bytes:
    return b"\x03" + der_len(len(data) + 1) + b"\x00" + data


def der_octet(data: bytes) -> bytes:
    return b"\x04" + der_len(len(data)) + data


def pem(t: str, body: bytes) -> str:
    b64 = base64.b64encode(body).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return (f"-----BEGIN {t}-----\n{lines}\n"
            f"-----END {t}-----\n")


N1024 = (1 << 1023) | 12345678901234567899
N2048 = (1 << 2047) | 999983
N3072 = (1 << 3071) | 999983
E3 = 3
E65537 = 65537


def pkcs1_pub(n: int, e: int) -> bytes:
    return der_seq(der_int(n), der_int(e))


def pkcs1_priv(n: int, e: int) -> bytes:
    return der_seq(der_int(0), der_int(n), der_int(e),
                   der_int(0x10001), der_int(3), der_int(0x10001))


def spki(n: int, e: int) -> bytes:
    return der_seq(der_seq(der_oid_rsa(), b"\x05\x00"),
                   der_bitstr(pkcs1_pub(n, e)))


def pkcs8_priv(n: int, e: int) -> bytes:
    return der_seq(der_int(0), der_seq(der_oid_rsa(), b"\x05\x00"),
                   der_octet(pkcs1_priv(n, e)))


def openssh_priv(n: int, e: int, cipher: str = "none") -> bytes:
    blob_name = b"ssh-rsa"
    pub = (struct.pack(">I", len(blob_name)) + blob_name
           + struct.pack(">I", 3) + e.to_bytes(3, "big")
           + struct.pack(">I", (n.bit_length() + 7) // 8)
           + n.to_bytes((n.bit_length() + 7) // 8, "big"))
    body = b"openssh-key-v1\x00"
    body += struct.pack(">I", len(cipher)) + cipher.encode()
    body += struct.pack(">I", len("none")) + b"none"
    body += struct.pack(">I", 0)  # kdf options kosong
    body += struct.pack(">I", 1) + struct.pack(">I", len(pub)) + pub
    body += struct.pack(">I", 42) + b"\x00" * 42  # encrypted section dummy
    return body


def ssh_rsa_line(n: int, e: int, comment: str = "lab@host") -> str:
    blob = (struct.pack(">I", 7) + b"ssh-rsa"
            + struct.pack(">I", (e.bit_length() + 7) // 8)
            + e.to_bytes((e.bit_length() + 7) // 8, "big")
            + struct.pack(">I", (n.bit_length() + 7) // 8)
            + n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return f"ssh-rsa {base64.b64encode(blob).decode()} {comment}"


def _tmpfile(content: str, suffix: str = ".pem") -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                     encoding="utf-8") as fh:
        fh.write(content)
        return Path(fh.name)


class TestPemParse(unittest.TestCase):
    def test_pkcs1_public_1024(self):
        f = _tmpfile(pem("RSA PUBLIC KEY", pkcs1_pub(N1024, E65537)))
        info = rka.parse_file(f)
        self.assertEqual(info["kind"], "public")
        self.assertEqual(info["bits"], 1024)
        self.assertEqual(info["exponent"], 65537)

    def test_spki_public_2048(self):
        f = _tmpfile(pem("PUBLIC KEY", spki(N2048, E65537)))
        info = rka.parse_file(f)
        self.assertEqual(info["bits"], 2048)
        self.assertEqual(info["exponent"], 65537)

    def test_pkcs1_private_unencrypted(self):
        f = _tmpfile(pem("RSA PRIVATE KEY", pkcs1_priv(N1024, E3)))
        info = rka.parse_file(f)
        self.assertEqual(info["kind"], "private")
        self.assertFalse(info["encrypted"])
        self.assertEqual(info["bits"], 1024)
        self.assertEqual(info["exponent"], 3)

    def test_pkcs8_private(self):
        f = _tmpfile(pem("PRIVATE KEY", pkcs8_priv(N2048, E65537)))
        info = rka.parse_file(f)
        self.assertEqual(info["bits"], 2048)
        self.assertFalse(info["encrypted"])

    def test_openssh_cipher_none(self):
        f = _tmpfile(pem("OPENSSH PRIVATE KEY",
                         openssh_priv(N2048, E65537, cipher="none")))
        info = rka.parse_file(f)
        self.assertEqual(info["kind"], "private")
        self.assertFalse(info["encrypted"])
        self.assertEqual(info["cipher"], "none")

    def test_openssh_cipher_bcrypt(self):
        f = _tmpfile(pem("OPENSSH PRIVATE KEY",
                         openssh_priv(N2048, E65537,
                                      cipher="aes256-ctr")))
        info = rka.parse_file(f)
        self.assertTrue(info["encrypted"])

    def test_ssh_rsa_line(self):
        f = _tmpfile(ssh_rsa_line(N1024, E65537) + " user@lab\n",
                     suffix=".pub")
        info = rka.parse_file(f)
        self.assertEqual(info["kind"], "public")
        self.assertEqual(info["bits"], 1024)

    def test_certificate_skipped(self):
        f = _tmpfile(pem("CERTIFICATE", b"\x30\x03\x02\x01\x00"))
        self.assertIsNone(rka.parse_file(f))


class TestAuditFindings(unittest.TestCase):
    def _audit(self, path: Path):
        return rka.audit_file(path, 2048, "windows")

    def _assert_contract(self, findings):
        for f in findings:
            self.assertEqual(validate_finding(f), [])
            self.assertEqual(f["status"], "confirmed")

    def test_1024_high(self):
        f = _tmpfile(pem("RSA PUBLIC KEY", pkcs1_pub(N1024, E65537)))
        findings, note = self._audit(f)
        self._assert_contract(findings)
        self.assertEqual(note["bits"], 1024)
        sevs = [x["severity"] for x in findings]
        self.assertIn("high", sevs)
        self.assertTrue(all(x["poc"] for x in findings))

    def test_2048_info_2030(self):
        f = _tmpfile(pem("PUBLIC KEY", spki(N2048, E65537)))
        findings, _ = self._audit(f)
        self._assert_contract(findings)
        self.assertEqual([x["severity"] for x in findings], ["info"])
        self.assertIn("2030", findings[0]["description"])

    def test_3072_clean(self):
        f = _tmpfile(pem("PUBLIC KEY", spki(N3072, E65537)))
        findings, _ = self._audit(f)
        self.assertEqual(findings, [])

    def test_exponent_3_high(self):
        f = _tmpfile(pem("RSA PRIVATE KEY", pkcs1_priv(N2048, E3)))
        findings, _ = self._audit(f)
        self._assert_contract(findings)
        self.assertTrue(any(x["severity"] == "high"
                            and "e=3" in x["title"] for x in findings))

    def test_unencrypted_private(self):
        f = _tmpfile(pem("RSA PRIVATE KEY", pkcs1_priv(N2048, E65537)))
        findings, _ = self._audit(f)
        self._assert_contract(findings)
        self.assertTrue(any(x["severity"] == "medium"
                            and "passphrase" in x["title"]
                            for x in findings))

    def test_openssh_none_unencrypted(self):
        f = _tmpfile(pem("OPENSSH PRIVATE KEY",
                         openssh_priv(N2048, E65537)))
        findings, _ = self._audit(f)
        self.assertTrue(any("passphrase" in x["title"] for x in findings))

    def test_openssh_bcrypt_no_flag(self):
        f = _tmpfile(pem("OPENSSH PRIVATE KEY",
                         openssh_priv(N2048, E65537,
                                      cipher="bcrypt")))
        findings, _ = self._audit(f)
        self.assertEqual(findings, [])

    def test_ssh_line_1024(self):
        f = _tmpfile(ssh_rsa_line(N1024, E65537), suffix=".pub")
        findings, note = self._audit(f)
        self.assertEqual(note["bits"], 1024)
        self.assertTrue(any(x["severity"] == "high" for x in findings))

    def test_unrelated_pem_skipped(self):
        f = _tmpfile(pem("CERTIFICATE", b"\x30\x03\x02\x01\x00"))
        findings, note = self._audit(f)
        self.assertEqual(findings, [])
        self.assertEqual(note["status"], "skipped")
        self.assertIn("CERTIFICATE", note["detail"])

    def test_garbage_skipped(self):
        f = _tmpfile("ini bukan kunci sama sekali\n", ".txt")
        findings, note = self._audit(f)
        self.assertEqual(findings, [])
        self.assertEqual(note["status"], "skipped")


class TestMain(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, Path]:
        out = Path(tempfile.mkdtemp()) / "findings.json"
        rc = rka.main(argv + ["--out", str(out)])
        return rc, out

    def test_findings_exit1(self):
        f1 = _tmpfile(pem("RSA PUBLIC KEY", pkcs1_pub(N1024, E65537)))
        f2 = _tmpfile(pem("PUBLIC KEY", spki(N2048, E65537)))
        rc, out = self._run(["--key", f"{f1},{f2}"])
        self.assertEqual(rc, 1)
        doc = __import__("json").loads(
            out.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["findings"]), 2)
        self.assertEqual(doc["data"]["parsed"], 2)
        self.assertEqual(doc["data"]["bits_distribution"].get("1024"), 1)

    def test_clean_exit0(self):
        f = _tmpfile(pem("PUBLIC KEY", spki(N3072, E65537)))
        rc, out = self._run(["--key", str(f)])
        self.assertEqual(rc, 0)
        doc = __import__("json").loads(
            out.read_text(encoding="utf-8"))
        self.assertEqual(doc["findings"], [])

    def test_no_keys_exit2(self):
        g = _tmpfile("garbage file\n", ".txt")
        rc, _ = self._run(["--key", str(g)])
        self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc, _ = self._run(["--key", "tidak-ada.pem"])
        self.assertEqual(rc, 2)

    def test_no_input_exit2(self):
        rc, _ = self._run([])
        self.assertEqual(rc, 2)

    def test_dir_scan(self):
        d = Path(tempfile.mkdtemp())
        (d / "a.pub").write_text(ssh_rsa_line(N1024, E65537),
                                 encoding="utf-8")
        (d / "readme.txt").write_text("bukan kunci", encoding="utf-8")
        rc, out = self._run(["--dir", str(d)])
        self.assertEqual(rc, 1)
        doc = __import__("json").loads(
            out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["parsed"], 1)


if __name__ == "__main__":
    unittest.main()
