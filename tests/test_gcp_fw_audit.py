"""test_gcp_fw_audit — audit ekspor firewall rules GCP offline (#0630),
nol jaringan, tanpa kredensial gcloud.

Fixture = ekspor JSON gcloud sintetis dari kelas risiko publik
(world-open port manajemen/DB, tanpa default-deny egress, logging mati);
bukan salinan kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import gcp_fw_audit as gfa  # noqa: E402


def _write(tmp_path, name: str, doc) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gcp_fw_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


def _rule(name: str, **kw) -> dict:
    rule = {
        "name": name,
        "direction": "INGRESS",
        "priority": 1000,
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
        "sourceRanges": ["10.0.0.0/8"],
        "logConfig": {"enable": False},
    }
    rule.update(kw)
    return rule


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gcp_fw_audit.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--rules", str(tmp_path / "nope.json"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_invalid_json_exit2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{bukan json", encoding="utf-8")
    rc, out, _ = _run("--rules", str(p))
    assert rc == 2 and out is None


def test_wrong_shape_exit2(tmp_path):
    p = _write(tmp_path, "shape.json", {"bukan": "list"})
    rc, out, _ = _run("--rules", str(p))
    assert rc == 2 and out is None


def test_empty_list_exit2(tmp_path):
    p = _write(tmp_path, "empty.json", [])
    rc, out, _ = _run("--rules", str(p))
    assert rc == 2 and out is None


def _deny_egress(name: str = "deny-all-egress") -> dict:
    return _rule(name, direction="EGRESS", priority=65534,
                 allowed=[], denied=[{"IPProtocol": "all"}],
                 sourceRanges=[], destinationRanges=["0.0.0.0/0"])


def test_single_object_accepted(tmp_path):
    p = _write(tmp_path, "one.json", _rule("allow-ssh-from-intranet"))
    rc, out, _ = _run("--rules", str(p))
    assert rc == 0 and out["stats"]["rules_total"] == 1


# ------------------------------------------------------- ingress
def test_clean_internal_rules(tmp_path):
    doc = [
        _rule("allow-internal-ssh", allowed=[{"IPProtocol": "tcp",
                                              "ports": ["22"]}],
              sourceRanges=["10.0.1.0/24"]),
        _rule("allow-https-web", sourceRanges=["10.10.0.0/16"],
              logConfig={"enable": True}),
        _rule("allow-egress-dns", direction="EGRESS",
              allowed=[{"IPProtocol": "udp", "ports": ["53"]}],
              destinationRanges=["8.8.8.8/32"]),
        _deny_egress(),
    ]
    p = _write(tmp_path, "clean.json", doc)
    rc, out, _ = _run("--rules", str(p))
    assert rc == 0 and out["findings"] == []
    assert out["stats"]["no_egress_deny"] == 1
    assert out["stats"]["logging_enabled"] == 1


def test_world_open_ssh_critical(tmp_path):
    p = _write(tmp_path, "ssh.json", [
        _rule("default-allow-ssh", allowed=[{"IPProtocol": "tcp",
                                             "ports": ["22"]}],
              sourceRanges=["0.0.0.0/0"]),
    ])
    rc, out, _ = _run("--rules", str(p))
    checks = _checks(out)
    assert "ingress-open-mgmt" in checks
    assert rc == 1
    sev = {f["check"]: f["severity"] for f in out["findings"]}
    assert sev["ingress-open-mgmt"] == "critical"


def test_world_open_rdp_and_all_protocol(tmp_path):
    doc = [
        _rule("allow-rdp", allowed=[{"IPProtocol": "tcp",
                                     "ports": ["3389"]}],
              sourceRanges=["::/0"]),
        _rule("allow-all", allowed=[{"IPProtocol": "all"}],
              sourceRanges=["0.0.0.0/0"]),
    ]
    p = _write(tmp_path, "rdp.json", doc)
    rc, out, _ = _run("--rules", str(p))
    checks = _checks(out)
    assert checks.count("ingress-open-mgmt") == 2  # rdp + all
    assert rc == 1


def test_world_open_db_critical(tmp_path):
    for port in ("3306", "5432", "6379", "27017"):
        doc = [_rule(f"db-{port}", allowed=[{"IPProtocol": "tcp",
                                             "ports": [port]}],
                    sourceRanges=["0.0.0.0/0"])]
        p = _write(tmp_path, f"db{port}.json", doc)
        rc, out, _ = _run("--rules", str(p))
        assert "ingress-open-db" in _checks(out)
        assert rc == 1


def test_world_open_port_range_covers_mgmt(tmp_path):
    p = _write(tmp_path, "range.json", [
        _rule("wide-range", allowed=[{"IPProtocol": "tcp",
                                      "ports": ["20-30"]}],
              sourceRanges=["0.0.0.0/0"]),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "ingress-open-mgmt" in _checks(out) and rc == 1


def test_tcp_without_ports_is_all_ports(tmp_path):
    p = _write(tmp_path, "any.json", [
        _rule("allow-all-tcp", allowed=[{"IPProtocol": "tcp"}],
              sourceRanges=["0.0.0.0/0"]),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "ingress-open-any" in _checks(out) and rc == 1


def test_world_open_web_is_medium(tmp_path):
    p = _write(tmp_path, "web.json", [
        _rule("allow-http", allowed=[{"IPProtocol": "tcp",
                                      "ports": ["80"]}],
              sourceRanges=["0.0.0.0/0"], logConfig={"enable": True}),
        _deny_egress(),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "ingress-open-world" in _checks(out)
    assert rc == 0  # medium tidak memicu default high
    rc2, _, _ = _run("--rules", str(p), "--fail-on", "medium")
    assert rc2 == 1


def test_ingress_untargeted_flagged(tmp_path):
    p = _write(tmp_path, "tgt.json", [
        _rule("allow-http-anywhere", allowed=[{"IPProtocol": "tcp",
                                               "ports": ["80"]}],
              sourceRanges=["0.0.0.0/0"], logConfig={"enable": True}),
        _rule("allow-http-web-only", allowed=[{"IPProtocol": "tcp",
                                               "ports": ["80"]}],
              sourceRanges=["0.0.0.0/0"], targetTags=["web"],
              logConfig={"enable": True}),
        _deny_egress(),
    ])
    _, out, _ = _run("--rules", str(p))
    checks = _checks(out)
    assert checks.count("ingress-untargeted") == 1


def test_disabled_rule_medium(tmp_path):
    p = _write(tmp_path, "dis.json", [
        _rule("old-rule", disabled=True, logConfig={"enable": True}),
        _deny_egress(),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "rule-disabled" in _checks(out)
    assert out["stats"]["disabled"] == 1
    assert rc == 0


def test_port_not_numeric_ignored(tmp_path):
    p = _write(tmp_path, "odd.json", [
        _rule("weird", allowed=[{"IPProtocol": "tcp",
                                 "ports": ["??"],
                                 }],
              sourceRanges=["0.0.0.0/0"]),
    ])
    _, out, _ = _run("--rules", str(p))
    # entry dengan ports tak ter-parse tetap world-open (medium)
    assert "ingress-open-world" in _checks(out)


# ------------------------------------------------------- postur proyek
def test_egress_no_deny_high(tmp_path):
    p = _write(tmp_path, "egress.json", [
        _rule("allow-internal-ssh", sourceRanges=["10.0.0.0/8"]),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "egress-no-deny" in _checks(out) and rc == 1
    assert out["stats"]["no_egress_deny"] == 0


def test_egress_tcp_udp_deny_suppresses(tmp_path):
    doc = [
        _rule("allow-internal-ssh", sourceRanges=["10.0.0.0/8"]),
        _rule("deny-egress", direction="EGRESS", priority=65534,
              denied=[{"IPProtocol": "tcp"}, {"IPProtocol": "udp"}],
              destinationRanges=["0.0.0.0/0"]),
    ]
    p = _write(tmp_path, "egress2.json", doc)
    rc, out, _ = _run("--rules", str(p))
    assert "egress-no-deny" not in _checks(out) and rc == 0


def test_logging_absent_medium(tmp_path):
    p = _write(tmp_path, "log.json", [
        _rule("allow-internal-ssh", sourceRanges=["10.0.0.0/8"]),
        _deny_egress(),
    ])
    rc, out, _ = _run("--rules", str(p))
    assert "firewall-logging-absent" in _checks(out) and rc == 0


def test_single_rule_describe_skips_project_checks(tmp_path):
    p = _write(tmp_path, "one.json",
               _rule("allow-internal-ssh", sourceRanges=["10.0.0.0/8"]))
    rc, out, _ = _run("--rules", str(p))
    checks = _checks(out)
    assert "egress-no-deny" not in checks
    assert "firewall-logging-absent" not in checks
    assert rc == 0
    assert any("satu objek rule" in n for n in out["notes"])


# ------------------------------------------------------- fail-closed
def test_unparsed_entry_high(tmp_path):
    p = _write(tmp_path, "mix.json", ["bukan-rule", _rule("ok-rule")])
    rc, out, _ = _run("--rules", str(p))
    assert "entry-unparsed" in _checks(out) and rc == 1
    assert out["stats"]["unparsed"] == 1
    assert any("fail-closed" in n for n in out["notes"])


# ------------------------------------------------------- anti-FP
def test_allow_rule_filters_and_records(tmp_path):
    doc = [
        _rule("default-allow-ssh", allowed=[{"IPProtocol": "tcp",
                                             "ports": ["22"]}],
              sourceRanges=["0.0.0.0/0"], logConfig={"enable": True}),
        _deny_egress(),
    ]
    p = _write(tmp_path, "allow.json", doc)
    rc, out, _ = _run("--rules", str(p), "--allow-rule", "default-allow-ssh")
    assert out["findings"] == [] and rc == 0
    assert out["stats"]["allowed_filtered"] == 2  # mgmt + untargeted
    assert any("--allow-rule" in n for n in out["notes"])


# ------------------------------------------------------- unit klasifikasi
def test_parse_ports_unit():
    proto, ranges = gfa._parse_ports({"IPProtocol": "tcp", "ports": ["22"]})
    assert proto == "tcp" and ranges == [(22, 22)]
    proto, ranges = gfa._parse_ports({"IPProtocol": "tcp"})
    assert ranges is None
    proto, ranges = gfa._parse_ports({"IPProtocol": "all"})
    assert proto == "all" and gfa._covers(ranges, 22)
    proto, ranges = gfa._parse_ports({"IPProtocol": "tcp",
                                      "ports": ["20-30"]})
    assert gfa._covers(ranges, 22) and not gfa._covers(ranges, 443)


def test_is_world_unit():
    assert gfa._is_world(["0.0.0.0/0"])
    assert gfa._is_world(["10.0.0.0/8", "::/0"])
    assert not gfa._is_world(["10.0.0.0/8"])
    assert not gfa._is_world(None)
