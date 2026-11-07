"""test_webshell_triage — triase webshell dari access log (#0565), nol
jaringan.

Fixture = access log CLF/combined sintetis. Pembagian ranah diuji:
sqli/lfi/xss di URI = web_log_intrusion (B07) — tool ini hanya webshell.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import webshell_triage as wt  # noqa: E402


def _line(ip: str, method: str, uri: str, status: int = 200,
          t: str = "18/Mar/2026:02:00:00 +0000",
          ua: str = "Mozilla/5.0") -> str:
    return (f'{ip} - - [{t}] "{method} {uri} HTTP/1.1" {status} 123 '
            f'"-" "{ua}"')


def _file(tmp_path: Path, lines: list[str], name: str = "acc.log") -> Path:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "webshell_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _findings(out, check):
    return [x for x in out["findings"] if x["check"] == check]


# ------------------------------------------------------- cek per-request
def test_cmd_param_high(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/uploads/img.php?cmd=whoami")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1, err
    f = _findings(out, "webshell-cmd-param")
    assert len(f) == 1 and f[0]["severity"] == "high"


def test_cmd_token_in_query(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/x.aspx?q=ipconfig&all=1")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1
    assert len(_findings(out, "webshell-cmd-param")) == 1


def test_encoded_cmd_param_decoded(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "POST",
                               "/up/shell.php?%63%6d%64=dir")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1
    f = _findings(out, "webshell-cmd-param")
    assert len(f) == 1


def test_webshell_name_high(tmp_path):
    for name in ("cmd.aspx", "shell.jsp", "wso.php", "b374k.php",
                 "aspxspy.aspx"):
        p = _file(tmp_path, [_line("203.0.113.5", "GET",
                                   f"/assets/{name}")],
                  name=f"{name}.log")
        rc, out, err = _run("--log", str(p), "--json")
        assert rc == 1, name
        assert len(_findings(out, "webshell-name")) == 1, name


def test_script_in_upload_dir(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/sites/default/files/cv.php")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1
    assert len(_findings(out, "script-in-upload-dir")) == 1


def test_double_extension(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/media/avatar.php;.jpg")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1
    assert len(_findings(out, "script-in-upload-dir")) == 1


def test_normal_script_not_in_upload_clean(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET", "/index.php"),
                         _line("203.0.113.5", "GET", "/api/v1/users"),
                         _line("203.0.113.5", "GET", "/login.php")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0 and out["findings"] == []


def test_post_to_static_ext_medium(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "POST",
                               "/uploads/note.txt", 200)])
    rc, out, err = _run("--log", str(p), "--fail-on", "medium", "--json")
    f = _findings(out, "post-to-static-ext")
    assert len(f) == 1 and f[0]["severity"] == "medium"


def test_post_to_static_4xx_not_flagged(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "POST",
                               "/uploads/note.txt", 404)])
    rc, out, err = _run("--log", str(p), "--fail-on", "low", "--json")
    assert _findings(out, "post-to-static-ext") == []


# ------------------------------------------------------- tomcat manager
def test_tomcat_manager_200_high_403_medium(tmp_path):
    p1 = _file(tmp_path, [_line("203.0.113.5", "POST",
                                "/manager/html/upload", 200)],
               name="a.log")
    rc1, out1, _ = _run("--log", str(p1), "--json")
    assert rc1 == 1
    assert _findings(out1, "tomcat-manager-deploy")[0]["severity"] == \
        "high"
    p2 = _file(tmp_path, [_line("203.0.113.5", "POST",
                                "/manager/html/", 403)], name="b.log")
    _, out2, _ = _run("--log", str(p2), "--fail-on", "medium", "--json")
    f2 = _findings(out2, "tomcat-manager-deploy")
    assert len(f2) == 1 and f2[0]["severity"] == "medium"


# ------------------------------------------------------- agregasi burst
def test_post_burst(tmp_path):
    t0 = "18/Mar/2026:02:00:0"
    lines = [_line("203.0.113.9", "POST", "/app/api.php?a=1", 200,
                   t=f"{t0}{i} +0000") for i in range(5)]
    rc, out, err = _run("--log", str(_file(tmp_path, lines)),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "webshell-post-burst")
    assert len(f) == 1 and "5 POST" in f[0]["message"]


def test_post_burst_below_threshold(tmp_path):
    lines = [_line("203.0.113.9", "POST", "/app/api.php?a=1", 200,
                   t=f"18/Mar/2026:02:00:0{i} +0000")
             for i in range(4)]
    rc, out, err = _run("--log", str(_file(tmp_path, lines)),
                        "--fail-on", "low", "--json")
    assert _findings(out, "webshell-post-burst") == []


def test_burst_custom_threshold_and_window(tmp_path):
    lines = [_line("203.0.113.9", "POST", "/app/api.php", 200,
                   t=f"18/Mar/2026:02:0{i}:00 +0000") for i in range(3)]
    rc, out, err = _run("--log", str(_file(tmp_path, lines)),
                        "--fail-on", "medium", "--burst", "3",
                        "--window", "180", "--json")
    assert len(_findings(out, "webshell-post-burst")) == 1


# ------------------------------------------------------- anti-FP
def test_allow_uri_and_ip(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/uploads/img.php?cmd=whoami")])
    rc, out, err = _run("--log", str(p), "--json",
                        "--allow-uri", "img.php")
    assert rc == 0 and out["findings"] == []
    rc2, out2, _ = _run("--log", str(_file(tmp_path, [_line(
        "203.0.113.5", "GET", "/uploads/img.php?cmd=whoami")],
        name="b.log")), "--json", "--allow-ip", "203.0.113.5")
    assert rc2 == 0 and out2["findings"] == []


# ------------------------------------------------------- fail-closed
def test_garbage_log_fails_closed(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("this is not a log\nat all\n", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2


def test_skipped_lines_counted(tmp_path):
    p = _file(tmp_path, [_line("203.0.113.5", "GET", "/index.php"),
                         "garbage line",
                         _line("203.0.113.5", "GET", "/about")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0 and out["stats"]["lines_skipped"] == 1


def test_no_timestamp_evaluated_but_excluded_from_burst(tmp_path):
    lines = [_line("203.0.113.9", "POST", "/app/api.php", 200,
                   t="bad/timestamp") for _ in range(6)]
    rc, out, err = _run("--log", str(_file(tmp_path, lines)),
                        "--fail-on", "low", "--json")
    assert _findings(out, "webshell-post-burst") == []
    assert out["stats"]["no_timestamp"] == 6
    assert any("timestamp" in n for n in out["notes"])


# ------------------------------------------------------- modes
def test_dir_mode_determinism_out(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "a.log").write_text(
        _line("203.0.113.5", "GET", "/uploads/x.php?cmd=id") + "\n",
        encoding="utf-8")
    (d / "b.log").write_text(
        _line("203.0.113.6", "POST", "/manager/html/", 200) + "\n",
        encoding="utf-8")
    rc1, o1, _ = _run("--dir", str(d), "--json")
    rc2, o2, _ = _run("--dir", str(d), "--json")
    assert rc1 == rc2 == 1 and o1 == o2
    outp = tmp_path / "rep.json"
    rc3, _, _ = _run("--dir", str(d), "--out", str(outp))
    assert rc3 == 1
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        wt.SCHEMA


def test_sqli_not_duplicated_here(tmp_path):
    # ranah web_log_intrusion B07: sqli/lfi/xss tidak ditandai di sini
    p = _file(tmp_path, [_line("203.0.113.5", "GET",
                               "/index.php?id=1%20union%20select%20*%20"
                               "from%20users")])
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0 and out["findings"] == []
