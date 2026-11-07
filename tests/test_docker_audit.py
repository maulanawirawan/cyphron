"""test_docker_audit — audit konfigurasi Docker offline (#0526 #0527),
nol jaringan, tanpa daemon.

Fixture = Dockerfile/daemon.json/compose sintetis dari kontrol hardening
kelas CIS Docker; bukan salinan kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import docker_audit as da  # noqa: E402


def _write(tmp_path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "docker_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- input
def test_no_target_error(tmp_path):
    rc, out, err = _run()
    assert rc == 2 and out is None


def test_missing_file_exit2(tmp_path):
    rc, out, _ = _run("--dockerfile", str(tmp_path / "nope"))
    assert rc == 2


def test_invalid_daemon_json_exit2(tmp_path):
    p = _write(tmp_path, "daemon.json", "{bukan json")
    rc, out, _ = _run("--daemon", str(p))
    assert rc == 2 and out is None


# ------------------------------------------------------- Dockerfile
GOOD_DOCKERFILE = """FROM python:3.12-slim@sha256:aaaa
WORKDIR /app
COPY . /app
USER 10001
HEALTHCHECK CMD python health.py
"""

def test_good_dockerfile_clean(tmp_path):
    p = _write(tmp_path, "Dockerfile", GOOD_DOCKERFILE)
    rc, out, _ = _run("--dockerfile", str(p))
    assert rc == 0 and out["findings"] == []


def test_latest_tag_and_root(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM ubuntu:latest\nCOPY . /app\n")
    rc, out, _ = _run("--dockerfile", str(p), "--fail-on", "medium")
    checks = _checks(out)
    assert "base-latest-tag" in checks and "runs-as-root" in checks
    assert rc == 1


def test_digest_pin_suppresses_base_checks(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM python:3.12-slim@sha256:bbb\nUSER app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    assert "base-latest-tag" not in _checks(out)
    assert "base-not-digest-pin" not in _checks(out)


def test_tag_without_digest_flagged_medium(tmp_path):
    p = _write(tmp_path, "Dockerfile", "FROM python:3.12-slim\nUSER app\n")
    rc, _, _ = _run("--dockerfile", str(p))
    assert rc == 0  # medium tidak memicu default high
    p2 = _write(tmp_path, "D2", "FROM python:3.12-slim\nUSER app\n")
    rc2, out2, _ = _run("--dockerfile", str(p2), "--fail-on", "medium")
    assert rc2 == 1 and "base-not-digest-pin" in _checks(out2)


def test_multistage_final_stage_user(tmp_path):
    content = """FROM golang:1.22@sha256:ccc AS builder
RUN go build .
FROM alpine:3.20@sha256:ddd
COPY --from=builder /app /app
ENTRYPOINT ["/app"]
"""
    p = _write(tmp_path, "Dockerfile", content)
    rc, out, _ = _run("--dockerfile", str(p))
    assert "runs-as-root" in _checks(out)
    # USER ada di stage builder saja -> tetap root di final.
    content2 = content + "USER nobody\n"
    p2 = _write(tmp_path, "D2", content2)
    rc2, out2, _ = _run("--dockerfile", str(p2))
    assert "runs-as-root" not in _checks(out2) and rc2 == 0


def test_curl_sh_install(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM alpine:3.20@sha256:ddd\n"
               "RUN curl -sSf https://get.example.sh | sh\n"
               "USER app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    assert rc == 1 and "curl-sh-install" in _checks(out)


def test_secret_in_env_and_arg(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM alpine:3.20@sha256:ddd\n"
               "ENV DB_PASSWORD=hunter2\n"
               "ARG deploy_token=ghp_xyz\n"
               "USER app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    assert rc == 1
    assert _checks(out).count("secret-in-env") == 2


def test_secret_env_reference_not_flagged(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM alpine:3.20@sha256:ddd\n"
               "ENV DB_PASSWORD=$DB_PASSWORD_FILE\n"
               "USER app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    assert "secret-in-env" not in _checks(out)


def test_add_remote_and_sudo(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM alpine:3.20@sha256:ddd\n"
               "ADD https://example.com/app.tar.gz /tmp/\n"
               "RUN sudo make install\n"
               "USER app\n")
    rc, out, _ = _run("--dockerfile", str(p), "--fail-on", "medium")
    checks = _checks(out)
    assert "add-remote" in checks and "sudo-in-run" in checks


def test_continuation_line_join(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM alpine:3.20@sha256:ddd\n"
               "RUN curl -sSf https://x.example/install.sh \\\n"
               "    | sh\n"
               "USER app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    assert "curl-sh-install" in _checks(out)


# ------------------------------------------------------- daemon.json
def test_remote_api_without_tls_high(tmp_path):
    p = _write(tmp_path, "daemon.json",
               json.dumps({"hosts": ["tcp://0.0.0.0:2375"]}))
    rc, out, _ = _run("--daemon", str(p))
    assert rc == 1 and "remote-api-plaintext" in _checks(out)


def test_remote_api_with_tls_ok(tmp_path):
    p = _write(tmp_path, "daemon.json",
               json.dumps({"hosts": ["tcp://0.0.0.0:2376"],
                           "tlsverify": True}))
    rc, out, _ = _run("--daemon", str(p))
    assert "remote-api-plaintext" not in _checks(out)


def test_icc_and_insecure_registries(tmp_path):
    p = _write(tmp_path, "daemon.json",
               json.dumps({"icc": True,
                           "insecure-registries": ["reg.corp:5000"]}))
    rc, out, _ = _run("--daemon", str(p), "--fail-on", "medium")
    checks = _checks(out)
    assert "icc-enabled" in checks and "insecure-registries" in checks


def test_log_unbounded(tmp_path):
    p = _write(tmp_path, "daemon.json", json.dumps({}))
    rc, out, _ = _run("--daemon", str(p), "--fail-on", "low")
    assert "log-unbounded" in _checks(out)


def test_log_maxsize_ok(tmp_path):
    p = _write(tmp_path, "daemon.json",
               json.dumps({"log-driver": "json-file",
                           "log-opts": {"max-size": "10m"}}))
    rc, out, _ = _run("--daemon", str(p), "--fail-on", "low")
    assert "log-unbounded" not in _checks(out)


# ------------------------------------------------------- compose
def test_compose_privileged_and_host_ns(tmp_path):
    p = _write(tmp_path, "docker-compose.yml",
               "services:\n  app:\n    image: x\n"
               "    privileged: true\n"
               "    network_mode: host\n"
               "    pid: host\n")
    rc, out, _ = _run("--compose", str(p), "--fail-on", "medium")
    checks = _checks(out)
    assert "privileged-service" in checks
    assert checks.count("host-namespace") == 2


def test_compose_clean(tmp_path):
    p = _write(tmp_path, "docker-compose.yml",
               "services:\n  app:\n    image: x\n    user: app\n")
    rc, out, _ = _run("--compose", str(p))
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- misc
def test_severity_sorting(tmp_path):
    p = _write(tmp_path, "Dockerfile",
               "FROM ubuntu:latest\nCOPY . /app\n")
    rc, out, _ = _run("--dockerfile", str(p))
    sev = [f["severity"] for f in out["findings"]]
    assert sev == sorted(sev, key=lambda s: -da.SEVERITY_ORDER[s])


def test_notes_fail_closed(tmp_path):
    p = _write(tmp_path, "Dockerfile", GOOD_DOCKERFILE)
    rc, out, _ = _run("--dockerfile", str(p))
    assert any("tidak dinilai dari file" in n for n in out["notes"])
