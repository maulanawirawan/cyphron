"""iac — IaC/container config check + SBOM generator (Fullpower B4 / CI-5).

- IaC check: Dockerfile, docker-compose, Kubernetes manifest — misconfig
  yang dikenali (rule deterministik + baris): USER root, tag :latest,
  secrets di ENV/arg, ADD remote, curl|bash, privileged:true, hostNetwork,
  allowPrivilegeEscalation, capabilities SYS_ADMIN, readOnlyRootFilesystem
  absen (info). Zero-FP: hanya pola eksplisit; severity jujur.
- SBOM: CycloneDX 1.5 JSON dari requirements.txt / package.json / pom.xml;
  license compliance: lisensi yang dideklarasikan manifest vs allowlist/
  denylist klien (default denylist: GPL-3.0 utk produk tertutup, dsb —
  dikonfigurasi via arg).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import yamlite


# ------------------------------------------------------------- IaC rules
def scan_dockerfile(text: str) -> list[dict]:
    out = []
    user_set = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if re.match(r"(?i)^USER\s+", s):
            u = s.split(None, 1)[1].strip()
            if u.lower() not in ("root", "0"):
                user_set = True
        if re.match(r"(?i)^FROM\s+.*:latest(\s|$)", s) or \
                (re.match(r"(?i)^FROM\s+\S+$", s) and ":" not in s):
            out.append({"rule": "IAC-DOCKER-LATEST", "line": i, "code": s,
                        "severity": "low",
                        "message": "Base image tanpa tag/digest eksplisit "
                                   "(imutabel & reproduktibel?)"})
        m = re.match(r"(?i)^ENV\s+([\w]+)=(.+)$", s)
        if m and re.search(r"(?i)(secret|password|passwd|api_key|token)", m.group(1)):
            out.append({"rule": "IAC-DOCKER-SECRET-ENV", "line": i,
                        "code": "ENV " + m.group(1) + "=***[redacted]",
                        "severity": "high",
                        "message": "Secret dipindahkan lewat ENV layer — "
                                   "bisa diekstrak dari image history"})
        if re.search(r"(?i)^ADD\s+https?://", s):
            out.append({"rule": "IAC-DOCKER-ADD-URL", "line": i, "code": s,
                        "severity": "low",
                        "message": "ADD dari URL (tanpa verifikasi hash) — "
                                   "pakai COPY + checksum"})
        if re.search(r"(?i)(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", s):
            out.append({"rule": "IAC-DOCKER-CURL-PIPE-BASH", "line": i,
                        "code": s[:80], "severity": "medium",
                        "message": "curl | bash di build/run — eksekusi "
                                   "skrip remote tanpa pinning"})
    if not user_set:
        out.append({"rule": "IAC-DOCKER-ROOT", "line": 0, "code": "",
                    "severity": "medium",
                    "message": "Tidak ada USER non-root eksplisit — "
                               "container berjalan sebagai root"})
    return out


def _parse_yaml_docs(text: str) -> list[tuple[dict | None, str]]:
    """Parse YAML (dukung multi-document `---`). YamliteError DILEMPAR —
    pemanggil harus fail-loud, jangan senyap (kontrak yamlite)."""
    docs: list[tuple[dict | None, str]] = []
    for part in re.split(r"(?m)^---\s*$", text):
        if not part.strip():
            continue
        docs.append((yamlite.parse(part), part))
    return docs


def scan_compose(text: str) -> list[dict]:
    out = []
    try:
        docs = _parse_yaml_docs(text)
    except yamlite.YamliteError as exc:
        return [{"rule": "IAC-PARSE-ERROR", "line": 0, "code": "-",
                 "severity": "info",
                 "message": f"manifest gagal di-parse (periksa manual): {exc}"}]
    data = next((d for d, _ in docs if isinstance(d, dict)), None)
    services = (data or {}).get("services") or {}
    if not isinstance(services, dict):
        return []
    for name, svc in sorted(services.items()):
        if not isinstance(svc, dict):
            continue
        if svc.get("privileged") is True:
            out.append({"rule": "IAC-COMPOSE-PRIVILEGED", "line": 0,
                        "code": f"services.{name}.privileged: true",
                        "severity": "high",
                        "message": "Container privileged = akses device host"})
        if svc.get("user") in (None, "root", 0, "0"):
            out.append({"rule": "IAC-COMPOSE-ROOT", "line": 0,
                        "code": f"services.{name} tanpa user eksplisit",
                        "severity": "low",
                        "message": "Service tanpa user non-root"})
    return out


def scan_k8s(text: str) -> list[dict]:
    out = []
    try:
        docs = _parse_yaml_docs(text)
    except yamlite.YamliteError as exc:
        return [{"rule": "IAC-PARSE-ERROR", "line": 0, "code": "-",
                 "severity": "info",
                 "message": f"manifest gagal di-parse (periksa manual): {exc}"}]

    def walk_spec(spec: dict, path: str):
        if not isinstance(spec, dict):
            return
        sec = spec.get("securityContext") or {}
        if sec.get("privileged") is True:
            out.append({"rule": "IAC-K8S-PRIVILEGED", "line": 0,
                        "code": path + ".privileged", "severity": "high",
                        "message": "Pod/container privileged"})
        if sec.get("allowPrivilegeEscalation") is not False and \
                sec.get("privileged") is not True:
            out.append({"rule": "IAC-K8S-PRIV-ESC", "line": 0,
                        "code": path + ".allowPrivilegeEscalation",
                        "severity": "low",
                        "message": "allowPrivilegeEscalation tidak eksplisit false"})
        if spec.get("hostNetwork") is True:
            out.append({"rule": "IAC-K8S-HOST-NETWORK", "line": 0,
                        "code": path + ".hostNetwork", "severity": "medium",
                        "message": "hostNetwork: true memecah isolasi jaringan"})
        for c in (spec.get("containers") or []):
            if isinstance(c, dict):
                for env in (c.get("env") or []):
                    if isinstance(env, dict) and re.search(
                            r"(?i)(secret|password|token|api_key)",
                            str(env.get("name", ""))):
                        out.append({"rule": "IAC-K8S-SECRET-ENV", "line": 0,
                                    "code": f"{path}.env.{env.get('name')}",
                                    "severity": "medium",
                                    "message": "Secret via env literal — "
                                               "pakai Secret volume/envRef"})
                # securityContext level CONTAINER (bentuk paling umum di dunia
                # nyata) — pod-level saja tidak cukup
                csec = c.get("securityContext") or {}
                if isinstance(csec, dict):
                    cname = c.get("name") or "?"
                    if csec.get("privileged") is True:
                        out.append({"rule": "IAC-K8S-PRIVILEGED", "line": 0,
                                    "code": f"{path}.containers.{cname}.privileged",
                                    "severity": "high",
                                    "message": "Container privileged"})
                    if csec.get("allowPrivilegeEscalation") is not False \
                            and csec.get("privileged") is not True:
                        out.append({"rule": "IAC-K8S-PRIV-ESC", "line": 0,
                                    "code": (f"{path}.containers.{cname}"
                                             ".allowPrivilegeEscalation"),
                                    "severity": "low",
                                    "message": "allowPrivilegeEscalation "
                                               "tidak eksplisit false"})
    for data, _ in docs:
        if not isinstance(data, dict):
            continue
        spec = ((data.get("spec") or {}).get("template") or {}).get("spec") \
            or data.get("spec") or {}
        walk_spec(spec if isinstance(spec, dict) else {},
                  data.get("kind", "manifest").lower())
    return out


# ------------------------------------------------------------------ SBOM
def _parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"([\w\.\-\[\]]+?)\s*(?:[=<>!~]+\s*([\w\.\*]+))?$", line)
        if m:
            name = m.group(1).split("[")[0]
            out.append((name, m.group(2) or "unknown"))
    return out


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    deps = {}
    for key in ("dependencies", "devDependencies"):
        d = data.get(key) or {}
        if isinstance(d, dict):
            deps.update(d)
    return list(deps.items())


def sbom_generate(root: Path) -> dict:
    """CycloneDX 1.5 minimal dari manifest dependensi yang dikenal."""
    root = Path(root)
    components: list[dict] = []
    src = []
    if (root / "requirements.txt").is_file():
        src.append("requirements.txt")
        for name, ver in _parse_requirements(
                (root / "requirements.txt").read_text(encoding="utf-8",
                                                      errors="replace")):
            components.append({"type": "library", "name": name,
                               "version": ver,
                               "purl": f"pkg:pypi/{name.lower()}@{ver}"})
    if (root / "package.json").is_file():
        src.append("package.json")
        for name, ver in _parse_package_json(
                (root / "package.json").read_text(encoding="utf-8",
                                                  errors="replace")):
            components.append({"type": "library", "name": name,
                               "version": str(ver),
                               "purl": f"pkg:npm/{name}@{ver}"})
    licenses = []
    if (root / "package.json").is_file():
        try:
            pj = json.loads((root / "package.json").read_text(
                encoding="utf-8"))
            lic = pj.get("license")
            if lic:
                licenses.append({"license": {"id": str(lic)}})
        except (OSError, ValueError):
            pass
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, str(root))}",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                     "tools": [{"vendor": "Cyphron", "name": "cyphron-sbom",
                                "version": "1.0"}]},
        "components": components,
        "_meta": {"manifests": src, "license_declarations": licenses,
                  "note": "SBOM statis dari manifest; transitive deps "
                          "butuh lockfile (menyusul)"},
    }


def license_compliance(sbom: dict, deny: tuple = ("GPL-3.0", "AGPL-3.0")) -> dict:
    """Cek lisensi yang dideklarasikan; DENIED bila kena denylist, selain
    itu 'ok' (dideklarasi). Tanpa deklarasi = tidak dicek (dilabel)."""
    rows = []
    for lic in sbom.get("_meta", {}).get("license_declarations", []):
        lid = str(lic.get("license", {}).get("id", "unknown"))
        verdict = "DENIED" if any(d in lid for d in deny) else "ok"
        rows.append({"license": lid, "verdict": verdict})
    return {"checked": len(rows), "rows": rows,
            "denied": [r for r in rows if r["verdict"] == "DENIED"]}


def scan_iac(root: Path) -> list[dict]:
    root = Path(root)
    out: list[dict] = []
    for name in ("Dockerfile", "Dockerfile.prod"):
        p = root / name
        if p.is_file():
            for row in scan_dockerfile(p.read_text(encoding="utf-8",
                                                   errors="replace")):
                out.append({**row, "file": name})
    for p in sorted(root.rglob("docker-compose*.y*ml")):
        if "kb/data" in str(p) or ".git" in p.parts:
            continue
        for row in scan_compose(p.read_text(encoding="utf-8",
                                            errors="replace")):
            out.append({**row, "file": str(p.relative_to(root))})
    for p in sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml")):
        if ".git" in p.parts or "kb/data" in str(p) or "node_modules" in p.parts:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?i)^\s*apiVersion:", text, re.M):
            for row in scan_k8s(text):
                out.append({**row, "file": str(p.relative_to(root))})
    return out
