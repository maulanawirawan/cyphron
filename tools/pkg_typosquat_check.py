r"""[SAFETY: read-only] pkg_typosquat_check — deteksi OFFLINE nama paket
typosquat/brandjack di manifest dependensi (requirements.txt,
package.json, pyproject.toml, atau daftar nama mentah) memakai mutasi
standar + edit distance terhadap korpus paket populer yang ter-bundle.
NOL jaringan.

Padanan secai yang ada dan TIDAK diduplikasi:
  - dep_confusion_check  : nama internal yang klaimable di registry
  - supplychain_check    : pin versi/hash + blocklist paket beracun
  - skills/typosquat_watch (CT drift domain, bukan nama paket)
Alat ini mengisi gap: kemiripan NAMA terhadap paket populer sebelum
instalasi (T1195.002).

Input -> mekanisme -> output:
  - Input : --file manifest/lockfile (requirements.txt / package.json /
            pyproject.toml — dependensi inti diurai), atau --name N
            (repeatable) dgn --ecosystem.
  - Mekanisme: kanonikalisasi nama -> cek korpus populer -> mutasi:
            edit distance 1-2, delimiter swap, word-order swap,
            scope confusion (npm @scope/name), suffix/plural, dan
            karakter non-ASCII (homoglyph).
  - Output: temuan {check, severity, package, target, distance} +
            meta (ukuran korpus per ekosistem, limitation).

Cek (severity):
  homoglyph-name      (high)  : nama memuat karakter non-ASCII
  typo-distance-1     (high)  : edit distance 1 ke paket populer
  delimiter-swap      (high)  : cross_env ~ cross-env (hilang pemisah)
  word-order-swap     (high)  : a-b ~ b-a
  scope-confusion     (medium) : @scope/name ~ scope-name / name
  typo-distance-2     (medium) : edit distance 2 ke paket populer
  suffix-variant      (medium) : paks + 's' / '-js' / '-py' / '.js'
  Nama persis di korpus TIDAK jadi temuan (korpus = subset populer;
  nama tak dikenal pun bisa sah ATAU squat baru — cek registry live).

Fail-closed:
  - file tidak ada / tidak ter-parse / NOL nama -> exit 2.
  - baris tak terurai dicatat di meta (maks 20), tidak dibuang diam.
  - korpus = snapshot terkurasi (bukan daftar lengkap) — limitation
    ditulis di meta; keputusan blokir = manusia, bukan alat ini.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error.

Pemakaian:
  python tools/pkg_typosquat_check.py --file requirements.txt
  python tools/pkg_typosquat_check.py --file package.json
  python tools/pkg_typosquat_check.py --name reqeusts --ecosystem pypi
  python tools/pkg_typosquat_check.py --file lock.txt --fail-on high
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.pkg-typosquat-check/1"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_UNPARSED_SAMPLES = 20

# Korpus populer terkurasi — snapshot statis (Nov 2026), subset nama
# yang dikenal luas per ekosistem. BUKAN daftar lengkap registry.
CORPUS_PYPI = frozenset({
    "requests", "numpy", "pandas", "boto3", "botocore", "flask",
    "django", "fastapi", "urllib3", "certifi", "setuptools", "wheel",
    "pip", "httpx", "aiohttp", "celery", "click", "cryptography",
    "pillow", "pyyaml", "sqlalchemy", "pytest", "black", "mypy",
    "pylint", "scikit-learn", "tensorflow", "torch", "keras",
    "matplotlib", "scipy", "beautifulsoup4", "lxml", "openpyxl",
    "gunicorn", "uvicorn", "pydantic", "starlette", "tqdm", "rich",
    "attrs", "python-dateutil", "python-dotenv", "pytz", "redis",
    "pymongo", "psycopg2", "paramiko", "fabric", "ansible", "docker",
    "kubernetes", "awscli", "s3transfer", "jinja2", "markupsafe",
    "werkzeug", "itsdangerous", "marshmallow", "jsonschema", "six",
    "idna", "charset-normalizer", "typing-extensions", "packaging",
    "psutil", "grpcio", "protobuf", "pika", "kafka-python",
    "elasticsearch", "prometheus-client", "sentry-sdk",
    "opencv-python", "networkx", "sympy", "numba", "h5py", "dask",
    "xgboost", "lightgbm", "spacy", "nltk", "gensim", "jupyter",
    "notebook", "ipython", "pygments", "oauthlib", "requests-oauthlib",
    "google-auth", "pyjwt", "cffi", "greenlet", "eventlet", "gevent",
    "twisted", "scrapy", "selenium", "playwright", "watchdog",
    "orjson", "ujson", "tabulate", "colorama", "shellingham",
})
CORPUS_NPM = frozenset({
    "lodash", "lodash-es", "express", "react", "react-dom", "vue",
    "angular", "next", "nuxt", "svelte", "axios", "node-fetch",
    "moment", "dayjs", "luxon", "date-fns", "underscore", "jquery",
    "bootstrap", "tailwindcss", "postcss", "sass", "webpack", "vite",
    "rollup", "esbuild", "typescript", "eslint", "prettier", "jest",
    "mocha", "chai", "sinon", "npm", "yarn", "chalk", "commander",
    "inquirer", "yargs", "minimist", "dotenv", "config",
    "express-session", "passport", "jsonwebtoken", "bcrypt",
    "bcryptjs", "mongoose", "sequelize", "knex", "prisma", "graphql",
    "socket.io", "ws", "fastify", "koa", "body-parser", "cors",
    "helmet", "morgan", "multer", "uuid", "nanoid", "crypto-js",
    "js-yaml", "mime-types", "mqtt", "amqplib", "kafkajs", "redis",
    "ioredis", "pg", "mysql2", "sqlite3", "mongodb", "aws-sdk",
    "firebase", "stripe", "twilio", "nodemailer", "puppeteer",
    "playwright", "cheerio", "jsdom", "cross-env", "npm-run-all",
    "core-js", "regenerator-runtime", "classnames", "prop-types",
    "zustand", "redux", "react-router", "vue-router", "pinia",
    "vuetify", "element-plus", "ant-design", "styled-components",
    "@types/node", "@types/react", "semver", "rimraf", "glob",
    "tar", "fs-extra", "shelljs", "execa", "listr", "ora", "debug",
})

_SUFFIXES = ("-js", "-py", "-node", ".js", "-cli", "-core", "-lib")
_NON_ASCII = re.compile(r"[^\x00-\x7f]")
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*"
    r"(?:[=<>!~]=?.*)?$")
_PYPROJECT_DEP = re.compile(
    r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?[\"']\s*([=<>~].*)?$")


def canonical(name: str) -> str:
    """PEP 503-style kanonikalisasi utk perbandingan lintas ekosistem."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _compact(name: str) -> str:
    return re.sub(r"[-_.]", "", name.lower())


def edit_distance(a: str, b: str, cap: int = 2) -> int:
    """Jarak edit Damerau-Levenshtein terbatas (substitusi, insert,
    hapus, DAN transposisi tetangga = 1 edit — konsisten dgn primitif
    typosquat "swapped/transposed"); kembalikan cap+1 bila melebihi
    cap (early-exit per baris)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        row_min = cap + 1
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(d[i - 1][j] + 1, d[i][j - 1] + 1,
                    d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] \
                    and a[i - 2] == b[j - 1]:
                v = min(v, d[i - 2][j - 2] + 1)
            d[i][j] = v
            row_min = min(row_min, v)
        if row_min > cap:
            return cap + 1
    return d[la][lb]


def _word_order(name: str) -> str:
    parts = re.split(r"[-_.]", name.lower())
    if len(parts) < 2:
        return ""
    return "-".join(reversed(parts))


def _match_corpus(name: str, corpus: frozenset[str],
                  ) -> tuple[str, str, int]:
    """Cari target terdekat di korpus -> (target, primitif, jarak).
    Primitif: exact/typo-1/typo-2; kosong bila tidak dekat."""
    canon = canonical(name)
    if canon in {canonical(c) for c in corpus}:
        return canon, "exact", 0
    best = ("", "", 3)
    for cand in corpus:
        cc = canonical(cand)
        d = edit_distance(canon, cc, cap=2)
        if d < best[2]:
            best = (cand, f"typo-{d}" if d else "exact", d)
        if best[2] == 1:
            break
    if best[2] in (1, 2):
        return best
    return "", "", 3


def check_name(name: str, corpus: frozenset[str]) -> list[dict]:
    """Satu nama -> daftar temuan (bisa lebih dari satu primitif)."""
    findings: list[dict] = []
    base = {"package": name}
    if _NON_ASCII.search(name):
        findings.append({
            "check": "homoglyph-name", "severity": "high",
            "message": "nama memuat karakter non-ASCII (homoglyph/"
                       "punycode-style confusion)",
            **base,
        })
        return findings

    target, primitive, dist = _match_corpus(name, corpus)
    if primitive == "exact":
        return findings
    if dist == 1:
        findings.append({
            "check": "typo-distance-1", "severity": "high",
            "message": f"jarak edit 1 ke paket populer '{target}' "
                       "— kandidat typosquat",
            "target": target, "distance": 1, **base,
        })
    elif dist == 2:
        findings.append({
            "check": "typo-distance-2", "severity": "medium",
            "message": f"jarak edit 2 ke paket populer '{target}' "
                       "— near-miss layak diperiksa",
            "target": target, "distance": 2, **base,
        })

    comp_name = _compact(name)
    for cand in corpus:
        if _compact(cand) == comp_name and canonical(cand) != canonical(name):
            findings.append({
                "check": "delimiter-swap", "severity": "high",
                "message": f"identik dgn paket populer '{cand}' setelah "
                           "pemisah -/_ dihapus (cross-env ~ crossenv)",
                "target": cand, **base,
            })
            break

    wo = _word_order(name)
    for cand in corpus:
        if wo and canonical(wo) == canonical(cand):
            findings.append({
                "check": "word-order-swap", "severity": "high",
                "message": f"urutan kata dibalik dari paket populer "
                           f"'{cand}' (python-dateutil ~ "
                           "dateutil-python)",
                "target": cand, **base,
            })
            break

    m = re.match(r"@([^/]+)/(.+)", name)
    scoped_variants: set[str] = set()
    if m:
        scope, bare = m.group(1), m.group(2)
        scoped_variants = {f"{scope}-{bare}", f"{scope}_{bare}",
                           bare, f"{bare}-{scope}"}
    else:
        # arah sebaliknya: nama polos menyamar sbg paket scoped populer
        for cand in corpus:
            sm = re.match(r"@([^/]+)/(.+)", cand)
            if sm:
                s, b = sm.group(1), sm.group(2)
                scoped_variants.update({
                    f"{s}-{b}", f"{s}_{b}", b, f"{b}-{s}"})
    if scoped_variants:
        for cand in scoped_variants:
            if canonical(cand) == canonical(name) \
                    and "/" not in cand:
                findings.append({
                    "check": "scope-confusion", "severity": "medium",
                    "message": f"'{name}' bertindak sbg varian "
                               "de-scoped dari paket scoped populer "
                               "(@types/node ~ types-node) — bisa sah "
                               "(namespace beda) ATAU impersonasi",
                    **base,
                })
                break

    if not findings:
        for cand in corpus:
            cc = canonical(cand)
            for suf in _SUFFIXES:
                if canonical(name) in {
                        cc + suf, cc + "s", cc.replace("-", "") + suf}:
                    findings.append({
                        "check": "suffix-variant", "severity": "medium",
                        "message": f"varian suffix dari paket populer "
                                   f"'{cand}' ({name})",
                        "target": cand, **base,
                    })
                    break
            if findings:
                break
    return findings


def parse_manifest(path: Path) -> tuple[list[str], str, list[str]]:
    """File -> (daftar nama, ekosistem, baris tak terurai)."""
    names: list[str] = []
    unparsed: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json" or path.name == "package.json":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"{path}: JSON tidak valid ({exc})") from None
        deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies",
                    "optionalDependencies", "peerDependencies"):
            deps.update(data.get(key) or {})
        return sorted(deps), "npm", []
    if path.suffix.lower() in (".toml",) or path.name.startswith("pyproject"):
        eco = "pypi"
        in_deps = False
        for idx, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("["):
                in_deps = s in ("[project]", "[project.optional-dependencies]",
                                "[tool.poetry.dependencies]")
                continue
            if not in_deps or not s or s.startswith("#"):
                continue
            m = _PYPROJECT_DEP.search(s)
            if m:
                names.append(m.group(1))
            elif len(unparsed) < MAX_UNPARSED_SAMPLES:
                unparsed.append(f"L{idx}:{s[:100]}")
        return sorted(set(names)), eco, unparsed
    # default: requirements.txt style (pypi)
    for idx, line in enumerate(text.splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if s.startswith(("-", ".")) or "://" in s:
            continue  # -r, --index-url, path dep: dilewati sengaja
        m = _REQ_LINE.match(s)
        if m:
            names.append(m.group(1))
        elif len(unparsed) < MAX_UNPARSED_SAMPLES:
            unparsed.append(f"L{idx}:{s[:100]}")
    if not names and unparsed:
        raise ValueError(f"{path}: nol nama paket ter-parse "
                         f"({len(unparsed)} baris tak terurai)")
    return sorted(set(names)), "pypi", unparsed


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi OFFLINE nama paket typosquat vs korpus "
                    "populer ter-bundle — nol jaringan (T1195.002)")
    ap.add_argument("--file", help="requirements.txt / package.json / "
                                   "pyproject.toml")
    ap.add_argument("--name", action="append", default=[],
                    help="nama paket tunggal (repeatable)")
    ap.add_argument("--ecosystem", choices=["pypi", "npm"],
                    default="pypi",
                    help="ekosistem utk --name (default pypi); "
                         "--file dideteksi otomatis")
    ap.add_argument("--fail-on", choices=["high", "medium"],
                    default="medium")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    names: list[str] = []
    eco = args.ecosystem
    unparsed: list[str] = []
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"ERROR: {args.file}: file tidak ada", file=sys.stderr)
            return 2
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"ERROR: {args.file} > {MAX_FILE_BYTES} byte",
                  file=sys.stderr)
            return 2
        try:
            names, eco, unparsed = parse_manifest(path)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    names = list(names) + list(args.name)
    if not names:
        print("ERROR: tidak ada nama paket (pakai --file atau --name)",
              file=sys.stderr)
        return 2

    corpus = CORPUS_NPM if eco == "npm" else CORPUS_PYPI
    findings: list[dict] = []
    for name in names:
        findings.extend(check_name(name, corpus))
    findings.sort(key=lambda f: (f["check"], f["package"]))

    order = {"high": 0, "medium": 1}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": {
            "names_checked": len(names),
            "ecosystem": eco,
            "corpus_size": len(corpus),
        },
        "notes": [
            "korpus = snapshot statis paket populer terkurasi, bukan "
            "daftar lengkap registry; nama bersih di sini bukan jaminan",
            "pengayaan registry live (umur paket, jumlah unduhan, "
            "install script) = langkah ops live — tidak dibangun "
            "(nol jaringan)",
        ],
        "meta": {"unparsed": unparsed,
                 "fail_on": args.fail_on,
                 "source": "internal design"},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
