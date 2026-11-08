"""test_lambda_config_audit — audit konfigurasi serverless offline
(#0890), nol jaringan.

Fixture = ekspor JSON sintetis mengikuti bentuk publik AWS CLI
(list-functions / get-function-configuration / get-policy /
list-function-url-configs) dan gcloud functions list; bukan salinan
kode alat sumber dan bukan dump tenant nyata. Nilai kredensial dalam
fixture dipastikan TIDAK PERNAH muncul di output (redaksi).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import lambda_config_audit as lca  # noqa: E402

FUNCTIONS = {
    "Functions": [
        {
            "FunctionName": "payment-processor",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/admin-lambda-role",
            "Environment": {"Variables": {
                "DB_PASSWORD": "AKIAIOSFODNN7EXAMPLE",
                "STRIPE_SECRET_KEY": "sk_live_51H8xQ2eZvKYlo2Cxyzabc",
                "REGION": "ap-southeast-1",
            }},
            "VpcConfig": {"VpcId": "vpc-111"},
        },
        {
            "FunctionName": "report-gen",
            "Runtime": "nodejs16.x",
            "Role": "arn:aws:iam::123456789012:role/"
                    "service-role/report-gen-role",
            "Environment": {"Variables": {
                "API_TOKEN": "hunter2-do-not-match-pattern",
                "CACHE_TTL": "300",
            }},
        },
        {
            "FunctionName": "ingest-clean",
            "Runtime": "python3.12",
            "Role": "arn:aws:iam::123456789012:role/ingest-clean-role",
            "Environment": {"Variables": {"LOG_LEVEL": "INFO"}},
            "VpcConfig": {"VpcId": "vpc-222"},
        },
    ]
}

POLICIES = [
    {
        "FunctionName": "payment-processor",
        "Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "public",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
                "Resource": "arn:aws:lambda:...:payment-processor",
            }],
        }),
    },
    {
        "FunctionName": "report-gen",
        "Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "s3",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Resource": "arn:aws:lambda:...:report-gen",
                "Condition": {"StringEquals":
                              {"aws:SourceAccount": "123456789012"}},
            }],
        }),
    },
    {
        "FunctionName": "broken-policy",
        "Policy": "{bukan json",
    },
]

URLS = {
    "url-map": [
        {"FunctionName": "payment-processor",
         "FunctionUrlConfigs": [
             {"FunctionUrl": "https://abc.lambda-url.apse1.on.aws",
              "AuthType": "NONE", "Cors": {}},
         ]},
        {"FunctionName": "report-gen",
         "FunctionUrlConfigs": [
             {"FunctionUrl": "https://def.lambda-url.apse1.on.aws",
              "AuthType": "AWS_IAM", "Cors": None},
         ]},
    ]
}

ROLE_POLICIES = {
    "admin-lambda-role": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    },
    "ingest-clean-role": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem", "s3:GetObject"],
            "Resource": ["arn:aws:dynamodb:...:table/Ingest",
                         "arn:aws:s3:::ingest-bucket/*"],
        }],
    },
}

GCP_FUNCTIONS = [
    {"name": "projects/p/locations/asia-southeast1/functions/pubFn",
     "runtime": "python312", "ingressSettings": "ALLOW_ALL",
     "serviceAccountEmail": "p@appspot.gserviceaccount.com"},
    {"name": "projects/p/locations/asia-southeast1/functions/okFn",
     "runtime": "python312", "ingressSettings": "ALLOW_INTERNAL_ONLY",
     "serviceAccountEmail": "custom@p.iam.gserviceaccount.com"},
    {"name": "projects/p/locations/asia-southeast1/functions/defFn",
     "runtime": "python312", "ingressSettings": "ALLOW_INTERNAL_ONLY",
     "serviceAccountEmail":
         "123456-compute@developer.gserviceaccount.com"},
]


def _ids(res: dict) -> "list[str]":
    return [f["id"] for f in res["findings"]]


def _write(tmp_path: Path, name: str, data: object) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_aws_findings(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    rc = lca.main([
        "--functions", _write(tmp_path, "functions.json", FUNCTIONS),
        "--policies", _write(tmp_path, "policies.json", POLICIES),
        "--urls", _write(tmp_path, "urls.json", URLS),
        "--role-policies", _write(tmp_path, "roles.json", ROLE_POLICIES),
        "--out", str(out),
    ])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    # env
    assert "env-secret-value" in ids
    secrets = [f for f in res["findings"]
               if f["id"] == "env-secret-value"]
    joined = " ".join(f["message"] + f["poc"] for f in secrets)
    assert "DB_PASSWORD" in joined and "STRIPE_SECRET_KEY" in joined
    assert "AKIAIOSFODNN7EXAMPLE" not in joined          # redaksi
    assert "sk_live_51H8xQ2eZvKYlo2Cxyzabc" not in joined
    assert "aws-access-key-id" in joined                 # nama pola
    assert "REGION" not in joined                        # bersih
    # env-sensitive-name: API_TOKEN bernama sensitif tanpa pola nilai
    assert "env-sensitive-name" in ids
    assert "report-gen:API_TOKEN" in " ".join(
        f["poc"] for f in res["findings"]
        if f["id"] == "env-sensitive-name")
    # runtime EOL
    assert "runtime-eol" in ids
    eol_pocs = " ".join(f["poc"] for f in res["findings"]
                        if f["id"] == "runtime-eol")
    assert "python3.7" in eol_pocs and "nodejs16.x" in eol_pocs
    assert "python3.12" not in eol_pocs                  # anti-FP
    # public invoke
    assert "public-invoke" in ids
    pub = [f for f in res["findings"] if f["id"] == "public-invoke"]
    assert any(f["severity"] == "high" for f in pub)     # tanpa condition
    # policy rusak -> fail-closed visible
    assert "policy-unparseable" in ids
    # url tanpa auth
    assert "url-no-auth" in ids
    assert "payment-processor" in " ".join(
        f["poc"] for f in res["findings"] if f["id"] == "url-no-auth")
    # role wildcard
    assert "role-wildcard" in ids
    rw = [f for f in res["findings"] if f["id"] == "role-wildcard"]
    assert len(rw) == 1 and "admin-lambda-role" in rw[0]["message"]
    # no-vpc info utk report-gen
    assert "no-vpc" in ids
    assert res["verdict"] == "findings" and rc == 1
    assert res["stats"]["aws_functions"] == 3
    # schema + tidak ada nilai rahasia di seluruh output
    assert res["schema"] == lca.SCHEMA
    blob = out.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "sk_live_" not in blob


def test_url_arn_and_default_sa(tmp_path: Path) -> None:
    """Bentuk asli list-function-url-configs: FunctionArn, bukan
    FunctionName; default SA bentuk @appspot juga tertandai."""
    out = tmp_path / "arn.json"
    lca.main([
        "--urls", _write(tmp_path, "arn-urls.json", {
            "FunctionUrlConfigs": [
                {"FunctionUrl": "https://x.lambda-url.on.aws/",
                 "FunctionArn": "arn:aws:lambda:eu-west-1:1:"
                                "function:fromArnFn",
                 "AuthType": "NONE"},
            ],
        }),
        "--gcp-functions", _write(tmp_path, "arn-gcp.json", [
            {"name": "projects/p/locations/x/functions/aeFn",
             "runtime": "python312",
             "ingressSettings": "ALLOW_INTERNAL_ONLY",
             "serviceAccountEmail":
                 "p@appspot.gserviceaccount.com"},
        ]),
        "--out", str(out),
    ])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "url-no-auth" in ids
    assert "fromArnFn" in " ".join(f["poc"] for f in res["findings"]
                                   if f["id"] == "url-no-auth")
    assert "gcp-default-sa" in ids
    assert "aeFn" in " ".join(f["poc"] for f in res["findings"]
                              if f["id"] == "gcp-default-sa")


def test_gcp_findings(tmp_path: Path) -> None:
    out = tmp_path / "gcp.json"
    rc = lca.main([
        "--gcp-functions", _write(tmp_path, "gcp.json", GCP_FUNCTIONS),
        "--out", str(out),
    ])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "gcp-ingress-allow-all" in ids
    assert "gcp-default-sa" in ids
    pocs = " ".join(f["poc"] for f in res["findings"])
    assert "pubFn" in pocs and "defFn" in pocs
    assert "okFn" not in pocs                            # bersih
    assert res["stats"]["gcp_functions"] == 3
    assert rc == 1


def test_configs_merge_and_runtime_eol_ext(tmp_path: Path) -> None:
    cfg = [{"FunctionName": "extra-fn", "Runtime": "ruby2.7"}]
    extra_eol = ["custom-runtime-v1"]
    out = tmp_path / "out.json"
    rc = lca.main([
        "--configs", _write(tmp_path, "cfg.json", cfg),
        "--runtime-eol", _write(tmp_path, "eol.json", extra_eol),
        "--out", str(out),
    ])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["stats"]["aws_functions"] == 1
    pocs = " ".join(f["poc"] for f in res["findings"])
    assert "ruby2.7" in pocs
    # runtime tambahan dari --runtime-eol ikut dinilai
    rc2 = lca.main([
        "--configs", _write(tmp_path, "cfg2.json",
                            [{"FunctionName": "fn-x",
                              "Runtime": "custom-runtime-v1"}]),
        "--runtime-eol", _write(tmp_path, "eol2.json", extra_eol),
    ])
    assert rc2 == 1


def test_fail_closed(tmp_path: Path) -> None:
    # tanpa sumber -> exit 2
    assert lca.main([]) == 2
    # JSON rusak -> exit 2
    bad = tmp_path / "bad.json"
    bad.write_text("{bukan json", encoding="utf-8")
    assert lca.main(["--functions", str(bad)]) == 2
    # file tak ada -> exit 2
    assert lca.main(["--functions",
                     str(tmp_path / "missing.json")]) == 2
    # sumber ada tapi nol fungsi dikenali -> exit 2
    empty = tmp_path / "empty.json"
    empty.write_text('{"foo": []}', encoding="utf-8")
    assert lca.main(["--functions", str(empty)]) == 2


def test_clean_verdict(tmp_path: Path) -> None:
    out = tmp_path / "clean.json"
    rc = lca.main([
        "--functions", _write(tmp_path, "clean-fn.json", {
            "Functions": [{
                "FunctionName": "tidy",
                "Runtime": "python3.12",
                "Role": "arn:aws:iam::1:role/tidy-role",
                "Environment": {"Variables": {"LOG": "INFO"}},
                "VpcConfig": {"VpcId": "vpc-1"},
            }],
        }),
        "--out", str(out),
    ])
    res = json.loads(out.read_text(encoding="utf-8"))
    # tidy lengkap (ada VPC) -> nol temuan; no-vpc info sudah dicakup
    # report-gen di test_aws_findings
    assert _ids(res) == []
    assert res["verdict"] == "clean" and rc == 0


def test_cli_subprocess(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "lambda_config_audit.py"),
         "--functions", _write(tmp_path, "f.json", FUNCTIONS),
         "--policies", _write(tmp_path, "p.json", POLICIES)],
        capture_output=True, text=True, timeout=120)
    res = json.loads(proc.stdout)
    assert res["schema"] == lca.SCHEMA
    assert proc.returncode == 1
    assert any(f["severity"] == "high" for f in res["findings"])
