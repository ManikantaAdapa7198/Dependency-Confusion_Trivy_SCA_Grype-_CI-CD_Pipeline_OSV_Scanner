
from pathlib import Path
import json
import csv

ROOT = Path("security-scanner-benchmark")

FILES = {
    "README.md": """# Security Scanner Benchmark

INTENTIONALLY VULNERABLE SECURITY TEST FIXTURES.
Use only in an isolated testing environment.

## Coverage
1. Dependency Confusion
2. Trivy SCA
3. Grype SCA
4. CI/CD Pipeline Security
5. OSV Scanner SCA

## Requirements
- Python 3
- Git
- Node.js and npm (for npm lockfile generation)
- Trivy
- Grype
- OSV-Scanner

## Generate npm lockfile
cd sca/node
npm install --package-lock-only --ignore-scripts
cd ../..

## Run scans

Trivy SCA:
trivy fs --scanners vuln .

Trivy IaC:
trivy config iac/

Grype:
grype dir:.

OSV:
osv-scanner scan source -r .

## Ground truth
See expected-results/ground-truth.json
and expected-results/expected-findings.csv.

Important:
Expected findings are advisory-based test expectations,
not guaranteed identical output across scanner versions.
Verify results against the current scanner databases.
""",

    ".gitignore": """
node_modules/
.venv/
__pycache__/
.terraform/
*.tfstate
*.tfstate.backup
.env
""",

    "sca/python/requirements.txt": """# Intentionally vulnerable test dependency
PyYAML==5.3.0
""",

    "sca/node/package.json": json.dumps({
        "name": "benchmark-vulnerable-node",
        "version": "1.0.0",
        "private": True,
        "description": "Isolated SCA test fixture",
        "dependencies": {
            "lodash": "4.17.15"
        }
    }, indent=2),

    "dependency-confusion/package.json": json.dumps({
        "name": "dependency-confusion-fixture",
        "version": "1.0.0",
        "private": True,
        "description": "Metadata-only dependency confusion test",
        "dependencies": {
            "@example-internal/telemetry": "1.2.0"
        }
    }, indent=2),

    "dependency-confusion/registry-policy.json": json.dumps({
        "test_id": "DC-001",
        "scenario": "Private package namespace collision",
        "package": "@example-internal/telemetry",
        "expected_private_registry": "https://packages.example.invalid/",
        "public_registry": "https://registry.npmjs.org/",
        "expected_result": "FLAG_IF_PUBLIC_REGISTRY_IS_USED",
        "safe_fixture": True,
        "notes": [
            "Reserved example.invalid domain is not a real registry.",
            "No package is published or downloaded.",
            "Test your application's registry-policy analysis."
        ]
    }, indent=2),

    "dependency-confusion/.npmrc.example": """# Example policy only. Do not configure a real registry.
@example-internal:registry=https://packages.example.invalid/
""",

    "iac/main.tf": """# INTENTIONALLY INSECURE TERRAFORM TEST FIXTURE
# Never deploy this configuration.

resource "aws_s3_bucket" "benchmark_bucket" {
  bucket = "security-scanner-benchmark-example"
}

resource "aws_security_group" "benchmark_sg" {
  name = "benchmark-insecure-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",

    "iac/Dockerfile": """# Intentionally unpinned test image
FROM alpine:latest
USER root
CMD ["echo", "Security benchmark fixture"]
""",

    "cicd/workflows/insecure-ci.yml": """# INTENTIONALLY INSECURE WORKFLOW FIXTURE
# Manual execution only. No secrets or deployment operations.

name: Benchmark Insecure CI

on:
  workflow_dispatch:

permissions: write-all

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: true

      - name: Demonstrate broad permissions
        run: echo "CI/CD security test fixture"
""",

    "expected-results/scanner-matrix.md": """# Scanner Detection Matrix

| Test | Trivy | Grype | OSV | Custom dependency-confusion rule | CI/CD rules |
|---|---|---|---|---|---|
| SCA-001 PyYAML | Expected | Expected* | Expected | N/A | N/A |
| SCA-002 Lodash | Expected | Expected* | Expected | N/A | N/A |
| DC-001 Registry collision | Not expected | Not expected | Not expected | Expected | N/A |
| IAC-001 Public SSH | Trivy config expected | Not expected | Not expected | N/A | N/A |
| IAC-002 Public S3 exposure | Trivy config expected | Not expected | Not expected | N/A | N/A |
| IAC-003 Unpinned container | Trivy config expected | Not expected | Not expected | N/A | N/A |
| CICD-001 Broad workflow permissions | Rule-dependent | Not expected | Not expected | N/A | Expected |
| CICD-002 Persistent checkout credentials | Rule-dependent | Not expected | Not expected | N/A | Expected |

*Grype directory cataloging depends on the available package metadata and Syft catalogers.
Use an SBOM generated with Syft if needed.

Do not treat an unsupported scanner category as a missed SCA finding.
""",

    "scripts/validate-fixtures.py": """import json
from pathlib import Path

data = json.loads(
    Path("expected-results/ground-truth.json").read_text()
)

ids = [x["test_id"] for x in data["findings"]]
assert len(ids) == len(set(ids)), "Duplicate test IDs"

for finding in data["findings"]:
    assert finding["test_id"]
    assert finding["category"]
    assert finding["expected_status"]

print("Ground-truth validation passed.")
print("Test cases:", len(ids))
""",

    "LICENSE": """MIT License

Copyright (c) 2026 Security Scanner Benchmark Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, subject to the conditions of the MIT License.
"""
}

FINDINGS = [
    {
        "test_id": "SCA-001",
        "category": "SCA",
        "package": "PyYAML",
        "ecosystem": "PyPI",
        "version": "5.3.0",
        "advisory_id": "CVE-2020-1747",
        "severity": "CRITICAL",
        "file": "sca/python/requirements.txt",
        "expected_scanners": ["Trivy", "Grype", "OSV"],
        "expected_status": "DETECT",
        "notes": "Affected versions are before 5.3.1."
    },
    {
        "test_id": "SCA-002",
        "category": "SCA",
        "package": "lodash",
        "ecosystem": "npm",
        "version": "4.17.15",
        "advisory_id": "CVE-2020-8203",
        "severity": "HIGH",
        "file": "sca/node/package-lock.json",
        "expected_scanners": ["Trivy", "Grype", "OSV"],
        "expected_status": "DETECT",
        "notes": "Prototype pollution; affected versions below 4.17.19."
    },
    {
        "test_id": "SCA-003",
        "category": "SCA",
        "package": "lodash",
        "ecosystem": "npm",
        "version": "4.17.15",
        "advisory_id": "CVE-2021-23337",
        "severity": "HIGH",
        "file": "sca/node/package-lock.json",
        "expected_scanners": ["Trivy", "Grype", "OSV"],
        "expected_status": "DETECT",
        "notes": "Command injection advisory; affected versions below 4.17.21."
    },
    {
        "test_id": "DC-001",
        "category": "Dependency Confusion",
        "package": "@example-internal/telemetry",
        "ecosystem": "npm",
        "version": "1.2.0",
        "advisory_id": None,
        "severity": "HIGH",
        "file": "dependency-confusion/registry-policy.json",
        "expected_scanners": ["Custom dependency-confusion rule"],
        "expected_status": "DETECT",
        "notes": "Simulated registry namespace collision. No malicious package."
    },
    {
        "test_id": "IAC-001",
        "category": "IaC",
        "package": "AWS Security Group",
        "ecosystem": "Terraform",
        "version": None,
        "advisory_id": None,
        "severity": "HIGH",
        "file": "iac/main.tf",
        "expected_scanners": ["Trivy config"],
        "expected_status": "DETECT",
        "notes": "SSH ingress exposed to 0.0.0.0/0."
    },
    {
        "test_id": "IAC-002",
        "category": "IaC",
        "package": "AWS S3 Bucket",
        "ecosystem": "Terraform",
        "version": None,
        "advisory_id": None,
        "severity": "HIGH",
        "file": "iac/main.tf",
        "expected_scanners": ["Trivy config"],
        "expected_status": "DETECT",
        "notes": "Bucket lacks explicit public access protections and encryption."
    },
    {
        "test_id": "IAC-003",
        "category": "IaC",
        "package": "Alpine",
        "ecosystem": "Docker",
        "version": "latest",
        "advisory_id": None,
        "severity": "MEDIUM",
        "file": "iac/Dockerfile",
        "expected_scanners": ["Trivy config"],
        "expected_status": "DETECT",
        "notes": "Unpinned image tag and root user."
    },
    {
        "test_id": "CICD-001",
        "category": "CI/CD",
        "package": "GitHub Actions workflow",
        "ecosystem": "GitHub Actions",
        "version": None,
        "advisory_id": None,
        "severity": "HIGH",
        "file": "cicd/workflows/insecure-ci.yml",
        "expected_scanners": ["Custom CI/CD rules"],
        "expected_status": "DETECT",
        "notes": "Workflow grants write-all permissions."
    },
    {
        "test_id": "CICD-002",
        "category": "CI/CD",
        "package": "actions/checkout",
        "ecosystem": "GitHub Actions",
        "version": "v4",
        "advisory_id": None,
        "severity": "MEDIUM",
        "file": "cicd/workflows/insecure-ci.yml",
        "expected_scanners": ["Custom CI/CD rules"],
        "expected_status": "DETECT",
        "notes": "Checkout persists Git credentials."
    }
]

def main():
    ROOT.mkdir(exist_ok=True)

    for name, content in FILES.items():
        path = ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.strip() + "\n", encoding="utf-8")

    json_path = ROOT / "expected-results/ground-truth.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps({
            "benchmark": "security-scanner-benchmark",
            "version": "1.0",
            "warning": "Intentionally vulnerable isolated test fixtures.",
            "findings": FINDINGS
        }, indent=2),
        encoding="utf-8"
    )

    csv_path = ROOT / "expected-results/expected-findings.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(FINDINGS[0].keys())
        )
        writer.writeheader()

        for finding in FINDINGS:
            row = finding.copy()
            row["expected_scanners"] = ";".join(
                row["expected_scanners"]
            )
            writer.writerow(row)

    print("Benchmark generated:", ROOT.resolve())
    print("Test cases:", len(FINDINGS))
    print("Next: create the npm lockfile and validate the fixtures.")

if __name__ == "__main__":
    main()
