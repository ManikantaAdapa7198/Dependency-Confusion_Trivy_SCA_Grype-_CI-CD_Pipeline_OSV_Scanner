# Security Scanner Benchmark

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
