# Scanner Detection Matrix

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
