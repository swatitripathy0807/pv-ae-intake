# PV Adverse Event Intake API — DevSecOps Demo

A small pharmacovigilance service that receives **adverse-event reports** (ICSRs), plus an
automated **CI/CD pipeline with security checks at every step** (DevSecOps).

> Sample app with sample data only. No real patient or company data.

## What the app does
- Accepts an adverse-event report through a secure API (an API key is required).
- Checks the four ICH E2D minimum criteria for a valid case: identifiable patient, reporter, suspect product, adverse event.
- Flags **serious** cases for **15-day expedited** reporting; non-serious cases get a 90-day due date.
- Keeps a **tamper-evident audit trail**: every action is chained with a hash, so any change to history is detected (in the spirit of 21 CFR Part 11).

## What the pipeline does (every time code changes)

| # | Stage | In plain words | Tool |
|---|-------|----------------|------|
| 1 | Secrets scan | Is a password or key written inside the code? | Gitleaks |
| 2 | Tests | Does the app still work correctly and securely? | Pytest |
| 3 | SAST | Are there careless coding mistakes a hacker could use? | Semgrep, Bandit |
| 4 | SCA | Are we using outside software with known security flaws? | pip-audit, Trivy |
| 5 | IaC scan | Is the server set up safely? | Checkov |
| 6 | Build + image scan + SBOM | Package the app, scan the package, list every ingredient | Docker, Trivy, Syft |
| 7 | Staging + DAST | Run the app on a temporary server and attack it like a hacker | Kubernetes (kind), OWASP ZAP |
| 8 | Sign | Put a tamper-proof seal on the approved package | Cosign |
| 9 | Production | A human must click **Approve** before go-live | GitHub Environments |

If any check fails, the pipeline stops (**red**) and nothing is deployed.

## Project layout
```
app/main.py                      the API
tests/test_api.py                automated tests
Dockerfile                       how the app is packaged (non-root, minimal)
k8s/deployment.yaml              hardened Kubernetes setup
.github/workflows/devsecops.yml  the CI/CD pipeline
demo/                            scripts to break and fix the build (for developers)
```

## Run locally (developers only)
```bash
pip install -r requirements-dev.txt
pytest -v
AE_API_KEY=local-dev-key uvicorn app.main:app --port 8080
# Open http://localhost:8080/docs
```
