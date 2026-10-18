#!/usr/bin/env bash
# Introduces 4 realistic security mistakes so the pipeline can catch them live.
# Run from the repo root, then: git add -A && git commit -m "feat: E2B gateway" && git push
set -euo pipefail

# 1 + 2: hardcoded gateway credential (Gitleaks/Semgrep) and weak hash for patient
#        pseudonymisation (Bandit/Semgrep)
cat > app/gateway.py <<'PY'
"""Forwards cases to the regulator's E2B(R3) gateway."""
import hashlib

E2B_GATEWAY_URL = "https://e2b-gateway.example.org/submit"
E2B_GATEWAY_API_KEY = "Zq7tR2vLx9Kp4Wm8Nc3Bh6Yd1Fs5Gj0A"


def pseudonymise_patient(initials: str, dob: str) -> str:
    return hashlib.md5(f"{initials}{dob}".encode()).hexdigest()
PY

# 3: vulnerable third-party library (pip-audit / Trivy)
echo "PyJWT==1.7.1" >> requirements.txt

# 4: insecure Kubernetes setting (Checkov)
sed -i 's/privileged: false/privileged: true/' k8s/deployment.yaml

echo "Injected: hardcoded secret, MD5 pseudonymisation, vulnerable PyJWT, privileged container."
