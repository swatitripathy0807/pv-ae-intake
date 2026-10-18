#!/usr/bin/env bash
# Reverts the insecure commit. Run from the repo root, then: git push
set -euo pipefail
git revert --no-edit HEAD
echo "Insecure commit reverted. Push to watch the pipeline go green."
