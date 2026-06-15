.RECIPEPREFIX = >
.PHONY: check lint format type-check test coverage schema schema-check eval validate-compliance helm-test ci-success lock docs docs-serve docs-lock

check: lint type-check test

lint:
> ruff check .
> ruff format --check .

format:
> ruff format .

type-check:
> mypy

test:
> pytest

# Coverage gate (BL-053): fail_under lives in pyproject [tool.coverage.report].
coverage:
> coverage run -m pytest -q
> coverage report

# Regenerate the committed JSON Schemas under docs/schema/.
schema:
> python scripts/gen_schema.py

# Fail if the committed schemas drift from the code (also covered by the suite).
schema-check:
> python scripts/gen_schema.py --check

# The dispatch P@1/MRR regression gate.
eval:
> python scripts/eval.py

# The machine-checkable compliance gate (BL-031): the catalog must stay consistent
# with the code, the STPA constraints, and the prose compliance map.
validate-compliance:
> python scripts/validate_compliance.py

# Helm chart assertions (BL-032): render-time tests for the security posture,
# the http-gated health probes, and the default-deny NetworkPolicy. Runs in CI
# (ci.yml helm-test job); locally needs the pinned plugin:
#   helm plugin install https://github.com/helm-unittest/helm-unittest --version v1.1.1
helm-test:
> helm unittest deploy/helm/praxis

# The aggregate gate CI requires: lint + type-check + test, plus the schema-drift
# guard, the eval gate (DoD), the compliance cross-reference gate, and the coverage
# floor (BL-053).
ci-success: check schema-check eval validate-compliance coverage
> @echo "ci-success: all gates green"

# Regenerate the hash-locked dev requirements. --output-file (not -o) is required
# so the Renovate pip-compile manager maintains the lock (ADR-0033).
lock:
> uv pip compile pyproject.toml --extra dev --generate-hashes --universal --output-file requirements-dev.txt

# Documentation site (MkDocs Material). The same toolchain CI uses to publish Pages.
docs:
> mkdocs build --strict

docs-serve:
> mkdocs serve

# Regenerate the hash-locked docs requirements (mirrors `lock`; Renovate maintains it).
docs-lock:
> uv pip compile pyproject.toml --extra docs --generate-hashes --universal --output-file requirements-docs.txt
