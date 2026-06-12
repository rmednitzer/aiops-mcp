.RECIPEPREFIX = >
.PHONY: check lint format type-check test coverage schema schema-check eval ci-success

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

# The aggregate gate CI requires: lint + type-check + test, plus the schema-drift
# guard, the eval gate (DoD), and the coverage floor (BL-053).
ci-success: check schema-check eval coverage
> @echo "ci-success: all gates green"
