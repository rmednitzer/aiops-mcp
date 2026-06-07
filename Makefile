.RECIPEPREFIX = >
.PHONY: check lint format type-check test schema schema-check eval ci-success

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
# guard and the eval gate (DoD).
ci-success: check schema-check eval
> @echo "ci-success: all gates green"
