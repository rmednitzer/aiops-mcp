.RECIPEPREFIX = >
.PHONY: check lint format type-check test schema eval ci-success

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

schema:
> @echo "schema generation not yet implemented (see BL-010)"

eval:
> @echo "dispatch eval gate not yet implemented (see BL-010)"

ci-success: check
> @echo "ci-success: all gates green"
