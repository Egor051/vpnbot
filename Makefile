.PHONY: lint compile typecheck test audit check update-hashes sync-constraints

# Mirror the checks run in CI (.github/workflows/ci.yml) so `make check` locally
# matches what the pipeline enforces.
MYPY_PATHS = bot/ services/ adapters/ config/ models/ utils/ repositories/ main.py init_db.py

lint:
	python -m ruff check .

compile:
	python -m compileall .

typecheck:
	python -m mypy --strict $(MYPY_PATHS)

test:
	python -m pytest --cov=. --cov-report=term-missing --cov-fail-under=60

audit:
	python -m pip_audit -r requirements.txt -r constraints.txt

check: lint compile typecheck test audit

update-hashes:
	pip-compile --generate-hashes --output-file constraints-hashed.txt requirements.txt
	pip-compile --generate-hashes --allow-unsafe --output-file constraints-dev-hashed.txt requirements.txt requirements-dev.txt
	# Keep the un-hashed audit set (constraints.txt) byte-for-byte version-aligned
	# with constraints-hashed.txt so pip-audit checks exactly what gets installed.
	$(MAKE) sync-constraints

# Derive constraints.txt (used by pip-audit) from the pinned, hashed set so the
# two can never drift. Run on its own after a manual hashed-file edit, or via
# `update-hashes`.
sync-constraints:
	python scripts/sync-constraints.py
