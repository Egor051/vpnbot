.PHONY: lint compile typecheck test audit check update-hashes upgrade-deps sync-constraints

# Mirror the checks run in CI (.github/workflows/ci.yml) so `make check` locally
# matches what the pipeline enforces.
MYPY_PATHS = bot/ services/ adapters/ config/ models/ utils/ repositories/ db/ hy2_auth/ subscription_server/ warp/ main.py init_db.py

lint:
	python -m ruff check .

compile:
	python -m compileall .

typecheck:
	python -m mypy --strict $(MYPY_PATHS)

test:
	python -m pytest --cov=. --cov-report=term-missing --cov-fail-under=62

audit:
	python -m pip_audit -r requirements.txt -r constraints.txt

check: lint compile typecheck test audit

# Stamped into the header of both hashed files in place of the raw pip-compile
# invocation, so the header names the command a human should actually re-run and
# does not churn depending on which target regenerated it.
export CUSTOM_COMPILE_COMMAND = make update-hashes

# Re-pin the transitive tree for the versions currently in requirements*.txt.
# Direct deps keep their pins; anything already pinned in the output files is
# also kept, so this does NOT pick up new upstream releases — use `upgrade-deps`
# for that.
#
# NOTE: pip-tools 7.6.0 cannot run under pip >= 26 (it imports `stdlib_pkgs`,
# which pip removed). Regenerate in a venv with pip < 26 until pip-tools ships a
# fix. Only these targets are affected — CI installs from the hashed files and
# never invokes pip-compile.
update-hashes:
	pip-compile --generate-hashes --output-file constraints-hashed.txt requirements.txt
	pip-compile --generate-hashes --allow-unsafe --output-file constraints-dev-hashed.txt requirements.txt requirements-dev.txt
	# Keep the un-hashed audit set (constraints.txt) byte-for-byte version-aligned
	# with constraints-hashed.txt so pip-audit checks exactly what gets installed.
	$(MAKE) sync-constraints

# Same as `update-hashes`, but lets every transitive dependency float up to its
# newest compatible release instead of holding the existing pins. Bump the direct
# pins in requirements*.txt first, then run this — otherwise the direct deps stay
# put while their dependencies move, which is rarely what a dependency bump means.
upgrade-deps:
	pip-compile --upgrade --generate-hashes --output-file constraints-hashed.txt requirements.txt
	pip-compile --upgrade --generate-hashes --allow-unsafe --output-file constraints-dev-hashed.txt requirements.txt requirements-dev.txt
	$(MAKE) sync-constraints

# Derive constraints.txt (used by pip-audit) from the pinned, hashed set so the
# two can never drift. Run on its own after a manual hashed-file edit, or via
# `update-hashes`.
sync-constraints:
	python scripts/sync-constraints.py
