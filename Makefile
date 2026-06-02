.PHONY: lint compile typecheck test check update-hashes

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

check: lint compile typecheck test

update-hashes:
	pip-compile --generate-hashes --output-file constraints-hashed.txt requirements.txt
	pip-compile --generate-hashes --allow-unsafe --output-file constraints-dev-hashed.txt requirements.txt requirements-dev.txt
