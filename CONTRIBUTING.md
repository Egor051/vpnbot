# Contributing

## Development Environment

### Prerequisites

- Python 3.12 (3.12.x)
- Linux (Ubuntu recommended; privileged deploy flows require Linux system tools)
- git

### Clone and install

```bash
git clone https://github.com/Egor051/vpnbot.git
cd vpnbot
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt -c constraints.txt
pip install -r requirements-dev.txt
```

### Environment file

Copy `.env.example` to `.env` and fill in the required values. `BOT_TOKEN` and `ADMIN_IDS`
are required for startup. VPN backend values (`XRAY_*`, `AWG_*`, etc.) are only needed when
testing that specific key type. Never commit your `.env`.

```bash
cp .env.example .env
# edit .env with your values
```

For local development without a privileged VDS, set `PRIVILEGE_HELPERS_ENABLED=false`. The
bot will call config adapters directly without going through sudo helpers.

## Code Quality

All gates below match what CI runs. Pass them locally before pushing.

### Lint (CI gate)

CI runs the full ruff check (style, security, and bugbear rules):

```bash
python -m ruff check .
```

For a fast pre-commit subset of the most critical rules:

```bash
python -m ruff check . --select=E9,F63,F7,F82
```

### Format

```bash
python -m ruff format --check .   # check only
python -m ruff format .            # apply
```

### Compile check

```bash
python -m compileall .
```

### Type checking

CI runs strict mypy over the source packages plus the entry points:

```bash
python -m mypy --strict bot/ services/ adapters/ config/ models/ utils/ repositories/ main.py init_db.py
```

All modules under those packages require full type annotations
(`strict = true` in `pyproject.toml`).

### Dependency audit

```bash
make audit
```

This runs `pip_audit` over `requirements.txt` + `constraints.txt` with no
ignored advisories (`make audit` carries no `--ignore-vuln` exceptions). Run it
before adding or upgrading a dependency; a clean run must report no known
vulnerabilities.

## Running Tests

```bash
python -m pytest
```

With coverage report:

```bash
python -m pytest --cov=. --cov-report=term-missing
```

CI enforces a minimum of 60% branch coverage. Tests live in `tests/` and do not
require a live VPN server — all system-level calls are mocked.

When adding a feature, add or update tests in `tests/`. Name files after the
feature area, e.g. `test_<area>.py`.

## All Local Gates at Once

```bash
python -m ruff check .
python -m compileall .
python -m mypy --strict bot/ services/ adapters/ config/ models/ utils/ repositories/ main.py init_db.py
python -m pytest --cov=. --cov-fail-under=60
make audit
```

(`make check` runs the ruff/compile/mypy/pytest/audit gates in one shot.)

## Code Standards

- Target Python 3.12 (3.12.x); use modern type-hint syntax (`X | Y`, `list[X]`, etc.).
- All public functions in the source packages require type annotations.
- Use `async def` for I/O-bound operations.
- Use per-user async locks (`services/user_locks.py`) when mutating user-owned state.
- Use config file locks (`adapters/file_lock.py`) when writing VPN config files.
- Use `adapters/shell_runner.py` instead of raw `subprocess` for shell commands.
- Mask secrets in logs and audit records via `utils/redact.py` and `services/audit.py`.
- Read all paths and settings from `config/settings.py`; do not hardcode paths.
- Keep backend adapters free of Telegram/bot logic; keep bot handlers free of
  infrastructure calls.

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `security`

Examples:

```
feat(xray): add short-ID rotation on key create
fix(awg): handle missing interface during reconciliation
docs: update deployment guide for managed MTProto
test(socks5): add helper revoke regression tests
perf: parallelize traffic-stats refresh
security: mask AWG preshared key in audit output
```

Scope is optional but encouraged for non-trivial changes. Keep the subject
concise and in the imperative mood ("add", not "added" or "adds").

## Branch Naming

```
<type>/<short-description>
```

Examples:

```
feat/mtproto-per-user-revoke
fix/xray-startup-reconcile
docs/contributing-guide
test/audit-privacy-coverage
```

## Testing Network Components Locally

The test suite mocks all system-level calls. For end-to-end testing against a
real VPN backend:

1. Set up a staging Ubuntu VM or VDS (do not use production).
2. Install Xray and/or AmneziaWG on the VM.
3. Set `PRIVILEGE_HELPERS_ENABLED=false` for dev (direct adapter calls, no sudo helpers).
4. Run `python init_db.py` to initialise the database.
5. Run `python main.py` and interact via Telegram.
6. Check logs with `journalctl -u vpn-bot` or the configured `LOG_DIR`.

For SOCKS5 or managed MTProto testing, install Dante/MTProxy on the staging server
and set `PRIVILEGE_HELPERS_ENABLED=true` with the helpers deployed as described in
`docs/deployment.md` and `deploy/helpers/README.md`.

## Security Considerations

When adding features, observe these requirements:

- **Secret masking**: Any new credential or token must be redacted in logs and
  audit records. Add patterns to `utils/redact.py` and cover them with tests.
- **Privilege separation**: Root-only operations (config writes, service restarts,
  user management) must go through the sudo helpers in `deploy/helpers/`. Never
  call elevated commands directly from bot or service code.
- **Ownership checks**: Users must see only their own VPN keys and proxy accesses.
  Admin-only actions must validate the caller's role (`bot/guards.py`).
- **Input validation**: Validate any input that reaches the database, config files,
  or shell commands. Do not build shell command strings from user-supplied data.
- **Config atomicity**: Xray and AWG config writes must use the backup/rollback
  pattern in `adapters/xray_config.py` and `adapters/awg_config.py`.
- **New environment variables**: Add to `.env.example` (empty value) and
  `config/settings.py`, and document the variable (valid range, security impact)
  in `docs/configuration.md` — the canonical reference the drift-guard test checks.
- **Documentation**: User-facing docs live in `docs/` as bilingual pairs
  (`<name>.md` + `<name>.ru.md`). When you change one language, mirror the change in
  the other; `README.md` and `README_RU.md` stay short and link into `docs/`.
- **New dependencies**: Add the pin to `requirements.txt` (or
  `requirements-dev.txt`), run `make update-hashes` (under Python 3.12) to
  regenerate the constraints files, and run `pip_audit` before committing. Never
  hand-edit `constraints.txt` — it is generated from `constraints-hashed.txt`.

## Pull Request Process

1. Open a PR against `main` with a descriptive title following the commit format.
2. Fill in the PR template: summary, change type, affected areas, testing steps,
   and security checklist.
3. All CI gates must pass (ruff, compileall, mypy, pytest ≥ 60% coverage, pip_audit).
4. A reviewer will check security implications, code clarity, test coverage, and
   adherence to project conventions.
5. Address review comments.
6. PRs are squash-merged to keep `main` history clean.

Do not force-push to `main`. Keep feature branches focused on a single change.
