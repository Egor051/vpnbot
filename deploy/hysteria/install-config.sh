#!/usr/bin/env bash
#
# install-config.sh — install deploy/hysteria/config.yaml as
# /etc/hysteria/config.yaml WITHOUT losing the live Traffic Stats secret.
#
# The tracked repo config carries a placeholder `secret: "<random-secret>"` in
# its trafficStats block (see config.yaml's own header). A bare
# `cp deploy/hysteria/config.yaml /etc/hysteria/config.yaml` overwrites the
# real secret with that placeholder, so hysteria-server starts rejecting the
# bot's stats/online/kick calls with 401 — silently, since the data plane
# itself still starts fine. This script is the ONLY supported way to (re)install
# the file: it copies the repo config AND injects the real secret from
# HYSTERIA2_STATS_SECRET in .env, so the placeholder never reaches disk.
#
# Before anything is written it also checks the installed hysteria binary
# ($HYSTERIA_BIN, default /usr/local/bin/hysteria): the repo config sets
# `congestion.bbrProfile`, which needs hysteria >= v2.8.0, and an older server
# would be handed a config it does not implement. A binary that is missing,
# older than that, or whose `version` output carries no parseable
# `Version: vX.Y.Z` line fails closed — the target is left untouched.
#
# Usage:
#   sudo bash deploy/hysteria/install-config.sh [--env <path>] [--target <path>]
#   sudo HYSTERIA_BIN=/path/to/hysteria bash deploy/hysteria/install-config.sh ...
#   bash deploy/hysteria/install-config.sh --selftest
#
# Exit codes:
#   0  installed (or --selftest passed)
#   1  fail-closed: a precondition was not met (see stderr) — nothing written
#   2  usage error
#
# Not a systemd hook — run by hand before restarting the service, same as
# deploy/hysteria/preflight-udp443.sh. hysteria-server is never restarted by
# this script; see the "next steps" it prints on success.
set -euo pipefail

ME="install-config"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_CONFIG="$SCRIPT_DIR/config.yaml"

# Test seam (NOT part of the public CLI): tests/test_hysteria_install_config.py
# sets these to drive the real install path without root / the `hysteria`
# system user, mirroring the DEPLOY_SELFTEST seam in scripts/deploy.sh. Left
# unset, behaviour is exactly "install -o hysteria -g hysteria -m 0600" as root.
REQUIRE_ROOT="${INSTALL_CONFIG_REQUIRE_ROOT:-1}"
OWNER="${INSTALL_CONFIG_OWNER:-hysteria}"
GROUP="${INSTALL_CONFIG_GROUP:-hysteria}"

# The hysteria-server binary whose version is checked before installing.
# Public knob (unlike the seam above): a host with the binary elsewhere sets it.
HYSTERIA_BIN="${HYSTERIA_BIN:-/usr/local/bin/hysteria}"
# Oldest release that understands `congestion.bbrProfile` in the repo config.
MIN_HYSTERIA_MAJOR=2
MIN_HYSTERIA_MINOR=8
MIN_HYSTERIA_PATCH=0
MIN_HYSTERIA_VERSION="v${MIN_HYSTERIA_MAJOR}.${MIN_HYSTERIA_MINOR}.${MIN_HYSTERIA_PATCH}"

die() {
  echo "$ME: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<EOF
usage: $ME [--env <path>] [--target <path>]
       $ME --selftest

  --env <path>     path to the bot's .env (default: /opt/vpn-service/.env)
  --target <path>  install destination (default: /etc/hysteria/config.yaml)
  --selftest       run built-in checks against a canned repo config, a
                    fake secret and mock hysteria binaries in a temp dir —
                    no root, no real files touched

  HYSTERIA_BIN     hysteria binary to version-check
                    (default: /usr/local/bin/hysteria; must be >= $MIN_HYSTERIA_VERSION)

Copies $REPO_CONFIG to <target>, replacing its trafficStats.secret
placeholder with HYSTERIA2_STATS_SECRET read from <env>. Refuses to
install unless HYSTERIA_BIN reports $MIN_HYSTERIA_VERSION or newer. Never
restarts hysteria-server; see the printed next-steps on success.
EOF
}

# check_hysteria_version <bin>
#
# Succeeds only if `<bin> version` reports MIN_HYSTERIA_VERSION or newer.
# Fails closed (message on stderr, non-zero) when the binary is missing or not
# executable, when `version` exits non-zero, or when no `Version: vX.Y.Z` line
# can be found. The real output starts with an ASCII-art banner (non-ASCII box
# characters) before its `Key: value` lines, so the line is searched for
# anywhere in the output, with grep -a so the banner never makes grep treat the
# text as binary. Components are compared numerically (v2.10.0 > v2.8.0).
check_hysteria_version() {
  local bin="$1" out line major minor patch
  if [[ ! -f "$bin" || ! -x "$bin" ]]; then
    echo "$ME: hysteria binary not found or not executable: $bin" \
      "-- install hysteria >= $MIN_HYSTERIA_VERSION or point HYSTERIA_BIN at it" >&2
    return 1
  fi
  if ! out="$("$bin" version 2>&1)"; then
    echo "$ME: '$bin version' failed -- cannot verify hysteria >= $MIN_HYSTERIA_VERSION" >&2
    return 1
  fi
  line="$(grep -a -m1 -E '^Version:[[:space:]]*v?[0-9]+\.[0-9]+\.[0-9]+' <<<"$out" || true)"
  if [[ ! "$line" =~ ^Version:[[:space:]]*v?([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    echo "$ME: no 'Version: vX.Y.Z' line in '$bin version' output" \
      "-- cannot verify hysteria >= $MIN_HYSTERIA_VERSION" >&2
    return 1
  fi
  # 10# so a component like "08" is decimal, not an invalid octal literal.
  major=$((10#${BASH_REMATCH[1]}))
  minor=$((10#${BASH_REMATCH[2]}))
  patch=$((10#${BASH_REMATCH[3]}))
  if ((major > MIN_HYSTERIA_MAJOR ||
    (major == MIN_HYSTERIA_MAJOR && minor > MIN_HYSTERIA_MINOR) ||
    (major == MIN_HYSTERIA_MAJOR && minor == MIN_HYSTERIA_MINOR && patch >= MIN_HYSTERIA_PATCH))); then
    return 0
  fi
  echo "$ME: $bin is v$major.$minor.$patch, the repo config needs >= $MIN_HYSTERIA_VERSION" \
    "(congestion.bbrProfile) -- upgrade hysteria first; nothing was installed" >&2
  return 1
}

# Reads repo_config and env_file, prints the transformed config (secret
# injected) to stdout. Fails closed (non-zero, message on stderr) if
# HYSTERIA2_STATS_SECRET is missing from env_file, or if repo_config does not
# contain exactly one indented `secret:` line. An empty (but present)
# HYSTERIA2_STATS_SECRET is a WARNING, not a failure (loopback-only stats API
# left unauthenticated is a deliberate, existing opt-out).
#
# Deliberately does NOT use PyYAML (not a project dependency): the placeholder
# line is replaced textually and json.dumps() is used to produce a valid
# YAML/JSON double-quoted scalar for the secret, so no quoting/escaping is
# left to hand-rolled shell string-munging.
transform_config() {
  local repo_config="$1" env_file="$2"
  python3 - "$repo_config" "$env_file" <<'PYEOF'
import json
import re
import sys

repo_config_path, env_path = sys.argv[1], sys.argv[2]

# Matches `KEY=value` / `export KEY=value` lines only when KEY starts at the
# first non-whitespace column, so a commented-out `# HYSTERIA2_STATS_SECRET=…`
# line never matches (the leading "#" is not whitespace).
SECRET_RE = re.compile(r"^[ \t]*(?:export[ \t]+)?HYSTERIA2_STATS_SECRET[ \t]*=[ \t]*(.*)$")
# The repo config's trafficStats.secret line: indented, `secret:` key exactly.
SECRET_LINE_RE = re.compile(r"^([ \t]+)secret:.*$")

PLACEHOLDER = "<random-secret>"


def dequote(raw: str) -> str:
    raw = raw.rstrip("\r\n")
    # A value wrapped in matching quotes is taken verbatim between them (no
    # escape processing) — this is what lets a secret contain '#', since an
    # unquoted value is otherwise taken to end-of-line with NO comment
    # stripping (unlike shell/dotenv convention): silently truncating a
    # secret at its first '#' would be a much worse footgun than not
    # supporting inline comments on this one line.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    return raw


found = False
secret = ""
with open(env_path, encoding="utf-8", errors="replace") as f:
    for line in f:
        m = SECRET_RE.match(line)
        if m:
            # Last-assignment-wins, same convention as scripts/vpnbot-hy2-warp-mark.
            found = True
            secret = dequote(m.group(1))

if not found:
    print(
        f"install-config: HYSTERIA2_STATS_SECRET not found in {env_path} "
        "-- set HYSTERIA2_STATS_SECRET in .env first",
        file=sys.stderr,
    )
    sys.exit(1)

if secret == "":
    print(
        f"install-config: WARNING: HYSTERIA2_STATS_SECRET is empty in {env_path} "
        "-- the Traffic Stats API will run without auth on loopback",
        file=sys.stderr,
    )

with open(repo_config_path, encoding="utf-8") as f:
    lines = f.readlines()

matches = [i for i, line in enumerate(lines) if SECRET_LINE_RE.match(line)]
if len(matches) != 1:
    print(
        f"install-config: expected exactly one indented 'secret:' line in "
        f"{repo_config_path}, found {len(matches)} -- refusing to guess",
        file=sys.stderr,
    )
    sys.exit(1)

idx = matches[0]
indent = SECRET_LINE_RE.match(lines[idx]).group(1)  # type: ignore[union-attr]
lines[idx] = f"{indent}secret: {json.dumps(secret)}\n"

output = "".join(lines)
if PLACEHOLDER in output:
    print(
        f"install-config: placeholder {PLACEHOLDER!r} still present after "
        "substitution -- refusing to install",
        file=sys.stderr,
    )
    sys.exit(1)

sys.stdout.write(output)
PYEOF
}

# write_mock_hysteria <path> <version-line>
#
# Selftest only: writes an executable stand-in for `hysteria` that, on
# `version`, prints what the real one does — a banner of non-ASCII box
# characters, then tab-separated `Key: value` lines. An empty <version-line>
# leaves the Version: line out (banner only).
write_mock_hysteria() {
  local path="$1" version_line="$2"
  {
    printf '#!/bin/sh\n'
    # shellcheck disable=SC2016  # literal $1: expanded by the mock, not here
    printf '[ "$1" = version ] || exit 2\n'
    printf "cat <<'BANNER'\n"
    printf '░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█░░░▀▀▄\n'
    printf '░█▀█░░█░░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█░░░▄▀░\n'
    printf 'a powerful, lightning fast and censorship resistant proxy\n'
    printf '\n'
    if [[ -n "$version_line" ]]; then
      printf '%s\n' "$version_line"
    fi
    printf 'BuildType:\trelease\n'
    printf 'Platform:\tlinux\n'
    printf 'BANNER\n'
  } >"$path"
  chmod 0755 "$path"
}

selftest() {
  local failures=0
  local workdir
  workdir="$(mktemp -d)"
  trap 'rm -rf "$workdir"' RETURN

  local canned_repo="$workdir/config.yaml"
  cat >"$canned_repo" <<'EOF2'
listen: :443

tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.pem

auth:
  type: http
  http:
    url: http://127.0.0.1:8444/auth

trafficStats:
  listen: 127.0.0.1:9999
  secret: "<random-secret>"
EOF2

  # Case 1: a secret with quote/backslash/hash characters round-trips exactly,
  # the placeholder disappears, and exactly one secret: line remains.
  local secret1='ab"cd\ef#gh'
  local env1="$workdir/env-ok"
  printf 'HYSTERIA2_STATS_SECRET=%s\n' "$secret1" >"$env1"
  local out1="$workdir/out1.yaml"
  if transform_config "$canned_repo" "$env1" >"$out1" 2>"$workdir/out1.err" && python3 - "$out1" "$secret1" <<'PYEOF'
import json
import re
import sys

content = open(sys.argv[1], encoding="utf-8").read()
expected = sys.argv[2]
assert "<random-secret>" not in content
lines = [line for line in content.splitlines() if re.match(r"^[ \t]+secret:", line)]
assert len(lines) == 1, f"expected exactly one secret: line, got {len(lines)}"
m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
assert json.loads(m.group(1)) == expected
PYEOF
  then
    echo "$ME: selftest PASS: secret with quotes/backslash/hash injected, placeholder removed" >&2
  else
    echo "$ME: selftest FAIL: secret injection" >&2
    failures=$((failures + 1))
  fi

  # Case 2: fail closed when HYSTERIA2_STATS_SECRET is absent from .env.
  local env2="$workdir/env-missing"
  printf 'SOME_OTHER_VAR=1\n' >"$env2"
  if transform_config "$canned_repo" "$env2" >/dev/null 2>"$workdir/out2.err"; then
    echo "$ME: selftest FAIL: missing HYSTERIA2_STATS_SECRET should have failed closed" >&2
    failures=$((failures + 1))
  elif grep -q 'HYSTERIA2_STATS_SECRET' "$workdir/out2.err"; then
    echo "$ME: selftest PASS: missing HYSTERIA2_STATS_SECRET fails closed" >&2
  else
    echo "$ME: selftest FAIL: missing-secret error message did not mention HYSTERIA2_STATS_SECRET" >&2
    failures=$((failures + 1))
  fi

  # Case 3: an empty (but present) secret warns and still succeeds.
  local env3="$workdir/env-empty"
  printf 'HYSTERIA2_STATS_SECRET=\n' >"$env3"
  if transform_config "$canned_repo" "$env3" >/dev/null 2>"$workdir/out3.err" && grep -q 'WARNING' "$workdir/out3.err"; then
    echo "$ME: selftest PASS: empty HYSTERIA2_STATS_SECRET warns and proceeds" >&2
  else
    echo "$ME: selftest FAIL: empty HYSTERIA2_STATS_SECRET should warn and still succeed" >&2
    failures=$((failures + 1))
  fi

  # Case 4: last-assignment-wins when HYSTERIA2_STATS_SECRET is set twice.
  local env4="$workdir/env-dup"
  printf 'HYSTERIA2_STATS_SECRET=first\nHYSTERIA2_STATS_SECRET=second\n' >"$env4"
  local out4="$workdir/out4.yaml"
  if transform_config "$canned_repo" "$env4" >"$out4" 2>/dev/null && grep -q 'secret: "second"' "$out4"; then
    echo "$ME: selftest PASS: last HYSTERIA2_STATS_SECRET assignment wins" >&2
  else
    echo "$ME: selftest FAIL: last-assignment-wins" >&2
    failures=$((failures + 1))
  fi

  # Cases 5+: the hysteria version guard, against mock binaries shaped like the
  # real `hysteria version` output. Never the host's binary: every case passes
  # an explicit path under $workdir, and HYSTERIA_BIN is not consulted at all.
  local mockdir="$workdir/bin" spec ver want got mock
  mkdir -p "$mockdir"
  for spec in 'v2.7.1|fail' 'v2.8.0|ok' 'v2.10.0|ok' '2.9.3|ok' 'v1.99.99|fail' 'v3.0.0|ok'; do
    ver="${spec%%|*}"
    want="${spec##*|}"
    mock="$mockdir/hysteria-$ver"
    write_mock_hysteria "$mock" "$(printf 'Version:\t%s' "$ver")"
    if check_hysteria_version "$mock" 2>/dev/null; then got=ok; else got=fail; fi
    if [[ "$got" == "$want" ]]; then
      echo "$ME: selftest PASS: version guard: $ver -> $want" >&2
    else
      echo "$ME: selftest FAIL: version guard: $ver gave $got, expected $want" >&2
      failures=$((failures + 1))
    fi
  done

  # Fail-closed cases: banner with no Version: line, an unparseable one, and no
  # binary at all.
  write_mock_hysteria "$mockdir/hysteria-banner-only" ""
  write_mock_hysteria "$mockdir/hysteria-garbage" "Version: banana"
  for spec in 'hysteria-banner-only|banner without a Version: line' \
    'hysteria-garbage|unparseable Version: line' \
    'does-not-exist|missing binary'; do
    mock="$mockdir/${spec%%|*}"
    if check_hysteria_version "$mock" 2>/dev/null; then
      echo "$ME: selftest FAIL: version guard: ${spec##*|} should have failed closed" >&2
      failures=$((failures + 1))
    else
      echo "$ME: selftest PASS: version guard: ${spec##*|} fails closed" >&2
    fi
  done

  if [[ "$failures" -ne 0 ]]; then
    echo "$ME: selftest: $failures failure(s)" >&2
    return 1
  fi
  echo "$ME: selftest: all checks passed" >&2
  return 0
}

main() {
  local env_file="/opt/vpn-service/.env"
  local target="/etc/hysteria/config.yaml"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env)
        [[ $# -ge 2 ]] || { usage; exit 2; }
        env_file="$2"
        shift 2
        ;;
      --target)
        [[ $# -ge 2 ]] || { usage; exit 2; }
        target="$2"
        shift 2
        ;;
      --selftest)
        selftest
        exit $?
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage
        exit 2
        ;;
    esac
  done

  if [[ "$REQUIRE_ROOT" == "1" ]]; then
    [[ "$EUID" -eq 0 ]] || die "must run as root -- writes to $target, owned by $OWNER:$GROUP (re-run with sudo)"
    id -u "$OWNER" >/dev/null 2>&1 || die "system user '$OWNER' not found -- install hysteria-server first"
  fi

  [[ -f "$REPO_CONFIG" ]] || die "repo config not found: $REPO_CONFIG"
  [[ -f "$env_file" ]] || die "env file not found: $env_file -- pass --env <path> or create it first"

  # Before any write (temp file, backup, target): an old binary must never be
  # handed a config it cannot run. check_hysteria_version prints the reason.
  check_hysteria_version "$HYSTERIA_BIN" || exit 1

  # Not `local`: the EXIT trap below fires after main() returns to top-level
  # scope, where a local variable would already be unset (unbound under -u).
  tmp="$(mktemp)"
  trap 'rm -f "${tmp:-}"' EXIT

  transform_config "$REPO_CONFIG" "$env_file" >"$tmp"

  if [[ -e "$target" ]]; then
    local backup
    backup="${target}.bak.$(date +%Y%m%dT%H%M%S)"
    cp -p "$target" "$backup" || die "failed to back up existing $target to $backup"
    echo "$ME: backed up existing $target -> $backup" >&2
  fi

  if [[ "$REQUIRE_ROOT" == "1" ]]; then
    install -o "$OWNER" -g "$GROUP" -m 0600 "$tmp" "$target" || die "failed to install $target"
  else
    install -m 0600 "$tmp" "$target" || die "failed to install $target"
  fi

  cat >&2 <<EOF2
$ME: installed $target (mode 0600, owner $OWNER:$GROUP)
$ME: hysteria-server was NOT restarted. Next steps:
  bash "$SCRIPT_DIR/preflight-udp443.sh"   # must exit 0 before (re)starting
  sudo systemctl restart hysteria-server
EOF2
}

main "$@"
