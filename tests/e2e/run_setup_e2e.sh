#!/usr/bin/env bash
# The first setup end to end on a real ubuntu-24.04 VM with systemd (CI job setup-e2e):
#
#   install.sh → /start claim_<code> → «🧭 Первичная настройка» driven through the mock Bot
#   API: the domain, the Cloudflare token (a mock Cloudflare API), the certificate (an
#   acme.sh home of a test CA, adopted), VLESS REALITY + Hysteria2 installed by the bot
#   (the real nginx, xray and hysteria — the pinned release files from the helper's release
#   cache), the firewall, TOTP skipped, the self-check — which must be green.
#
# The network is CLOSED for root while the setup runs (an iptables owner match: every
# packet root sends off loopback is rejected): nothing the bot or its helpers do may need
# it. What they need comes from fixtures prepared before (tests/e2e/setup_e2e_fixtures.py,
# apt-get --download-only).
#
# Run as root: sudo MOCK_PYTHON=<python with aiohttp> bash tests/e2e/run_setup_e2e.sh
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"
MOCK_PYTHON="${MOCK_PYTHON:?MOCK_PYTHON must point at a python with aiohttp}"
MOCK="http://127.0.0.1:8081"
CF="http://127.0.0.1:8082"
TOKEN="7000000001:AAE2e$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
CF_TOKEN="cfE2E_$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
DOMAIN="vpn.e2e.test"
ZONE="e2e.test"
OPERATOR=424242
APP_DIR=/opt/vpn-service
WORK="$(mktemp -d)"
PIDS=()

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'E2E FAILURE: %s\n' "$*" >&2; exit 1; }

open_network() {
  iptables -D OUTPUT -m owner --uid-owner 0 ! -o lo -j REJECT 2>/dev/null || true
  ip6tables -D OUTPUT -m owner --uid-owner 0 ! -o lo -j REJECT 2>/dev/null || true
}
cleanup() {
  open_network
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || fail "run as root"
[[ ! -e "$APP_DIR" ]] || fail "$APP_DIR already exists — this must run on a fresh VM"

export INSTALL_REPO="file://${REPO_ROOT}"
export INSTALL_REF
INSTALL_REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
export TELEGRAM_API_BASE="$MOCK"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

wait_http() {
  local url="$1"
  for _ in $(seq 1 50); do curl -fsS --max-time 2 "$url" >/dev/null 2>&1 && return 0; sleep 0.2; done
  fail "$url did not come up"
}

# --------------------------------------------------------------------------- #
step "mocks: Bot API on ${MOCK}, Cloudflare API on ${CF}"
MOCK_BOT_TOKEN="$TOKEN" "$MOCK_PYTHON" "${REPO_ROOT}/tests/e2e/mock_telegram_api.py" --port 8081 >"${WORK}/tg.log" 2>&1 &
PIDS+=($!)
MOCK_CF_TOKEN="$CF_TOKEN" MOCK_CF_ZONE="$ZONE" "$MOCK_PYTHON" "${REPO_ROOT}/tests/e2e/mock_cloudflare_api.py" --port 8082 \
  >"${WORK}/cf.log" 2>&1 &
PIDS+=($!)
wait_http "${MOCK}/_control/health"
wait_http "${CF}/_control/health"

# --------------------------------------------------------------------------- #
step "fixtures (network still open): release cache, the acme.sh home of a test CA, /etc/hosts, .debs"
python3 "${REPO_ROOT}/tests/e2e/setup_e2e_fixtures.py" releases
python3 "${REPO_ROOT}/tests/e2e/setup_e2e_fixtures.py" acme
HOST_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
[[ -n "$HOST_IP" ]] || fail "no global IPv4 on this VM"
python3 "${REPO_ROOT}/tests/e2e/setup_e2e_fixtures.py" hosts "$HOST_IP"
apt-get update -q >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --download-only --no-install-recommends nginx >/dev/null

# --------------------------------------------------------------------------- #
step "install.sh"
printf '1\n%s\n' "$TOKEN" | bash "$INSTALL_SH" >"${WORK}/install.out" 2>"${WORK}/install.err" \
  || { cat "${WORK}/install.err"; fail "install.sh failed"; }
link="$(grep -oE 'https://t\.me/vpnbot_ci_bot\?start=claim_[A-Za-z0-9_-]+' "${WORK}/install.out" | head -n1)"
code="${link##*start=claim_}"
[[ -n "$code" ]] || fail "no claim link"
for helper in vpn-bot-protocol-install vpn-bot-wizard-protocol vpn-bot-ufw-apply vpn-bot-cert; do
  [[ -x "/usr/local/sbin/${helper}" ]] || fail "install.sh did not install ${helper}"
done
# The bot talks to the mock Cloudflare API (loopback http only — config/settings.py).
printf 'CLOUDFLARE_API_BASE=%s/client/v4\n' "$CF" >>"$APP_DIR/.env"
systemctl restart vpn-bot.service
sleep 5

# --------------------------------------------------------------------------- #
step "the network is closed for root from here on"
iptables -A OUTPUT -m owner --uid-owner 0 ! -o lo -j REJECT
ip6tables -A OUTPUT -m owner --uid-owner 0 ! -o lo -j REJECT 2>/dev/null || true
if curl -fsS --max-time 5 https://github.com >/dev/null 2>&1; then fail "root still reaches the network"; fi

# --------------------------------------------------------------------------- #
step "claim, then «🧭 Первичная настройка» (offered: no protocol on the host)"
curl -fsS --max-time 5 -H 'Content-Type: application/json' \
  -d "{\"user_id\": ${OPERATOR}, \"text\": \"/start claim_${code}\"}" "${MOCK}/_control/inject" >/dev/null
python3 "${REPO_ROOT}/tests/e2e/drive_setup.py" "$OPERATOR" "$DOMAIN" "$CF_TOKEN" | tee "${WORK}/drive.out" \
  || fail "the first setup did not succeed"

# --------------------------------------------------------------------------- #
step "the host after the setup"
for unit in vpn-bot xray nginx hysteria-server vpnbot-hy2-auth; do
  [[ "$(systemctl is-active "${unit}.service")" == active ]] || fail "${unit} is not active"
done
ss -Hltn | grep -q '127.0.0.1:8443' || fail "the self-steal does not listen"
ss -Hlun | grep -qE '(\*|0\.0\.0\.0|\[::\]):443\b' || fail "hysteria does not listen on UDP 443"
grep -q "^XRAY_SNI=${DOMAIN}$" "$APP_DIR/.env" || fail "XRAY_SNI is not the domain"
grep -q '^HYSTERIA2_ENABLED=true$' "$APP_DIR/.env" || fail "HYSTERIA2_ENABLED is not true"
[[ "$(stat -c '%U %a' /usr/local/etc/xray/config.json)" == "nobody 640" ]] || fail "config.json owner/mode"
openssl s_client -connect 127.0.0.1:8443 -servername "$DOMAIN" -alpn h2 -verify_hostname "$DOMAIN" \
  -verify_return_error -brief </dev/null 2>&1 | grep -q 'ALPN protocol: h2' || fail "the self-steal does not serve h2"
records="$(curl -fsS "${CF}/_control/records")"
[[ "$records" == "[]" ]] || fail "the token check left records at Cloudflare: ${records}"
python3 - <<'PY' || fail "the self-check was not green"
import sqlite3
conn = sqlite3.connect("file:/opt/vpn-service/data/vpn.db?mode=ro", uri=True)
row = conn.execute("SELECT state, summary FROM wizard_runs WHERE mode = 'selfcheck' ORDER BY id DESC LIMIT 1").fetchone()
print("self-check:", row)
assert row is not None and row[0] == "succeeded" and "red=0" in row[1], row
PY
for secret in "$TOKEN" "$CF_TOKEN" "$code"; do
  for f in /var/log/vpn-bot-install.* "$APP_DIR"/logs/bot.log* /var/log/vpn-bot-wizard/*.log /var/log/vpn-bot-protocol-install.log; do
    [[ -f "$f" ]] || continue
    if grep -qF -- "$secret" "$f"; then fail "a secret reached ${f}"; fi
  done
done
step "E2E OK"
