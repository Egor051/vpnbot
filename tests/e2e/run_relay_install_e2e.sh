#!/usr/bin/env bash
#
# End-to-end check of scripts/install.sh in RELAY mode on a real systemd host, as
# root. Run by the `relay-installer-e2e` job of .github/workflows/ci.yml on a fresh
# ubuntu-24.04 runner VM; never run it on a host you care about — it installs a relay
# (nftables DNAT, an authorized_keys line for root) and removes it again.
#
#   sudo bash tests/e2e/run_relay_install_e2e.sh
#
# The "main server" is simulated on this host: its DNS names are /etc/hosts entries
# pointing at addresses of a dummy interface, where a TCP listener answers on 443
# (so `vpn-relay-apply check` reaches the upstream). The "bot" is this script with an
# ed25519 key of its own; the pairing code comes from services/relay_pairing.py.
#
# Phases, each one a hard assertion:
#   R0. a HAND-MADE relay: /etc/vpn-relay.nft + vpn-relay.service, table loaded;
#   R1. a failure injected after the relay started rolls back: the live table, the
#       hand-made file and unit, authorized_keys, ip_forward — all as before;
#   R2. a real install ADOPTS it: one table ip vpnrelay, exactly one DNAT per port
#       (to the new target), the old relay kept in /var/backups/vpn-relay, units
#       active, one restricted authorized_keys line, no token or code in any log;
#   R3. the agent over a real ssh: nothing but hello before the pairing, a wrong
#       token refused, hello, status; shell syntax, other commands, an interactive
#       shell and port forwarding refused;
#   R4. apply re-points the forward (one DNAT, the new address); an ssh port refused;
#   R5. the resolve timer: the name moves to another address -> the table follows;
#   R6. uninstall: tables, units, helpers, the key line gone; the backup stays.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"
FIXTURES="${REPO_ROOT}/tests/fixtures/relay"
WORK="$(mktemp -d)"
MAIN_A=198.51.100.10
MAIN_B=198.51.100.20
OLD_UPSTREAM=192.0.2.77
TARGET=vpn-main.e2e.test
ALT=vpn-alt.e2e.test
AUTH_KEYS=/root/.ssh/authorized_keys
LISTENERS=()

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'RELAY E2E FAILURE: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local pid
  for pid in "${LISTENERS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || fail "run as root"
[[ ! -e /opt/vpn-service ]] || fail "/opt/vpn-service already exists — this must run on a fresh VM"

export INSTALL_REPO="file://${REPO_ROOT}"
export INSTALL_REF
INSTALL_REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

installer() { bash "$INSTALL_SH" "$@"; }

# `nft list table ip vpnrelay` without counters and handles: what the table IS.
table_shape() { nft list table ip vpnrelay 2>/dev/null | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'; }

dnat_count() { nft list ruleset | grep -cE "$1 dport $2 .*dnat (ip )?to" || true; }

sha() { if [[ -e "$1" ]]; then sha256sum "$1" | cut -d' ' -f1; else echo absent; fi; }

newest() { { ls -1t /var/log/vpn-bot-install.*."$1" 2>/dev/null || true; } | head -n1; }

ssh_main() {
  ssh -F /dev/null -i "${WORK}/main_key" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="${WORK}/known_hosts" \
    -o ConnectTimeout=10 root@127.0.0.1 "$@"
}

# rc of an ssh request, its JSON on stdout in $WORK/out.json. `--` first: OpenSSH parses
# options after the destination too, so a request starting with "-" would be ssh's own.
agent() {
  local rc
  set +e
  ssh_main -- "$1" >"${WORK}/out.json" 2>"${WORK}/out.err"
  rc=$?
  set -e
  printf '%s' "$rc"
}

json_field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2]))' "${WORK}/out.json" "$1"; }

pairing_code() {
  python3 - "$REPO_ROOT" "$(cat "${WORK}/main_key.pub")" "$1" <<'PY'
import sys, time
sys.path.insert(0, sys.argv[1])
from services.relay_pairing import PairingCode, encode_pairing_code
print(encode_pairing_code(PairingCode(target_host="vpn-main.e2e.test", tcp_ports=(443,), udp_ports=(443,),
                                      main_pubkey=sys.argv[2], token=sys.argv[3], exp=int(time.time()) + 1800)))
PY
}

assert_no_secret_in_logs() {
  local secret="$1" what="$2" f
  for f in /var/log/vpn-bot-install.* /etc/vpn-relay/*; do
    [[ -f "$f" ]] || continue
    if grep -qF -- "$secret" "$f"; then fail "${what} found in ${f}"; fi
  done
  if journalctl --no-pager -t vpn-relay-agent 2>/dev/null | grep -qF -- "$secret"; then fail "${what} in the journal"; fi
}

# --------------------------------------------------------------------------- #
step "setup: nftables, sshd with key login for root, a simulated main server"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 update -qq
apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends nftables openssh-server git curl >/dev/null
# Test environment only (the installer never touches sshd's configuration): make sure
# root may log in with a key on this runner image.
if [[ "$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2}')" == no ]]; then
  printf 'PermitRootLogin prohibit-password\n' >/etc/ssh/sshd_config.d/00-e2e-root-key.conf
fi
systemctl enable --now ssh.socket 2>/dev/null || systemctl enable --now ssh.service
systemctl restart ssh.socket 2>/dev/null || systemctl restart ssh.service
ip link add e2e-main type dummy
ip addr add "${MAIN_A}/32" dev e2e-main
ip addr add "${MAIN_B}/32" dev e2e-main
ip link set e2e-main up
for addr in "$MAIN_A" "$MAIN_B"; do
  python3 -m http.server 443 --bind "$addr" >/dev/null 2>&1 &
  LISTENERS+=("$!")
done
printf '%s %s\n%s %s\n' "$MAIN_A" "$TARGET" "$MAIN_B" "$ALT" >>/etc/hosts
ssh-keygen -q -t ed25519 -N '' -C vpn-bot-relay@e2e -f "${WORK}/main_key"
mkdir -p /root/.ssh && chmod 0700 /root/.ssh
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2eOperatorKeyOperatorKeyOperatorKey00 operator@e2e\n' >>"$AUTH_KEYS"
chmod 0600 "$AUTH_KEYS"
FORWARD_BEFORE="$(sysctl -n net.ipv4.ip_forward)"

# --------------------------------------------------------------------------- #
step "R0. a hand-made relay"
sed "s/150\.251\.152\.243/${OLD_UPSTREAM}/g" "${FIXTURES}/vpn-relay.nft" >/etc/vpn-relay.nft
sed "s/150\.251\.152\.243/${OLD_UPSTREAM}/g" "${FIXTURES}/vpn-relay.manual.service" >/etc/systemd/system/vpn-relay.service
systemctl daemon-reload
systemctl enable --now vpn-relay.service
table_shape >"${WORK}/table.before"
grep -q "dnat to ${OLD_UPSTREAM}:443" "${WORK}/table.before" || fail "the hand-made table did not load"
nft_file_before="$(sha /etc/vpn-relay.nft)"
unit_before="$(sha /etc/systemd/system/vpn-relay.service)"
keys_before="$(sha "$AUTH_KEYS")"

# --------------------------------------------------------------------------- #
step "R1. failure injected after the relay started: everything as before"
TOKEN1="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
CODE1="$(pairing_code "$TOKEN1")"
set +e
printf '%s\n' "$CODE1" | INSTALL_INJECT_FAILURE=after_relay_start installer --relay >"${WORK}/r1.out" 2>"${WORK}/r1.err"
rc=$?
set -e
cat "${WORK}/r1.err"
[[ "$rc" == 1 ]] || fail "injected failure exited ${rc}, expected 1"
manifest="$(newest manifest)"
tail -n1 "$manifest" | grep -q '^# rolled back' || fail "manifest does not end with '# rolled back'"
grep -q $'^adopted\t/etc/vpn-relay.nft' "$manifest" || fail "the hand-made file was not recorded as adopted"
table_shape >"${WORK}/table.r1"
diff -u "${WORK}/table.before" "${WORK}/table.r1" || fail "the live table is not the hand-made one after the rollback"
[[ "$(sha /etc/vpn-relay.nft)" == "$nft_file_before" ]] || fail "/etc/vpn-relay.nft not restored"
[[ "$(sha /etc/systemd/system/vpn-relay.service)" == "$unit_before" ]] || fail "the hand-made unit not restored"
[[ "$(sha "$AUTH_KEYS")" == "$keys_before" ]] || fail "authorized_keys changed"
[[ "$(sysctl -n net.ipv4.ip_forward)" == "$FORWARD_BEFORE" ]] || fail "ip_forward not restored"
for gone in /opt/vpn-service /etc/vpn-relay /usr/local/sbin/vpn-relay-agent /usr/local/sbin/vpn-relay-apply \
  /etc/systemd/system/vpn-relay-resolve.timer /etc/sysctl.d/90-vpn-relay.conf; do
  [[ ! -e "$gone" ]] || fail "left behind: ${gone}"
done
[[ "$(dnat_count tcp 443)" == 1 && "$(dnat_count udp 443)" == 1 ]] || fail "DNAT count after the rollback"
assert_no_secret_in_logs "$TOKEN1" "the token"
assert_no_secret_in_logs "$CODE1" "the pairing code"

# --------------------------------------------------------------------------- #
step "R2. install: adopts the hand-made relay, one DNAT per port"
TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
CODE="$(pairing_code "$TOKEN")"
printf '%s\n' "$CODE" | installer --relay >"${WORK}/r2.out" 2>"${WORK}/r2.err"
cat "${WORK}/r2.err"
cat "${WORK}/r2.out"
tail -n1 "$(newest manifest)" | grep -q '^# committed' || fail "manifest not committed"
[[ "$(nft list tables | grep -c '^table ip vpnrelay$')" == 1 ]] || fail "not exactly one table ip vpnrelay"
[[ "$(dnat_count tcp 443)" == 1 ]] || fail "tcp 443: $(dnat_count tcp 443) DNAT rules"
[[ "$(dnat_count udp 443)" == 1 ]] || fail "udp 443: $(dnat_count udp 443) DNAT rules"
nft list table ip vpnrelay | grep -q "dnat to ${MAIN_A}:443" || fail "the DNAT does not point at ${TARGET} (${MAIN_A})"
if nft list ruleset | grep -q "$OLD_UPSTREAM"; then fail "the old upstream is still in the ruleset"; fi
[[ ! -e /etc/vpn-relay.nft ]] || fail "/etc/vpn-relay.nft is still there (it would be loaded again)"
backup="$(ls -d /var/backups/vpn-relay/adopt-* | tail -n1)"
[[ "$(sha "${backup}/files/etc/vpn-relay.nft")" == "$nft_file_before" ]] || fail "the hand-made file is not in the backup"
ls "${backup}"/ip-vpnrelay.*.nft >/dev/null 2>&1 || fail "no dump of the old table in ${backup}"
systemctl is-active --quiet vpn-relay.service || fail "vpn-relay.service not active"
systemctl is-enabled --quiet vpn-relay.service || fail "vpn-relay.service not enabled"
systemctl is-active --quiet vpn-relay-resolve.timer || fail "vpn-relay-resolve.timer not active"
grep -q '^ExecStart=/usr/local/sbin/vpn-relay-apply apply' /etc/systemd/system/vpn-relay.service || fail "the unit is not the repo's"
[[ "$(grep -c 'command="/usr/local/sbin/vpn-relay-agent"' "$AUTH_KEYS")" == 1 ]] || fail "not exactly one agent key line"
grep -q '^restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 ' "$AUTH_KEYS" || fail "the key line is not restricted"
grep -q 'operator@e2e' "$AUTH_KEYS" || fail "the operator's own key was lost"
[[ "$(stat -c '%a' /etc/vpn-relay/pairing.json)" == 600 ]] || fail "pairing.json is not 0600"
grep -q '^RELAY_UPSTREAM_HOST=vpn-main.e2e.test$' /opt/vpn-service/.env || fail ".env has no RELAY_UPSTREAM_HOST"
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail "ip_forward is not 1"
[[ "$(cat /etc/sysctl.d/90-vpn-relay.conf | head -n1)" == "net.ipv4.ip_forward = 1" ]] || fail "no sysctl.d file"
nft list chain ip vpnrelay relayfwd | grep -q 'policy drop' || fail "the forward chain is not policy drop"
nft list chain ip vpnrelay relayfwd | grep -q 'maxseg size set rt mtu' || fail "no MSS clamp"
nft list chain ip vpnrelay post | grep -q masquerade || fail "no masquerade"
grep -qE '^[[:space:]]+[0-9.]+:[0-9]+$' "${WORK}/r2.out" || fail "the installer did not print the relay's address for the bot"
assert_no_secret_in_logs "$TOKEN" "the token"
assert_no_secret_in_logs "$CODE" "the pairing code"

# --------------------------------------------------------------------------- #
step "R3. the agent over ssh"
[[ "$(agent status)" == 3 ]] || fail "status before hello: $(cat "${WORK}/out.json")"
[[ "$(agent "hello $(python3 -c 'print("Z" * 43)')")" == 3 ]] || fail "a wrong token was accepted"
[[ "$(agent "hello ${TOKEN}")" == 0 ]] || fail "hello failed: $(cat "${WORK}/out.json" "${WORK}/out.err")"
[[ "$(json_field ok)" == True ]] || fail "hello not ok"
[[ "$(json_field target_host)" == "$TARGET" ]] || fail "hello: target_host"
[[ "$(agent "hello ${TOKEN}")" == 0 ]] || fail "a repeated hello with the same token failed"
[[ "$(agent status)" == 0 ]] || fail "status failed: $(cat "${WORK}/out.json")"
[[ "$(json_field live_target)" == "$MAIN_A" ]] || fail "status: live_target"
for bad in "status; id" "status && id" 'status $(id)' "id" "sh -c id" "uninstall now" "--internal-uninstall" \
  "apply target=${ALT};id tcp=443 udp=443"; do
  rc="$(agent "$bad")"
  [[ "$rc" == 2 ]] || fail "'${bad}' exited ${rc}, expected 2"
done
set +e
ssh_main -tt </dev/null >"${WORK}/shell.out" 2>&1
rc=$?
set -e
[[ "$rc" == 2 ]] || fail "an interactive login exited ${rc}, expected 2 (refused)"
set +e
ssh_main -o ExitOnForwardFailure=yes -R 127.0.0.1:18022:127.0.0.1:22 status >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" != 0 ]] || fail "port forwarding was allowed (restrict)"
[[ -d /opt/vpn-service && -e /usr/local/sbin/vpn-relay-agent ]] || fail "a refused request changed something"
assert_no_secret_in_logs "$TOKEN" "the token"

# --------------------------------------------------------------------------- #
step "R4. apply: re-point the forward; the ssh port is refused"
[[ "$(agent "apply target=${ALT} tcp=443 udp=443")" == 0 ]] || fail "apply failed: $(cat "${WORK}/out.json")"
nft list table ip vpnrelay | grep -q "dnat to ${MAIN_B}:443" || fail "apply did not move the DNAT to ${MAIN_B}"
[[ "$(dnat_count tcp 443)" == 1 && "$(dnat_count udp 443)" == 1 ]] || fail "DNAT count after apply"
ssh_port="$(ss -Hltnp | awk '/"sshd/ {n = split($4, a, ":"); print a[n]; exit}')"
[[ -n "$ssh_port" ]] || ssh_port="$(systemctl show -p Listen ssh.socket | grep -oE ':[0-9]+ ' | head -n1 | tr -dc '0-9')"
[[ "$(agent "apply target=${TARGET} tcp=443,${ssh_port} udp=443")" == 2 ]] || fail "forwarding the ssh port was not refused"
nft list table ip vpnrelay | grep -q "dnat to ${MAIN_B}:443" || fail "a refused apply changed the table"

# --------------------------------------------------------------------------- #
step "R5. the resolve timer follows the name"
systemctl list-timers --all --no-pager | grep -q vpn-relay-resolve.timer || fail "the timer is not scheduled"
sed -i "s/^${MAIN_B} ${ALT}\$/${MAIN_A} ${ALT}/" /etc/hosts
systemctl start vpn-relay-resolve.service
nft list table ip vpnrelay | grep -q "dnat to ${MAIN_A}:443" || fail "the table did not follow ${ALT} to ${MAIN_A}"
[[ "$(dnat_count tcp 443)" == 1 && "$(dnat_count udp 443)" == 1 ]] || fail "DNAT count after the re-resolve"
systemctl start vpn-relay-resolve.service
journalctl -u vpn-relay-resolve.service --no-pager -n 20 | grep -q unchanged || fail "an unchanged address was not reported as unchanged"

# --------------------------------------------------------------------------- #
step "R6. uninstall"
[[ "$(agent uninstall)" == 0 ]] || fail "uninstall failed: $(cat "${WORK}/out.json" "${WORK}/out.err")"
if nft list table ip vpnrelay >/dev/null 2>&1; then fail "table ip vpnrelay still there"; fi
for gone in /opt/vpn-service /etc/vpn-relay /usr/local/sbin/vpn-relay-agent /usr/local/sbin/vpn-relay-apply \
  /etc/systemd/system/vpn-relay.service /etc/systemd/system/vpn-relay-resolve.timer /etc/sysctl.d/90-vpn-relay.conf; do
  [[ ! -e "$gone" ]] || fail "left behind after uninstall: ${gone}"
done
if grep -q 'vpn-relay-agent' "$AUTH_KEYS"; then fail "the agent's key line is still in authorized_keys"; fi
grep -q 'operator@e2e' "$AUTH_KEYS" || fail "uninstall removed the operator's key"
[[ -e "${backup}/files/etc/vpn-relay.nft" ]] || fail "the adoption backup was removed"
[[ "$(agent status)" == 255 ]] || fail "the bot's key still logs in after uninstall"

step "ALL RELAY E2E CHECKS PASSED"
