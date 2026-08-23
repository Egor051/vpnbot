#!/usr/bin/env bash
# acme.sh --reloadcmd hook: fan a renewed certificate out to every consumer.
#
# WHY THIS FILE EXISTS
# -------------------
# Nothing in this repo issues or renews certificates — acme.sh does, outside the
# repo (docs/deployment.md, docs/subscription.md). But the *fan-out* after a
# renewal is project-specific and load-bearing, and it was living only on the
# host as an untracked shell script (/usr/local/sbin/acme-reload.sh), so a
# rebuilt or migrated host had nothing to restore it from. This is that hook,
# tracked and parameterised.
#
# The renewal is not finished when the files land in TLS_DIR. Two consumers read
# the material at START-UP ONLY and keep serving the OLD chain until they are
# restarted:
#
#   * hysteria-server   — reads its own copy under /etc/hysteria;
#   * vpn-bot-subscription — reads TLS_DIR directly and terminates TLS itself
#     (nothing proxies it — the nginx vhost on this host is REALITY's self-steal
#     target, not a front end for this endpoint), and its unit says so in as many
#     words: "The key is read ONCE at startup, so an acme.sh renewal is picked up
#     by restarting this unit from its --reloadcmd."
#
# A hook that restarts only hysteria leaves the subscription endpoint serving an
# expired certificate to clients until something else happens to restart it.
# Restarting BOTH is the point of this script.
#
# It also re-asserts ownership and modes on TLS_DIR, because acme.sh writes those
# files as root with its own umask, and vpn-bot-subscription reads them as the
# unprivileged vpn-bot user (root:vpn-bot 0750 dir, 0640 key — docs/subscription.md).
# Without this step a renewal can silently make the key unreadable to the very
# service that needs it.
#
# INSTALL — no copy step: run it straight out of the checkout, exactly like
# deploy/update-ip2asn.sh is run by deploy/vpn-bot-ip2asn.service. A deploy
# advances the checkout, so the hook is refreshed with it and never goes stale
# the way a hand-copied /usr/local/sbin/ copy does.
#
#   sudo chmod 0755 /opt/vpn-service/deploy/vpn-bot-acme-reload.sh
#   sudo acme.sh --install-cert -d <DOMAIN> \
#     --key-file       <TLS_DIR>/privkey.pem \
#     --fullchain-file <TLS_DIR>/fullchain.pem \
#     --reloadcmd      "/opt/vpn-service/deploy/vpn-bot-acme-reload.sh"
#
# Verify by hand, read-only, without waiting for a renewal:
#   sudo /opt/vpn-service/deploy/vpn-bot-acme-reload.sh --dry-run
#
# Every knob below is an environment variable with a default, so a host that
# names things differently overrides it in the acme.sh reloadcmd rather than
# editing this file:
#   TLS_DIR=/etc/vpn-bot/tls SUBSCRIPTION_UNIT=... /opt/.../vpn-bot-acme-reload.sh
set -euo pipefail

TLS_DIR="${TLS_DIR:-/etc/vpn-bot/tls}"
TLS_OWNER="${TLS_OWNER:-root}"
TLS_GROUP="${TLS_GROUP:-vpn-bot}"
FULLCHAIN_NAME="${FULLCHAIN_NAME:-fullchain.pem}"
PRIVKEY_NAME="${PRIVKEY_NAME:-privkey.pem}"

# Hysteria2 keeps its own copy: the daemon runs as an unprivileged user that has
# no business reading vpn-bot's TLS directory. Set HYSTERIA_CERT= to skip.
HYSTERIA_CERT="${HYSTERIA_CERT:-/etc/hysteria/cert.pem}"
HYSTERIA_KEY="${HYSTERIA_KEY:-/etc/hysteria/key.pem}"
HYSTERIA_OWNER="${HYSTERIA_OWNER:-hysteria}"
HYSTERIA_GROUP="${HYSTERIA_GROUP:-hysteria}"

# Units restarted because they read the material once at startup. A unit that is
# not installed on this host is skipped, not an error — the same hook serves a
# host running only one of the two backends.
RESTART_UNITS="${RESTART_UNITS:-hysteria-server vpn-bot-subscription}"
# Units merely reloaded (no connection drop). nginx is here because it is a THIRD
# reader of the renewed material, not an optional extra: it serves the loopback
# vhost that Xray REALITY uses as its self-steal `target`, straight off TLS_DIR.
# Skipping it leaves an unauthenticated probe looking at an expired certificate on
# the very site that is supposed to make this host look ordinary. Absence is still
# tolerated (a host running only Hysteria2 has no nginx) and RELOAD_UNITS= skips it.
RELOAD_UNITS="${RELOAD_UNITS:-nginx}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

log() { printf '[%s] acme-reload: %s\n' "$(date -Is)" "$*"; }
run() {
	if (( DRY_RUN )); then
		log "DRY-RUN would run: $*"
	else
		"$@"
	fi
}
unit_exists() { systemctl cat -- "$1" >/dev/null 2>&1; }

fullchain="$TLS_DIR/$FULLCHAIN_NAME"
privkey="$TLS_DIR/$PRIVKEY_NAME"

# Fail loudly and BEFORE touching anything: acme.sh has just written these, so a
# missing file means the --install-cert paths and this hook disagree, and silently
# restarting services on a half-installed cert is worse than not running at all.
for f in "$fullchain" "$privkey"; do
	[[ -s "$f" ]] || {
		log "FATAL: $f is missing or empty — check the acme.sh --install-cert paths"
		exit 1
	}
done
log "renewed material present in $TLS_DIR"

# 1. Re-assert what the unprivileged reader needs. Idempotent; silent when already right.
run chown "$TLS_OWNER:$TLS_GROUP" "$TLS_DIR" "$fullchain" "$privkey"
run chmod 0750 "$TLS_DIR"
run chmod 0644 "$fullchain"
run chmod 0640 "$privkey"

# 2. Hand Hysteria2 its own copy.
if [[ -n "$HYSTERIA_CERT" && -d "$(dirname -- "$HYSTERIA_CERT")" ]]; then
	run install -o "$HYSTERIA_OWNER" -g "$HYSTERIA_GROUP" -m 0644 "$fullchain" "$HYSTERIA_CERT"
	run install -o "$HYSTERIA_OWNER" -g "$HYSTERIA_GROUP" -m 0600 "$privkey" "$HYSTERIA_KEY"
	log "copied to $HYSTERIA_CERT / $HYSTERIA_KEY"
else
	log "skipping the Hysteria2 copy (no $HYSTERIA_CERT target on this host)"
fi

# 3. Restart/reload the consumers. Each is attempted even if an earlier one fails
#    — a failed nginx reload must not be the reason the subscription endpoint keeps
#    serving an expired certificate — and the hook still exits non-zero so the
#    failure lands in the acme.sh cron log instead of being swallowed.
failed=()
for unit in $RESTART_UNITS; do
	if unit_exists "$unit"; then
		log "restarting $unit"
		run systemctl restart -- "$unit" || failed+=("restart:$unit")
	else
		log "skipping $unit (not installed on this host)"
	fi
done
for unit in $RELOAD_UNITS; do
	if unit_exists "$unit"; then
		log "reloading $unit"
		run systemctl reload -- "$unit" || failed+=("reload:$unit")
	else
		log "skipping $unit (not installed on this host)"
	fi
done

if (( ${#failed[@]} )); then
	log "FAILED: ${failed[*]}"
	exit 1
fi
log "done"
