#!/usr/bin/env bash
# acme.sh --reloadcmd hook: fan a renewed certificate out to every consumer.
#
# WHY THIS FILE EXISTS
# -------------------
# Nothing in this repo issues or renews certificates — acme.sh does, outside the
# repo (docs/deployment.md, docs/subscription.md). But the *fan-out* after a
# renewal is project-specific and load-bearing, and it lived only on the host as
# an untracked shell script (/usr/local/sbin/acme-reload.sh), so a rebuilt or
# migrated host had nothing to restore it from. This is that hook, tracked.
#
# The renewal is not finished when the files land in TLS_DIR. Three consumers keep
# serving the OLD chain until they are told otherwise:
#
#   * nginx               — serves the loopback vhost Xray REALITY uses as its
#                           self-steal target, straight off TLS_DIR -> reload;
#   * hysteria-server     — UDP/443, reads its own copy under /etc/hysteria at
#                           start-up -> restart;
#   * vpn-bot-subscription — :2096, reads TLS_DIR once at start-up -> try-restart:
#                           a unit an operator stopped is NOT started by a renewal.
#
# A hook that restarts only hysteria leaves the subscription endpoint serving an
# expired certificate until something else happens to restart it.
#
# FAILURE POLICY — no `set -e`, on purpose. Every step is attempted even when an
# earlier one failed: a failed hysteria copy (or nginx reload) must not be the
# reason the OTHER consumers keep the old certificate. Each failure is recorded and
# the hook exits 1 at the end, so it lands in the acme.sh cron log instead of being
# swallowed. (The hand-written predecessor behaved the same way: `|| rc=1` per step.)
# The one dependency that IS honoured: Hysteria2's cert and key are written to
# temporary names and moved into place together, and hysteria-server is restarted
# only when both landed. A half-copied pair (new cert, old key) would stop the
# healthy daemon that still serves the previous pair, and fail it at the next boot.
#
# OWNERSHIP AND MODES — re-asserted on every run, because acme.sh writes the files
# as root with its own umask, and vpn-bot-subscription reads them as the
# unprivileged vpn-bot user. The defaults reproduce the main server exactly
# (measured 2026-11-04) — change them only together with that host:
#   TLS_DIR                    root:root     0755  (the directory)
#   TLS_DIR/fullchain.pem      root:vpn-bot  0640
#   TLS_DIR/privkey.pem        root:vpn-bot  0640
#   TLS_DIR/cert.pem           NOT touched (no consumer reads it)
#   /etc/hysteria/cert.pem     hysteria:hysteria 0644  (copy of fullchain.pem)
#   /etc/hysteria/key.pem      hysteria:hysteria 0600  (copy of privkey.pem)
#
# INSTALL — by the deploy, not by hand. scripts/deploy.sh installs this file as
# /usr/local/sbin/acme-reload.sh (MANAGED_HOST_FILES, class hook, root:root 0755):
# that is the path acme.sh's Le_ReloadCmd names, so acme.sh itself is never
# touched. Before installing a changed copy, Phase 1 runs it with --dry-run and
# refuses a candidate that does not exit 0. On a new host, point acme.sh at it once:
#
#   sudo acme.sh --install-cert -d <DOMAIN> \
#     --key-file       <TLS_DIR>/privkey.pem \
#     --fullchain-file <TLS_DIR>/fullchain.pem \
#     --reloadcmd      "/usr/local/sbin/acme-reload.sh"
#
# Verify by hand, read-only, without waiting for a renewal:
#   sudo /usr/local/sbin/acme-reload.sh --dry-run
#
# Every knob below is an environment variable with a default, so a host that names
# things differently overrides it in the acme.sh reloadcmd rather than editing this
# file:   TLS_DIR=/etc/vpn-bot/tls TRY_RESTART_UNITS=... /usr/local/sbin/acme-reload.sh
set -uo pipefail

TLS_DIR="${TLS_DIR:-/etc/vpn-bot/tls}"
TLS_DIR_OWNER="${TLS_DIR_OWNER:-root}"
TLS_DIR_GROUP="${TLS_DIR_GROUP:-root}"
TLS_DIR_MODE="${TLS_DIR_MODE:-0755}"
# The two files vpn-bot-subscription reads, group-readable by the vpn-bot user.
TLS_OWNER="${TLS_OWNER:-root}"
TLS_GROUP="${TLS_GROUP:-vpn-bot}"
FULLCHAIN_MODE="${FULLCHAIN_MODE:-0640}"
PRIVKEY_MODE="${PRIVKEY_MODE:-0640}"
FULLCHAIN_NAME="${FULLCHAIN_NAME:-fullchain.pem}"
PRIVKEY_NAME="${PRIVKEY_NAME:-privkey.pem}"

# Hysteria2 keeps its own copy: the daemon runs as an unprivileged user that has
# no business reading vpn-bot's TLS directory. Set HYSTERIA_CERT= to skip.
HYSTERIA_CERT="${HYSTERIA_CERT:-/etc/hysteria/cert.pem}"
HYSTERIA_KEY="${HYSTERIA_KEY:-/etc/hysteria/key.pem}"
HYSTERIA_OWNER="${HYSTERIA_OWNER:-hysteria}"
HYSTERIA_GROUP="${HYSTERIA_GROUP:-hysteria}"
# The unit that reads that copy: never restarted when the copy failed.
HYSTERIA_UNIT="${HYSTERIA_UNIT:-hysteria-server}"

# Units merely reloaded (no connection drop). nginx is a reader of the renewed
# material, not an optional extra: it serves REALITY's self-steal target. Skipping
# it leaves an unauthenticated probe looking at an expired certificate on the very
# site that is supposed to make this host look ordinary.
RELOAD_UNITS="${RELOAD_UNITS:-nginx}"
# Units restarted because they read the material once at start-up.
RESTART_UNITS="${RESTART_UNITS:-$HYSTERIA_UNIT}"
# Restarted only when already running (systemctl try-restart): a renewal must not
# bring back a unit an operator stopped.
TRY_RESTART_UNITS="${TRY_RESTART_UNITS:-vpn-bot-subscription}"
# A unit that is not installed on this host is skipped, not an error — the same
# hook serves a host running only some of the consumers.

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

log() { printf '[%s] acme-reload: %s\n' "$(date -Is)" "$*"; }
failed=()
# Run one step; in --dry-run only print it. A failure is recorded under $1, the
# step returns 1, and the hook carries on with the next step.
step() {
	local label="$1"
	shift
	if (( DRY_RUN )); then
		log "DRY-RUN would run: $*"
		return 0
	fi
	"$@" && return 0
	log "FAILED (${label}): $*"
	failed+=("$label")
	return 1
}
unit_exists() { systemctl cat -- "$1" >/dev/null 2>&1; }

fullchain="$TLS_DIR/$FULLCHAIN_NAME"
privkey="$TLS_DIR/$PRIVKEY_NAME"

# Fail loudly and BEFORE touching anything: acme.sh has just written these, so a
# missing file means the --install-cert paths and this hook disagree, and
# restarting services on a half-installed cert is worse than not running at all.
for f in "$fullchain" "$privkey"; do
	[[ -s "$f" ]] || {
		log "FATAL: $f is missing or empty — check the acme.sh --install-cert paths"
		exit 1
	}
done
log "renewed material present in $TLS_DIR"

# 1. Re-assert what the unprivileged reader needs (table in the header).
#    Idempotent; silent when already right.
step "perms:$TLS_DIR" chown "$TLS_DIR_OWNER:$TLS_DIR_GROUP" "$TLS_DIR"
step "perms:$TLS_DIR" chmod "$TLS_DIR_MODE" "$TLS_DIR"
step "perms:$fullchain" chown "$TLS_OWNER:$TLS_GROUP" "$fullchain"
step "perms:$fullchain" chmod "$FULLCHAIN_MODE" "$fullchain"
step "perms:$privkey" chown "$TLS_OWNER:$TLS_GROUP" "$privkey"
step "perms:$privkey" chmod "$PRIVKEY_MODE" "$privkey"

# 2. Hand Hysteria2 its own copy — both files under temporary names first, then
#    moved into place together, so a failure leaves the previous pair intact.
hysteria_copy_ok=1
if [[ -n "$HYSTERIA_CERT" && -d "$(dirname -- "$HYSTERIA_CERT")" ]]; then
	cert_new="${HYSTERIA_CERT}.acme-new"
	key_new="${HYSTERIA_KEY}.acme-new"
	step "copy:$HYSTERIA_CERT" install -o "$HYSTERIA_OWNER" -g "$HYSTERIA_GROUP" -m 0644 "$fullchain" "$cert_new" \
		&& step "copy:$HYSTERIA_KEY" install -o "$HYSTERIA_OWNER" -g "$HYSTERIA_GROUP" -m 0600 "$privkey" "$key_new" \
		&& step "copy:$HYSTERIA_CERT" mv -f -- "$cert_new" "$HYSTERIA_CERT" \
		&& step "copy:$HYSTERIA_KEY" mv -f -- "$key_new" "$HYSTERIA_KEY" \
		|| hysteria_copy_ok=0
	if (( ! hysteria_copy_ok )); then
		(( DRY_RUN )) || rm -f -- "$cert_new" "$key_new"
		log "the Hysteria2 copy FAILED — the previous cert/key pair is left in place"
	fi
else
	log "skipping the Hysteria2 copy (no $HYSTERIA_CERT target on this host)"
fi

# 3. Reload / restart the consumers — each one attempted whatever happened above.
for unit in $RELOAD_UNITS; do
	if unit_exists "$unit"; then
		log "reloading $unit"
		step "reload:$unit" systemctl reload -- "$unit"
	else
		log "skipping $unit (not installed on this host)"
	fi
done
for unit in $RESTART_UNITS; do
	if [[ "$unit" == "$HYSTERIA_UNIT" ]] && (( ! hysteria_copy_ok )); then
		# It still serves the previous pair from memory; a restart now would stop it.
		log "NOT restarting $unit: its certificate copy failed (it keeps serving the previous pair)"
		failed+=("restart:$unit (skipped)")
		continue
	fi
	if unit_exists "$unit"; then
		log "restarting $unit"
		step "restart:$unit" systemctl restart -- "$unit"
	else
		log "skipping $unit (not installed on this host)"
	fi
done
for unit in $TRY_RESTART_UNITS; do
	if unit_exists "$unit"; then
		log "restarting $unit if it is running"
		step "try-restart:$unit" systemctl try-restart -- "$unit"
	else
		log "skipping $unit (not installed on this host)"
	fi
done

if (( ${#failed[@]} )); then
	log "FAILED: ${failed[*]} — every other step was still attempted"
	exit 1
fi
log "done"
