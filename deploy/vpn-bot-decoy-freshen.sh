#!/usr/bin/env bash
# Decoy-site freshener: keep the REALITY self-steal target and the Hysteria2
# masquerade serving the SAME, plausibly-maintained static site.
#
# WHY THIS FILE EXISTS
# -------------------
# Two data planes on this host answer a probe with a real website instead of a
# reset, and they answer with the same one:
#
#   * Xray REALITY forwards an unauthenticated TLS probe to its `target`, a
#     loopback vhost served by nginx out of DECOY_ROOT (docs/deployment.md);
#   * Hysteria2 serves `masquerade.type: file` out of MASQ_DIR over the existing
#     UDP/443 QUIC path (docs/hysteria.md).
#
# Nothing keeps those two trees in step on its own, and MASQ_DIR is read by an
# unprivileged daemon that cannot read the nginx docroot. That mirroring was
# living only on the host as an untracked cron script, so a rebuilt or migrated
# host had nothing to restore it from and would have silently ended up with the
# two data planes presenting DIFFERENT sites — or, if MASQ_DIR were left empty,
# with Hysteria2 answering probes with 404 while nginx answered with a site.
# This is that mirroring, tracked and parameterised.
#
# It also drives the freshness pass. A static decoy whose "last updated" date is
# months old is a tell on its own, so the site carries rolling timestamps and
# something has to advance them. That rewriter is NOT tracked here and cannot be:
# it necessarily encodes the decoy's own markup — which files, which patterns,
# which fake incident history — and that content is unique per deployment and is
# the whole point of a decoy. So it stays a deployment-local script that this
# hook merely CALLS, via DECOY_FRESHEN_HOOK. Unset or absent, the freshness pass
# is skipped and the mirroring still runs.
#
# nginx needs no reload: it serves DECOY_ROOT from disk per request (`try_files`),
# so a rewritten file is live immediately.
#
# INSTALL — no copy step: run it straight out of the checkout, exactly like
# deploy/update-ip2asn.sh and deploy/vpn-bot-acme-reload.sh. A deploy advances
# the checkout, so this is refreshed with it and never goes stale the way a
# hand-copied /usr/local/sbin/ copy does. Deliberately cron, NOT a systemd unit:
# every deploy/*.service basename is enrolled into deploy.sh's UNIT_SET
# (deploy/managed-units.list), so shipping a unit for a job the host runs from
# cron would make Phase 1 report it not-installed on every deploy — opening a new
# repo/host divergence instead of closing one.
#
#   sudo chmod 0755 /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh
#   sudo crontab -e
#   # pick an off-peak minute; nothing depends on the exact time
#   7 3 * * * /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh >/dev/null 2>&1
#
# Verify by hand, read-only, without waiting for the cron window:
#   sudo /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh --dry-run
#
# Every knob below is an environment variable with a default, so a host that
# names things differently overrides it in the cron line rather than editing this
# file:
#   DECOY_ROOT=/var/www/<DECOY_SITE> MASQ_DIR=/etc/hysteria/masq /opt/.../vpn-bot-decoy-freshen.sh
set -euo pipefail

# nginx docroot for the REALITY self-steal vhost — the source of truth for both
# data planes. No default worth guessing: a wrong value here is a --delete away
# from emptying MASQ_DIR, so it is required explicitly.
DECOY_ROOT="${DECOY_ROOT:-}"

# Hysteria2 `masquerade.file.dir`. Mirrored FROM DECOY_ROOT, never the other way.
MASQ_DIR="${MASQ_DIR:-/etc/hysteria/masq}"
MASQ_OWNER="${MASQ_OWNER:-hysteria}"
MASQ_GROUP="${MASQ_GROUP:-hysteria}"

# Deployment-local rewriter that advances the decoy's rolling timestamps. Left
# empty on a host that serves a decoy with no dated content. See the header for
# why this cannot be tracked in the repo.
DECOY_FRESHEN_HOOK="${DECOY_FRESHEN_HOOK:-}"

# Sanity anchor: a file that must exist in DECOY_ROOT for it to be a real site.
# Both consumers need it — nginx `index`, and Hysteria2's file masquerade.
INDEX_NAME="${INDEX_NAME:-index.html}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

log() { printf '[%s] decoy-freshen: %s\n' "$(date -Is)" "$*"; }
run() {
	if (( DRY_RUN )); then
		log "DRY-RUN would run: $*"
	else
		"$@"
	fi
}

# Fail loudly and BEFORE touching anything. `rsync --delete` is destructive by
# design: pointed at a missing or empty source it would faithfully empty
# MASQ_DIR, turning the Hysteria2 decoy into a bare 404 while nginx keeps
# serving a site — a mismatch between the two data planes is exactly the tell
# this whole mechanism exists to avoid.
[[ -n "$DECOY_ROOT" ]] || {
	log "FATAL: DECOY_ROOT is not set — refusing to mirror from an unknown source"
	exit 1
}
[[ -d "$DECOY_ROOT" ]] || {
	log "FATAL: DECOY_ROOT=$DECOY_ROOT is not a directory"
	exit 1
}
[[ -s "$DECOY_ROOT/$INDEX_NAME" ]] || {
	log "FATAL: $DECOY_ROOT/$INDEX_NAME is missing or empty — DECOY_ROOT does not look like the decoy site"
	exit 1
}
command -v rsync >/dev/null || {
	log "FATAL: rsync is not installed — it is what mirrors DECOY_ROOT into MASQ_DIR"
	exit 1
}
log "decoy source present at $DECOY_ROOT"

# 1. Advance the rolling timestamps, if this deployment has a rewriter. A failure
#    here is fatal on purpose: mirroring a half-rewritten tree would publish
#    inconsistent dates to both data planes, which is worse than stale ones.
if [[ -n "$DECOY_FRESHEN_HOOK" ]]; then
	if [[ -x "$DECOY_FRESHEN_HOOK" ]]; then
		log "running freshener $DECOY_FRESHEN_HOOK"
		run "$DECOY_FRESHEN_HOOK"
	else
		log "FATAL: DECOY_FRESHEN_HOOK=$DECOY_FRESHEN_HOOK is not executable"
		exit 1
	fi
else
	log "no DECOY_FRESHEN_HOOK set — skipping the freshness pass, mirroring as-is"
fi

# 2. Mirror into the Hysteria2 masquerade directory. Skipped entirely when
#    Hysteria2 is not deployed here, the same way vpn-bot-acme-reload.sh skips
#    its Hysteria2 copy — the same hook serves a host running only Xray.
masq_parent="$(dirname -- "$MASQ_DIR")"
if [[ -d "$masq_parent" ]]; then
	[[ -d "$MASQ_DIR" ]] || run install -o "$MASQ_OWNER" -g "$MASQ_GROUP" -m 0755 -d "$MASQ_DIR"
	run rsync -a --delete "$DECOY_ROOT/" "$MASQ_DIR/"
	# The daemon reads this tree as an unprivileged user, and rsync preserves the
	# nginx-side ownership, so re-assert it every pass rather than once at install.
	run chown -R "$MASQ_OWNER:$MASQ_GROUP" "$MASQ_DIR"
	log "mirrored $DECOY_ROOT -> $MASQ_DIR (owner $MASQ_OWNER:$MASQ_GROUP)"
else
	log "skipping the Hysteria2 mirror (no $masq_parent on this host)"
fi

log "done"
