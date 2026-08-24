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
#   * Hysteria2 answers a failed handshake with its masquerade over the existing
#     UDP/443 QUIC path (docs/hysteria.md).
#
# HOW Hysteria2 gets that site decides how much this hook has to do, and the two
# layouts are not equivalent:
#
#   * `masquerade.type: proxy` — what deploy/hysteria/config.yaml ships. Hysteria2
#     reverse-proxies the SAME loopback listener REALITY targets, so both planes
#     read one docroot. Nothing can drift apart because there is only one tree, and
#     step 2 below deliberately does nothing.
#   * `masquerade.type: file` — Hysteria2 reads MASQ_DIR itself, as an unprivileged
#     daemon that cannot read the nginx docroot. Now there ARE two trees and
#     nothing keeps them in step on its own: left alone they end up presenting
#     DIFFERENT sites, or MASQ_DIR stays empty and Hysteria2 answers probes with a
#     404 while nginx answers with a site. Step 2 is that mirroring, and it runs.
#
# The mirroring was living only on the host as an untracked cron script, so a
# rebuilt or migrated host had nothing to restore it from. This is it, tracked and
# parameterised — with the layout check that keeps it from writing a stale second
# copy on hosts that no longer read one.
#
# It also drives the freshness pass, and THAT part runs on every layout. A static
# decoy whose "last updated" date is months old is a tell on its own, so the site
# carries rolling timestamps and something has to advance them. That rewriter is
# NOT tracked here and cannot be: it necessarily encodes the decoy's own markup —
# which files, which patterns, which fake incident history — and that content is
# unique per deployment and is the whole point of a decoy. So it stays a
# deployment-local script that this hook merely CALLS, via DECOY_FRESHEN_HOOK.
# Unset or absent, the freshness pass is skipped.
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

# Hysteria2 `masquerade.file.dir`. Mirrored FROM DECOY_ROOT, never the other way —
# and only when the live config actually declares `masquerade.type: file`. Under
# the shipped `type: proxy` layout this directory is not read at all and is left
# untouched; see step 2.
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
	log "no DECOY_FRESHEN_HOOK set — skipping the freshness pass"
fi

# 2. Mirror into the Hysteria2 masquerade directory — but ONLY when Hysteria2 is
#    actually configured to serve that directory.
#
#    This guard is the whole reason step 2 is conditional rather than unconditional.
#    With `masquerade.type: proxy` (the layout deploy/hysteria/config.yaml ships)
#    Hysteria2 reverse-proxies the decoy from the same local HTTPS listener nginx
#    serves DECOY_ROOT on, so MASQ_DIR is never opened: mirroring into it would burn
#    IO to populate a directory nothing reads, and — worse — would leave a stale
#    second copy on disk that looks authoritative to whoever finds it next.
#    With `masquerade.type: file` the mirror IS the mechanism, so it still runs.
#    Absent config (Xray-only host) or no parser: skip, and say which.
HYSTERIA_CONF="${HYSTERIA_CONF:-/etc/hysteria/config.yaml}"
masq_parent="$(dirname -- "$MASQ_DIR")"
masq_type=""
if [[ -r "$HYSTERIA_CONF" ]]; then
	# Deliberately not a YAML parse: this is a shell hook that may run from cron on a
	# host with no PyYAML. `masquerade:` is top-level and its `type:` is the first
	# indented key under it, so a two-line window is enough and cannot match the
	# unrelated `auth.type` or `trafficStats` keys.
	masq_type="$(awk '
		/^masquerade:/ { inblock = 1; next }
		inblock && /^[^[:space:]]/ { inblock = 0 }
		inblock && $1 == "type:" { print $2; exit }
	' "$HYSTERIA_CONF" 2>/dev/null || true)"
fi
if [[ ! -d "$masq_parent" ]]; then
	log "skipping the Hysteria2 mirror (no $masq_parent on this host)"
elif [[ "$masq_type" == "proxy" ]]; then
	log "skipping the Hysteria2 mirror: $HYSTERIA_CONF serves masquerade.type: proxy,"
	log "  so $MASQ_DIR is not read — DECOY_ROOT is the single source of truth"
elif [[ -z "$masq_type" ]]; then
	log "skipping the Hysteria2 mirror: could not read masquerade.type from $HYSTERIA_CONF"
	log "  (set MASQ_DIR= to silence this, or check the file exists and is readable)"
else
	[[ -d "$MASQ_DIR" ]] || run install -o "$MASQ_OWNER" -g "$MASQ_GROUP" -m 0755 -d "$MASQ_DIR"
	run rsync -a --delete "$DECOY_ROOT/" "$MASQ_DIR/"
	# The daemon reads this tree as an unprivileged user, and rsync preserves the
	# nginx-side ownership, so re-assert it every pass rather than once at install.
	run chown -R "$MASQ_OWNER:$MASQ_GROUP" "$MASQ_DIR"
	log "mirrored $DECOY_ROOT -> $MASQ_DIR (masquerade.type: $masq_type, owner $MASQ_OWNER:$MASQ_GROUP)"
fi

log "done"
