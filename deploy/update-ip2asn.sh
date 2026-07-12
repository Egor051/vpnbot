#!/usr/bin/env bash
#
# Refresh the iptoasn IPv4->ASN database consumed by the anomaly detector
# (adapters/ip_asn.py). Downloads ip2asn-v4.tsv.gz, validates it, and atomically
# installs it at DEST. On ANY failure the existing database is left untouched.
#
# Runs unprivileged (as vpn-bot) from deploy/vpn-bot-ip2asn.timer, and is safe to
# run by hand for a one-off refresh. Behaviour is overridable via the IP2ASN_*
# environment variables below.
set -euo pipefail

ME="update-ip2asn"

DATA_DIR="${IP2ASN_DATA_DIR:-/opt/vpn-service/data}"
DEST="${IP2ASN_DEST:-${DATA_DIR}/ip2asn-v4.tsv}"
URL="${IP2ASN_URL:-https://iptoasn.com/data/ip2asn-v4.tsv.gz}"
MIN_LINES="${IP2ASN_MIN_LINES:-100000}"
MIN_FREE_KB="${IP2ASN_MIN_FREE_KB:-51200}" # ~50 MiB headroom for .gz + .tsv
CURL_MAX_TIME="${IP2ASN_CURL_MAX_TIME:-180}"

# ----------------------------------------------------------------- preconditions
command -v curl >/dev/null 2>&1 || { echo "${ME}: curl not found" >&2; exit 1; }
command -v gzip >/dev/null 2>&1 || { echo "${ME}: gzip not found" >&2; exit 1; }

if [[ ! -d "${DATA_DIR}" ]]; then
  echo "${ME}: data directory ${DATA_DIR} does not exist" >&2
  exit 1
fi
if [[ ! -w "${DATA_DIR}" ]]; then
  echo "${ME}: data directory ${DATA_DIR} is not writable" >&2
  exit 1
fi

avail_kb="$(df -Pk "${DATA_DIR}" | awk 'NR==2 {print $4}')"
if [[ -z "${avail_kb}" || "${avail_kb}" -lt "${MIN_FREE_KB}" ]]; then
  echo "${ME}: not enough free space in ${DATA_DIR} (need ${MIN_FREE_KB} KiB, have ${avail_kb:-0})" >&2
  exit 1
fi

# ------------------------------------------------------------- download (staged)
# Temp files live in DATA_DIR so the final install is a same-filesystem atomic
# rename. The trap removes them on any early exit, so a failed run never leaves a
# partial file behind and never touches the live database.
tmp_gz="$(mktemp "${DATA_DIR}/.ip2asn-v4.tsv.gz.XXXXXX")"
tmp_tsv="$(mktemp "${DATA_DIR}/.ip2asn-v4.tsv.XXXXXX")"
trap 'rm -f "${tmp_gz}" "${tmp_tsv}"' EXIT

echo "${ME}: downloading ${URL}"
if ! curl -fsSL --max-time "${CURL_MAX_TIME}" -o "${tmp_gz}" "${URL}"; then
  echo "${ME}: download failed from ${URL}" >&2
  exit 1
fi

if ! gzip -dc "${tmp_gz}" > "${tmp_tsv}"; then
  echo "${ME}: gunzip failed (corrupt download?)" >&2
  exit 1
fi

# ------------------------------------------------------------------- validation
lines="$(wc -l < "${tmp_tsv}")"
if [[ "${lines}" -lt "${MIN_LINES}" ]]; then
  echo "${ME}: only ${lines} rows (< ${MIN_LINES}); refusing to install" >&2
  exit 1
fi

# A well-formed iptoasn row is TAB-separated with >=3 fields whose first two are
# IPv4 range endpoints. Confirm the first and last rows parse before installing.
_valid_row() {
  awk -F '\t' '
    function ipv4(s) { return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ }
    { if (NF >= 3 && ipv4($1) && ipv4($2)) { exit 0 } else { exit 1 } }
  ' <<< "$1"
}

first_row="$(head -n 1 "${tmp_tsv}")"
last_row="$(tail -n 1 "${tmp_tsv}")"
if ! _valid_row "${first_row}"; then
  echo "${ME}: first row does not parse: ${first_row}" >&2
  exit 1
fi
if ! _valid_row "${last_row}"; then
  echo "${ME}: last row does not parse: ${last_row}" >&2
  exit 1
fi

# -------------------------------------------------------------- install (atomic)
chmod 0644 "${tmp_tsv}"
mv -f "${tmp_tsv}" "${DEST}" # atomic rename; the old database is replaced in place
trap 'rm -f "${tmp_gz}"' EXIT # tmp_tsv is now DEST; only the .gz remains
rm -f "${tmp_gz}"
trap - EXIT

echo "${ME}: installed ${lines} ranges to ${DEST}"
