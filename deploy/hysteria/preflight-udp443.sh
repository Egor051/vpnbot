#!/usr/bin/env bash
#
# preflight-udp443.sh — operator preflight for the Hysteria2 UDP/443 migration.
#
# Fail-closed: refuses (non-zero exit) if UDP/443 is already held by a process
# that is not hysteria-server itself, so `systemctl restart hysteria-server`
# never silently steals a port from something else. TCP/443 (Xray REALITY) is a
# different transport and is intentionally ignored — TCP/443 and UDP/443
# coexist by design.
#
# Not a systemd hook (the hysteria-server unit is hand-maintained outside this
# repo) — run by hand before restarting the service:
#   bash deploy/hysteria/preflight-udp443.sh
#
# Exit codes:
#   0  UDP/443 is free, or held only by a hysteria* process
#   1  UDP/443 is held by a foreign (non-hysteria) process
#   2  usage error
#   3  a UDP/443 socket exists but its owner could not be determined
#      (commonly: not running as root — `ss -p` needs root to attribute
#      sockets it does not own); fails closed rather than guessing
set -euo pipefail

ME="preflight-udp443"

usage() {
  cat >&2 <<EOF
usage: $ME [--selftest]
  (no args)   check the live UDP/443 socket ownership; run as root for
              accurate process attribution
  --selftest  run built-in checks against canned ss(8) output — no real
              socket, no root required
EOF
}

# Reads ss(8) `-tulnp`-style lines (Netid State Recv-Q Send-Q Local:Port
# Peer:Port [Process]) from stdin, one socket per line. Evaluates only UDP
# sockets bound to local port 443; every other line (including any TCP/443
# entry) is ignored. Prints a one-line verdict to stderr and returns the exit
# code described in the header comment above.
evaluate_udp443() {
  local line netid local_addr port owners owner status=0 saw_any=0 saw_unknown=0

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    read -r netid _state _recvq _sendq local_addr _peer <<<"$line"
    [[ "$netid" == "udp" ]] || continue
    port="${local_addr##*:}"
    [[ "$port" == "443" ]] || continue
    saw_any=1

    owners="$(grep -oE '"[^"]+"' <<<"$line" | tr -d '"')" || true
    if [[ -z "$owners" ]]; then
      saw_unknown=1
      continue
    fi
    while IFS= read -r owner; do
      [[ -z "$owner" ]] && continue
      case "$owner" in
        hysteria*) ;;
        *)
          echo "$ME: UDP/443 is held by '$owner' (not hysteria-server) — refusing" >&2
          status=1
          ;;
      esac
    done <<<"$owners"
  done

  if [[ "$status" -ne 0 ]]; then
    return "$status"
  fi
  if [[ "$saw_unknown" -eq 1 ]]; then
    echo "$ME: UDP/443 is in use but the owning process could not be determined (run as root?)" >&2
    return 3
  fi
  if [[ "$saw_any" -eq 0 ]]; then
    echo "$ME: UDP/443 is free" >&2
  else
    echo "$ME: UDP/443 is held by hysteria-server — OK" >&2
  fi
  return 0
}

selftest() {
  local failures=0

  local foreign_case
  foreign_case=$'udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=100,fd=10))\ntcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=100,fd=11))'
  if evaluate_udp443 <<<"$foreign_case" 2>/dev/null; then
    echo "$ME: selftest FAIL: foreign UDP/443 owner should have been refused" >&2
    failures=$((failures + 1))
  else
    echo "$ME: selftest PASS: foreign UDP/443 owner refused" >&2
  fi

  local hysteria_case
  hysteria_case=$'udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("hysteria-server",pid=200,fd=12))\ntcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=201,fd=13))'
  if evaluate_udp443 <<<"$hysteria_case" 2>/dev/null; then
    echo "$ME: selftest PASS: hysteria-server on UDP/443 accepted" >&2
  else
    echo "$ME: selftest FAIL: hysteria-server on UDP/443 should have been accepted" >&2
    failures=$((failures + 1))
  fi

  local tcp_only_case
  tcp_only_case=$'tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=300,fd=14))\nudp UNCONN 0 0 0.0.0.0:11880 0.0.0.0:* users:(("hysteria-server",pid=301,fd=15))'
  if evaluate_udp443 <<<"$tcp_only_case" 2>/dev/null; then
    echo "$ME: selftest PASS: TCP/443 busy + UDP/443 free accepted" >&2
  else
    echo "$ME: selftest FAIL: TCP/443 busy must not block UDP/443 (different transport)" >&2
    failures=$((failures + 1))
  fi

  local unknown_owner_case
  unknown_owner_case=$'udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*'
  if evaluate_udp443 <<<"$unknown_owner_case" 2>/dev/null; then
    echo "$ME: selftest FAIL: unattributable UDP/443 owner should fail closed" >&2
    failures=$((failures + 1))
  else
    echo "$ME: selftest PASS: unattributable UDP/443 owner fails closed" >&2
  fi

  if [[ "$failures" -ne 0 ]]; then
    echo "$ME: selftest: $failures failure(s)" >&2
    return 1
  fi
  echo "$ME: selftest: all checks passed" >&2
  return 0
}

main() {
  case "${1:-}" in
    "")
      command -v ss >/dev/null 2>&1 || { echo "$ME: ss(8) not found" >&2; exit 3; }
      evaluate_udp443 < <(ss -H -tulnp 2>/dev/null)
      ;;
    --selftest)
      selftest
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
}

main "$@"
