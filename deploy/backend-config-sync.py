#!/usr/bin/env python3
#
# backend-config-sync.py — reconcile the two CO-OWNED backend configs with the repo.
#
# WHY THIS EXISTS
#
# Three backend configs, three different ownership models. The third column is the
# whole reason this script is not just a `cp`:
#
#   /etc/hysteria/config.yaml          operator only    deploy/hysteria/install-config.sh
#                                                       copies it whole (the bot never
#                                                       writes this file — it writes DB
#                                                       rows, hy2_auth reads them live)
#   /usr/local/etc/xray/config.json    operator + BOT   this script
#   /etc/amnezia/amneziawg/awg0.conf   operator + BOT   this script (check only)
#
# The bot REWRITES the latter two on every key issue/revoke (adapters/xray_config.py
# via os.replace, adapters/awg_config.py via atomic_write_text). Copying a tracked
# file over either one would delete every live key. So the repo cannot ship an
# installable config for them — it ships a SKELETON, and this script reconciles the
# two owners' regions separately.
#
# WHO OWNS WHAT (the one definition; tests/test_backend_config_sync.py pins these
# against the adapters, so this file cannot silently drift from the writer)
#
#   xray  bot:      inbounds[*].settings.clients
#                   inbounds[*].streamSettings.realitySettings.shortIds
#                   outbounds[*].sendThrough   (freedom outbounds; re-asserted on
#                                               every write by apply_warp_send_through)
#         operator: everything else — log, dns, api, policy, routing, stats, the
#                   inbound skeletons (ports, REALITY keys, target, serverNames)
#
#   awg   bot:      each block delimited by
#                   `# vpn-bot peer start key_id=<N> ...` .. `# vpn-bot peer end key_id=<N>`
#         operator: the whole [Interface] section
#
# Placeholders (`<LIKE_THIS>`) in the skeleton match ANY live value, so no secret has
# to be in the repo for `check` to work.
#
# USAGE
#   python deploy/backend-config-sync.py check [--repo-root DIR]
#   python deploy/backend-config-sync.py install-xray [--dry-run] [--env PATH]
#   python deploy/backend-config-sync.py --selftest
#
# EXIT CODES
#   0  no structural drift / installed / selftest passed
#   1  fail-closed: a precondition was not met (see stderr) — nothing written
#   2  usage error
#   3  structural drift found (`check` only) — nothing is ever written by `check`
#
# A backend that is not deployed at all (no live config file) is NOT drift: it is
# reported as absent and exits 0, the same policy as an `absent-ok` entry in
# deploy.sh's OUT_OF_REPO_HELPERS. A host running only Hysteria2 must not fail here.

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ME = "backend-config-sync"

# --- the bot-owned region definitions (pinned by tests against adapters/) ---------
AWG_MANAGED_START_PREFIX = "# vpn-bot peer start key_id="
AWG_MANAGED_END_PREFIX = "# vpn-bot peer end key_id="
FREEDOM_OUTBOUND_PROTOCOL = "freedom"
XRAY_BOT_OWNED_INBOUND_PATHS = (
    ("settings", "clients"),
    ("streamSettings", "realitySettings", "shortIds"),
)
XRAY_BOT_OWNED_OUTBOUND_KEYS = ("sendThrough",)

# A placeholder standing in for a whole value.
PLACEHOLDER_RE = re.compile(r"^<[A-Z0-9_]+>$")
# Any placeholder, for values that only partly consist of one (AWG PostUp lines).
ANY_PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_]+>")

# install-xray only: where a placeholder's real value comes from. Anything not
# listed here is resolved by PRESERVING the live file's value at the same path —
# which is the only possible source for a secret the repo must not hold, and for a
# port whose .env semantics are ambiguous.
PLACEHOLDER_ENV = {
    "<REALITY_SERVER_NAME>": "XRAY_SNI",
    "<XHTTP_PATH>": "XRAY_XHTTP_PATH",
}

DEFAULT_XRAY_CONF = "/usr/local/etc/xray/config.json"
DEFAULT_AWG_CONF = "/etc/amnezia/amneziawg/awg0.conf"


def warn(msg: str) -> None:
    print(f"[{ME}] WARN: {msg}", file=sys.stderr)


def die(msg: str, code: int = 1) -> None:
    print(f"[{ME}] FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


# --- .env reading -----------------------------------------------------------------
def read_env(path: Path) -> dict[str, str]:
    """Parse KEY=value lines. A key must start at the first column, so a
    commented-out `# KEY=...` never matches (the leading '#' is not whitespace)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", raw)
        if not m:
            continue
        val = m.group(2).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        values[m.group(1)] = val
    return values


# --- xray: strip the bot-owned region ---------------------------------------------
def strip_xray_bot_owned(config: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy with every bot-owned region emptied/removed, so what is
    left is exactly the operator's structure and can be compared."""
    cfg = json.loads(json.dumps(config))

    for inbound in cfg.get("inbounds", []) or []:
        if not isinstance(inbound, dict):
            continue
        for path in XRAY_BOT_OWNED_INBOUND_PATHS:
            node = inbound
            for key in path[:-1]:
                node = node.get(key) if isinstance(node, dict) else None
                if not isinstance(node, dict):
                    node = None
                    break
            if isinstance(node, dict) and path[-1] in node:
                node[path[-1]] = []

    for outbound in cfg.get("outbounds", []) or []:
        if not isinstance(outbound, dict):
            continue
        # ONLY freedom outbounds, matching apply_warp_send_through() exactly. Popping
        # sendThrough from every outbound would be a wider exclusion than the writer's
        # region, so a hand-set sendThrough on some other outbound — operator
        # structure the bot never touches — would stop being reported as drift.
        if outbound.get("protocol") != FREEDOM_OUTBOUND_PROTOCOL:
            continue
        for key in XRAY_BOT_OWNED_OUTBOUND_KEYS:
            outbound.pop(key, None)

    return cfg


def key_inbounds_by_tag(cfg: dict[str, Any]) -> dict[str, Any]:
    """inbounds are matched by tag, never by position — the order on the host is
    whatever history produced, and reordering is not drift."""
    out: dict[str, Any] = {}
    for index, inbound in enumerate(cfg.get("inbounds", []) or []):
        if not isinstance(inbound, dict):
            continue
        tag = inbound.get("tag") or f"<untagged #{index}>"
        out[str(tag)] = inbound
    return out


def key_outbounds(cfg: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for index, outbound in enumerate(cfg.get("outbounds", []) or []):
        if not isinstance(outbound, dict):
            continue
        tag = outbound.get("tag") or outbound.get("protocol") or f"<#{index}>"
        out[str(tag)] = outbound
    return out


# --- generic structural comparison ------------------------------------------------
def compare(expected: Any, actual: Any, path: str, findings: list[str]) -> None:
    """Compare a skeleton value against a live one. A placeholder matches anything.

    Reports three kinds of finding and nothing else: a key the skeleton has and the
    host lacks, a key the host has and the skeleton lacks, and a leaf whose value
    differs. Extra keys are reported because on these two files an unexplained extra
    key is how an out-of-band hand edit shows up.
    """
    if isinstance(expected, str) and PLACEHOLDER_RE.match(expected):
        return  # placeholder: any live value is acceptable

    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in expected:
            if key not in actual:
                findings.append(f"MISSING on host   {path}.{key}")
            else:
                compare(expected[key], actual[key], f"{path}.{key}", findings)
        for key in actual:
            if key not in expected:
                findings.append(f"EXTRA on host     {path}.{key}")
        return

    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            findings.append(
                f"DIFFERS           {path}: skeleton has {len(expected)} item(s), host has {len(actual)}"
            )
            return
        for index, (exp_item, act_item) in enumerate(zip(expected, actual)):
            compare(exp_item, act_item, f"{path}[{index}]", findings)
        return

    if type(expected) is not type(actual) or expected != actual:
        findings.append(f"DIFFERS           {path}: skeleton {expected!r} vs host {actual!r}")


def check_xray(skeleton_path: Path, live_path: Path) -> tuple[int, list[str]]:
    """Returns (drift_count, report_lines)."""
    lines: list[str] = []
    if not live_path.is_file():
        lines.append(f"  xray:  {live_path} absent — backend not deployed here, not drift")
        return 0, lines
    if not skeleton_path.is_file():
        die(f"skeleton missing: {skeleton_path}")

    try:
        live = json.loads(live_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read live xray config {live_path}: {exc}")
    try:
        skeleton = json.loads(skeleton_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read skeleton {skeleton_path}: {exc}")

    live_clean = strip_xray_bot_owned(live)
    skel_clean = strip_xray_bot_owned(skeleton)

    findings: list[str] = []

    # Top level, minus the two lists that need tag-matching.
    for key in sorted(set(skel_clean) | set(live_clean)):
        if key in ("inbounds", "outbounds"):
            continue
        if key not in live_clean:
            findings.append(f"MISSING on host   {key}")
        elif key not in skel_clean:
            findings.append(f"EXTRA on host     {key}")
        else:
            compare(skel_clean[key], live_clean[key], key, findings)

    skel_in, live_in = key_inbounds_by_tag(skel_clean), key_inbounds_by_tag(live_clean)
    for tag in sorted(set(skel_in) | set(live_in)):
        if tag not in live_in:
            findings.append(f"MISSING on host   inbounds[tag={tag}] (whole inbound)")
        elif tag not in skel_in:
            findings.append(f"EXTRA on host     inbounds[tag={tag}] (whole inbound)")
        else:
            compare(skel_in[tag], live_in[tag], f"inbounds[{tag}]", findings)

    skel_out, live_out = key_outbounds(skel_clean), key_outbounds(live_clean)
    for tag in sorted(set(skel_out) | set(live_out)):
        if tag not in live_out:
            findings.append(f"MISSING on host   outbounds[{tag}] (whole outbound)")
        elif tag not in skel_out:
            findings.append(f"EXTRA on host     outbounds[{tag}] (whole outbound)")
        else:
            compare(skel_out[tag], live_out[tag], f"outbounds[{tag}]", findings)

    # Census of the bot-owned region: never drift, but the operator wants the number.
    census = []
    for tag, inbound in sorted(key_inbounds_by_tag(live).items()):
        settings = inbound.get("settings")
        clients = settings.get("clients") if isinstance(settings, dict) else None
        if isinstance(clients, list):
            census.append(f"{tag}={len(clients)}")
    lines.append(
        f"  xray:  {len(findings)} structural finding(s); bot-owned clients: "
        + (", ".join(census) if census else "none")
    )
    lines.extend(f"    {f}" for f in findings)
    return len(findings), lines


# --- awg --------------------------------------------------------------------------
def parse_awg_interface(text: str) -> dict[str, str]:
    """Key/value pairs of the [Interface] section only. Comments and every [Peer]
    section are ignored — peers are runtime state, not structure."""
    values: dict[str, str] = {}
    in_interface = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_interface = line.lower() == "[interface]"
            continue
        if not in_interface or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def count_awg_peers(text: str) -> tuple[int, int]:
    """(total [Peer] sections, how many carry a vpn-bot managed marker)."""
    total = 0
    managed = 0
    pending_marker = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(AWG_MANAGED_START_PREFIX):
            pending_marker = True
            continue
        if line == "[Peer]":
            total += 1
            if pending_marker:
                managed += 1
            pending_marker = False
            continue
        if line and not line.startswith("#"):
            pending_marker = False
    return total, managed


def check_awg(example_path: Path, live_path: Path) -> tuple[int, list[str]]:
    lines: list[str] = []
    if not live_path.is_file():
        lines.append(f"  awg:   {live_path} absent — backend not deployed here, not drift")
        return 0, lines
    if not example_path.is_file():
        die(f"example missing: {example_path}")

    try:
        live_text = live_path.read_text(encoding="utf-8")
    except OSError as exc:
        die(f"cannot read live awg config {live_path}: {exc}")
    example_text = example_path.read_text(encoding="utf-8")

    expected = parse_awg_interface(example_text)
    actual = parse_awg_interface(live_text)
    findings: list[str] = []
    for key in expected:
        if key not in actual:
            findings.append(f"MISSING on host   [Interface].{key}")
            continue
        pattern = expected[key]
        if ANY_PLACEHOLDER_RE.search(pattern):
            # Partly-literal value (e.g. PostUp): placeholders become wildcards, so
            # the literal skeleton around them is still asserted.
            regex = "".join(
                ".*" if ANY_PLACEHOLDER_RE.fullmatch(part) else re.escape(part)
                for part in re.split(r"(<[A-Z0-9_]+>)", pattern)
            )
            if not re.fullmatch(regex, actual[key]):
                findings.append(
                    f"DIFFERS           [Interface].{key}: host value does not match the skeleton shape"
                )
        elif expected[key] != actual[key]:
            findings.append(
                f"DIFFERS           [Interface].{key}: skeleton {expected[key]!r} vs host {actual[key]!r}"
            )
    for key in actual:
        if key not in expected:
            findings.append(f"EXTRA on host     [Interface].{key}")

    total, managed = count_awg_peers(live_text)
    unmanaged = total - managed
    lines.append(
        f"  awg:   {len(findings)} structural finding(s); peers: {total} total, "
        f"{managed} bot-managed, {unmanaged} hand-added"
    )
    lines.extend(f"    {f}" for f in findings)
    if unmanaged:
        # Not drift — but a peer with no marker is invisible to the bot while still
        # holding an address out of AWG_NETWORK, so it must never pass silently.
        lines.append(
            f"    INFO: {unmanaged} [Peer] block(s) carry no vpn-bot marker — the bot "
            f"cannot see or revoke those, and their addresses are not reserved"
        )
    return len(findings), lines


# --- install-xray -----------------------------------------------------------------
def extract_bot_state(live: dict[str, Any]) -> dict[str, Any]:
    """Pull the bot-owned region out of the live config so it can be put back."""
    clients: dict[str, list[Any]] = {}
    short_ids: dict[str, list[Any]] = {}
    for tag, inbound in key_inbounds_by_tag(live).items():
        settings = inbound.get("settings")
        if isinstance(settings, dict) and isinstance(settings.get("clients"), list):
            clients[tag] = settings["clients"]
        reality = (inbound.get("streamSettings") or {}).get("realitySettings")
        if isinstance(reality, dict) and isinstance(reality.get("shortIds"), list):
            short_ids[tag] = reality["shortIds"]
    send_through = [
        ob.get("sendThrough")
        for ob in (live.get("outbounds") or [])
        if isinstance(ob, dict) and ob.get("protocol") == FREEDOM_OUTBOUND_PROTOCOL
    ]
    return {"clients": clients, "shortIds": short_ids, "sendThrough": send_through}


def resolve_placeholders(
    node: Any, live_node: Any, env: dict[str, str], path: str, unresolved: list[str]
) -> Any:
    """Walk the skeleton, replacing every placeholder with a real value.

    Resolution order, and there is no third source: the mapped .env variable, then
    the live config's value at the SAME path. A placeholder that neither provides is
    collected in *unresolved* and makes the install fail closed — writing `<...>`
    into a load-bearing config would take the data plane down.
    """
    if isinstance(node, str) and PLACEHOLDER_RE.match(node):
        env_key = PLACEHOLDER_ENV.get(node)
        if env_key and env.get(env_key):
            return env[env_key]
        if live_node is not None and not (
            isinstance(live_node, str) and PLACEHOLDER_RE.match(live_node)
        ):
            return live_node
        unresolved.append(f"{node} at {path} (env {env_key or '—'}, no live value to preserve)")
        return node

    if isinstance(node, dict):
        live_dict = live_node if isinstance(live_node, dict) else {}
        return {
            key: resolve_placeholders(val, live_dict.get(key), env, f"{path}.{key}", unresolved)
            for key, val in node.items()
        }

    if isinstance(node, list):
        live_list = live_node if isinstance(live_node, list) else []
        return [
            resolve_placeholders(
                item, live_list[index] if index < len(live_list) else None, env,
                f"{path}[{index}]", unresolved,
            )
            for index, item in enumerate(node)
        ]

    return node


def install_xray(
    skeleton_path: Path, live_path: Path, env_path: Path, *, dry_run: bool, xray_bin: str | None
) -> int:
    if not live_path.is_file():
        die(
            f"{live_path} does not exist. This subcommand MERGES the repo structure into a live "
            f"config; it cannot bootstrap one, because the REALITY private key exists only there. "
            f"For a fresh host, install the skeleton by hand and fill in the placeholders."
        )
    if not skeleton_path.is_file():
        die(f"skeleton missing: {skeleton_path}")

    try:
        live = json.loads(live_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read live xray config {live_path}: {exc}")
    skeleton = json.loads(skeleton_path.read_text(encoding="utf-8"))

    state = extract_bot_state(live)
    total_clients = sum(len(v) for v in state["clients"].values())
    if not state["clients"]:
        die(
            "the live config has no `settings.clients` list on any inbound. That is not a config "
            "this script should rewrite — refusing before touching anything."
        )

    env = read_env(env_path)
    unresolved: list[str] = []
    live_by_tag = key_inbounds_by_tag(live)
    merged = resolve_placeholders(skeleton, live, env, "$", unresolved)

    # Placeholders inside inbounds resolve against the live inbound with the SAME
    # TAG, not the same index — the walk above matched by position, so redo those.
    for index, inbound in enumerate(merged.get("inbounds", []) or []):
        tag = str(inbound.get("tag") or "")
        if tag in live_by_tag:
            merged["inbounds"][index] = resolve_placeholders(
                skeleton["inbounds"][index], live_by_tag[tag], env,
                f"$.inbounds[{tag}]", unresolved,
            )
    unresolved = sorted(set(unresolved))
    if unresolved:
        die(
            "unresolved placeholder(s) — nothing written:\n       "
            + "\n       ".join(unresolved)
        )

    # Put the bot-owned region back, matched by tag.
    for inbound in merged.get("inbounds", []) or []:
        tag = str(inbound.get("tag") or "")
        if tag in state["clients"]:
            inbound.setdefault("settings", {})["clients"] = state["clients"][tag]
        if tag in state["shortIds"]:
            reality = (inbound.get("streamSettings") or {}).get("realitySettings")
            if isinstance(reality, dict):
                reality["shortIds"] = state["shortIds"][tag]
    freedom_index = 0
    for outbound in merged.get("outbounds", []) or []:
        if outbound.get("protocol") != FREEDOM_OUTBOUND_PROTOCOL:
            continue
        if freedom_index < len(state["sendThrough"]):
            value = state["sendThrough"][freedom_index]
            if value:
                outbound["sendThrough"] = value
        freedom_index += 1

    content = json.dumps(merged, ensure_ascii=False, indent=2) + "\n"

    merged_clients = sum(
        len(ib.get("settings", {}).get("clients", []))
        for ib in merged.get("inbounds", [])
        if isinstance(ib, dict)
    )
    if merged_clients != total_clients:
        die(
            f"refusing to write: {total_clients} client(s) read from the live config but "
            f"{merged_clients} in the merged result. An inbound tag in the skeleton does not "
            f"match the host — reconcile the tags first."
        )

    if dry_run:
        print(content, end="")
        print(
            f"[{ME}] --dry-run: nothing written. Would preserve {total_clients} client(s) "
            f"across {len(state['clients'])} inbound(s).",
            file=sys.stderr,
        )
        return 0

    # Validate BEFORE replacing: a config xray rejects would take :443 down on the
    # next restart, and the bot's own writes would then fail on a file it cannot parse.
    stat = live_path.stat()
    tmp_dir = live_path.parent
    fd, tmp_name = tempfile.mkstemp(dir=tmp_dir, prefix=".backend-config-sync.", suffix=".json")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, stat.st_mode & 0o7777)
        try:
            os.chown(tmp_path, stat.st_uid, stat.st_gid)
        except PermissionError:
            warn("could not preserve owner/group (not root?) — check the installed file")

        if xray_bin:
            result = subprocess.run(
                [xray_bin, "run", "-test", "-config", str(tmp_path)],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                die(
                    "xray rejected the merged config — nothing written:\n"
                    + (result.stderr or result.stdout).strip()
                )
        else:
            die(
                "the `xray` binary was not found, so the merged config cannot be validated. "
                "Refusing to install an unvalidated config over a live one."
            )

        backup = live_path.with_suffix(live_path.suffix + ".pre-sync")
        shutil.copy2(live_path, backup)
        os.replace(tmp_path, live_path)
        tmp_path = None  # type: ignore[assignment]
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()

    print(f"[{ME}] installed {live_path} (previous copy kept at {backup})")
    print(f"[{ME}] preserved {total_clients} client(s), {len(state['shortIds'])} shortIds list(s)")
    print(f"[{ME}] next: systemctl restart xray   # NOT done here — pick the window yourself")
    return 0


# --- selftest ---------------------------------------------------------------------
def selftest() -> int:
    live = {
        "inbounds": [
            {
                "tag": "vless-in",
                "port": 443,
                "settings": {"clients": [{"id": "a"}, {"id": "b"}], "decryption": "none"},
                "streamSettings": {
                    "realitySettings": {"shortIds": ["dead"], "privateKey": "SECRET", "target": "127.0.0.1:8443"}
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "sendThrough": "10.9.9.9"}],
    }
    stripped = strip_xray_bot_owned(live)
    assert stripped["inbounds"][0]["settings"]["clients"] == []
    assert stripped["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] == []
    assert "sendThrough" not in stripped["outbounds"][0]
    assert live["inbounds"][0]["settings"]["clients"] != [], "input must not be mutated"

    findings: list[str] = []
    compare({"k": "<PLACEHOLDER>"}, {"k": "anything at all"}, "$", findings)
    assert findings == [], findings
    compare({"k": 1}, {"k": 2}, "$", findings)
    assert len(findings) == 1 and "DIFFERS" in findings[0], findings

    findings = []
    compare({"a": 1}, {"b": 1}, "$", findings)
    assert any("MISSING" in f for f in findings) and any("EXTRA" in f for f in findings), findings

    # bool must not compare equal to int 1 — a JSON true/1 mix-up is real drift
    findings = []
    compare({"k": True}, {"k": 1}, "$", findings)
    assert len(findings) == 1, findings

    iface = parse_awg_interface(
        "# c\n[Interface]\nPrivateKey = x\nJc = 4\n\n[Peer]\nPublicKey = y\n"
    )
    assert iface == {"PrivateKey": "x", "Jc": "4"}, iface

    total, managed = count_awg_peers(
        f"[Interface]\nPrivateKey = x\n\n{AWG_MANAGED_START_PREFIX}1 owner=2\n[Peer]\n"
        "PublicKey = a\n# vpn-bot peer end key_id=1\n\n[Peer]\nPublicKey = b\n"
    )
    assert (total, managed) == (2, 1), (total, managed)

    unresolved: list[str] = []
    out = resolve_placeholders(
        {"a": "<REALITY_SERVER_NAME>", "b": "<REALITY_PRIVATE_KEY>", "c": "<NOWHERE>"},
        {"b": "live-key"},
        {"XRAY_SNI": "example.invalid"},
        "$",
        unresolved,
    )
    assert out["a"] == "example.invalid" and out["b"] == "live-key", out
    assert len(unresolved) == 1 and "<NOWHERE>" in unresolved[0], unresolved

    print(f"[{ME}] selftest passed")
    return 0


# --- CLI --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="backend-config-sync.py", add_help=True)
    parser.add_argument("--selftest", action="store_true", help="run internal checks and exit")
    sub = parser.add_subparsers(dest="cmd")

    repo_default = Path(__file__).resolve().parent.parent

    p_check = sub.add_parser("check", help="read-only structural drift report")
    p_check.add_argument("--repo-root", type=Path, default=repo_default)
    p_check.add_argument("--xray-config", type=Path, default=Path(DEFAULT_XRAY_CONF))
    p_check.add_argument("--awg-config", type=Path, default=Path(DEFAULT_AWG_CONF))

    p_inst = sub.add_parser("install-xray", help="merge the repo structure into the live config")
    p_inst.add_argument("--repo-root", type=Path, default=repo_default)
    p_inst.add_argument("--xray-config", type=Path, default=Path(DEFAULT_XRAY_CONF))
    p_inst.add_argument("--env", type=Path, default=None)
    p_inst.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.cmd:
        parser.print_help(sys.stderr)
        return 2

    root = args.repo_root.resolve()
    skeleton = root / "deploy" / "xray" / "config.skeleton.json"

    if args.cmd == "check":
        example = root / "deploy" / "awg" / "awg0.conf.example"
        print(f"[{ME}] structural drift, live host vs {root}")
        x_count, x_lines = check_xray(skeleton, args.xray_config)
        a_count, a_lines = check_awg(example, args.awg_config)
        for line in x_lines + a_lines:
            print(line)
        total = x_count + a_count
        if total:
            print(
                f"[{ME}] {total} structural finding(s). The bot-owned regions (xray clients/"
                f"shortIds/sendThrough, awg peers) were excluded and are never drift."
            )
            return 3
        print(f"[{ME}] no structural drift")
        return 0

    env_path = args.env or (root / ".env")
    return install_xray(
        skeleton, args.xray_config, env_path,
        dry_run=args.dry_run, xray_bin=shutil.which("xray"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
