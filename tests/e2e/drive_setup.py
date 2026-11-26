"""Drive «🧭 Первичная настройка» through the mock Bot API (tests/e2e/run_setup_e2e.sh). Not a test module.

It plays the operator: presses the buttons the bot shows (callback queries injected into the
mock), types the domain and the Cloudflare token, and follows the setup's row in
``wizard_runs`` until it ends. The bot restarts on its own while it runs (every install
does), so a message is always looked up again by its buttons, never remembered.

  python3 drive_setup.py <operator id> <domain> <cloudflare token>

Exit 0 when the setup succeeded; the last state otherwise.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import urllib.request
from typing import Any

MOCK = "http://127.0.0.1:8081"
DB = "file:/opt/vpn-service/data/vpn.db?mode=ro"
TIMEOUT = 1500


def call(path: str, body: dict[str, Any] | None = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{MOCK}/_control/{path}", data=data,  # noqa: S310 — the loopback mock
                                 headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — the loopback mock
        return json.loads(resp.read())


def messages(chat: int) -> list[tuple[int, dict[str, Any]]]:
    out = []
    for key, msg in call("messages").items():
        if key.isdigit() and int(msg.get("chat_id", 0)) == chat:
            out.append((int(key), msg))
    return sorted(out)


def find_button(chat: int, prefix: str) -> tuple[int, str] | None:
    """The newest message of *chat* with a button whose data starts with *prefix*."""
    for mid, msg in reversed(messages(chat)):
        for b in msg.get("buttons", []):
            if b["data"].startswith(prefix):
                return mid, b["data"]
    return None


def press(user: int, mid: int, data: str) -> None:
    print(f"press {data} on message {mid}", flush=True)
    call("inject", {"user_id": user, "callback_data": data, "message_id": mid})


def say(user: int, text: str, what: str) -> None:
    print(f"type {what}", flush=True)
    call("inject", {"user_id": user, "text": text})


def setup_row() -> dict[str, Any] | None:
    try:
        conn = sqlite3.connect(DB, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM wizard_runs WHERE mode = 'setup' ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    return dict(row) if row is not None else None


def runs() -> list[dict[str, Any]]:
    conn = sqlite3.connect(DB, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT id, mode, state, summary FROM wizard_runs ORDER BY id")]
    conn.close()
    return rows


def bot_said(chat: int, last: int = 8) -> str:
    """The bot's last messages to *chat* (what the operator would read), for a failure."""
    try:
        shown = messages(chat)[-last:]
    except (OSError, ValueError) as exc:
        return f"(messages: {type(exc).__name__}: {exc})"
    return "\n".join(f"  #{mid}: {str(m.get('text', ''))[:600]!r} {[b['data'] for b in m.get('buttons', [])]}"
                     for mid, m in shown)


def fail(why: str, chat: int) -> SystemExit:
    try:
        all_runs: Any = runs()
    except sqlite3.Error as exc:
        all_runs = f"({type(exc).__name__}: {exc})"
    return SystemExit(f"E2E FAILURE: {why}\nsetup row: {setup_row()}\nruns: {all_runs}\n"
                      f"the bot's last messages:\n{bot_said(chat)}")


_seen: list[Any] = [None]


def progress(chat: int) -> None:
    """Print the setup's step when it moves; stop at once when a step failed."""
    row = setup_row()
    if row is None:
        return
    params = json.loads(row["params_json"] or "{}")
    now = (row["current_step"], params.get("waiting"), params.get("child"), params.get("note"))
    if now != _seen[0]:
        _seen[0] = now
        print(f"  setup: step={now[0]} waiting={now[1]} child={now[2]} note={now[3]!r}", flush=True)
    if row["state"] == "running" and params.get("waiting") == "retry":
        raise fail(f"setup step {row['current_step']} failed: {params.get('note')}", chat)


def wait_for(what: str, check: Any, chat: int, timeout: float = TIMEOUT) -> Any:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            progress(chat)
            last = check()
        except (OSError, ValueError, sqlite3.Error) as exc:
            last = None
            print(f"  ({what}: {type(exc).__name__}: {exc})", flush=True)
        if last:
            return last
        time.sleep(2)
    raise fail(f"timed out waiting for {what}", chat)


def main() -> int:
    user, domain, token = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    start = wait_for("the setup's offer after the claim", lambda: find_button(user, "setup:start"), user, 60)
    press(user, *start)
    ask = wait_for("the domain prompt", lambda: find_button(user, "setup:ask:domain:"), user, 60)
    press(user, *ask)
    wait_for("«send the domain»", lambda: any("vpn.example.com" in m.get("text", "") for _, m in messages(user)),
             user, 60)
    say(user, domain, "the domain")
    ask = wait_for("the token prompt", lambda: find_button(user, "setup:ask:token:"), user, 60)
    press(user, *ask)
    time.sleep(3)
    say(user, token, "the Cloudflare token")
    # The token is checked at once: the setup moves past it, or the bot says why not.
    wait_for("the token accepted (the setup past its token step)",
             lambda: (row := setup_row()) is not None and row["current_step"] not in ("domain", "token"), user, 60)
    go = wait_for("the protocols' confirmation (after the certificate)", lambda: find_button(user, "setup:go:"), user)
    press(user, *go)

    def totp_or_done() -> Any:
        row = setup_row()
        if row and row["finished_at"]:
            return "done"
        return find_button(user, "setup:totp:skip:")

    got = wait_for("the TOTP step (after the installs and the firewall)", totp_or_done, user)
    if got != "done":
        press(user, *got)

    def finished() -> Any:
        row = setup_row()
        return row if row and row["finished_at"] else None

    row = wait_for("the end of the setup (the self-check)", finished, user)
    print(json.dumps({k: row[k] for k in ("id", "state", "current_step", "summary")}), flush=True)
    for run in runs():
        print(f"run #{run['id']} {run['mode']}: {run['state']} — {str(run['summary'])[:200]}", flush=True)
    if row["state"] != "succeeded":
        raise fail(f"the setup ended {row['state']}", user)
    return 0


if __name__ == "__main__":
    sys.exit(main())
