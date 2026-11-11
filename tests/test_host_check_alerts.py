"""services/host_check.py — superadmin alerts from the host invariants state file.

The bot reads /var/lib/vpn-bot-host-check/last.json (written by
scripts/vpn-bot-host-check) and alerts only on a CHANGE: a row that turns BEATEN or
MISMATCH, a LATENT that is new, once when it is clean again — never twice for the
same row, across restarts too (what was reported lives in schema_meta).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from i18n import use_locale
from services.host_check import (
    META_KEY,
    HostCheckMonitor,
    HostCheckStateError,
    Reported,
    parse_report,
)


class Store:
    def __init__(self) -> None:
        self.meta: dict[str, str] = {}

    async def get_meta(self, key: str) -> str | None:
        return self.meta.get(key)

    async def set_meta(self, key: str, value: str) -> None:
        self.meta[key] = value


def _row(verdict: str, key: str, path: str = "/etc/x", family: str = "sshd", text: str = "t") -> dict[str, str]:
    return {"verdict": verdict, "family": family, "key": key, "path": path, "text": text}


def _write(path: Path, *rows: dict[str, str], at: str = "2026-11-11T05:00:00Z") -> None:
    data: dict[str, Any] = {"version": 1, "generated_at": at, "role": "main", "mode": "installed",
                            "counts": {}, "rows": list(rows)}
    path.write_text(json.dumps(data), encoding="utf-8")


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.path = tmp / "last.json"
        self.store = Store()
        self.sent: list[str] = []
        self.monitor = self.fresh()

    def fresh(self) -> HostCheckMonitor:
        """A monitor as a restarted bot builds it: same store, nothing in memory."""

        async def send(text: str) -> None:
            self.sent.append(text)

        return HostCheckMonitor(store=self.store, admin_ids=frozenset({1}), path=self.path, send=send)


async def test_a_new_beaten_row_alerts_once(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("OK", "pubkeyauthentication"),
           _row("BEATEN", "passwordauthentication", "/etc/ssh/sshd_config.d/50-cloud-init.conf",
                text="50-cloud-init.conf:1 = yes wins over the repo value no"))
    with use_locale("en"):
        await h.monitor.check_once()
        await h.monitor.check_once()
    assert len(h.sent) == 1, h.sent
    msg = h.sent[0]
    assert "BEATEN/MISMATCH 1, LATENT 0" in msg
    assert "<b>BEATEN</b> sshd <code>passwordauthentication</code> — 50-cloud-init.conf:1 = yes wins" in msg
    assert "pubkeyauthentication" not in msg
    assert json.loads(h.store.meta[META_KEY]) == {
        "fatal": ["BEATEN|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf"], "latent": []}


async def test_no_repeat_after_a_restart(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("MISMATCH", "net.ipv4.ip_forward", family="sysctl"))
    await h.monitor.check_once()
    _write(h.path, _row("MISMATCH", "net.ipv4.ip_forward", family="sysctl", text="new wording"), at="2026-11-12T05:00:00Z")
    await h.fresh().check_once()
    assert len(h.sent) == 1, "the same row after a bot restart (every deploy) is not reported again"


async def test_a_new_latent_alerts_and_an_old_one_does_not(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("LATENT", "permitrootlogin", "/etc/ssh/sshd_config"))
    await h.monitor.check_once()
    _write(h.path, _row("LATENT", "permitrootlogin", "/etc/ssh/sshd_config"),
           _row("LATENT", "vm.swappiness", "/etc/sysctl.d/10-x.conf", family="sysctl"))
    with use_locale("en"):
        await h.monitor.check_once()
    assert len(h.sent) == 2
    assert "vm.swappiness" in h.sent[1] and "permitrootlogin" not in h.sent[1]
    assert "LATENT 2" in h.sent[1]


async def test_accepted_warn_and_ok_never_alert(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("ACCEPTED", "a"), _row("WARN", "b"), _row("OK", "c"), _row("INFO", "d"), _row("PENDING", "e"))
    await h.monitor.check_once()
    assert h.sent == []


async def test_the_way_back_is_reported_once(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("BEATEN", "k"))
    await h.monitor.check_once()
    _write(h.path, _row("OK", "k"), at="2026-11-12T05:00:00Z")
    with use_locale("en"):
        await h.monitor.check_once()
        await h.monitor.check_once()
    assert len(h.sent) == 2
    assert "back in line" in h.sent[1] and "2026-11-12T05:00:00Z" in h.sent[1]
    assert Reported.load(h.store.meta[META_KEY]) == Reported(frozenset(), frozenset())


async def test_a_row_that_turns_from_latent_to_beaten_alerts(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("LATENT", "k", "/etc/a"))
    await h.monitor.check_once()
    _write(h.path, _row("BEATEN", "k", "/etc/a"))
    await h.monitor.check_once()
    assert len(h.sent) == 2 and "BEATEN" in h.sent[1]


async def test_a_latent_that_goes_and_comes_back_alerts_again(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("LATENT", "k"))
    await h.monitor.check_once()
    _write(h.path)
    await h.monitor.check_once()
    _write(h.path, _row("LATENT", "k"))
    await h.monitor.check_once()
    assert len(h.sent) == 2, "gone and back is a change; LATENT going away alone says nothing"


async def test_nothing_is_sent_or_remembered_without_a_bot(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("BEATEN", "k"))
    monitor = HostCheckMonitor(store=h.store, admin_ids=frozenset({1}), path=h.path)
    await monitor.check_once()
    assert h.store.meta == {}, "an early pass must not swallow the alert"


async def test_a_missing_or_broken_file_is_logged_once_and_never_alerts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    h = Harness(tmp_path)
    with caplog.at_level(logging.WARNING, logger="services.host_check"):
        await h.monitor.check_once()
        await h.monitor.check_once()
        h.path.write_text("{not json", encoding="utf-8")
        await h.monitor.check_once()
    assert h.sent == [] and h.store.meta == {}
    messages = [r.getMessage() for r in caplog.records]
    assert sum("has not run on this host yet" in m for m in messages) == 1
    assert sum("not a host check state file" in m for m in messages) == 1


async def test_many_new_rows_are_capped(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, *[_row("LATENT", f"k{i}") for i in range(20)])
    with use_locale("en"):
        await h.monitor.check_once()
    assert h.sent[0].count("<b>LATENT</b>") == 15 and "… and 5 more" in h.sent[0]


async def test_row_text_is_escaped(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("BEATEN", "<k>", text="a <b>bold</b> & claim"))
    await h.monitor.check_once()
    assert "&lt;k&gt;" in h.sent[0] and "a &lt;b&gt;bold&lt;/b&gt; &amp; claim" in h.sent[0]


async def test_the_russian_text(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    _write(h.path, _row("BEATEN", "k"))
    with use_locale("ru"):
        await h.monitor.check_once()
    assert "Состояние хоста" in h.sent[0]


@pytest.mark.parametrize("raw", [
    "[]",
    '{"generated_at": "x", "role": "main"}',
    '{"generated_at": "x", "role": "main", "rows": [{"verdict": 1}]}',
    '{"generated_at": "x", "role": "main", "rows": ["x"]}',
])
def test_parse_report_refuses_anything_else(raw: str) -> None:
    with pytest.raises(HostCheckStateError):
        parse_report(raw)


def test_reported_survives_garbage() -> None:
    assert Reported.load("{broken") == Reported(frozenset(), frozenset())
    assert Reported.load(None) == Reported(frozenset(), frozenset())
    r = Reported(frozenset({"a"}), frozenset({"b"}))
    assert Reported.load(r.dump()) == r


def test_the_loop_is_wired_and_gated() -> None:
    root = Path(__file__).resolve().parents[1]
    main = (root / "main.py").read_text(encoding="utf-8")
    assert "settings.host_check_interval > 0 and services.host_check is not None" in main
    assert "host_check_loop(services.host_check, settings.host_check_interval)" in main
    app = (root / "bot" / "app.py").read_text(encoding="utf-8")
    assert "HostCheckMonitor(store=db, admin_ids=settings.admin_ids)" in app
    assert "host_check_monitor.bot = bot" in app
