"""Tests for VLESS (HTTP) riding vless-in's REALITY via the XHTTP fallback dest.

In the fallback topology the XHTTP inbound (``vless-xhttp-reality``) is the dest of
vless-in's REALITY fallback: it listens on loopback, carries ``security: none``
(no REALITY of its own) and only holds the http ``clients[]``. These tests pin the
adapter behaviour against a config.json that mirrors that server layout:

- the XHTTP inbound is detected by VLESS *presence* (not REALITY);
- the http adapter (require_reality=False) provisions/revokes clients into the
  XHTTP inbound (never vless-in) and never touches REALITY shortIds;
- the legacy REALITY-only adapter would reject that inbound (the original bug);
- the TCP adapter on vless-in is unaffected (flow + managed shortIds).
"""

import asyncio
import json
from pathlib import Path

import pytest

from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import XrayInboundNotFoundError
from adapters.xray_config import (
    XrayConfigAdapter,
    vless_inbound_present,
    vless_reality_inbound_present,
)
from models.dto import ShellResult

TCP_TAG = "vless-in"
XHTTP_TAG = "vless-xhttp-reality"
VLESS_IN_SHORT_ID = "ff69b6f523de0d17"
XHTTP_PATH = "/v1/messages/stream"


class _XraySystemctl:
    """Minimal stand-in: config-test always passes, reload succeeds, service active."""

    async def xray_test_config(self, path: Path) -> ShellResult:
        json.loads(path.read_text(encoding="utf-8"))
        return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

    async def reload(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "reload", service_name), 0, "", "")

    async def restart(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "restart", service_name), 0, "", "")

    async def is_active(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")


def _write_server_config(path: Path) -> None:
    """config.json mirroring the server: REALITY vless-in + fallback XHTTP dest."""
    path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": TCP_TAG,
                        "port": 443,
                        "protocol": "vless",
                        "settings": {
                            "clients": [],
                            # DEFAULT catch-all fallback (no "path"): a path-based VLESS
                            # fallback does not match h2 XHTTP, so the working topology
                            # routes all fall-through REALITY traffic to the loopback
                            # XHTTP dest and validates the path on that inbound.
                            "fallbacks": [{"dest": 8001, "xver": 0}],
                        },
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {
                                "serverNames": ["googletagmanager.com"],
                                "shortIds": [VLESS_IN_SHORT_ID],
                            },
                        },
                    },
                    {
                        "tag": XHTTP_TAG,
                        "listen": "127.0.0.1",
                        "port": 8001,
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "none",
                            "network": "xhttp",
                            "xhttpSettings": {"path": XHTTP_PATH, "mode": "auto"},
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def _adapter(path: Path, tag: str, *, require_reality: bool) -> XrayConfigAdapter:
    return XrayConfigAdapter(
        config_path=path,
        service_name="xray",
        apply_mode="reload",
        inbound_tag=tag,
        allow_restart_on_rollback=False,
        backup=BackupAdapter(ClockProvider(), keep_last=0),
        systemctl=_XraySystemctl(),  # type: ignore[arg-type]
        require_reality=require_reality,
    )


def _inbound(path: Path, tag: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return next(i for i in data["inbounds"] if i["tag"] == tag)


def test_xhttp_dest_detected_by_vless_presence_not_reality(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    _write_server_config(config_path)

    # The security:none XHTTP dest is detected by VLESS presence...
    assert vless_inbound_present(config_path, XHTTP_TAG) is True
    # ...but NOT by the REALITY-only probe (this is exactly why http keys broke).
    assert vless_reality_inbound_present(config_path, XHTTP_TAG) is False
    # vless-in is still a REALITY inbound.
    assert vless_reality_inbound_present(config_path, TCP_TAG) is True


def test_legacy_reality_adapter_rejects_the_xhttp_dest(tmp_path: Path) -> None:
    """A require_reality=True adapter on the XHTTP tag fails — the original bug."""
    config_path = tmp_path / "config.json"
    _write_server_config(config_path)
    legacy = _adapter(config_path, XHTTP_TAG, require_reality=True)
    with pytest.raises(XrayInboundNotFoundError):
        legacy.find_client(uuid_value="whatever")
    # list_short_ids on the relaxed adapter never raises (no REALITY there).
    assert _adapter(config_path, XHTTP_TAG, require_reality=False).list_short_ids() == set()


def test_http_provision_and_revoke_target_xhttp_inbound_only(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "config.json"
        _write_server_config(config_path)
        http = _adapter(config_path, XHTTP_TAG, require_reality=False)

        # Provision: UUID goes into vless-xhttp-reality.clients[], flowless, and the
        # vless-in REALITY shortIds are NOT touched (manage_short_id=False).
        await http.add_client(
            uuid_value="11111111-1111-4111-8111-111111111111",
            email_label="xray_AHTTP",
            short_id=VLESS_IN_SHORT_ID,
            flow="",
            manage_short_id=False,
        )
        xhttp_clients = _inbound(config_path, XHTTP_TAG)["settings"]["clients"]
        assert [c["id"] for c in xhttp_clients] == ["11111111-1111-4111-8111-111111111111"]
        assert "flow" not in xhttp_clients[0]
        # vless-in untouched: no clients added, shortIds unchanged.
        vless_in = _inbound(config_path, TCP_TAG)
        assert vless_in["settings"]["clients"] == []
        assert vless_in["streamSettings"]["realitySettings"]["shortIds"] == [VLESS_IN_SHORT_ID]
        assert http.find_client(uuid_value="11111111-1111-4111-8111-111111111111") is not None

        # Revoke: UUID removed from vless-xhttp-reality.clients[].
        await http.remove_client(
            uuid_value="11111111-1111-4111-8111-111111111111",
            email_label="xray_AHTTP",
            short_id=None,
            remove_short_id=False,
        )
        assert _inbound(config_path, XHTTP_TAG)["settings"]["clients"] == []

    asyncio.run(run())


def test_tcp_provision_unchanged_on_vless_in(tmp_path: Path) -> None:
    """The TCP adapter still adds flow + manages REALITY shortIds on vless-in."""

    async def run() -> None:
        config_path = tmp_path / "config.json"
        _write_server_config(config_path)
        tcp = _adapter(config_path, TCP_TAG, require_reality=True)

        await tcp.add_client(
            uuid_value="22222222-2222-4222-8222-222222222222",
            email_label="xray_ATCP",
            short_id="aabbccddeeff0011",
            flow="xtls-rprx-vision",
            manage_short_id=True,
        )
        vless_in = _inbound(config_path, TCP_TAG)
        clients = vless_in["settings"]["clients"]
        assert [c["id"] for c in clients] == ["22222222-2222-4222-8222-222222222222"]
        assert clients[0]["flow"] == "xtls-rprx-vision"
        assert set(vless_in["streamSettings"]["realitySettings"]["shortIds"]) == {
            VLESS_IN_SHORT_ID,
            "aabbccddeeff0011",
        }
        # The XHTTP dest is untouched by a TCP provision.
        assert _inbound(config_path, XHTTP_TAG)["settings"]["clients"] == []

    asyncio.run(run())


def test_rename_clients_renames_by_uuid_and_is_idempotent(tmp_path: Path) -> None:
    """rename_clients changes only emails (by UUID); a matching mapping is a no-op."""

    async def run() -> None:
        config_path = tmp_path / "config.json"
        _write_server_config(config_path)
        http = _adapter(config_path, XHTTP_TAG, require_reality=False)
        uuid = "11111111-1111-4111-8111-111111111111"
        await http.add_client(
            uuid_value=uuid,
            email_label="xray_AHTTP",
            short_id=VLESS_IN_SHORT_ID,
            flow="",
            manage_short_id=False,
        )

        # Rename to the new transport/profile scheme: email changes, UUID preserved.
        renamed = await http.rename_clients({uuid: "xray_http_base_Ab3dE"})
        assert renamed == 1
        clients = _inbound(config_path, XHTTP_TAG)["settings"]["clients"]
        assert clients[0]["id"] == uuid
        assert clients[0]["email"] == "xray_http_base_Ab3dE"

        # Idempotent no-op once the email already matches (nothing to apply).
        assert await http.rename_clients({uuid: "xray_http_base_Ab3dE"}) == 0
        # Unknown UUIDs are ignored.
        assert await http.rename_clients({"does-not-exist": "xray_http_base_Zzzzz"}) == 0
        # Empty mapping is a no-op.
        assert await http.rename_clients({}) == 0

    asyncio.run(run())


class _RecordingSystemctl(_XraySystemctl):
    """Records reload/restart calls (reload can be made to fail) for apply-path tests."""

    def __init__(self, *, reload_ok: bool = True) -> None:
        self.calls: list[str] = []
        self.reload_ok = reload_ok

    async def reload(self, service_name: str) -> ShellResult:
        self.calls.append("reload")
        return ShellResult(("systemctl", "reload", service_name), 0 if self.reload_ok else 1, "", "")

    async def restart(self, service_name: str) -> ShellResult:
        self.calls.append("restart")
        return ShellResult(("systemctl", "restart", service_name), 0, "", "")


class _RecordingShell:
    """Captures shell invocations and replays a fixed statsquery payload."""

    def __init__(self, payload: str = "") -> None:
        self.payload = payload
        self.calls: list[tuple[str, ...]] = []

    async def run(self, args: list[str], **kwargs: object) -> ShellResult:
        self.calls.append(tuple(args))
        return ShellResult(tuple(args), 0, self.payload, "")


def _adapter_with(
    path: Path,
    tag: str,
    *,
    require_reality: bool,
    systemctl: object,
    shell: object | None = None,
    stats_server: str = "",
) -> XrayConfigAdapter:
    return XrayConfigAdapter(
        config_path=path,
        service_name="xray",
        apply_mode="reload",
        inbound_tag=tag,
        allow_restart_on_rollback=False,
        backup=BackupAdapter(ClockProvider(), keep_last=0),
        systemctl=systemctl,  # type: ignore[arg-type]
        shell=shell,  # type: ignore[arg-type]
        stats_server=stats_server,
        require_reality=require_reality,
    )


def test_rename_clients_prefer_restart_routes_through_restart_not_reload(tmp_path: Path) -> None:
    """prefer_restart applies the rename via `systemctl restart`, default via `reload`."""

    async def run() -> None:
        config_path = tmp_path / "config.json"
        _write_server_config(config_path)
        sysctl = _RecordingSystemctl()
        http = _adapter_with(config_path, XHTTP_TAG, require_reality=False, systemctl=sysctl)
        uuid = "11111111-1111-4111-8111-111111111111"
        await http.add_client(
            uuid_value=uuid, email_label="xray_AHTTP",
            short_id=VLESS_IN_SHORT_ID, flow="", manage_short_id=False,
        )

        sysctl.calls.clear()  # ignore the provision apply; focus on the rename
        renamed = await http.rename_clients({uuid: "xray_http_base_Ab3dE"}, prefer_restart=True)
        assert renamed == 1
        # The unit's reload does not rebuild clients, so prefer_restart restarts instead.
        assert sysctl.calls == ["restart"]
        assert _inbound(config_path, XHTTP_TAG)["settings"]["clients"][0]["email"] == "xray_http_base_Ab3dE"

        # Idempotent no-op: nothing to apply, so neither restart nor reload runs.
        sysctl.calls.clear()
        assert await http.rename_clients({uuid: "xray_http_base_Ab3dE"}, prefer_restart=True) == 0
        assert sysctl.calls == []

        # Default path (no prefer_restart) still applies through reload.
        sysctl.calls.clear()
        assert await http.rename_clients({uuid: "xray_AHTTP"}) == 1
        assert sysctl.calls == ["reload"]

    asyncio.run(run())


def test_rename_clients_prefer_restart_verifies_runtime_via_statsquery(tmp_path: Path) -> None:
    """After the restart rename the runtime is checked against `xray api statsquery`."""

    async def run() -> None:
        config_path = tmp_path / "config.json"
        _write_server_config(config_path)
        uuid = "11111111-1111-4111-8111-111111111111"
        sysctl = _RecordingSystemctl()
        provisioner = _adapter_with(config_path, XHTTP_TAG, require_reality=False, systemctl=sysctl)
        await provisioner.add_client(
            uuid_value=uuid, email_label="xray_AHTTP",
            short_id=VLESS_IN_SHORT_ID, flow="", manage_short_id=False,
        )

        # statsquery reports the renamed label -> verification finds the live counter.
        payload = json.dumps({
            "stat": [
                {"name": "user>>>xray_http_base_Ab3dE>>>traffic>>>downlink", "value": 0},
                {"name": "user>>>xray_http_base_Ab3dE>>>traffic>>>uplink", "value": 0},
            ]
        })
        shell = _RecordingShell(payload)
        http = _adapter_with(
            config_path, XHTTP_TAG, require_reality=False,
            systemctl=sysctl, shell=shell, stats_server="127.0.0.1:10085",
        )
        assert await http.rename_clients({uuid: "xray_http_base_Ab3dE"}, prefer_restart=True) == 1
        # The restart-applied rename is verified by polling the live stats API.
        assert any(call[:3] == ("xray", "api", "statsquery") for call in shell.calls)

    asyncio.run(run())
