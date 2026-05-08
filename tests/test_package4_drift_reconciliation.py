from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.xray_config import XrayConfigAdapter
from config.settings import Settings
from db.database import Database
from models.dto import ShellResult, TelegramUserProfile, User, VpnKey
from models.enums import AuditEntityType, ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.errors import InvalidOperation
from services.xray import XrayService


VALID_AWG_PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="",
        xray_public_host="vpn.example.com",
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=True,
        xray_allow_restart_on_rollback=False,
        xray_stats_server="",
        awg_config_path=tmp_path / "awg.conf",
        awg_interface="awg0",
        awg_network="10.0.0.0/24",
        awg_server_address="10.0.0.1",
        awg_endpoint_host="vpn.example.com",
        awg_endpoint_port=443,
        awg_server_public_key="server-public",
        awg_client_dns="1.1.1.1",
        awg_mtu=None,
        awg_allowed_ips="0.0.0.0/0, ::/0",
        awg_persistent_keepalive=25,
        awg_use_preshared_key=True,
        default_proxy_type="",
        default_proxy_host="",
        default_proxy_port=None,
        default_proxy_login="",
        default_proxy_password="",
        default_proxy_note="",
        audit_retention_days=180,
        config_backup_keep_last=20,
    )
    values.update(overrides)
    return Settings(**values)


def _write_xray_config(path: Path, *, clients: list[dict[str, object]] | None = None, short_ids: list[str] | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "vless",
                        "settings": {"clients": list(clients or [])},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"shortIds": list(short_ids or [])},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_awg_config(path: Path, peer_blocks: str = "") -> None:
    path.write_text(
        f"""
[Interface]
PrivateKey = server-private
Address = 10.0.0.1/24
ListenPort = 443
PublicKey = server-public
{peer_blocks}
""".lstrip(),
        encoding="utf-8",
    )


def _managed_awg_peer(key_id: int, public_key: str, client_ip: str, *, label: str = "awg_A7kQz", owner: int = 100) -> str:
    return f"""
# vpn-bot peer start key_id={key_id} owner={owner} label={label}
[Peer]
PublicKey = {public_key}
AllowedIPs = {client_ip}/32
# vpn-bot peer end key_id={key_id}
"""


def _manual_awg_peer(public_key: str, client_ip: str) -> str:
    return f"""
[Peer]
PublicKey = {public_key}
AllowedIPs = {client_ip}/32
"""


class _XraySystemctl:
    def __init__(self, *, fail_reload: bool = False) -> None:
        self.fail_reload = fail_reload

    async def xray_test_config(self, path: Path) -> ShellResult:
        json.loads(path.read_text(encoding="utf-8"))
        return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

    async def reload(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "reload", service_name), 1 if self.fail_reload else 0, "", "reload failed")

    async def restart(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "restart", service_name), 0, "", "")

    async def is_active(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")


class _AwgShell:
    def __init__(self, runtime: dict[str, str] | None = None, *, fail_remove: bool = False) -> None:
        self.runtime = dict(runtime or {})
        self.fail_remove = fail_remove

    async def run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 15.0,
        sensitive_values: list[str] | None = None,
        max_output_chars: int | None = None,
    ) -> ShellResult:
        if args[:2] == ["awg-quick", "strip"]:
            return ShellResult(tuple(args), 0, Path(args[2]).read_text(encoding="utf-8"), "")
        if args[:2] == ["awg", "show"]:
            return ShellResult(tuple(args), 0, self._show_output(), "")
        if args[:4] == ["awg", "set", "awg0", "peer"]:
            public_key = args[4]
            if args[-1] == "remove":
                if self.fail_remove:
                    return ShellResult(tuple(args), 1, "", "remove failed")
                self.runtime.pop(public_key, None)
                return ShellResult(tuple(args), 0, "", "")
            allowed_ip = args[args.index("allowed-ips") + 1]
            self.runtime[public_key] = allowed_ip
            return ShellResult(tuple(args), 0, "", "")
        if args[:3] == ["awg", "syncconf", "awg0"]:
            self.runtime = self._peers_from_config(Path(args[3]).read_text(encoding="utf-8"))
            return ShellResult(tuple(args), 0, "", "")
        return ShellResult(tuple(args), 127, "", "command not found")

    def _show_output(self) -> str:
        lines = ["interface: awg0", "  public key: server-public"]
        for public_key, allowed_ip in self.runtime.items():
            lines.extend(["", f"peer: {public_key}", f"  allowed ips: {allowed_ip}"])
        return "\n".join(lines)

    def _peers_from_config(self, text: str) -> dict[str, str]:
        peers: dict[str, str] = {}
        current_public_key: str | None = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line == "[Peer]":
                current_public_key = None
                continue
            if "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key == "PublicKey":
                current_public_key = value
            elif key == "AllowedIPs" and current_public_key:
                peers[current_public_key] = value
        return peers


class _Audit:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    async def write(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    async def write_best_effort(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    @property
    def actions(self) -> list[str]:
        return [str(item["action"]) for item in self.items]


class _Users:
    user_locks = None

    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    async def require_superadmin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


async def _repo(tmp_path: Path) -> tuple[Database, VpnKeyRepository]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
    return db, VpnKeyRepository(db)


async def _xray_key(repo: VpnKeyRepository, status: VpnKeyStatus, *, key_id_suffix: str = "001") -> VpnKey:
    uuid_value = f"00000000-0000-4000-8000-000000000{key_id_suffix}"
    email_label = f"xray_A7k{key_id_suffix[-2:]}"
    payload = {
        "uuid": uuid_value,
        "email_label": email_label,
        "short_id": "abcd",
        "short_id_managed": True,
        "flow": "xtls-rprx-vision",
    }
    key = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        note=None,
        payload=payload,
        public_payload={"email_label": email_label, "short_id": "abcd"},
        created_by=100,
        now="now",
        uuid=uuid_value,
        email_label=email_label,
    )
    await repo.mark_active(key.id, "active", payload=payload, public_payload={"email_label": email_label, "short_id": "abcd"})
    if status == VpnKeyStatus.REVOKED:
        await repo.mark_revoked(key.id, 100, "revoked")
    elif status != VpnKeyStatus.ACTIVE:
        await repo.set_status(key.id, status, "status")
    refreshed = await repo.get_by_id(key.id)
    assert refreshed is not None
    return refreshed


async def _awg_key(repo: VpnKeyRepository, status: VpnKeyStatus, *, public_key: str = "public-active", client_ip: str = "10.0.0.2") -> VpnKey:
    payload = {
        "private_key": VALID_AWG_PRIVATE_KEY,
        "public_key": public_key,
        "preshared_key": "super-secret-psk",
        "client_ip": client_ip,
        "email_label": "awg_A7kQz",
    }
    key = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.AWG,
        note=None,
        payload=payload,
        public_payload={"public_key": public_key, "client_ip": client_ip, "email_label": "awg_A7kQz"},
        created_by=100,
        now="now",
        email_label="awg_A7kQz",
        public_key=public_key,
        client_ip=client_ip,
    )
    await repo.mark_active(key.id, "active", payload=payload, public_payload=key.public_payload)
    if status == VpnKeyStatus.REVOKED:
        await repo.mark_revoked(key.id, 100, "revoked")
    elif status != VpnKeyStatus.ACTIVE:
        await repo.set_status(key.id, status, "status")
    refreshed = await repo.get_by_id(key.id)
    assert refreshed is not None
    return refreshed


def _xray_service(
    tmp_path: Path,
    repo: object,
    adapter: object,
    audit: _Audit,
    health: BackendHealth | None = None,
) -> XrayService:
    return XrayService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=SimpleNamespace(uuid4=lambda: "00000000-0000-4000-8000-000000000999", xray_short_id=lambda: "abcd", generated_key_name=lambda prefix: f"{prefix}_A7kQz"),  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        backend_health=health,
    )


def _awg_service(
    tmp_path: Path,
    repo: object,
    adapter: object,
    audit: _Audit,
    health: BackendHealth | None = None,
) -> AwgService:
    return AwgService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        backend_health=health,
    )


def _xray_adapter(path: Path, *, fail_reload: bool = False) -> XrayConfigAdapter:
    return XrayConfigAdapter(
        config_path=path,
        service_name="xray",
        apply_mode="reload",
        inbound_tag="",
        allow_restart_on_rollback=False,
        backup=BackupAdapter(ClockProvider(), keep_last=0),
        systemctl=_XraySystemctl(fail_reload=fail_reload),  # type: ignore[arg-type]
    )


def _awg_adapter(path: Path, shell: _AwgShell) -> AwgConfigAdapter:
    return AwgConfigAdapter(
        config_path=path,
        interface="awg0",
        backup=BackupAdapter(ClockProvider(), keep_last=0),
        shell=shell,  # type: ignore[arg-type]
        persistent_keepalive=25,
    )


def test_xray_active_db_key_missing_from_config_is_restored(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "xray.json"
        _write_xray_config(config_path)
        db, repo = await _repo(tmp_path)
        try:
            key = await _xray_key(repo, VpnKeyStatus.ACTIVE)
            audit = _Audit()
            service = _xray_service(tmp_path, repo, _xray_adapter(config_path), audit)

            summary = await service.startup_reconcile()

            client = _xray_adapter(config_path).find_client(uuid_value=key.uuid, email_label=key.email_label)
            assert client is not None
            assert summary["recovered"] == 1
            assert "xray_startup_active_restored" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_xray_revoked_key_present_in_config_is_removed(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            key = await _xray_key(repo, VpnKeyStatus.REVOKED)
            config_path = tmp_path / "xray.json"
            _write_xray_config(config_path, clients=[{"id": key.uuid, "email": key.email_label}], short_ids=["abcd"])
            audit = _Audit()
            service = _xray_service(tmp_path, repo, _xray_adapter(config_path), audit)

            await service.startup_reconcile()

            assert _xray_adapter(config_path).list_clients() == []
            assert "xray_startup_non_live_removed" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_xray_bot_managed_orphan_is_removed_and_manual_orphan_degrades(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            config_path = tmp_path / "xray.json"
            _write_xray_config(
                config_path,
                clients=[
                    {"id": "00000000-0000-4000-8000-000000000111", "email": "xray_A7kQz"},
                    {"id": "00000000-0000-4000-8000-000000000222", "email": "manual-client"},
                ],
            )
            health = BackendHealth()
            audit = _Audit()
            service = _xray_service(tmp_path, repo, _xray_adapter(config_path), audit, health)

            await service.startup_reconcile()

            clients = _xray_adapter(config_path).list_clients()
            assert [client["email"] for client in clients] == ["manual-client"]
            with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
                health.require_mutation_allowed(VpnKeyType.XRAY)
            assert "xray_startup_orphan_removed" in audit.actions
            assert "xray_startup_drift_degraded" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_xray_orphan_removal_apply_failure_degrades_without_leaking_uuid(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            orphan_uuid = "00000000-0000-4000-8000-000000000333"
            config_path = tmp_path / "xray.json"
            _write_xray_config(config_path, clients=[{"id": orphan_uuid, "email": "xray_B7kQz"}])
            health = BackendHealth()
            audit = _Audit()
            service = _xray_service(tmp_path, repo, _xray_adapter(config_path, fail_reload=True), audit, health)

            summary = await service.startup_reconcile()

            assert summary["failed"] == 1
            with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
                health.require_mutation_allowed(VpnKeyType.XRAY)
            assert orphan_uuid not in str(audit.items)
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_active_db_key_missing_from_config_and_runtime_is_restored_without_secret_audit(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "awg.conf"
        _write_awg_config(config_path)
        shell = _AwgShell()
        db, repo = await _repo(tmp_path)
        try:
            key = await _awg_key(repo, VpnKeyStatus.ACTIVE)
            audit = _Audit()
            service = _awg_service(tmp_path, repo, _awg_adapter(config_path, shell), audit)

            summary = await service.startup_reconcile()

            assert summary["recovered"] == 1
            assert shell.runtime == {key.public_key: f"{key.client_ip}/32"}
            assert "PublicKey = public-active" in config_path.read_text(encoding="utf-8")
            assert "awg_startup_active_restored" in audit.actions
            assert VALID_AWG_PRIVATE_KEY not in str(audit.items)
            assert "super-secret-psk" not in str(audit.items)
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_revoked_peer_present_in_config_and_runtime_is_removed(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            key = await _awg_key(repo, VpnKeyStatus.REVOKED, public_key="public-revoked", client_ip="10.0.0.3")
            config_path = tmp_path / "awg.conf"
            _write_awg_config(config_path, _managed_awg_peer(key.id, "public-revoked", "10.0.0.3"))
            shell = _AwgShell({"public-revoked": "10.0.0.3/32"})
            audit = _Audit()
            service = _awg_service(tmp_path, repo, _awg_adapter(config_path, shell), audit)

            await service.startup_reconcile()

            assert "public-revoked" not in config_path.read_text(encoding="utf-8")
            assert shell.runtime == {}
            assert "awg_startup_non_live_removed" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_bot_managed_orphan_removed_and_manual_orphan_degrades(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            config_path = tmp_path / "awg.conf"
            _write_awg_config(
                config_path,
                _managed_awg_peer(999, "public-managed-orphan", "10.0.0.8")
                + _manual_awg_peer("public-manual", "10.0.0.9"),
            )
            shell = _AwgShell({"public-managed-orphan": "10.0.0.8/32", "public-manual": "10.0.0.9/32"})
            health = BackendHealth()
            audit = _Audit()
            service = _awg_service(tmp_path, repo, _awg_adapter(config_path, shell), audit, health)

            await service.startup_reconcile()

            text = config_path.read_text(encoding="utf-8")
            assert "public-managed-orphan" not in text
            assert "public-manual" in text
            with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
                health.require_mutation_allowed(VpnKeyType.AWG)
            assert "awg_startup_orphan_removed" in audit.actions
            assert "awg_startup_drift_degraded" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_config_runtime_mismatch_is_synced_from_safe_config(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            key = await _awg_key(repo, VpnKeyStatus.ACTIVE, public_key="public-sync", client_ip="10.0.0.4")
            config_path = tmp_path / "awg.conf"
            _write_awg_config(config_path, _managed_awg_peer(key.id, "public-sync", "10.0.0.4"))
            shell = _AwgShell()
            audit = _Audit()
            service = _awg_service(tmp_path, repo, _awg_adapter(config_path, shell), audit)

            await service.startup_reconcile()

            assert shell.runtime == {"public-sync": "10.0.0.4/32"}
            assert "awg_startup_runtime_synced" in audit.actions
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_orphan_removal_failure_degrades_backend(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            config_path = tmp_path / "awg.conf"
            _write_awg_config(config_path, _managed_awg_peer(999, "public-remove-fails", "10.0.0.10"))
            shell = _AwgShell({"public-remove-fails": "10.0.0.10/32"}, fail_remove=True)
            health = BackendHealth()
            audit = _Audit()
            service = _awg_service(tmp_path, repo, _awg_adapter(config_path, shell), audit, health)

            summary = await service.startup_reconcile()

            assert summary["failed"] == 1
            with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
                health.require_mutation_allowed(VpnKeyType.AWG)
            assert "public-remove-fails" not in str(audit.items)
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_degraded_vpn_backend_blocks_create_revoke_delete_and_reconcile_only_for_that_backend(
    tmp_path: Path,
    key_type: VpnKeyType,
) -> None:
    health = BackendHealth()
    health.mark_degraded(key_type, "test degraded")
    audit = _Audit()
    xray = _xray_service(tmp_path, object(), object(), audit, health)
    awg = _awg_service(tmp_path, object(), object(), audit, health)

    if key_type == VpnKeyType.XRAY:
        with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
            asyncio.run(xray.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None))
        with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
            asyncio.run(xray.revoke_xray_key(1, 1))
        with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
            asyncio.run(xray.delete_xray_key(1, 1))
        with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
            asyncio.run(xray.reconcile_key_status(1, 1))
        health.require_mutation_allowed(VpnKeyType.AWG)
    else:
        with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
            asyncio.run(awg.create_awg_key(100, TelegramUserProfile(100, "user", "User"), None))
        with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
            asyncio.run(awg.revoke_awg_key(1, 1))
        with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
            asyncio.run(awg.delete_awg_key(1, 1))
        with pytest.raises(InvalidOperation, match="AWG-операции временно заблокированы"):
            asyncio.run(awg.reconcile_key_status(1, 1))
        health.require_mutation_allowed(VpnKeyType.XRAY)

    health.require_mutation_allowed(ProxyAccessType.SOCKS5)
    health.require_mutation_allowed(ProxyAccessType.MTPROTO)
