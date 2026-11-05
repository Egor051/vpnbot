"""Tests for the off-site system bundle (host-level state).

The system bundle is a THIRD encrypted artifact sent alongside the ``*.db.enc`` DB
backup and the ``vpnbot_recovery_*`` bundle, through the same loop and under the
same Fernet key. These tests cover what it adds over the recovery bundle —
directory walking, symlinks stored as targets, the policy exclusions (the hard SSH
host-key policy and the configurable OFFSITE_BACKUP_SYSTEM_EXCLUDE set), the size
guardrails and the manifest summary — plus the delivery glue and the guarantee that
the two pre-existing artifacts are untouched by it.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import tarfile
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from adapters.clock import ClockProvider
from config.settings import (
    DEFAULT_OFFSITE_SYSTEM_EXCLUDE,
    DEFAULT_OFFSITE_SYSTEM_PATHS,
    SettingsError,
    load_settings,
)
from services.offsite_backup import OffsiteBackupService, offsite_backup_loop


def _make_service(
    *,
    system_sources: list[Path] | tuple[Path, ...] = (),
    recovery_sources: list[Path] | tuple[Path, ...] = (),
    include_system: bool = True,
    include_recovery: bool = False,
    encryption_key: str | None = None,
    system_exclude: list[str] | tuple[str, ...] = (),
) -> OffsiteBackupService:
    key = encryption_key if encryption_key is not None else Fernet.generate_key().decode()
    return OffsiteBackupService(
        db=object(),  # type: ignore[arg-type]  # the bundle path never touches the DB
        db_path=Path("/nonexistent/vpn.db"),
        encryption_key=key,
        clock=ClockProvider(),
        recovery_sources=recovery_sources,
        include_recovery=include_recovery,
        system_sources=system_sources,
        include_system=include_system,
        system_exclude=system_exclude,
    )


def _extract(service: OffsiteBackupService, encrypted: bytes) -> tuple[dict, dict[str, bytes]]:
    raw = service.decrypt_backup(encrypted)
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar.getmembers():
            extracted = tar.extractfile(member)
            members[member.name] = extracted.read() if extracted is not None else b""
    return json.loads(members["MANIFEST.json"]), members


def _by_path(manifest: dict) -> dict[str, dict]:
    return {entry["path"]: entry for entry in manifest["files"]}


class FakeBot:
    def __init__(self, fail_for: frozenset[int] = frozenset()) -> None:
        self.documents: list[tuple[int, bytes, str]] = []
        self._fail_for = fail_for

    async def send_document(self, chat_id, *, document, caption=None):  # noqa: ANN001
        if chat_id in self._fail_for:
            raise RuntimeError("send failed")
        self.documents.append((chat_id, document.data, document.filename))


@pytest.mark.asyncio
async def test_system_bundle_walks_directories_and_roundtrips(tmp_path: Path) -> None:
    etc = tmp_path / "etc"
    (etc / "nginx" / "conf.d").mkdir(parents=True)
    (etc / "nginx" / "conf.d" / "selfsteal.conf").write_text("server {}", encoding="utf-8")
    (etc / "nginx" / "conf.d" / "api.conf").write_text("server { listen 8443; }", encoding="utf-8")
    (etc / "passwd").write_text("hysteria:x:992:992::/var/lib/hysteria:/usr/sbin/nologin\n", encoding="utf-8")

    service = _make_service(system_sources=[etc / "nginx" / "conf.d", etc / "passwd"])
    built = await service.create_system_bundle()
    assert built is not None
    encrypted, filename = built
    assert filename.startswith("vpnbot_system_")
    assert filename.endswith(".tar.gz.enc")

    manifest, members = _extract(service, encrypted)
    by_path = _by_path(manifest)
    # The directory source expanded into both of its files, and the file source came
    # through unchanged.
    for expected in (
        etc / "nginx" / "conf.d" / "selfsteal.conf",
        etc / "nginx" / "conf.d" / "api.conf",
        etc / "passwd",
    ):
        assert by_path[str(expected)]["included"] is True
        assert by_path[str(expected)]["kind"] == "file"

    for entry in manifest["files"]:
        if entry["kind"] != "file" or not entry["included"]:
            continue
        member = entry["member"]
        assert member.startswith("files/")
        assert ".." not in member
        assert members[member] == Path(entry["path"]).read_bytes()


@pytest.mark.asyncio
async def test_system_bundle_manifest_summary_counts(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    root.mkdir()
    (root / "a.conf").write_text("a", encoding="utf-8")
    (root / "b.conf").write_text("bb", encoding="utf-8")
    (root / "link.conf").symlink_to(root / "a.conf")
    missing = tmp_path / "absent.conf"

    service = _make_service(system_sources=[root, missing])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, _ = _extract(service, built[0])

    summary = manifest["summary"]
    # The summary is what makes a silently-degraded bundle visible at a glance, so
    # its counters must match the per-file list exactly.
    assert summary["files_included"] == 2
    assert summary["files_skipped"] == 1  # the missing source
    assert summary["symlinks"] == 1
    assert summary["bytes_included"] == 3  # "a" + "bb"
    assert summary["truncated"] is False
    assert summary["sources"] == [str(root), str(missing)]
    assert summary["skipped_by_reason"] == {"FileNotFoundError": 1}


@pytest.mark.asyncio
async def test_system_bundle_records_symlink_target_not_content(tmp_path: Path) -> None:
    units = tmp_path / "system"
    wants = units / "multi-user.target.wants"
    wants.mkdir(parents=True)
    real_unit = units / "xray.service"
    real_unit.write_text("[Service]\nExecStart=/usr/local/bin/xray\n", encoding="utf-8")
    (wants / "xray.service").symlink_to(real_unit)

    service = _make_service(system_sources=[units])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    link = by_path[str(wants / "xray.service")]
    # Enablement is the information here: the link is stored as its target so unit
    # content is not duplicated once per *.wants entry.
    assert link["kind"] == "symlink"
    assert link["target"] == str(real_unit)
    assert "member" not in link
    assert by_path[str(real_unit)]["kind"] == "file"
    assert members["files/" + str(real_unit).lstrip("/")] == real_unit.read_bytes()


@pytest.mark.asyncio
async def test_system_bundle_does_not_follow_symlinked_directory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "keep.conf").write_text("keep", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.conf").write_text("secret", encoding="utf-8")
    (root / "loop").symlink_to(root)  # a self-referential link must not hang the walk
    (root / "elsewhere").symlink_to(outside)

    service = _make_service(system_sources=[root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    assert by_path[str(root / "loop")]["kind"] == "symlink"
    assert by_path[str(root / "elsewhere")]["kind"] == "symlink"
    # Not descended into: the linked-to tree contributes no member.
    assert all("secret.conf" not in name for name in members)


@pytest.mark.asyncio
async def test_system_bundle_excludes_ssh_host_private_keys(tmp_path: Path) -> None:
    ssh = tmp_path / "ssh"
    ssh.mkdir()
    (ssh / "sshd_config").write_text("PermitRootLogin prohibit-password\n", encoding="utf-8")
    (ssh / "ssh_host_ed25519_key").write_text("PRIVATE", encoding="utf-8")
    (ssh / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA", encoding="utf-8")

    service = _make_service(system_sources=[ssh])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    private = by_path[str(ssh / "ssh_host_ed25519_key")]
    # Kept out on purpose, but still NAMED in the manifest — an omission nobody can
    # see is the failure mode this whole bundle exists to fix.
    assert private["included"] is False
    assert private["reason"] == "excluded_by_policy"
    assert all(b"PRIVATE" not in data for data in members.values())
    # The public side, which is what actually prevents a lockout, is bundled.
    assert by_path[str(ssh / "sshd_config")]["included"] is True
    assert by_path[str(ssh / "ssh_host_ed25519_key.pub")]["included"] is True


@pytest.mark.asyncio
async def test_system_bundle_skips_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real ceilings are megabytes; shrink them so the test costs no disk.
    monkeypatch.setattr("services.offsite_backup._SYSTEM_MAX_FILE_BYTES", 16)
    root = tmp_path / "etc"
    root.mkdir()
    small = root / "small.conf"
    small.write_text("ok", encoding="utf-8")
    big = root / "big.bin"
    big.write_bytes(b"\0" * 17)

    service = _make_service(system_sources=[root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    assert by_path[str(big)]["included"] is False
    assert by_path[str(big)]["reason"] == "too_large"
    assert by_path[str(big)]["size"] == 17
    assert by_path[str(small)]["included"] is True
    assert manifest["summary"]["truncated"] is True
    assert all("big.bin" not in name for name in members)


@pytest.mark.asyncio
async def test_system_bundle_stops_at_total_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("services.offsite_backup._SYSTEM_MAX_TOTAL_BYTES", 10)
    root = tmp_path / "etc"
    root.mkdir()
    # The walk visits files in sorted order, so this is deterministic: 1.bin fits,
    # 2.bin would push the running total past the ceiling.
    (root / "1.bin").write_bytes(b"\0" * 8)
    (root / "2.bin").write_bytes(b"\0" * 8)

    service = _make_service(system_sources=[root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    summary = manifest["summary"]
    assert summary["truncated"] is True
    assert summary["bytes_included"] == 8
    assert by_path[str(root / "1.bin")]["included"] is True
    assert by_path[str(root / "2.bin")]["reason"] == "bundle_size_limit"
    assert all("2.bin" not in name for name in members)


@pytest.mark.asyncio
async def test_system_bundle_skips_unreadable_file_best_effort(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    root.mkdir()
    readable = root / "ok.conf"
    readable.write_text("ok", encoding="utf-8")
    locked = root / "locked.conf"
    locked.write_text("nope", encoding="utf-8")
    locked.chmod(0o000)

    if os.geteuid() == 0:
        pytest.skip("root ignores file modes, so this cannot be made unreadable here")

    service = _make_service(system_sources=[root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    assert by_path[str(readable)]["included"] is True
    assert by_path[str(locked)]["included"] is False
    assert "reason" in by_path[str(locked)]
    assert all("locked.conf" not in name for name in members)


@pytest.mark.asyncio
async def test_system_bundle_none_when_nothing_readable(tmp_path: Path) -> None:
    service = _make_service(system_sources=[tmp_path / "a", tmp_path / "b"])
    assert await service.create_system_bundle() is None


@pytest.mark.asyncio
async def test_system_bundle_dedupes_overlapping_sources(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    root.mkdir()
    inner = root / "x.conf"
    inner.write_text("data", encoding="utf-8")

    # A directory source plus a file inside it: the expanded set must still yield one
    # entry, or the tar would carry the same member name twice.
    service = _make_service(system_sources=[root, inner, root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, _ = _extract(service, built[0])
    assert sum(1 for e in manifest["files"] if e["path"] == str(inner)) == 1


@pytest.mark.asyncio
async def test_system_bundle_prunes_noise_directories(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    (root / "__pycache__").mkdir(parents=True)
    (root / "__pycache__" / "junk.pyc").write_bytes(b"junk")
    (root / "real.conf").write_text("real", encoding="utf-8")

    service = _make_service(system_sources=[root])
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])

    assert all("junk.pyc" not in name for name in members)
    assert all("__pycache__" not in e["path"] for e in manifest["files"])


@pytest.mark.asyncio
async def test_system_bundle_gated_off_and_without_key(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")

    off = _make_service(system_sources=[present], include_system=False)
    assert off.system_enabled is False
    assert await off.send_system_to_admins(FakeBot(), frozenset({1})) is None  # type: ignore[arg-type]

    empty = _make_service(system_sources=[])
    assert empty.system_enabled is False

    keyless = _make_service(system_sources=[present], encryption_key="")
    assert keyless.system_enabled is False
    with pytest.raises(RuntimeError, match="OFFSITE_BACKUP_ENCRYPTION_KEY"):
        await keyless.create_system_bundle()


@pytest.mark.asyncio
async def test_system_bundle_shares_key_and_ttl_with_db_backup(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    key = Fernet.generate_key().decode()
    service = _make_service(system_sources=[present], encryption_key=key)

    built = await service.create_system_bundle()
    assert built is not None
    # The same key that decrypts the DB backup decrypts this — that is the whole
    # compatibility contract.
    assert service.decrypt_backup(built[0]).startswith(b"\x1f\x8b")

    stale = Fernet(key.encode()).encrypt_at_time(b"payload", int(time.time()) - 40 * 86400)
    with pytest.raises(RuntimeError, match="устарел"):
        service.decrypt_backup(stale)


@pytest.mark.asyncio
async def test_send_system_to_admins_delivers_per_admin(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    service = _make_service(system_sources=[present])
    bot = FakeBot(fail_for=frozenset({2}))

    result = await service.send_system_to_admins(bot, frozenset({1, 2}))  # type: ignore[arg-type]
    assert result == {"success": 1, "failed": 1, "total": 2}
    assert len(bot.documents) == 1
    _, data, filename = bot.documents[0]
    assert filename.startswith("vpnbot_system_")
    raw = service.decrypt_backup(data)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        assert "MANIFEST.json" in tar.getnames()


@pytest.mark.asyncio
async def test_recovery_bundle_shape_unchanged_by_system_support(tmp_path: Path) -> None:
    """The pre-existing recovery bundle must be byte-shape identical."""
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=secret\n", encoding="utf-8")
    sysfile = tmp_path / "sys.conf"
    sysfile.write_text("sys", encoding="utf-8")

    service = _make_service(
        recovery_sources=[env_file],
        include_recovery=True,
        system_sources=[sysfile],
        include_system=True,
    )
    built = await service.create_recovery_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])

    # No summary block and no "kind" key: the recovery manifest keeps its old shape,
    # and the system source never leaks into it.
    assert "summary" not in manifest
    assert set(manifest.keys()) == {"created_at", "files"}
    assert [e["path"] for e in manifest["files"]] == [str(env_file)]
    assert all("kind" not in e for e in manifest["files"])
    assert all("sys.conf" not in name for name in members)


class _FakeService:
    """Stand-in for OffsiteBackupService that drives offsite_backup_loop."""

    def __init__(self, *, recovery_enabled: bool, system_enabled: bool, recovery_raises: bool = False) -> None:
        self.recovery_enabled = recovery_enabled
        self.system_enabled = system_enabled
        self._recovery_raises = recovery_raises
        self.backup_sent = 0
        self.recovery_sent = 0
        self.system_sent = 0
        self.recorded = 0

    async def get_last_backup_time(self):
        return None

    async def send_to_admins(self, bot, admin_ids):  # noqa: ANN001
        self.backup_sent += 1
        return {"success": 1, "failed": 0, "total": len(admin_ids)}

    async def record_backup_sent(self) -> None:
        self.recorded += 1

    async def send_recovery_to_admins(self, bot, admin_ids):  # noqa: ANN001
        self.recovery_sent += 1
        if self._recovery_raises:
            raise RuntimeError("recovery exploded")
        return {"success": 1, "failed": 0, "total": len(admin_ids)}

    async def send_system_to_admins(self, bot, admin_ids):  # noqa: ANN001
        self.system_sent += 1
        return {"success": 1, "failed": 0, "total": len(admin_ids)}


def _stop_after_one_iteration(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    async def fake_sleep(_delay: float) -> None:
        calls["n"] += 1
        # First sleep is the startup delay; the second is the trailing
        # sleep(interval) after one full iteration — stop there.
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr("services.offsite_backup.asyncio.sleep", fake_sleep)


@pytest.mark.asyncio
async def test_loop_sends_all_three_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeService(recovery_enabled=True, system_enabled=True)
    _stop_after_one_iteration(monkeypatch)

    with pytest.raises(asyncio.CancelledError):
        await offsite_backup_loop(service, FakeBot(), frozenset({1}), interval=10)  # type: ignore[arg-type]

    assert (service.backup_sent, service.recovery_sent, service.system_sent) == (1, 1, 1)
    # Only the DB backup moves the scheduling anchor.
    assert service.recorded == 1


@pytest.mark.asyncio
async def test_loop_skips_system_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeService(recovery_enabled=True, system_enabled=False)
    _stop_after_one_iteration(monkeypatch)

    with pytest.raises(asyncio.CancelledError):
        await offsite_backup_loop(service, FakeBot(), frozenset({1}), interval=10)  # type: ignore[arg-type]

    assert service.system_sent == 0
    assert service.backup_sent == 1


@pytest.mark.asyncio
async def test_loop_sends_system_even_when_recovery_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeService(recovery_enabled=True, system_enabled=True, recovery_raises=True)
    _stop_after_one_iteration(monkeypatch)

    with pytest.raises(asyncio.CancelledError):
        await offsite_backup_loop(service, FakeBot(), frozenset({1}), interval=10)  # type: ignore[arg-type]

    # A blown recovery bundle must not suppress the system bundle behind it.
    assert service.recovery_sent == 1
    assert service.system_sent == 1


# --- Default path set ----------------------------------------------------------


def test_default_system_paths_cover_the_new_locations() -> None:
    defaults = set(DEFAULT_OFFSITE_SYSTEM_PATHS)
    for added in (
        "/etc/systemd",
        "/var/www",
        "/etc/logrotate.d",
        "/etc/cron.d",
        "/etc/sudoers.d",
        "/var/spool/cron/crontabs",
    ):
        assert Path(added) in defaults, added
    # Replaced by their parent directory, which covers them and their siblings.
    for replaced in (
        "/etc/systemd/system",
        "/etc/systemd/journald.conf",
        "/var/spool/cron/crontabs/root",
    ):
        assert Path(replaced) not in defaults, replaced


def test_no_default_system_path_is_nested_in_another() -> None:
    # A child of another default entry is walked twice for nothing — and is exactly
    # what a stale /etc/systemd/system next to /etc/systemd would look like.
    for path in DEFAULT_OFFSITE_SYSTEM_PATHS:
        for other in DEFAULT_OFFSITE_SYSTEM_PATHS:
            if other != path:
                assert not path.is_relative_to(other), f"{path} is inside {other}"


# --- Configurable exclusions ---------------------------------------------------

_EXCLUDED_BY_DEFAULT = (
    "/usr/local/etc/xray/config.json.20260731T095519Z.1785491719000000000.Zm9vYmFyYmF6cXV4.bak",
    "/etc/amnezia/amneziawg/awg0.conf.20260731T095519Z.1785491719000000000.Zm9vYmFyYmF6cXV4.bak",
    "/etc/hysteria/config.yaml.bak443",
    "/etc/hysteria/config.yaml.bak.20260731T095519",
    "/etc/vpn-bot/tls/cert.pem.selfsigned.bak",
    "/usr/local/etc/xray/config.json.bak-20260731T095519Z",
    "/root/.acme.sh/dnsapi/dns_cf.sh",
    "/root/.acme.sh/deploy/haproxy.sh",
    "/root/.acme.sh/notify/telegram.sh",
)
_KEPT_BY_DEFAULT = (
    "/usr/local/etc/xray/config.json",
    "/etc/amnezia/amneziawg/awg0.conf",
    "/etc/nginx/conf.d/anycastedge.net.conf",
    "/var/www/anycastedge/index.html",
    "/etc/sudoers.d/vpn-bot",
    "/etc/systemd/journald.conf.d/10-vpn-bot.conf",
    "/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf",
    "/root/.acme.sh/account.conf",
    "/root/.acme.sh/acme.sh",
    "/root/.acme.sh/anycastedge.net_ecc/fullchain.cer",
    "/var/spool/cron/crontabs/root",
)


@pytest.mark.parametrize("path", _EXCLUDED_BY_DEFAULT)
def test_default_exclude_matches_config_copies_and_acme_code(path: str) -> None:
    service = _make_service(system_exclude=DEFAULT_OFFSITE_SYSTEM_EXCLUDE)
    assert service._system_excluded(Path(path)) is True


@pytest.mark.parametrize("path", _KEPT_BY_DEFAULT)
def test_default_exclude_keeps_live_state(path: str) -> None:
    service = _make_service(system_exclude=DEFAULT_OFFSITE_SYSTEM_EXCLUDE)
    assert service._system_excluded(Path(path)) is False


def _rebased(root: Path, patterns: tuple[str, ...]) -> tuple[str, ...]:
    """Move absolute globs under a fixture root; leave ``*…`` globs as they are."""
    return tuple(str(root) + pattern if pattern.startswith("/") else pattern for pattern in patterns)


@pytest.mark.asyncio
async def test_default_policy_on_a_fixture_host_tree(tmp_path: Path) -> None:
    files = {
        # left out by DEFAULT_OFFSITE_SYSTEM_EXCLUDE
        "usr/local/etc/xray/config.json.20260731T095519Z.1785491719000000000.Zm9vYmFy.bak": "OLD-XRAY",
        "etc/hysteria/config.yaml.bak443": "OLD-HY2",
        "etc/vpn-bot/tls/cert.pem.selfsigned.bak": "OLD-CERT",
        "usr/local/etc/xray/config.json.bak-20260731T095519Z": "OLD-XRAY-2",
        "root/.acme.sh/dnsapi/dns_cf.sh": "ACME-HOOK",
        # left out by the hard policy
        "etc/ssh/ssh_host_ed25519_key": "PRIVATE",
        # kept
        "usr/local/etc/xray/config.json": "{}",
        "etc/hysteria/config.yaml": "listen: :443",
        "root/.acme.sh/account.conf": "SAVED_CF_Token=x",
        "etc/nginx/conf.d/anycastedge.net.conf": "server {}",
        "var/www/anycastedge/index.html": "<html></html>",
        "etc/sudoers.d/vpn-bot": "vpn-bot ALL=(root) NOPASSWD: /usr/local/sbin/vpn-bot-xray-apply",
        "etc/systemd/journald.conf.d/10-vpn-bot.conf": "[Journal]\nSystemMaxUse=500M\n",
        "etc/ssh/sshd_config": "PermitRootLogin prohibit-password",
    }
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    sources = [tmp_path / "usr" / "local" / "etc" / "xray"]
    sources += [tmp_path / str(path).lstrip("/") for path in DEFAULT_OFFSITE_SYSTEM_PATHS]
    service = _make_service(
        system_sources=sources,
        system_exclude=_rebased(tmp_path, DEFAULT_OFFSITE_SYSTEM_EXCLUDE),
    )
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    for rel in list(files)[:6]:
        entry = by_path[str(tmp_path / rel)]
        assert entry["included"] is False, rel
        assert entry["reason"] == "excluded_by_policy", rel
        assert "member" not in entry and "sha256" not in entry, rel
    for rel in list(files)[6:]:
        assert by_path[str(tmp_path / rel)]["included"] is True, rel

    payload = b"".join(members.values())
    for secret in (b"OLD-XRAY", b"OLD-HY2", b"OLD-CERT", b"ACME-HOOK", b"PRIVATE"):
        assert secret not in payload
    assert manifest["summary"]["skipped_by_reason"]["excluded_by_policy"] == 6


@pytest.mark.asyncio
async def test_ssh_host_key_policy_survives_a_replaced_exclude_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _minimal_required(monkeypatch, tmp_path)
    monkeypatch.setenv("OFFSITE_BACKUP_SYSTEM_EXCLUDE", "/nonexistent/*")
    settings = load_settings()
    assert settings.offsite_backup_system_exclude == ("/nonexistent/*",)

    ssh = tmp_path / "ssh"
    ssh.mkdir()
    (ssh / "ssh_host_ed25519_key").write_text("PRIVATE", encoding="utf-8")
    (ssh / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA", encoding="utf-8")
    (ssh / "sshd_config.bak").write_text("old", encoding="utf-8")

    service = _make_service(system_sources=[ssh], system_exclude=settings.offsite_backup_system_exclude)
    built = await service.create_system_bundle()
    assert built is not None
    manifest, members = _extract(service, built[0])
    by_path = _by_path(manifest)

    # Not part of the configurable set, so replacing that set cannot switch it off.
    assert by_path[str(ssh / "ssh_host_ed25519_key")]["reason"] == "excluded_by_policy"
    assert all(b"PRIVATE" not in data for data in members.values())
    # The replaced set really did replace the default: *.bak is back in.
    assert by_path[str(ssh / "sshd_config.bak")]["included"] is True


@pytest.mark.asyncio
async def test_exclusion_applies_to_a_symlink_by_its_own_path(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    root.mkdir()
    live = root / "awg0.conf"
    live.write_text("[Interface]", encoding="utf-8")
    (root / "awg0.conf.bak").symlink_to(live)  # excluded: the link's own name matches
    (root / "current.conf").symlink_to(root / "awg0.conf.old.bak")  # kept: only its target matches

    service = _make_service(system_sources=[root], system_exclude=("*.bak",))
    built = await service.create_system_bundle()
    assert built is not None
    manifest, _ = _extract(service, built[0])
    by_path = _by_path(manifest)

    excluded = by_path[str(root / "awg0.conf.bak")]
    assert excluded == {"path": str(root / "awg0.conf.bak"), "kind": "symlink", "included": False,
                        "reason": "excluded_by_policy"}
    kept = by_path[str(root / "current.conf")]
    assert kept["kind"] == "symlink" and kept["included"] is True
    # Only the recorded link counts as a symlink; the excluded one is a skip.
    assert manifest["summary"]["symlinks"] == 1
    assert manifest["summary"]["skipped_by_reason"] == {"excluded_by_policy": 1}


@pytest.mark.asyncio
async def test_summary_counts_skips_by_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("services.offsite_backup._SYSTEM_MAX_FILE_BYTES", 16)
    root = tmp_path / "etc"
    root.mkdir()
    (root / "keep.conf").write_text("ok", encoding="utf-8")
    (root / "a.conf.bak").write_text("a", encoding="utf-8")
    (root / "b.conf.bak-1").write_text("b", encoding="utf-8")
    (root / "ssh_host_rsa_key").write_text("k", encoding="utf-8")
    (root / "big.bin").write_bytes(b"\0" * 17)

    service = _make_service(
        system_sources=[root, tmp_path / "gone.conf"],
        system_exclude=DEFAULT_OFFSITE_SYSTEM_EXCLUDE,
    )
    built = await service.create_system_bundle()
    assert built is not None
    manifest, _ = _extract(service, built[0])
    summary = manifest["summary"]

    assert summary["skipped_by_reason"] == {
        "FileNotFoundError": 1,
        "excluded_by_policy": 3,
        "too_large": 1,
    }
    assert summary["files_included"] == 1
    assert summary["files_skipped"] == 5
    assert sum(summary["skipped_by_reason"].values()) == summary["files_skipped"]


# --- OFFSITE_BACKUP_SYSTEM_EXCLUDE / _EXCLUDE_EXTRA ----------------------------


def _minimal_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))


@pytest.mark.parametrize(
    ("exclude", "extra", "expected"),
    [
        (None, None, DEFAULT_OFFSITE_SYSTEM_EXCLUDE),
        # Blank keeps the default — unlike OFFSITE_BACKUP_SYSTEM_PATHS, where a blank
        # value empties the set.
        ("", None, DEFAULT_OFFSITE_SYSTEM_EXCLUDE),
        ("   ", "", DEFAULT_OFFSITE_SYSTEM_EXCLUDE),
        ("/srv/a/*, *.old", None, ("/srv/a/*", "*.old")),
        (None, "*.orig", (*DEFAULT_OFFSITE_SYSTEM_EXCLUDE, "*.orig")),
        ("/srv/a/*", "*.orig,/var/www/*/cache/*", ("/srv/a/*", "*.orig", "/var/www/*/cache/*")),
    ],
)
def test_exclude_replaces_and_exclude_extra_appends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exclude: str | None,
    extra: str | None,
    expected: tuple[str, ...],
) -> None:
    _minimal_required(monkeypatch, tmp_path)
    if exclude is not None:
        monkeypatch.setenv("OFFSITE_BACKUP_SYSTEM_EXCLUDE", exclude)
    if extra is not None:
        monkeypatch.setenv("OFFSITE_BACKUP_SYSTEM_EXCLUDE_EXTRA", extra)
    assert load_settings().offsite_backup_system_exclude == expected


@pytest.mark.parametrize("name", ["OFFSITE_BACKUP_SYSTEM_EXCLUDE", "OFFSITE_BACKUP_SYSTEM_EXCLUDE_EXTRA"])
@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("config.json.bak", r"config\.json\.bak .*начните шаблон с \*"),
        ("*.bak,etc/ssh/*", r"etc/ssh/\* .*абсолютный путь"),
        ("?.bak", r"\?\.bak"),
        ("*.bak,,*.old", "пустой шаблон"),
        ("*.bak,", "пустой шаблон"),
    ],
)
def test_exclude_rejects_bad_globs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, value: str, message: str
) -> None:
    _minimal_required(monkeypatch, tmp_path)
    monkeypatch.setenv(name, value)
    with pytest.raises(SettingsError, match=message):
        load_settings()
