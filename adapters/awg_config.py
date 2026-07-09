
import asyncio
import hashlib
import ipaddress
import os
import tempfile
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from adapters.backup import BackupAdapter
from adapters.errors import AwgApplyError, AwgConfigError, AwgPeerAlreadyExistsError
from adapters.file_lock import ConfigFileLock
from adapters.privileged_helpers import PrivilegedHelperRunner, cleanup_staging_path, write_private_staging_file
from adapters.shell_runner import (
    COMMAND_NOT_FOUND_RETURNCODE,
    COMMAND_NOT_FOUND_STDERR,
    ShellRunner,
)
from adapters.validation import reject_option_like, validate_ip, validate_wireguard_key
from models.dto import ShellResult

logger = logging.getLogger(__name__)

MACHINE_OUTPUT_LIMIT = 1024 * 1024


@dataclass(frozen=True, slots=True)
class AwgServerConfig:
    listen_port: int | None
    public_key: str | None
    interface_options: dict[str, str]
    address: str | None = None


@dataclass(slots=True)
class _AwgSection:
    name: str
    lines: list[str]
    options: dict[str, str]


class AwgConfigAdapter:
    _CLIENT_INTERFACE_KEYS: ClassVar[set[str]] = {
        "DNS",
        "MTU",
        "Jc",
        "Jmin",
        "Jmax",
        "S1",
        "S2",
        "S3",
        "S4",
        "H1",
        "H2",
        "H3",
        "H4",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
    }
    _CRITICAL_PEER_KEYS: ClassVar[set[str]] = {"PublicKey", "AllowedIPs", "PresharedKey"}
    _CRITICAL_INTERFACE_KEYS: ClassVar[set[str]] = {
        "PrivateKey",
        "Address",
        "ListenPort",
        "Jc",
        "Jmin",
        "Jmax",
        "S1",
        "S2",
        "S3",
        "S4",
        "H1",
        "H2",
        "H3",
        "H4",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
    }

    def __init__(
        self,
        *,
        config_path: Path,
        interface: str,
        backup: BackupAdapter,
        shell: ShellRunner,
        persistent_keepalive: int,
        helper_runner: PrivilegedHelperRunner | None = None,
        helper_path: Path | None = None,
        helper_staging_dir: Path | None = None,
    ) -> None:
        if config_path.is_symlink():
            raise AwgConfigError("AWG config path не должен быть symlink. Укажите реальный путь к awg0.conf.")
        self.config_path = config_path
        # The interface name reaches a subprocess argv slot (awg show <iface>, awg set
        # <iface> ...); reject option-like values so it can never be parsed as a flag.
        reject_option_like(interface, "AWG interface", error=AwgConfigError)
        self.interface = interface
        self.backup = backup
        self.shell = shell
        self.persistent_keepalive = persistent_keepalive
        self.helper_runner = helper_runner
        self.helper_path = helper_path or Path("/usr/local/sbin/vpn-bot-awg-apply")
        self.helper_staging_dir = helper_staging_dir or Path("/run/vpn-bot/awg")

    async def generate_private_key(self) -> str:
        """Generate a new AWG/WG private key."""
        result = await self._run_awg_or_wg(["genkey"], timeout=10)
        if not result.ok or not result.stdout:
            raise AwgApplyError("Не удалось сгенерировать AWG private key")
        return result.stdout.splitlines()[0].strip()

    async def generate_public_key(self, private_key: str) -> str:
        """Derive the public key for the given private key."""
        result = await self._run_awg_or_wg(
            ["pubkey"],
            input_text=private_key + "\n",
            timeout=10,
            sensitive_values=[private_key],
        )
        if not result.ok or not result.stdout:
            raise AwgApplyError("Не удалось сгенерировать AWG public key")
        return result.stdout.splitlines()[0].strip()

    async def generate_preshared_key(self) -> str:
        """Generate a new AWG/WG preshared key."""
        result = await self._run_awg_or_wg(["genpsk"], timeout=10)
        if not result.ok or not result.stdout:
            raise AwgApplyError("Не удалось сгенерировать AWG preshared key")
        return result.stdout.splitlines()[0].strip()

    def read_server_config(self) -> AwgServerConfig:
        """Read and return the server interface configuration from the config file."""
        text = self._read_text()
        sections = self._parse_sections(text)
        interface = next((section for section in sections if section.name == "Interface"), None)
        if interface is None:
            raise AwgConfigError("В AWG config не найден [Interface]")

        listen_port = self._parse_int(interface.options.get("ListenPort"))
        options = {
            key: value
            for key, value in interface.options.items()
            if key in self._CLIENT_INTERFACE_KEYS
        }
        return AwgServerConfig(
            listen_port=listen_port,
            public_key=interface.options.get("PublicKey"),
            interface_options=options,
            address=interface.options.get("Address"),
        )

    async def add_peer(
        self,
        *,
        key_id: int,
        owner_user_id: int,
        public_key: str,
        preshared_key: str | None,
        client_ip: str,
        label: str | None = None,
    ) -> None:
        """Add a peer to the config and runtime, rolling back on failure."""
        # Defence-in-depth: keys are server-generated, but validate at the adapter boundary
        # so a malformed value can never be interpolated into an awg0.conf [Peer] block or
        # an `awg set` argv (mirrors the strict label check).
        validate_wireguard_key(public_key, "AWG public_key", error=AwgConfigError)
        if preshared_key is not None:
            validate_wireguard_key(preshared_key, "AWG preshared_key", error=AwgConfigError)
        validate_ip(client_ip, "AWG client_ip", error=AwgConfigError)
        if self._using_helper():
            await self._add_peer_via_helper(
                key_id=key_id,
                owner_user_id=owner_user_id,
                public_key=public_key,
                preshared_key=preshared_key,
                client_ip=client_ip,
                label=label,
            )
            return
        async with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            snapshot = await self._snapshot_config()
            backup_path = await asyncio.to_thread(self.backup.create_backup, self.config_path)
            wrote_config = False
            touched_runtime = False
            try:
                original = await self._read_text_async()
                await self._assert_config_unchanged(snapshot)
                sections = self._parse_sections(original)
                if self._managed_block_exists(original, key_id):
                    if not await self.verify_runtime_peer(public_key):
                        touched_runtime = True
                        if not await self._add_peer_runtime(public_key, preshared_key, client_ip):
                            raise AwgApplyError("AWG peer есть в config, но не применён в runtime")
                    return
                if self._find_peer(sections, public_key=public_key, client_ip=client_ip) is not None:
                    raise AwgPeerAlreadyExistsError("AWG peer с таким public key или client_ip уже есть в конфиге")

                updated = original.rstrip() + "\n\n" + self._peer_block(
                    key_id=key_id,
                    owner_user_id=owner_user_id,
                    public_key=public_key,
                    preshared_key=preshared_key,
                    client_ip=client_ip,
                    label=label,
                )
                await self._validate_candidate_config(updated)
                await self._assert_config_unchanged(snapshot)
                await asyncio.to_thread(
                    self.backup.atomic_write_text, self.config_path, updated, mode_from=self.config_path
                )
                wrote_config = True

                touched_runtime = True
                if not await self._add_peer_runtime(public_key, preshared_key, client_ip):
                    raise AwgApplyError("Не удалось применить AWG peer в runtime")
                if not await self.verify_runtime_peer(public_key):
                    raise AwgApplyError("AWG peer добавлен командой, но не найден в runtime")
            except Exception as exc:
                rollback_errors = await self._rollback_add_peer(
                    backup_path=backup_path,
                    wrote_config=wrote_config,
                    touched_runtime=touched_runtime,
                    public_key=public_key,
                )
                self._raise_with_rollback_summary("AWG peer add failed", exc, rollback_errors)

    async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
        """Remove a peer from the config and runtime, rolling back on failure."""
        if public_key is not None:
            validate_wireguard_key(public_key, "AWG public_key", error=AwgConfigError)
        if self._using_helper():
            await self._remove_peer_via_helper(key_id=key_id, public_key=public_key)
            return
        async with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            snapshot = await self._snapshot_config()
            backup_path = await asyncio.to_thread(self.backup.create_backup, self.config_path)
            wrote_config = False
            runtime_removed = False
            try:
                original = await self._read_text_async()
                await self._assert_config_unchanged(snapshot)
                updated = self._remove_managed_block(original, key_id)
                if updated == original and public_key:
                    updated = self._remove_peer_section_by_identity(original, public_key=public_key)
                if updated != original:
                    await self._validate_candidate_config(updated)
                    await self._assert_config_unchanged(snapshot)
                    await asyncio.to_thread(
                        self.backup.atomic_write_text, self.config_path, updated, mode_from=self.config_path
                    )
                    wrote_config = True

                if public_key and not await self._remove_peer_runtime(public_key):
                    raise AwgApplyError("Не удалось удалить AWG peer из runtime")
                runtime_removed = public_key is not None
                if public_key and await self.verify_runtime_peer(public_key):
                    raise AwgApplyError("AWG peer удалён командой, но всё ещё найден в runtime")
                if public_key and self.find_peer(public_key=public_key, client_ip=None) is not None:
                    raise AwgApplyError("AWG peer удалён из runtime, но всё ещё найден в config")
            except Exception as exc:
                rollback_errors = await self._rollback_remove_peer(
                    backup_path=backup_path,
                    wrote_config=wrote_config,
                    runtime_removed=runtime_removed,
                )
                self._raise_with_rollback_summary("AWG peer remove failed", exc, rollback_errors)

    async def _add_peer_via_helper(
        self,
        *,
        key_id: int,
        owner_user_id: int,
        public_key: str,
        preshared_key: str | None,
        client_ip: str,
        label: str | None,
    ) -> None:
        lock_dir = self.helper_staging_dir
        async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
            snapshot = await self._snapshot_config()
            original = await self._read_text_async()
            await self._assert_config_unchanged(snapshot)
            sections = self._parse_sections(original)
            if self._managed_block_exists(original, key_id):
                await self._apply_config_text_via_helper(original)
                return
            if self._find_peer(sections, public_key=public_key, client_ip=client_ip) is not None:
                raise AwgPeerAlreadyExistsError("AWG peer с таким public key или client_ip уже есть в конфиге")

            updated = original.rstrip() + "\n\n" + self._peer_block(
                key_id=key_id,
                owner_user_id=owner_user_id,
                public_key=public_key,
                preshared_key=preshared_key,
                client_ip=client_ip,
                label=label,
            )
            self._parse_sections(updated)
            await self._assert_config_unchanged(snapshot)
            await self._apply_config_text_via_helper(updated)

    async def _remove_peer_via_helper(self, *, key_id: int, public_key: str | None) -> None:
        lock_dir = self.helper_staging_dir
        async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
            snapshot = await self._snapshot_config()
            original = await self._read_text_async()
            await self._assert_config_unchanged(snapshot)
            updated = self._remove_managed_block(original, key_id)
            if updated == original and public_key:
                updated = self._remove_peer_section_by_identity(original, public_key=public_key)
            if updated == original and public_key is None:
                return
            self._parse_sections(updated)
            await self._assert_config_unchanged(snapshot)
            await self._apply_config_text_via_helper(updated)
            if public_key and await self.verify_runtime_peer(public_key):
                raise AwgApplyError("AWG peer удалён командой, но всё ещё найден в runtime")

    async def _apply_config_text_via_helper(self, text: str) -> None:
        self._parse_sections(text)
        candidate_path: Path | None = None
        try:
            candidate_path = await asyncio.to_thread(
                write_private_staging_file,
                self.helper_staging_dir,
                prefix=f".{self.config_path.name}.",
                suffix=".conf",
                content=text,
            )
            result = await self._run_helper(["apply", str(candidate_path)], timeout=90, max_output_chars=2048)
            if not result.ok:
                raise AwgApplyError(f"AWG helper apply failed: rc={result.returncode}")
        finally:
            cleanup_staging_path(candidate_path)

    def client_interface_options(self) -> dict[str, str]:
        """Return client-facing interface options from the config, or empty if missing."""
        if not self.config_path.exists():
            return {}
        return self.read_server_config().interface_options

    def find_peer(self, *, public_key: str | None = None, client_ip: str | None = None) -> dict[str, str] | None:
        """Find a config peer matching the given public key or client IP."""
        return self._find_peer(self._parse_sections(self._read_text()), public_key=public_key, client_ip=client_ip)

    def list_config_peers(self) -> list[dict[str, str]]:
        """Return all peer blocks defined in the config file."""
        return self._parse_peer_blocks(self._read_text())

    def list_peer_allowed_ips(self) -> set[str]:
        """Return the set of AllowedIPs across all peers in the config."""
        ips: set[str] = set()
        for section in self._parse_sections(self._read_text()):
            if section.name != "Peer":
                continue
            allowed_ips = section.options.get("AllowedIPs", "")
            for part in allowed_ips.split(","):
                value = part.strip()
                if not value:
                    continue
                ips.add(value)
        return ips

    def find_managed_peer_public_key(self, key_id: int) -> str | None:
        """Return the public key of the managed peer block for the given key id."""
        block = self._managed_block_lines(self._read_text(), key_id)
        if not block:
            return None
        for raw_line in block:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key == "PublicKey" and value:
                return value
        return None

    async def ensure_interface_active(self) -> None:
        """Verify the AWG interface is available and active."""
        if self._using_helper():
            result = await self._run_helper(["status"], timeout=20)
            if not result.ok:
                raise AwgApplyError(f"AWG interface {self.interface} недоступен или не активен")
            return
        result = await self._show_interface()
        if not result.ok:
            raise AwgApplyError(f"AWG interface {self.interface} недоступен или не активен")

    async def verify_runtime_peer(self, public_key: str) -> bool:
        """Return whether the peer with the given public key is present in runtime."""
        if self._using_helper():
            result = await self._run_helper(["show-peers"], timeout=20, max_output_chars=MACHINE_OUTPUT_LIMIT)
            if not result.ok:
                return False
            return any(line.strip() == f"peer: {public_key}" for line in result.stdout.splitlines())
        result = await self._show_interface()
        if not result.ok:
            return False
        return any(line.strip() == f"peer: {public_key}" for line in result.stdout.splitlines())

    async def list_runtime_peers(self) -> list[dict[str, str]]:
        """Return all peers currently active in the AWG runtime."""
        if self._using_helper():
            result = await self._run_helper(["show-peers"], timeout=20, max_output_chars=MACHINE_OUTPUT_LIMIT)
            if not result.ok:
                raise AwgApplyError(f"Не удалось получить AWG runtime peers для {self.interface}")
            return self._parse_runtime_peers(result.stdout)
        result = await self._show_interface()
        if not result.ok:
            raise AwgApplyError(f"Не удалось получить AWG runtime peers для {self.interface}")
        return self._parse_runtime_peers(result.stdout)

    async def sync_runtime_from_config(self) -> None:
        """Synchronize the AWG runtime to match the on-disk config."""
        if self._using_helper():
            lock_dir = self.helper_staging_dir
            async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
                await self._apply_config_text_via_helper(await self._read_text_async())
            return
        async with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            await self._validate_candidate_config(await self._read_text_async())
            await self._sync_runtime_from_config(self.config_path)

    async def remove_runtime_peer(self, public_key: str) -> None:
        """Remove the peer with the given public key from the AWG runtime."""
        validate_wireguard_key(public_key, "AWG public_key", error=AwgConfigError)
        if self._using_helper():
            lock_dir = self.helper_staging_dir
            async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
                await self._apply_config_text_via_helper(await self._read_text_async())
                if await self.verify_runtime_peer(public_key):
                    raise AwgApplyError("AWG peer удалён командой, но всё ещё найден в runtime")
            return
        async with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            if not await self._remove_peer_runtime(public_key):
                raise AwgApplyError("Не удалось удалить AWG peer из runtime")
            if await self.verify_runtime_peer(public_key):
                raise AwgApplyError("AWG peer удалён командой, но всё ещё найден в runtime")

    async def list_transfer(self) -> dict[str, tuple[int, int]]:
        """Return per-peer received and sent byte counts from the AWG runtime."""
        if self._using_helper():
            result = await self._run_helper(["show-transfer"], timeout=20, max_output_chars=MACHINE_OUTPUT_LIMIT)
            if not result.ok:
                raise AwgApplyError("Не удалось получить AWG transfer через helper")
            return self.parse_transfer_output(result.stdout, source="awg")
        result = await self.shell.run(
            ["awg", "show", self.interface, "transfer"],
            timeout=10,
            max_output_chars=MACHINE_OUTPUT_LIMIT,
        )
        source = "awg"
        if not result.ok:
            result = await self.shell.run(
                ["wg", "show", self.interface, "transfer"],
                timeout=10,
                max_output_chars=MACHINE_OUTPUT_LIMIT,
            )
            source = "wg"
        if not result.ok:
            raise AwgApplyError(f"Не удалось получить AWG transfer через awg/wg: {result.stderr or result.stdout}")
        return self.parse_transfer_output(result.stdout, source=source)

    @staticmethod
    def parse_transfer_output(text: str, *, source: str = "awg") -> dict[str, tuple[int, int]]:
        """Parse awg/wg transfer output into a mapping of public key to byte counts.

        Malformed lines are skipped (and logged), not fatal: a single junk line from a
        format drift must not discard the whole transfer snapshot.
        """
        transfers: dict[str, tuple[int, int]] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                logger.warning("Пропущена некорректная строка %s transfer: %r", source, line)
                continue
            public_key, received_raw, sent_raw = parts
            try:
                received_bytes = int(received_raw)
                sent_bytes = int(sent_raw)
            except ValueError:
                logger.warning("Пропущены некорректные байты %s transfer: %r", source, line)
                continue
            transfers[public_key] = (received_bytes, sent_bytes)
        return transfers

    def _read_text(self) -> str:
        try:
            return self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc

    async def _read_text_async(self) -> str:
        return await asyncio.to_thread(self._read_text)

    async def _snapshot_config(self) -> tuple[int, int, bytes]:
        def _do() -> tuple[int, int, bytes]:
            try:
                stat = self.config_path.stat()
                raw = self.config_path.read_bytes()
            except FileNotFoundError as exc:
                raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc
            return stat.st_mtime_ns, stat.st_size, hashlib.blake2b(raw).digest()
        return await asyncio.to_thread(_do)

    async def _assert_config_unchanged(self, snapshot: tuple[int, int, bytes]) -> None:
        mtime_ns, size, expected_hash = snapshot

        def _do() -> None:
            try:
                current_stat = self.config_path.stat()
            except FileNotFoundError as exc:
                raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc
            if (current_stat.st_mtime_ns, current_stat.st_size) != (mtime_ns, size):
                raise AwgConfigError("AWG config изменился во время операции. Изменения не применены.")
            # mtime+size match: verify a hash of the WHOLE file to catch same-size
            # same-mtime substitutions anywhere in the config (not just the first 64 KiB).
            try:
                current_raw = self.config_path.read_bytes()
            except FileNotFoundError as exc:
                raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc
            if hashlib.blake2b(current_raw).digest() != expected_hash:
                raise AwgConfigError("AWG config изменился во время операции. Изменения не применены.")

        await asyncio.to_thread(_do)

    async def _validate_candidate_config(self, text: str) -> None:
        self._parse_sections(text)
        tmp_path: Path | None = None
        try:
            old_umask = os.umask(0o177)
            try:
                with tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=self.config_path.parent,
                    prefix=f".{self.config_path.name}.",
                    suffix=".conf",
                    delete=False,
                ) as tmp:
                    tmp.write(text)
                    tmp.flush()
                    await asyncio.to_thread(os.fsync, tmp.fileno())
                    tmp_path = Path(tmp.name)
            finally:
                os.umask(old_umask)
            result = await self._quick_strip(tmp_path)
            if not result.ok:
                raise AwgConfigError("AWG config не прошёл проверку awg-quick/wg-quick strip")
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    @staticmethod
    def _is_command_missing(result: ShellResult) -> bool:
        # Distinguish "binary not installed" (ShellRunner's FileNotFoundError sentinel)
        # from a genuine rc=127 exit of an existing binary, so the awg->wg fallback only
        # triggers when awg/awg-quick is actually absent.
        return result.returncode == COMMAND_NOT_FOUND_RETURNCODE and result.stderr == COMMAND_NOT_FOUND_STDERR

    async def _quick_strip(self, path: Path) -> ShellResult:
        result = await self.shell.run(["awg-quick", "strip", str(path)], timeout=10)
        if not self._is_command_missing(result):
            return result
        result = await self.shell.run(["wg-quick", "strip", str(path)], timeout=10)
        if self._is_command_missing(result):
            raise AwgConfigError("Не найден awg-quick или wg-quick для проверки AWG config")
        return result

    async def _sync_runtime_from_config(self, config_path: Path) -> None:
        stripped_path: Path | None = None
        try:
            stripped = await self._quick_strip(config_path)
            if not stripped.ok:
                raise AwgApplyError("Не удалось подготовить AWG config для syncconf")
            old_umask = os.umask(0o177)
            try:
                with tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=config_path.parent,
                    prefix=f".{config_path.name}.",
                    suffix=".conf",
                    delete=False,
                ) as tmp:
                    tmp.write(stripped.stdout)
                    tmp.flush()
                    await asyncio.to_thread(os.fsync, tmp.fileno())
                    stripped_path = Path(tmp.name)
            finally:
                os.umask(old_umask)
            result = await self._run_awg_or_wg(["syncconf", self.interface, str(stripped_path)], timeout=15)
            if not result.ok:
                raise AwgApplyError("Не удалось синхронизировать AWG runtime из восстановленного config")
        except AwgConfigError as exc:
            raise AwgApplyError("Не удалось проверить восстановленный AWG config перед syncconf") from exc
        finally:
            if stripped_path is not None:
                stripped_path.unlink(missing_ok=True)

    def _parse_sections(self, text: str) -> list[_AwgSection]:
        sections: list[_AwgSection] = []
        current: _AwgSection | None = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1].strip()
                if name not in {"Interface", "Peer"}:
                    raise AwgConfigError(f"Неизвестная секция AWG config: [{name}]")
                current = _AwgSection(name=name, lines=[raw_line], options={})
                sections.append(current)
                continue
            if current is None:
                if line and not line.startswith("#"):
                    raise AwgConfigError("AWG config содержит параметры до первой секции")
                continue
            current.lines.append(raw_line)
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            self._reject_duplicate_critical_key(current, key)
            current.options[key] = value

        if not any(section.name == "Interface" for section in sections):
            raise AwgConfigError("В AWG config не найден [Interface]")
        return sections

    def _reject_duplicate_critical_key(self, section: _AwgSection, key: str) -> None:
        critical = self._CRITICAL_INTERFACE_KEYS if section.name == "Interface" else self._CRITICAL_PEER_KEYS
        if key in critical and key in section.options:
            raise AwgConfigError(f"Дублирующий критичный параметр AWG config: [{section.name}] {key}")

    def _find_peer(
        self,
        sections: list[_AwgSection],
        *,
        public_key: str | None,
        client_ip: str | None,
    ) -> dict[str, str] | None:
        for section in sections:
            if section.name != "Peer":
                continue
            if public_key and section.options.get("PublicKey") == public_key:
                return dict(section.options)
            allowed_ips = section.options.get("AllowedIPs", "")
            if client_ip and self._allowed_ips_contains(allowed_ips, client_ip):
                return dict(section.options)
        return None

    def _parse_peer_blocks(self, text: str) -> list[dict[str, str]]:
        peers: list[dict[str, str]] = []
        lines = text.splitlines()
        pending_marker: dict[str, str] = {}
        index = 0
        while index < len(lines):
            stripped = lines[index].strip()
            marker = self._managed_start_marker(stripped)
            if marker:
                pending_marker = marker
                index += 1
                continue
            if stripped == "[Peer]":
                block_lines = [lines[index]]
                index += 1
                while index < len(lines):
                    next_stripped = lines[index].strip()
                    if next_stripped.startswith("[") and next_stripped.endswith("]"):
                        break
                    block_lines.append(lines[index])
                    index += 1
                section = self._parse_sections("\n".join(["[Interface]", *block_lines]))[-1]
                peer = dict(section.options)
                peer.update(pending_marker)
                peers.append(peer)
                pending_marker = {}
                continue
            if stripped and not stripped.startswith("#"):
                pending_marker = {}
            index += 1
        return peers

    def _managed_start_marker(self, line: str) -> dict[str, str]:
        prefix = "# vpn-bot peer start key_id="
        if not line.startswith(prefix):
            return {}
        rest = line[len(prefix):]
        parts = rest.split()
        if not parts:
            return {}
        try:
            key_id = int(parts[0])
        except ValueError:
            return {}
        marker = {"_managed_key_id": str(key_id)}
        for part in parts[1:]:
            if part.startswith("label="):
                label = part.split("=", 1)[1].strip()
                if label:
                    marker["_managed_label"] = label
        return marker

    def _remove_peer_section_by_identity(self, text: str, *, public_key: str) -> str:
        lines = text.splitlines()
        updated_lines: list[str] = []
        index = 0
        removed = False
        while index < len(lines):
            if lines[index].strip() != "[Peer]":
                updated_lines.append(lines[index])
                index += 1
                continue

            start = index
            block = [lines[index]]
            index += 1
            while index < len(lines):
                stripped = lines[index].strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    break
                block.append(lines[index])
                index += 1
            section = self._parse_sections("\n".join(["[Interface]", *block]))[-1]
            if section.options.get("PublicKey") == public_key:
                removed = True
                continue
            updated_lines.extend(lines[start:index])

        if not removed:
            return text
        return "\n".join(updated_lines).rstrip() + "\n"

    async def list_peer_endpoints(self) -> dict[str, str]:
        """Return {public_key: source_ip} for peers that have an active endpoint."""
        peers = await self.list_runtime_peers()
        result: dict[str, str] = {}
        for peer in peers:
            pub = peer.get("PublicKey")
            endpoint = peer.get("Endpoint")
            if not pub or not endpoint:
                continue
            # endpoint is "ip:port" for IPv4 or "[ipv6]:port" for IPv6
            ip = endpoint.rsplit(":", 1)[0].strip("[]")
            if ip:
                result[pub] = ip
        return result

    def _parse_runtime_peers(self, text: str) -> list[dict[str, str]]:
        peers: list[dict[str, str]] = []
        current: dict[str, str] | None = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("peer: "):
                current = {"PublicKey": line.split("peer: ", 1)[1].strip()}
                peers.append(current)
                continue
            if current is None or ":" not in line:
                continue
            key, value = [part.strip() for part in line.split(":", 1)]
            if key == "allowed ips":
                current["AllowedIPs"] = value
            elif key == "endpoint":
                current["Endpoint"] = value
        return peers

    def _allowed_ips_contains(self, allowed_ips: str, client_ip: str) -> bool:
        try:
            candidate = self._ip_address(client_ip)
        except ValueError:
            return False
        for part in allowed_ips.split(","):
            value = part.strip()
            if not value:
                continue
            try:
                network = self._ip_network(value)
            except ValueError:
                continue
            if network.version == candidate.version and candidate in network:
                return True
        return False

    def _validate_label(self, label: str) -> None:
        # label is written into a single-line config comment marker
        # ("# vpn-bot peer start key_id=N owner=M label=<label>"). Any whitespace/newline
        # or control char could inject extra config lines (e.g. a rogue [Peer] with
        # AllowedIPs = 0.0.0.0/0) or break marker round-trip parsing.
        if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
            raise AwgConfigError("AWG peer label содержит недопустимые символы")

    def _peer_block(
        self,
        key_id: int,
        owner_user_id: int,
        public_key: str,
        preshared_key: str | None,
        client_ip: str,
        label: str | None = None,
    ) -> str:
        if label:
            self._validate_label(label)
        label_part = f" label={label}" if label else ""
        lines = [
            f"# vpn-bot peer start key_id={key_id} owner={owner_user_id}{label_part}",
            "[Peer]",
            f"PublicKey = {public_key}",
        ]
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
        lines.extend(
            [
                f"AllowedIPs = {client_ip}/32",
                f"# vpn-bot peer end key_id={key_id}",
                "",
            ]
        )
        return "\n".join(lines)

    def _managed_block_exists(self, text: str, key_id: int) -> bool:
        return any(line.startswith(f"# vpn-bot peer start key_id={key_id} ") for line in text.splitlines())

    def _remove_managed_block(self, text: str, key_id: int) -> str:
        lines = text.splitlines()
        start_marker = f"# vpn-bot peer start key_id={key_id} "
        end_marker = f"# vpn-bot peer end key_id={key_id}"
        start_index: int | None = None
        end_index: int | None = None

        for index, line in enumerate(lines):
            stripped = line.strip()
            if start_index is None and stripped.startswith(start_marker):
                start_index = index
                continue
            if start_index is not None and stripped == end_marker:
                end_index = index
                break

        if start_index is None:
            return text
        if end_index is None:
            raise AwgConfigError(f"Найден start-marker key_id={key_id}, но не найден end-marker")

        updated_lines = lines[:start_index] + lines[end_index + 1:]
        return "\n".join(updated_lines).rstrip() + "\n"

    def _managed_block_lines(self, text: str, key_id: int) -> list[str] | None:
        lines = text.splitlines()
        start_marker = f"# vpn-bot peer start key_id={key_id} "
        end_marker = f"# vpn-bot peer end key_id={key_id}"
        start_index: int | None = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            if start_index is None and stripped.startswith(start_marker):
                start_index = index
                continue
            if start_index is not None and stripped == end_marker:
                return lines[start_index: index + 1]
        return None

    async def _rollback_add_peer(
        self,
        *,
        backup_path: Path,
        wrote_config: bool,
        touched_runtime: bool,
        public_key: str,
    ) -> list[str]:
        errors: list[str] = []
        if wrote_config:
            try:
                await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
            except Exception:
                logger.error("AWG rollback failed: restore config after add_peer error", exc_info=True)
                errors.append("restore config")
        if touched_runtime:
            try:
                await self._remove_peer_runtime(public_key)
            except Exception:
                logger.error("AWG rollback failed: runtime cleanup after add_peer error", exc_info=True)
                errors.append("runtime cleanup")
        return errors

    async def _rollback_remove_peer(
        self,
        *,
        backup_path: Path,
        wrote_config: bool,
        runtime_removed: bool,
    ) -> list[str]:
        errors: list[str] = []
        if wrote_config:
            try:
                await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
            except Exception:
                logger.error("AWG rollback failed: restore config after remove_peer error", exc_info=True)
                errors.append("restore config")
        if runtime_removed:
            try:
                await self._sync_runtime_from_config(self.config_path)
            except Exception:
                logger.error("AWG rollback failed: runtime sync after remove_peer error", exc_info=True)
                errors.append("runtime sync")
        return errors

    def _raise_with_rollback_summary(self, context: str, primary: Exception, rollback_errors: list[str]) -> None:
        if rollback_errors:
            steps = ", ".join(rollback_errors)
            raise AwgApplyError(f"{context}: {primary}; rollback failed steps: {steps}") from primary
        raise primary

    async def _add_peer_runtime(self, public_key: str, preshared_key: str | None, client_ip: str) -> bool:
        args = ["set", self.interface, "peer", public_key]
        temp_path: str | None = None
        try:
            if preshared_key:
                # Write the PSK next to the (private) config, not the world-shared /tmp,
                # with a hidden prefix — content is 0600 but the private dir avoids leaving
                # secret-bearing temp files in a shared tmpfs. Direct mode only (the bot owns
                # this dir here); helper mode embeds the PSK in the applied config text.
                old_umask = os.umask(0o177)
                try:
                    with tempfile.NamedTemporaryFile(
                        "w",
                        encoding="utf-8",
                        dir=self.config_path.parent,
                        prefix=f".{self.config_path.name}.psk.",
                        delete=False,
                    ) as tmp:
                        tmp.write(preshared_key + "\n")
                        tmp.flush()
                        await asyncio.to_thread(os.fsync, tmp.fileno())
                        temp_path = tmp.name
                finally:
                    os.umask(old_umask)
                args.extend(["preshared-key", temp_path])
            args.extend(["allowed-ips", f"{client_ip}/32", "persistent-keepalive", str(self.persistent_keepalive)])
            result = await self._run_awg_or_wg(args, timeout=15, sensitive_values=[preshared_key or ""])
            return result.ok
        finally:
            if temp_path:
                Path(temp_path).unlink(missing_ok=True)

    async def _remove_peer_runtime(self, public_key: str) -> bool:
        result = await self._run_awg_or_wg(["set", self.interface, "peer", public_key, "remove"], timeout=15)
        return result.ok

    async def _show_interface(self) -> ShellResult:
        return await self._run_awg_or_wg(["show", self.interface], timeout=10)

    async def _run_awg_or_wg(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 15.0,
        sensitive_values: list[str] | None = None,
    ) -> ShellResult:
        result = await self.shell.run(["awg", *args], input_text=input_text, timeout=timeout, sensitive_values=sensitive_values or [])
        if not self._is_command_missing(result):
            return result
        return await self.shell.run(["wg", *args], input_text=input_text, timeout=timeout, sensitive_values=sensitive_values or [])

    async def _run_helper(
        self,
        args: list[str],
        *,
        timeout: float,
        max_output_chars: int = 2048,
    ) -> ShellResult:
        if self.helper_runner is None:
            raise AwgApplyError("AWG privileged helper is not configured")
        return await self.helper_runner.run(
            self.helper_path,
            args,
            timeout=timeout,
            max_output_chars=max_output_chars,
        )

    def _using_helper(self) -> bool:
        return self.helper_runner is not None

    def _parse_int(self, value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise AwgConfigError(f"AWG integer parameter has invalid value: {value}") from exc

    def _ip_network(self, value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(value, strict=False)

    def _ip_address(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(value)
