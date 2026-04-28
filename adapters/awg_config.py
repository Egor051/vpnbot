from __future__ import annotations

import os
import tempfile
import logging
from dataclasses import dataclass
from pathlib import Path

from adapters.backup import BackupAdapter
from adapters.errors import AwgApplyError, AwgConfigError, AwgPeerAlreadyExistsError
from adapters.file_lock import ConfigFileLock
from adapters.shell_runner import ShellRunner
from models.dto import ShellResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AwgServerConfig:
    listen_port: int | None
    public_key: str | None
    interface_options: dict[str, str]


@dataclass(slots=True)
class _AwgSection:
    name: str
    lines: list[str]
    options: dict[str, str]


class AwgConfigAdapter:
    _CLIENT_INTERFACE_KEYS = {
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

    def __init__(
        self,
        *,
        config_path: Path,
        interface: str,
        backup: BackupAdapter,
        shell: ShellRunner,
        persistent_keepalive: int,
    ) -> None:
        self.config_path = config_path
        self.interface = interface
        self.backup = backup
        self.shell = shell
        self.persistent_keepalive = persistent_keepalive

    async def generate_private_key(self) -> str:
        result = await self._run_awg_or_wg(["genkey"], timeout=10)
        if not result.ok or not result.stdout:
            raise AwgApplyError("Не удалось сгенерировать AWG private key")
        return result.stdout.splitlines()[0].strip()

    async def generate_public_key(self, private_key: str) -> str:
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
        result = await self._run_awg_or_wg(["genpsk"], timeout=10)
        if not result.ok or not result.stdout:
            raise AwgApplyError("Не удалось сгенерировать AWG preshared key")
        return result.stdout.splitlines()[0].strip()

    def read_server_config(self) -> AwgServerConfig:
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
        with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            snapshot = self._snapshot_config()
            backup_path = self.backup.create_backup(self.config_path)
            wrote_config = False
            touched_runtime = False
            try:
                original = self._read_text()
                self._assert_config_unchanged(snapshot)
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
                self._assert_config_unchanged(snapshot)
                self.backup.atomic_write_text(self.config_path, updated, mode_from=self.config_path)
                wrote_config = True

                touched_runtime = True
                if not await self._add_peer_runtime(public_key, preshared_key, client_ip):
                    raise AwgApplyError("Не удалось применить AWG peer в runtime")
                if not await self.verify_runtime_peer(public_key):
                    raise AwgApplyError("AWG peer добавлен командой, но не найден в runtime")
            except Exception:
                if wrote_config:
                    self.backup.restore(backup_path, self.config_path, mode_from=self.config_path)
                if touched_runtime:
                    await self._remove_peer_runtime(public_key)
                raise

    async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
        with ConfigFileLock(self.config_path):
            await self.ensure_interface_active()
            snapshot = self._snapshot_config()
            backup_path = self.backup.create_backup(self.config_path)
            wrote_config = False
            runtime_removed = False
            try:
                original = self._read_text()
                self._assert_config_unchanged(snapshot)
                updated = self._remove_managed_block(original, key_id)
                if updated != original:
                    await self._validate_candidate_config(updated)
                    self._assert_config_unchanged(snapshot)
                    self.backup.atomic_write_text(self.config_path, updated, mode_from=self.config_path)
                    wrote_config = True

                if public_key and not await self._remove_peer_runtime(public_key):
                    raise AwgApplyError("Не удалось удалить AWG peer из runtime")
                runtime_removed = public_key is not None
                if public_key and await self.verify_runtime_peer(public_key):
                    raise AwgApplyError("AWG peer удалён командой, но всё ещё найден в runtime")
                if public_key and self.find_peer(public_key=public_key, client_ip=None) is not None:
                    raise AwgApplyError("AWG peer удалён из runtime, но всё ещё найден в config")
            except Exception as exc:
                if wrote_config:
                    self.backup.restore(backup_path, self.config_path, mode_from=self.config_path)
                if runtime_removed:
                    try:
                        await self._sync_runtime_from_config(self.config_path)
                    except Exception as restore_exc:
                        logger.error("AWG config restored, but runtime restore failed after remove_peer error", exc_info=True)
                        raise AwgApplyError("AWG config восстановлен, но runtime не удалось синхронизировать после ошибки удаления peer") from restore_exc
                raise

    def client_interface_options(self) -> dict[str, str]:
        if not self.config_path.exists():
            return {}
        return self.read_server_config().interface_options

    def find_peer(self, *, public_key: str | None = None, client_ip: str | None = None) -> dict[str, str] | None:
        return self._find_peer(self._parse_sections(self._read_text()), public_key=public_key, client_ip=client_ip)

    def list_peer_allowed_ips(self) -> set[str]:
        ips: set[str] = set()
        for section in self._parse_sections(self._read_text()):
            if section.name != "Peer":
                continue
            allowed_ips = section.options.get("AllowedIPs", "")
            for part in allowed_ips.split(","):
                value = part.strip()
                if not value:
                    continue
                ips.add(value.split("/", 1)[0].strip())
        return ips

    async def ensure_interface_active(self) -> None:
        result = await self._show_interface()
        if not result.ok:
            raise AwgApplyError(f"AWG interface {self.interface} недоступен или не активен")

    async def verify_runtime_peer(self, public_key: str) -> bool:
        result = await self._show_interface()
        if not result.ok:
            return False
        return any(line.strip() == f"peer: {public_key}" for line in result.stdout.splitlines())

    async def list_transfer(self) -> dict[str, tuple[int, int]]:
        result = await self.shell.run(["awg", "show", self.interface, "transfer"], timeout=10)
        source = "awg"
        if not result.ok:
            result = await self.shell.run(["wg", "show", self.interface, "transfer"], timeout=10)
            source = "wg"
        if not result.ok:
            raise AwgApplyError(f"Не удалось получить AWG transfer через awg/wg: {result.stderr or result.stdout}")
        return self.parse_transfer_output(result.stdout, source=source)

    @staticmethod
    def parse_transfer_output(text: str, *, source: str = "awg") -> dict[str, tuple[int, int]]:
        transfers: dict[str, tuple[int, int]] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                raise AwgApplyError(f"Некорректная строка {source} transfer: {line}")
            public_key, received_raw, sent_raw = parts
            try:
                received_bytes = int(received_raw)
                sent_bytes = int(sent_raw)
            except ValueError as exc:
                raise AwgApplyError(f"Некорректные байты {source} transfer: {line}") from exc
            transfers[public_key] = (received_bytes, sent_bytes)
        return transfers

    def _read_text(self) -> str:
        try:
            return self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc

    def _snapshot_config(self) -> tuple[int, int]:
        try:
            stat = self.config_path.stat()
        except FileNotFoundError as exc:
            raise AwgConfigError(f"AWG config не найден: {self.config_path}") from exc
        return stat.st_mtime_ns, stat.st_size

    def _assert_config_unchanged(self, snapshot: tuple[int, int]) -> None:
        current = self._snapshot_config()
        if current != snapshot:
            raise AwgConfigError("AWG config изменился во время операции. Изменения не применены.")

    async def _validate_candidate_config(self, text: str) -> None:
        self._parse_sections(text)
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.config_path.parent, suffix=".conf", delete=False) as tmp:
                tmp.write(text)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = Path(tmp.name)
            result = await self._quick_strip(tmp_path)
            if not result.ok:
                raise AwgConfigError("AWG config не прошёл проверку awg-quick/wg-quick strip")
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    async def _quick_strip(self, path: Path) -> ShellResult:
        result = await self.shell.run(["awg-quick", "strip", str(path)], timeout=10)
        if result.returncode != 127:
            return result
        result = await self.shell.run(["wg-quick", "strip", str(path)], timeout=10)
        if result.returncode == 127:
            raise AwgConfigError("Не найден awg-quick или wg-quick для проверки AWG config")
        return result

    async def _sync_runtime_from_config(self, config_path: Path) -> None:
        stripped_path: Path | None = None
        try:
            stripped = await self._quick_strip(config_path)
            if not stripped.ok:
                raise AwgApplyError("Не удалось подготовить AWG config для syncconf")
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=config_path.parent, suffix=".conf", delete=False) as tmp:
                tmp.write(stripped.stdout)
                tmp.flush()
                os.fsync(tmp.fileno())
                stripped_path = Path(tmp.name)
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
            current.options[key] = value

        if not any(section.name == "Interface" for section in sections):
            raise AwgConfigError("В AWG config не найден [Interface]")
        return sections

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
            if client_ip and any(part.strip().split("/", 1)[0] == client_ip for part in allowed_ips.split(",")):
                return dict(section.options)
        return None

    def _peer_block(
        self,
        key_id: int,
        owner_user_id: int,
        public_key: str,
        preshared_key: str | None,
        client_ip: str,
        label: str | None = None,
    ) -> str:
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

        updated_lines = lines[:start_index] + lines[end_index + 1 :]
        return "\n".join(updated_lines).rstrip() + "\n"

    async def _add_peer_runtime(self, public_key: str, preshared_key: str | None, client_ip: str) -> bool:
        args = ["set", self.interface, "peer", public_key]
        temp_path: str | None = None
        try:
            if preshared_key:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
                    tmp.write(preshared_key + "\n")
                    tmp.flush()
                    os.fsync(tmp.fileno())
                    temp_path = tmp.name
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
        if result.returncode != 127:
            return result
        return await self.shell.run(["wg", *args], input_text=input_text, timeout=timeout, sensitive_values=sensitive_values or [])

    def _parse_int(self, value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise AwgConfigError(f"AWG integer parameter has invalid value: {value}") from exc


def self_check_allowed_ips_parser() -> bool:
    text = """
[Interface]
PrivateKey = server
Address = 10.0.0.1/24

[Peer]
PublicKey = a
AllowedIPs = 10.0.0.2/32, fd00::2/128

[Peer]
PublicKey = b
AllowedIPs = 10.0.0.3/32
"""
    adapter = AwgConfigAdapter(
        config_path=Path("/tmp/unused-awg.conf"),
        interface="unused",
        backup=BackupAdapter.__new__(BackupAdapter),
        shell=ShellRunner(),
        persistent_keepalive=25,
    )
    sections = adapter._parse_sections(text)
    ips: set[str] = set()
    for section in sections:
        if section.name != "Peer":
            continue
        for part in section.options.get("AllowedIPs", "").split(","):
            if part.strip():
                ips.add(part.strip().split("/", 1)[0])
    return {"10.0.0.2", "fd00::2", "10.0.0.3"} == ips
