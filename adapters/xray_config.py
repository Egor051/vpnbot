
import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.backup import BackupAdapter
from adapters.errors import (
    XrayApplyError,
    XrayClientAlreadyExistsError,
    XrayConfigError,
    XrayInboundNotFoundError,
)
from adapters.file_lock import ConfigFileLock
from adapters.file_ops import async_copy_stat, async_fsync_parent
from adapters.privileged_helpers import PrivilegedHelperRunner, cleanup_staging_path, write_private_staging_file
from adapters.shell_runner import TIMEOUT_RETURNCODE, ShellRunner
from adapters.systemctl import SystemCtlAdapter


logger = logging.getLogger(__name__)

# Allows printable email-safe characters; leading '-' is forbidden to prevent
# flag injection when email_label is passed as a positional CLI argument.
_EMAIL_SAFE_RE = re.compile(r'^[a-zA-Z0-9@._+][a-zA-Z0-9@._+-]*$')


@dataclass(frozen=True, slots=True)
class XrayClientApplyResult:
    short_id_inserted: bool = False


class XrayConfigAdapter:
    def __init__(
        self,
        *,
        config_path: Path,
        service_name: str,
        apply_mode: str,
        inbound_tag: str,
        allow_restart_on_rollback: bool,
        backup: BackupAdapter,
        systemctl: SystemCtlAdapter,
        shell: ShellRunner | None = None,
        stats_server: str = "",
        helper_runner: PrivilegedHelperRunner | None = None,
        helper_path: Path | None = None,
        helper_staging_dir: Path | None = None,
    ) -> None:
        if config_path.is_symlink():
            raise XrayConfigError("Xray config path не должен быть symlink. Укажите реальный путь к config.json.")
        self.config_path = config_path
        self.service_name = service_name
        if apply_mode not in {"reload", "restart", "api"}:
            raise XrayConfigError("Xray apply mode должен быть reload, restart или api")
        if apply_mode == "api":
            if not stats_server:
                raise XrayConfigError("XRAY_APPLY_MODE=api требует stats_server (XRAY_STATS_SERVER)")
            if shell is None:
                raise XrayConfigError("XRAY_APPLY_MODE=api требует ShellRunner")
            if not inbound_tag:
                raise XrayConfigError("XRAY_APPLY_MODE=api требует inbound_tag (XRAY_INBOUND_TAG)")
            if helper_runner is not None:
                raise XrayConfigError(
                    "XRAY_APPLY_MODE=api несовместим с privilege helpers. "
                    "Отключите PRIVILEGE_HELPERS_ENABLED или используйте другой apply mode."
                )
        self.apply_mode = apply_mode
        self.inbound_tag = inbound_tag
        self.allow_restart_on_rollback = allow_restart_on_rollback
        self.backup = backup
        self.systemctl = systemctl
        self.shell = shell
        self.stats_server = stats_server
        self.helper_runner = helper_runner
        self.helper_path = helper_path or Path("/usr/local/sbin/vpnbot-xray-apply")
        self.helper_staging_dir = helper_staging_dir or Path("/run/vpn-bot/xray")
        if self.apply_mode == "restart":
            logger.warning("XRAY_APPLY_MODE=restart: Xray config changes will restart service %s", self.service_name)

    async def add_client(
        self,
        *,
        uuid_value: str,
        email_label: str,
        short_id: str,
        flow: str,
        manage_short_id: bool,
    ) -> XrayClientApplyResult:
        """Add a VLESS/REALITY client to the inbound and apply the config."""
        # Defence-in-depth: email_label is server-generated, but enforce the safe charset
        # at the adapter boundary so a malformed/crafted label can never reach the config
        # (and never a CLI flag position). Leading '-' is rejected to prevent flag injection.
        if not email_label or _EMAIL_SAFE_RE.match(email_label) is None:
            raise XrayConfigError("Xray email_label содержит недопустимые символы")
        lock_dir = self.helper_staging_dir if self._using_helper() else None
        async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = await self._snapshot_config()
            backup_path = None if self._using_helper() else await asyncio.to_thread(
                self.backup.create_backup, self.config_path
            )
            temp_path: Path | None = None
            try:
                config = await asyncio.to_thread(self._read_config, self.config_path)
                await self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                clients = self._clients(inbound)
                if self._find_client_in_list(clients, uuid_value=uuid_value, email_label=email_label) is not None:
                    raise XrayClientAlreadyExistsError("Xray client с таким UUID/email уже существует")

                client: dict[str, Any] = {"id": uuid_value, "email": email_label}
                if flow:
                    client["flow"] = flow
                clients.append(client)
                short_id_inserted = False
                if manage_short_id:
                    short_id_inserted = self._add_short_id(inbound, short_id)

                temp_path = await self._write_temp_config(config, self.config_path)
                if not self._using_helper() and self.apply_mode == "api" and not short_id_inserted:
                    await self._install_candidate_api(
                        temp_path, snapshot, backup_path,
                        action="add", uuid_value=uuid_value,
                        email_label=email_label, flow=flow,
                    )
                else:
                    await self._install_candidate(temp_path, snapshot, backup_path)
                return XrayClientApplyResult(short_id_inserted=short_id_inserted)
            finally:
                self._cleanup_temp(temp_path)

    async def remove_client(
        self,
        *,
        uuid_value: str | None,
        email_label: str | None,
        short_id: str | None,
        remove_short_id: bool,
    ) -> None:
        """Remove a client from the inbound and apply the config."""
        lock_dir = self.helper_staging_dir if self._using_helper() else None
        async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = await self._snapshot_config()
            backup_path = None if self._using_helper() else await asyncio.to_thread(
                self.backup.create_backup, self.config_path
            )
            temp_path: Path | None = None
            try:
                config = await asyncio.to_thread(self._read_config, self.config_path)
                await self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                clients = self._clients(inbound)
                changed = False

                api_email = ""
                if not self._using_helper() and self.apply_mode == "api":
                    found = self._find_client_in_list(clients, uuid_value=uuid_value, email_label=email_label)
                    api_email = found.get("email", "") if found else (email_label or "")

                new_clients = [client for client in clients if not self._matches_client_for_remove(client, uuid_value, email_label)]
                if len(new_clients) != len(clients):
                    inbound["settings"]["clients"] = new_clients
                    changed = True
                short_id_removed = bool(remove_short_id and short_id and self._remove_short_id(inbound, short_id))
                if short_id_removed:
                    changed = True

                if not changed:
                    return

                temp_path = await self._write_temp_config(config, self.config_path)
                if not self._using_helper() and self.apply_mode == "api" and not short_id_removed:
                    await self._install_candidate_api(
                        temp_path, snapshot, backup_path,
                        action="remove", email_label=api_email,
                    )
                else:
                    await self._install_candidate(temp_path, snapshot, backup_path)
            finally:
                self._cleanup_temp(temp_path)

    async def ensure_short_id(self, short_id: str) -> bool:
        """Add the short id to the inbound if missing and apply the config."""
        if not short_id:
            return False
        lock_dir = self.helper_staging_dir if self._using_helper() else None
        async with ConfigFileLock(self.config_path, lock_dir=lock_dir):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = await self._snapshot_config()
            backup_path = None if self._using_helper() else await asyncio.to_thread(
                self.backup.create_backup, self.config_path
            )
            temp_path: Path | None = None
            try:
                config = await asyncio.to_thread(self._read_config, self.config_path)
                await self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                if not self._add_short_id(inbound, short_id):
                    return False

                temp_path = await self._write_temp_config(config, self.config_path)
                await self._install_candidate(temp_path, snapshot, backup_path)
                return True
            finally:
                self._cleanup_temp(temp_path)

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, Any] | None:
        """Find a client in the inbound matching the given UUID or email."""
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        found = self._find_client_in_list(self._clients(inbound), uuid_value=uuid_value, email_label=email_label)
        return dict(found) if found is not None else None

    def list_clients(self) -> list[dict[str, Any]]:
        """Return all clients configured on the target inbound."""
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        return [dict(client) for client in self._clients(inbound) if isinstance(client, dict)]

    def list_short_ids(self) -> set[str]:
        """Return the set of REALITY short ids configured on the inbound."""
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        short_ids = self._reality_settings(inbound).get("shortIds")
        if not isinstance(short_ids, list):
            raise XrayConfigError("Xray realitySettings.shortIds должен быть списком")
        return {str(short_id) for short_id in short_ids}

    def _read_config(self, path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise XrayConfigError(f"Xray config не найден: {path}") from exc
        except json.JSONDecodeError as exc:
            raise XrayConfigError(f"Xray config содержит невалидный JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise XrayConfigError("Xray config должен быть JSON-объектом")
        return data

    async def _snapshot_config(self) -> tuple[int, int, bytes]:
        def _do() -> tuple[int, int, bytes]:
            try:
                stat = self.config_path.stat()
                raw = self.config_path.read_bytes()
            except FileNotFoundError as exc:
                raise XrayConfigError(f"Xray config не найден: {self.config_path}") from exc
            return stat.st_mtime_ns, stat.st_size, hashlib.blake2b(raw[:65536]).digest()
        return await asyncio.to_thread(_do)

    async def _assert_config_unchanged(self, snapshot: tuple[int, int, bytes]) -> None:
        mtime_ns, size, expected_hash = snapshot

        def _do() -> None:
            try:
                current_stat = self.config_path.stat()
            except FileNotFoundError as exc:
                raise XrayConfigError(f"Xray config не найден: {self.config_path}") from exc
            if (current_stat.st_mtime_ns, current_stat.st_size) != (mtime_ns, size):
                raise XrayConfigError("Xray config изменился во время операции. Изменения не применены.")
            # mtime+size match: verify content hash to catch same-size same-mtime substitutions
            try:
                current_raw = self.config_path.read_bytes()
            except FileNotFoundError as exc:
                raise XrayConfigError(f"Xray config не найден: {self.config_path}") from exc
            if hashlib.blake2b(current_raw[:65536]).digest() != expected_hash:
                raise XrayConfigError("Xray config изменился во время операции. Изменения не применены.")

        await asyncio.to_thread(_do)

    def _target_inbound(self, config: dict[str, Any]) -> dict[str, Any]:
        inbounds = config.get("inbounds")
        if not isinstance(inbounds, list):
            raise XrayInboundNotFoundError("В Xray config не найден список inbounds")

        if self.inbound_tag:
            for inbound in inbounds:
                if isinstance(inbound, dict) and inbound.get("tag") == self.inbound_tag:
                    if not self._is_vless_reality(inbound):
                        raise XrayInboundNotFoundError(
                            f"Xray inbound tag={self.inbound_tag!r} найден, но это не VLESS/REALITY inbound"
                        )
                    return inbound
            raise XrayInboundNotFoundError(f"Xray inbound tag={self.inbound_tag!r} не найден")

        candidates = [inbound for inbound in inbounds if isinstance(inbound, dict) and self._is_vless_reality(inbound)]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            raise XrayInboundNotFoundError(
                "В Xray config найдено несколько VLESS/Reality inbound. "
                "Укажите XRAY_INBOUND_TAG, чтобы бот не выбрал неправильный inbound."
            )
        raise XrayInboundNotFoundError("Не найден Xray inbound protocol=vless и security=reality")

    def _is_vless_reality(self, inbound: dict[str, Any]) -> bool:
        stream = inbound.get("streamSettings")
        return (
            inbound.get("protocol") == "vless"
            and isinstance(stream, dict)
            and stream.get("security") == "reality"
            and isinstance(inbound.get("settings"), dict)
        )

    def _clients(self, inbound: dict[str, Any]) -> list[Any]:
        settings = inbound.setdefault("settings", {})
        if not isinstance(settings, dict):
            raise XrayConfigError("Xray inbound.settings должен быть объектом")
        clients = settings.setdefault("clients", [])
        if not isinstance(clients, list):
            raise XrayConfigError("Xray inbound settings.clients должен быть списком")
        return clients

    def _find_client_in_list(
        self,
        clients: list[Any],
        *,
        uuid_value: str | None,
        email_label: str | None,
    ) -> dict[str, Any] | None:
        for client in clients:
            if not isinstance(client, dict):
                continue
            if uuid_value and client.get("id") == uuid_value:
                return client
            if email_label and client.get("email") == email_label:
                return client
        return None

    def _matches_client_for_remove(self, client: Any, uuid_value: str | None, email_label: str | None) -> bool:
        if not isinstance(client, dict):
            return False
        if uuid_value:
            return client.get("id") == uuid_value
        return bool(email_label and client.get("email") == email_label)

    def _add_short_id(self, inbound: dict[str, Any], short_id: str) -> bool:
        reality = self._reality_settings(inbound)
        short_ids = reality.setdefault("shortIds", [])
        if not isinstance(short_ids, list):
            raise XrayConfigError("Xray realitySettings.shortIds должен быть списком")
        if short_id not in short_ids:
            short_ids.append(short_id)
            return True
        return False

    def _remove_short_id(self, inbound: dict[str, Any], short_id: str) -> bool:
        reality = self._reality_settings(inbound)
        short_ids = reality.get("shortIds")
        if not isinstance(short_ids, list) or short_id not in short_ids:
            return False
        reality["shortIds"] = [value for value in short_ids if value != short_id]
        return True

    def _reality_settings(self, inbound: dict[str, Any]) -> dict[str, Any]:
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict):
            raise XrayConfigError("Xray inbound.streamSettings должен быть объектом")
        reality = stream.get("realitySettings")
        if not isinstance(reality, dict):
            raise XrayConfigError("Xray inbound.streamSettings.realitySettings должен быть объектом")
        return reality

    async def _write_temp_config(self, config: dict[str, Any], mode_from: Path) -> Path:
        content = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        json.loads(content)
        if self._using_helper():
            return await asyncio.to_thread(
                write_private_staging_file,
                self.helper_staging_dir,
                prefix=f".{self.config_path.name}.",
                suffix=".json",
                content=content,
            )
        old_umask = os.umask(0o177)
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.config_path.parent,
                prefix=f".{self.config_path.name}.",
                suffix=".json",
                delete=False,
            ) as file:
                file.write(content)
                file.flush()
                await asyncio.to_thread(os.fsync, file.fileno())
                temp_path = Path(file.name)
        finally:
            os.umask(old_umask)
        if mode_from.exists():
            await async_copy_stat(mode_from, temp_path)
        return temp_path

    async def _install_candidate(
        self,
        temp_path: Path,
        snapshot: tuple[int, int, bytes],
        backup_path: Path | None,
    ) -> None:
        if self._using_helper():
            await self._assert_config_unchanged(snapshot)
            await self._apply_helper(temp_path, snapshot)
            return
        if backup_path is None:
            raise XrayApplyError("Xray backup is not available for direct apply")
        await self._test_config(temp_path)
        await self._assert_config_unchanged(snapshot)
        await self._replace_main_config(temp_path, self.config_path)
        await self._apply_or_restore(backup_path)

    async def _apply_helper(self, candidate_path: Path, snapshot: tuple[int, int, bytes]) -> None:
        if self.helper_runner is None:
            raise XrayApplyError("Xray privileged helper is not configured")
        result = await self.helper_runner.run(
            self.helper_path,
            ["apply", str(candidate_path)],
            timeout=90,
            max_output_chars=2048,
        )
        if result.ok:
            return
        if result.returncode == TIMEOUT_RETURNCODE:
            # The helper runs privileged via sudo; on our timeout it may still be applying
            # (the unprivileged bot cannot kill the root child). Retrying could run two
            # concurrent applies against the same config/runtime, so fail instead.
            raise XrayApplyError("Xray helper apply timed out; not retrying to avoid concurrent apply")
        logger.warning("Xray helper apply failed on attempt 1: rc=%s; retrying in 2s", result.returncode)
        await asyncio.sleep(2)
        await self._assert_config_unchanged(snapshot)
        result = await self.helper_runner.run(
            self.helper_path,
            ["apply", str(candidate_path)],
            timeout=90,
            max_output_chars=2048,
        )
        if not result.ok:
            raise XrayApplyError(f"Xray helper apply failed after 2 attempts: rc={result.returncode}")

    async def _test_config(self, path: Path) -> None:
        result = await self.systemctl.xray_test_config(path)
        if not result.ok:
            raise XrayApplyError("Xray config не прошёл проверку")

    async def _ensure_current_config_valid(self) -> None:
        result = await self.systemctl.xray_test_config(self.config_path)
        if not result.ok:
            raise XrayConfigError(
                "Текущий Xray config не проходит проверку. Операция отменена без backup, reload или restart."
            )

    async def _replace_main_config(self, temp_path: Path, mode_from: Path) -> None:
        if mode_from.exists():
            await async_copy_stat(mode_from, temp_path)
        await asyncio.to_thread(os.replace, temp_path, self.config_path)
        await async_fsync_parent(self.config_path)

    async def _apply_or_restore(self, backup_path: Path) -> None:
        if self.apply_mode == "restart":
            await self._restart_or_restore(backup_path)
            return
        await self._reload_or_restore(backup_path)

    async def _reload_or_restore(self, backup_path: Path) -> None:
        result = await self.systemctl.reload(self.service_name)
        if result.ok:
            active = await self.systemctl.is_active(self.service_name)
            if active.ok and active.stdout.strip() == "active":
                return
        await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
        restored_test = await self.systemctl.xray_test_config(self.config_path)
        if not restored_test.ok:
            raise XrayApplyError("Xray reload failed, backup restored, но восстановленный config не прошёл проверку")
        if self.allow_restart_on_rollback:
            restart = await self.systemctl.restart(self.service_name)
            if not restart.ok:
                raise XrayApplyError("Xray reload failed, backup restored, но restart также не удался")
        raise XrayApplyError("Не удалось применить Xray config через reload; backup восстановлен")

    async def _restart_or_restore(self, backup_path: Path) -> None:
        logger.info("Applying Xray config via systemctl restart %s", self.service_name)
        if await self._restart_service():
            return
        await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
        restored_test = await self.systemctl.xray_test_config(self.config_path)
        if not restored_test.ok:
            raise XrayApplyError("Xray restart failed, backup restored, но восстановленный config не прошёл проверку")
        if not await self._restart_service():
            raise XrayApplyError("Xray restart failed, backup restored, но restart восстановленного config также не удался")
        raise XrayApplyError("Не удалось применить Xray config через restart; backup восстановлен и Xray перезапущен")

    async def _restart_service(self) -> bool:
        result = await self.systemctl.restart(self.service_name)
        if not result.ok:
            return False
        active = await self.systemctl.is_active(self.service_name)
        return active.ok and active.stdout.strip() == "active"

    async def _install_candidate_api(
        self,
        temp_path: Path,
        snapshot: tuple[int, int, bytes],
        backup_path: Path | None,
        *,
        action: str,
        uuid_value: str = "",
        email_label: str = "",
        flow: str = "",
    ) -> None:
        if backup_path is None:
            raise XrayApplyError("Xray backup is not available for API apply")
        await self._test_config(temp_path)
        await self._assert_config_unchanged(snapshot)
        await self._replace_main_config(temp_path, self.config_path)
        try:
            if action == "add":
                await self._api_add_user(uuid_value, email_label, flow)
            else:
                await self._api_remove_user(email_label)
        except Exception as exc:
            await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
            # Restore xray runtime from the backup inbound config via adi.
            # After rmi+adi failure the inbound may be absent from runtime;
            # adi with the just-restored disk config brings it back.
            try:
                await self._api_reload_inbound()
            except Exception:
                logger.error("xray api adi rollback failed; falling back to reload/restart", exc_info=True)
                reload_result = await self.systemctl.reload(self.service_name)
                if not reload_result.ok and self.allow_restart_on_rollback:
                    try:
                        await self.systemctl.restart(self.service_name)
                    except Exception:
                        logger.error("Xray restart after API rollback also failed", exc_info=True)
            raise XrayApplyError(f"xray api {action} failed, config restored from backup") from exc

    async def _api_add_user(self, uuid_value: str, email_label: str, flow: str) -> None:
        await self._api_reload_inbound()

    async def _api_remove_user(self, email_label: str) -> None:
        await self._api_reload_inbound()

    async def _api_reload_inbound(self) -> None:
        """Sync the running xray inbound with the current on-disk config via rmi + adi."""
        assert self.shell is not None
        config = await asyncio.to_thread(self._read_config, self.config_path)
        inbound = self._target_inbound(config)
        inbound_payload = {"inbounds": [inbound]}

        tmp_path: Path | None = None
        try:
            # Write next to the (private) config rather than /tmp: the payload carries the
            # server REALITY privateKey and all client UUIDs. umask(0o177) guarantees the
            # file is 0600 from creation (no copy-then-chmod world-readable window).
            content = json.dumps(inbound_payload, ensure_ascii=False)
            old_umask = os.umask(0o177)
            try:
                with tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=self.config_path.parent,
                    prefix=f".{self.config_path.name}.inbound.",
                    suffix=".json",
                    delete=False,
                ) as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                    tmp_path = Path(f.name)
            finally:
                os.umask(old_umask)

            rmi_result = await self.shell.run(
                ["xray", "api", "rmi", f"--server={self.stats_server}", self.inbound_tag],
                timeout=10,
            )
            if not rmi_result.ok:
                # Normal on first run or when inbound is not yet loaded in runtime.
                logger.debug(
                    "xray api rmi returned non-ok for tag=%r (may be normal): %s",
                    self.inbound_tag,
                    rmi_result.stderr or rmi_result.stdout,
                )

            adi_result = await self.shell.run(
                ["xray", "api", "adi", f"--server={self.stats_server}", str(tmp_path)],
                timeout=10,
            )
            if not adi_result.ok:
                raise XrayApplyError(f"xray api adi failed: {adi_result.stderr or adi_result.stdout}")
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    def _cleanup_temp(self, temp_path: Path | None) -> None:
        cleanup_staging_path(temp_path)

    def _using_helper(self) -> bool:
        return self.helper_runner is not None
