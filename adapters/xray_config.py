
import asyncio
import json
import logging
import os
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
from adapters.file_ops import copy_stat, fsync_parent
from adapters.privileged_helpers import PrivilegedHelperRunner, cleanup_staging_path, write_private_staging_file
from adapters.shell_runner import ShellRunner
from adapters.systemctl import SystemCtlAdapter


logger = logging.getLogger(__name__)


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
        async with ConfigFileLock(self._lock_target()):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = self._snapshot_config()
            backup_path = None if self._using_helper() else self.backup.create_backup(self.config_path)
            temp_path: Path | None = None
            try:
                config = self._read_config(self.config_path)
                self._assert_config_unchanged(snapshot)
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

                temp_path = self._write_temp_config(config, self.config_path)
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
        async with ConfigFileLock(self._lock_target()):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = self._snapshot_config()
            backup_path = None if self._using_helper() else self.backup.create_backup(self.config_path)
            temp_path: Path | None = None
            try:
                config = self._read_config(self.config_path)
                self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                clients = self._clients(inbound)
                changed = False

                _api_email = ""
                if not self._using_helper() and self.apply_mode == "api":
                    found = self._find_client_in_list(clients, uuid_value=uuid_value, email_label=email_label)
                    _api_email = found.get("email", "") if found else (email_label or "")

                new_clients = [client for client in clients if not self._matches_client_for_remove(client, uuid_value, email_label)]
                if len(new_clients) != len(clients):
                    inbound["settings"]["clients"] = new_clients
                    changed = True
                if remove_short_id and short_id and self._remove_short_id(inbound, short_id):
                    changed = True

                if not changed:
                    return

                temp_path = self._write_temp_config(config, self.config_path)
                if not self._using_helper() and self.apply_mode == "api":
                    await self._install_candidate_api(
                        temp_path, snapshot, backup_path,
                        action="remove", email_label=_api_email,
                    )
                else:
                    await self._install_candidate(temp_path, snapshot, backup_path)
            finally:
                self._cleanup_temp(temp_path)

    async def ensure_short_id(self, short_id: str) -> bool:
        if not short_id:
            return False
        async with ConfigFileLock(self._lock_target()):
            if not self._using_helper():
                await self._ensure_current_config_valid()
            snapshot = self._snapshot_config()
            backup_path = None if self._using_helper() else self.backup.create_backup(self.config_path)
            temp_path: Path | None = None
            try:
                config = self._read_config(self.config_path)
                self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                if not self._add_short_id(inbound, short_id):
                    return False

                temp_path = self._write_temp_config(config, self.config_path)
                await self._install_candidate(temp_path, snapshot, backup_path)
                return True
            finally:
                self._cleanup_temp(temp_path)

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, Any] | None:
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        found = self._find_client_in_list(self._clients(inbound), uuid_value=uuid_value, email_label=email_label)
        return dict(found) if found is not None else None

    def list_clients(self) -> list[dict[str, Any]]:
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        return [dict(client) for client in self._clients(inbound) if isinstance(client, dict)]

    def list_short_ids(self) -> set[str]:
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

    def _snapshot_config(self) -> tuple[int, int]:
        try:
            stat = self.config_path.stat()
        except FileNotFoundError as exc:
            raise XrayConfigError(f"Xray config не найден: {self.config_path}") from exc
        return stat.st_mtime_ns, stat.st_size

    def _assert_config_unchanged(self, snapshot: tuple[int, int]) -> None:
        current = self._snapshot_config()
        if current != snapshot:
            raise XrayConfigError("Xray config изменился во время операции. Изменения не применены.")

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

    def _write_temp_config(self, config: dict[str, Any], mode_from: Path) -> Path:
        content = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        json.loads(content)
        if self._using_helper():
            return write_private_staging_file(
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
                os.fsync(file.fileno())
                temp_path = Path(file.name)
        finally:
            os.umask(old_umask)
        if mode_from.exists():
            copy_stat(mode_from, temp_path)
        return temp_path

    async def _install_candidate(
        self,
        temp_path: Path,
        snapshot: tuple[int, int],
        backup_path: Path | None,
    ) -> None:
        if self._using_helper():
            self._assert_config_unchanged(snapshot)
            await self._apply_helper(temp_path, snapshot)
            return
        if backup_path is None:
            raise XrayApplyError("Xray backup is not available for direct apply")
        await self._test_config(temp_path)
        self._assert_config_unchanged(snapshot)
        self._replace_main_config(temp_path, self.config_path)
        await self._apply_or_restore(backup_path)

    async def _apply_helper(self, candidate_path: Path, snapshot: tuple[int, int]) -> None:
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
        logger.warning("Xray helper apply failed on attempt 1: rc=%s; retrying in 2s", result.returncode)
        await asyncio.sleep(2)
        self._assert_config_unchanged(snapshot)
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

    def _replace_main_config(self, temp_path: Path, mode_from: Path) -> None:
        if mode_from.exists():
            copy_stat(mode_from, temp_path)
        os.replace(temp_path, self.config_path)
        fsync_parent(self.config_path)

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
        self.backup.restore(backup_path, self.config_path, mode_from=self.config_path)
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
        self.backup.restore(backup_path, self.config_path, mode_from=self.config_path)
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
        snapshot: tuple[int, int],
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
        self._assert_config_unchanged(snapshot)
        self._replace_main_config(temp_path, self.config_path)
        try:
            if action == "add":
                await self._api_add_user(uuid_value, email_label, flow)
            else:
                await self._api_remove_user(email_label)
        except Exception as exc:
            self.backup.restore(backup_path, self.config_path, mode_from=self.config_path)
            raise XrayApplyError(f"xray api {action} failed, config restored from backup") from exc

    async def _api_add_user(self, uuid_value: str, email_label: str, flow: str) -> None:
        assert self.shell is not None
        user_json = {
            "inboundTag": self.inbound_tag,
            "user": {
                "email": email_label,
                "level": 0,
                "account": {
                    "@type": "type.googleapis.com/xray.proxy.vless.Account",
                    "id": uuid_value,
                    "flow": flow,
                },
            },
        }
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(user_json, f)
                tmp_path = Path(f.name)
            result = await self.shell.run(
                ["xray", "api", "adu", f"--server={self.stats_server}", str(tmp_path)],
                timeout=10,
            )
            if not result.ok:
                raise XrayApplyError(f"xray api adu failed: {result.stderr or result.stdout}")
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    async def _api_remove_user(self, email_label: str) -> None:
        assert self.shell is not None
        result = await self.shell.run(
            ["xray", "api", "rmu",
             f"--server={self.stats_server}",
             f"-tag={self.inbound_tag}",
             email_label],
            timeout=10,
        )
        if not result.ok:
            raise XrayApplyError(f"xray api rmu failed: {result.stderr or result.stdout}")

    def _cleanup_temp(self, temp_path: Path | None) -> None:
        cleanup_staging_path(temp_path)

    def _using_helper(self) -> bool:
        return self.helper_runner is not None

    def _lock_target(self) -> Path:
        if self._using_helper():
            return self.helper_staging_dir / "config.json"
        return self.config_path

