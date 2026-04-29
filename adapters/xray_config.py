from __future__ import annotations

import json
import logging
import os
import tempfile
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
from adapters.systemctl import SystemCtlAdapter


logger = logging.getLogger(__name__)


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
    ) -> None:
        self.config_path = config_path
        self.service_name = service_name
        if apply_mode not in {"reload", "restart"}:
            raise XrayConfigError("Xray apply mode должен быть reload или restart")
        self.apply_mode = apply_mode
        self.inbound_tag = inbound_tag
        self.allow_restart_on_rollback = allow_restart_on_rollback
        self.backup = backup
        self.systemctl = systemctl
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
    ) -> None:
        with ConfigFileLock(self.config_path):
            await self._ensure_current_config_valid()
            snapshot = self._snapshot_config()
            backup_path = self.backup.create_backup(self.config_path)
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
                if manage_short_id:
                    self._add_short_id(inbound, short_id)

                temp_path = self._write_temp_config(config, self.config_path)
                await self._test_config(temp_path)
                self._assert_config_unchanged(snapshot)
                self._replace_main_config(temp_path, self.config_path)
                await self._apply_or_restore(backup_path)
            except Exception:
                self._cleanup_temp(temp_path)
                raise

    async def remove_client(
        self,
        *,
        uuid_value: str | None,
        email_label: str | None,
        short_id: str | None,
        remove_short_id: bool,
    ) -> None:
        with ConfigFileLock(self.config_path):
            await self._ensure_current_config_valid()
            snapshot = self._snapshot_config()
            backup_path = self.backup.create_backup(self.config_path)
            temp_path: Path | None = None
            try:
                config = self._read_config(self.config_path)
                self._assert_config_unchanged(snapshot)
                inbound = self._target_inbound(config)
                clients = self._clients(inbound)
                changed = False

                new_clients = [
                    client
                    for client in clients
                    if not (
                        isinstance(client, dict)
                        and ((uuid_value and client.get("id") == uuid_value) or (email_label and client.get("email") == email_label))
                    )
                ]
                if len(new_clients) != len(clients):
                    inbound["settings"]["clients"] = new_clients
                    changed = True
                if remove_short_id and short_id and self._remove_short_id(inbound, short_id):
                    changed = True

                if not changed:
                    return

                temp_path = self._write_temp_config(config, self.config_path)
                await self._test_config(temp_path)
                self._assert_config_unchanged(snapshot)
                self._replace_main_config(temp_path, self.config_path)
                await self._apply_or_restore(backup_path)
            except Exception:
                self._cleanup_temp(temp_path)
                raise

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, Any] | None:
        config = self._read_config(self.config_path)
        inbound = self._target_inbound(config)
        found = self._find_client_in_list(self._clients(inbound), uuid_value=uuid_value, email_label=email_label)
        return dict(found) if found is not None else None

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

    def _add_short_id(self, inbound: dict[str, Any], short_id: str) -> None:
        reality = self._reality_settings(inbound)
        short_ids = reality.setdefault("shortIds", [])
        if not isinstance(short_ids, list):
            raise XrayConfigError("Xray realitySettings.shortIds должен быть списком")
        if short_id not in short_ids:
            short_ids.append(short_id)

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
        if mode_from.exists():
            self._copy_stat(mode_from, temp_path)
        return temp_path

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
            self._copy_stat(mode_from, temp_path)
        os.replace(temp_path, self.config_path)
        self._fsync_parent(self.config_path)

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

    def _cleanup_temp(self, temp_path: Path | None) -> None:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)

    def _copy_stat(self, source: Path, target: Path) -> None:
        stat = source.stat()
        os.chmod(target, stat.st_mode)
        if os.name != "posix":
            return
        try:
            os.chown(target, stat.st_uid, stat.st_gid)
        except OSError:
            pass

    def _fsync_parent(self, path: Path) -> None:
        if os.name != "posix":
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        fd: int | None = None
        try:
            fd = os.open(path.parent, flags)
            os.fsync(fd)
        except OSError:
            pass
        finally:
            if fd is not None:
                os.close(fd)
