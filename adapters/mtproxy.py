
import asyncio
import json
import os
import re
import secrets as secrets_module
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.errors import MtProxyApplyError, MtProxyError, MtProxyRollbackError
from adapters.file_ops import fsync_parent
from adapters.privileged_helpers import (
    PrivilegedHelperRunner,
    cleanup_staging_path,
    create_private_staging_dir,
    write_private_staging_file,
)
from adapters.shell_runner import ShellRunner
from adapters.systemctl import SystemCtlAdapter
from models.dto import ShellResult

_MANAGED_RUNTIME_NOT_INITIALIZED = (
    "MTProto managed runtime is not initialized; run manual setup/preflight first"
)


@dataclass(frozen=True, slots=True)
class MtProxyManagedSecret:
    secret: str
    fingerprint: str
    owner_user_id: int | None = None
    access_id: int | None = None


@dataclass(frozen=True, slots=True)
class MtProxyApplyResult:
    changed: bool
    generation: int
    rollback_performed: bool = False


@dataclass(frozen=True, slots=True)
class MtProxyRuntimeStatus:
    systemd_active: bool | None
    port_listening: bool | None


class MtProxyAdapter:
    def __init__(
        self,
        *,
        shell: ShellRunner,
        systemctl: SystemCtlAdapter,
        service_name: str,
        binary_path: Path,
        run_user: str,
        run_group: str,
        proxy_secret_path: Path,
        proxy_multi_conf_path: Path,
        managed_secrets_path: Path,
        managed_env_path: Path,
        managed_wrapper_path: Path | None = None,
        backup_dir: Path | None = None,
        port: int,
        internal_stats_port: int | None,
        workers: int,
        apply_timeout_seconds: int,
        rollback_on_apply_failure: bool,
        keep_last_backups: int,
        helper_runner: PrivilegedHelperRunner | None = None,
        helper_path: Path | None = None,
        helper_staging_dir: Path | None = None,
    ) -> None:
        self.shell = shell
        self.systemctl = systemctl
        self.service_name = service_name
        self.binary_path = binary_path
        self.run_user = run_user
        self.run_group = run_group
        self.proxy_secret_path = proxy_secret_path
        self.proxy_multi_conf_path = proxy_multi_conf_path
        self.managed_secrets_path = managed_secrets_path
        self.managed_env_path = managed_env_path
        self.managed_wrapper_path = managed_wrapper_path
        self.backup_root = backup_dir or managed_secrets_path.parent / "backups"
        self.port = port
        self.internal_stats_port = internal_stats_port
        self.workers = workers
        self.apply_timeout_seconds = apply_timeout_seconds
        self.rollback_on_apply_failure = rollback_on_apply_failure
        self.keep_last_backups = keep_last_backups
        self.helper_runner = helper_runner
        self.helper_path = helper_path or Path("/usr/local/sbin/vpnbot-mtproxy-apply")
        self.helper_staging_dir = helper_staging_dir or Path("/run/vpn-bot/mtproxy")

    def read_current_managed_secrets(self) -> list[MtProxyManagedSecret]:
        document = self._read_store_document()
        return self._document_user_secrets(document)

    def read_runtime_managed_secrets(self) -> list[MtProxyManagedSecret]:
        document = self._read_store_document()
        items = document.get("runtime_secrets")
        if not isinstance(items, list):
            return self._document_user_secrets(document)
        secrets: list[MtProxyManagedSecret] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("purpose") == "empty-placeholder" or item.get("fingerprint") == "empty-placeholder":
                continue
            raw_secret = str(item.get("secret") or "")
            fingerprint = str(item.get("fingerprint") or "")
            if not raw_secret or not fingerprint:
                continue
            secrets.append(
                MtProxyManagedSecret(
                    secret=raw_secret,
                    fingerprint=fingerprint,
                    owner_user_id=self._optional_int(item.get("owner_user_id")),
                    access_id=self._optional_int(item.get("access_id")),
                )
            )
        return self._normalize_secrets(secrets)

    def write_managed_secrets_atomically(self, secrets: list[MtProxyManagedSecret]) -> None:
        current = self._read_store_document()
        document = self._store_document(secrets, current)
        self._atomic_write_text(self.managed_secrets_path, self._json_dump(document), mode=0o600)

    async def init_managed_runtime_baseline(self) -> MtProxyApplyResult:
        """Create an empty managed runtime baseline and verify mtproxy can run it.

        This is intended for deploy/manual setup. Normal issue/revoke requires this
        baseline to already exist, so the first user apply always has known-good
        files to roll back to.
        """
        self._ensure_wrapper_ready()
        current = self._read_store_document()
        generation = int(current.get("generation") or 0)
        document = self._store_document([], current, generation=generation)
        if self._using_helper():
            await self._apply_document_via_helper(document)
            return MtProxyApplyResult(changed=True, generation=generation)
        self._write_runtime_files(document)
        self.ensure_managed_permissions()
        restart = await self.restart_mtproxy()
        if not restart.ok:
            raise MtProxyApplyError("MTProxy baseline restart failed")
        if not await self.check_mtproxy_active():
            raise MtProxyApplyError("MTProxy baseline service is not active after restart")
        if not await self.check_mtproxy_listening():
            raise MtProxyApplyError("MTProxy baseline port is not listening after restart")
        return MtProxyApplyResult(changed=True, generation=generation)

    def ensure_managed_runtime_ready(self) -> bool:
        missing = [str(path) for path in self._managed_files() if not path.exists()]
        if missing:
            raise MtProxyApplyError(_MANAGED_RUNTIME_NOT_INITIALIZED)
        self._ensure_wrapper_ready()
        self._read_store_document()
        return self.ensure_managed_permissions()

    def ensure_managed_permissions(self) -> bool:
        changed = False
        changed = self._chmod_dir(self.managed_secrets_path.parent) or changed
        changed = self._chmod_dir(self.backup_root) or changed
        for target in self._managed_files():
            if target.exists():
                changed = self._chmod_file(target) or changed
        if self.backup_root.exists():
            for path in self.backup_root.rglob("*"):
                if path.is_dir():
                    changed = self._chmod_dir(path) or changed
                elif path.is_file():
                    changed = self._chmod_file(path, executable=os.access(path, os.X_OK)) or changed
        return changed

    def backup_managed_files(self) -> str:
        backup_id = f"{int(time.time())}-{time.time_ns()}-{secrets_module.token_hex(4)}"
        backup_dir = self._backup_dir(backup_id)
        backup_dir.mkdir(parents=True, exist_ok=False)
        self._chmod_dir(backup_dir)
        manifest: dict[str, Any] = {"version": 1, "files": []}
        for target in self._managed_files():
            backup_path: Path | None = None
            if target.exists():
                backup_path = backup_dir / target.name
                shutil.copy2(target, backup_path)
                self._chmod_file(backup_path, executable=os.access(target, os.X_OK))
            manifest["files"].append(
                {
                    "target": str(target),
                    "backup": str(backup_path) if backup_path is not None else None,
                }
            )
        self._atomic_write_text(backup_dir / "manifest.json", self._json_dump(manifest), mode=0o600)
        self._cleanup_old_backups()
        return backup_id

    def restore_backup(self, backup_id: str) -> None:
        backup_dir = self._backup_dir(backup_id)
        manifest_path = backup_dir / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise MtProxyRollbackError("MTProxy backup manifest not found or invalid") from exc
        for item in manifest.get("files", []):
            target = Path(str(item.get("target") or ""))
            backup_value = item.get("backup")
            if not target:
                continue
            if backup_value is None:
                raise MtProxyRollbackError("MTProxy backup is incomplete")
            backup_path = Path(str(backup_value))
            if not backup_path.exists():
                raise MtProxyRollbackError("MTProxy backup file is missing")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, target)
            self._chmod_file(target, executable=os.access(backup_path, os.X_OK))

    async def apply_managed_secrets(self, secrets: list[MtProxyManagedSecret]) -> MtProxyApplyResult:
        self.ensure_managed_runtime_ready()
        desired = self._normalize_secrets(secrets)
        current_document = self._read_store_document()
        current = self._document_user_secrets(current_document)
        current_generation = int(current_document.get("generation") or 0)
        current_runtime_document = self._store_document(current, current_document, generation=current_generation)
        if self._same_secret_set(current, desired) and self._runtime_files_current(current_runtime_document):
            return MtProxyApplyResult(changed=False, generation=current_generation)
        next_generation = current_generation + 1
        desired_document = self._store_document(desired, current_document, generation=next_generation)

        if self._using_helper():
            try:
                await self._apply_document_via_helper(desired_document)
            except Exception as exc:
                raise MtProxyApplyError(self._redact(f"MTProxy helper apply failed: {exc}", desired)) from exc
            return MtProxyApplyResult(changed=True, generation=next_generation)

        backup_id = self.backup_managed_files()
        try:
            self._write_runtime_files(desired_document)
            restart = await self.restart_mtproxy()
            if not restart.ok:
                raise MtProxyApplyError("MTProxy restart failed")
            if not await self.check_mtproxy_active():
                raise MtProxyApplyError("MTProxy service is not active after restart")
            if not await self.check_mtproxy_listening():
                raise MtProxyApplyError("MTProxy port is not listening after restart")
            return MtProxyApplyResult(changed=True, generation=next_generation)
        except Exception as exc:
            if not self.rollback_on_apply_failure:
                raise MtProxyApplyError(self._redact(f"MTProxy apply failed: {exc}", desired)) from exc
            rollback_error: Exception | None = None
            try:
                self.restore_backup(backup_id)
                await self.restart_mtproxy()
                if not await self.check_mtproxy_active():
                    raise MtProxyRollbackError("MTProxy rollback restart did not become active")
            except Exception as rollback_exc:
                rollback_error = rollback_exc
            if rollback_error is not None:
                message = self._redact(
                    f"MTProxy apply failed: {exc}; rollback failed: {rollback_error}",
                    desired,
                )
                raise MtProxyApplyError(message) from exc
            message = self._redact(f"MTProxy apply failed: {exc}; rollback restored previous files", desired)
            raise MtProxyApplyError(message) from exc

    async def restart_mtproxy(self) -> ShellResult:
        return await self.systemctl.restart(self.service_name)

    async def check_mtproxy_active(self) -> bool:
        result = await self.systemctl.is_active(self.service_name)
        return result.ok and result.stdout.strip() == "active"

    async def check_mtproxy_listening(self) -> bool:
        deadline = time.monotonic() + self.apply_timeout_seconds
        while True:
            if await self._check_mtproxy_listening_once():
                return True
            now = time.monotonic()
            if now >= deadline:
                return False
            await asyncio.sleep(min(0.25, deadline - now))
            if time.monotonic() >= deadline:
                return False

    async def _check_mtproxy_listening_once(self) -> bool:
        result = await self.shell.run(["ss", "-tlnp"], timeout=self.apply_timeout_seconds, max_output_chars=65536)
        if not result.ok:
            return False
        token = f":{self.port}"
        expected_names = {"mtproto-proxy", self.binary_path.name}
        active_without_process_info = False
        for line in result.stdout.splitlines():
            if token not in line or not self._line_has_listen_port(line):
                continue
            if any(name and name in line for name in expected_names):
                return True
            if "users:(" not in line:
                active_without_process_info = True
                continue
            return False
        return active_without_process_info and await self.check_mtproxy_active()

    async def runtime_status(self) -> MtProxyRuntimeStatus:
        if self._using_helper():
            result = await self._run_helper(["status"], timeout=self.apply_timeout_seconds)
            if not result.ok:
                return MtProxyRuntimeStatus(systemd_active=None, port_listening=None)
            tokens = set(result.stdout.split())
            return MtProxyRuntimeStatus(systemd_active="active" in tokens, port_listening="listening" in tokens)
        active: bool | None
        listening: bool | None
        try:
            active = await self.check_mtproxy_active()
        except Exception:
            active = None
        try:
            listening = await self.check_mtproxy_listening()
        except Exception:
            listening = None
        return MtProxyRuntimeStatus(systemd_active=active, port_listening=listening)

    def _managed_files(self) -> tuple[Path, ...]:
        return (
            self.managed_secrets_path,
            self.managed_env_path,
        )

    def _read_store_document(self) -> dict[str, Any]:
        try:
            data = json.loads(self.managed_secrets_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "generation": 0, "secrets": [], "runtime_secrets": []}
        except json.JSONDecodeError as exc:
            raise MtProxyError("MTProxy managed secrets file contains invalid JSON") from exc
        if not isinstance(data, dict):
            raise MtProxyError("MTProxy managed secrets file must be a JSON object")
        return data

    def _document_user_secrets(self, document: dict[str, Any]) -> list[MtProxyManagedSecret]:
        items = document.get("secrets")
        if not isinstance(items, list):
            return []
        secrets: list[MtProxyManagedSecret] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_secret = str(item.get("secret") or "")
            fingerprint = str(item.get("fingerprint") or "")
            if not raw_secret or not fingerprint:
                continue
            secrets.append(
                MtProxyManagedSecret(
                    secret=raw_secret,
                    fingerprint=fingerprint,
                    owner_user_id=self._optional_int(item.get("owner_user_id")),
                    access_id=self._optional_int(item.get("access_id")),
                )
            )
        return self._normalize_secrets(secrets)

    def _store_document(
        self,
        secrets: list[MtProxyManagedSecret],
        current_document: dict[str, Any],
        *,
        generation: int | None = None,
    ) -> dict[str, Any]:
        normalized = self._normalize_secrets(secrets)
        generation_value = int(current_document.get("generation") or 0) if generation is None else generation
        runtime_items = [self._secret_dict(item) for item in normalized]
        if not runtime_items:
            placeholder = self._empty_runtime_placeholder(current_document)
            runtime_items = [placeholder]
        return {
            "version": 1,
            "generation": generation_value,
            "managed_by": "vpn-bot",
            "secrets": [self._secret_dict(item) for item in normalized],
            "runtime_secrets": runtime_items,
        }

    def _empty_runtime_placeholder(self, current_document: dict[str, Any]) -> dict[str, Any]:
        for item in current_document.get("runtime_secrets", []):
            if isinstance(item, dict) and item.get("purpose") == "empty-placeholder" and item.get("secret"):
                return dict(item)
        secret = secrets_module.token_hex(16)
        return {
            "secret": secret,
            "fingerprint": "empty-placeholder",
            "purpose": "empty-placeholder",
        }

    def _runtime_files_current(self, document: dict[str, Any]) -> bool:
        return (
            self.managed_secrets_path.exists()
            and self.managed_env_path.exists()
            and self.managed_secrets_path.read_text(encoding="utf-8") == self._json_dump(document)
            and self.managed_env_path.read_text(encoding="utf-8") == self._env_content()
        )

    def _write_runtime_files(self, document: dict[str, Any]) -> None:
        self._atomic_write_text(self.managed_secrets_path, self._json_dump(document), mode=0o600)
        self._atomic_write_text(self.managed_env_path, self._env_content(), mode=0o600)
        self.ensure_managed_permissions()

    async def _apply_document_via_helper(self, document: dict[str, Any]) -> None:
        staging_dir: Path | None = None
        try:
            staging_dir = create_private_staging_dir(self.helper_staging_dir, prefix="apply-")
            write_private_staging_file(
                staging_dir,
                prefix="",
                suffix="managed-secrets.json",
                content=self._json_dump(document),
            ).rename(staging_dir / "managed-secrets.json")
            write_private_staging_file(
                staging_dir,
                prefix="",
                suffix="mtproxy.env",
                content=self._env_content(),
            ).rename(staging_dir / "mtproxy.env")
            result = await self._run_helper(["apply", str(staging_dir)], timeout=self.apply_timeout_seconds + 30)
            if not result.ok:
                raise MtProxyApplyError(f"MTProxy helper apply failed: rc={result.returncode}")
        finally:
            cleanup_staging_path(staging_dir)

    async def _run_helper(self, args: list[str], *, timeout: float) -> Any:
        if self.helper_runner is None:
            raise MtProxyApplyError("MTProxy privileged helper is not configured")
        return await self.helper_runner.run(
            self.helper_path,
            args,
            timeout=timeout,
            max_output_chars=2048,
        )

    def _using_helper(self) -> bool:
        return self.helper_runner is not None

    def _env_content(self) -> str:
        values = {
            "MTPROTO_BINARY_PATH": str(self.binary_path),
            "MTPROTO_RUN_USER": self.run_user,
            "MTPROTO_RUN_GROUP": self.run_group,
            "MTPROTO_PROXY_SECRET_PATH": str(self.proxy_secret_path),
            "MTPROTO_PROXY_MULTI_CONF_PATH": str(self.proxy_multi_conf_path),
            "MTPROTO_MANAGED_SECRETS_PATH": str(self.managed_secrets_path),
            "MTPROTO_PORT": str(self.port),
            "MTPROTO_INTERNAL_STATS_PORT": str(self.internal_stats_port or 8888),
            "MTPROTO_WORKERS": str(self.workers),
        }
        return "".join(f"{key}={value}\n" for key, value in values.items())

    def _json_dump(self, value: dict[str, Any]) -> str:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def _normalize_secrets(self, secrets: list[MtProxyManagedSecret]) -> list[MtProxyManagedSecret]:
        seen: set[str] = set()
        result: list[MtProxyManagedSecret] = []
        for item in sorted(secrets, key=lambda value: (value.fingerprint, value.secret)):
            self._validate_secret(item.secret)
            if item.fingerprint in seen:
                continue
            seen.add(item.fingerprint)
            result.append(item)
        return result

    def _same_secret_set(
        self,
        left: list[MtProxyManagedSecret],
        right: list[MtProxyManagedSecret],
    ) -> bool:
        left_pairs = {(item.fingerprint, item.secret, item.owner_user_id, item.access_id) for item in left}
        right_pairs = {(item.fingerprint, item.secret, item.owner_user_id, item.access_id) for item in right}
        return left_pairs == right_pairs

    def _secret_dict(self, item: MtProxyManagedSecret) -> dict[str, Any]:
        data: dict[str, Any] = {
            "secret": item.secret,
            "fingerprint": item.fingerprint,
        }
        if item.owner_user_id is not None:
            data["owner_user_id"] = item.owner_user_id
        if item.access_id is not None:
            data["access_id"] = item.access_id
        return data

    def _validate_secret(self, secret: str) -> None:
        if len(secret) != 32:
            raise MtProxyError("MTProto secret must be 32 hex characters")
        try:
            int(secret, 16)
        except ValueError as exc:
            raise MtProxyError("MTProto secret must be hex") from exc

    def _redact(self, text: str, secrets: list[MtProxyManagedSecret]) -> str:
        redacted = text
        for item in secrets:
            redacted = redacted.replace(item.secret, "***")
        return redacted

    def _backup_dir(self, backup_id: str) -> Path:
        return self.backup_root / backup_id

    def _cleanup_old_backups(self) -> None:
        root = self.backup_root
        if self.keep_last_backups <= 0 or not root.exists():
            return
        backups = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in backups[self.keep_last_backups :]:
            shutil.rmtree(path, ignore_errors=True)

    def _atomic_write_text(self, target: Path, content: str, *, mode: int) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        self._chmod_dir(target.parent)
        tmp_path = target.with_name(f".{target.name}.{time.time_ns()}.{secrets_module.token_hex(4)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(str(tmp_path), flags, mode)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, target)
            fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def _chmod_file(self, path: Path, *, executable: bool = False) -> bool:
        if os.name != "posix":
            return False
        mode = 0o700 if executable else 0o600
        try:
            current = path.stat().st_mode & 0o777
            if current == mode:
                return False
            path.chmod(mode)
            return True
        except OSError:
            return False

    def _chmod_dir(self, path: Path) -> bool:
        if os.name != "posix":
            return False
        try:
            path.mkdir(parents=True, exist_ok=True)
            current = path.stat().st_mode & 0o777
            if current == 0o700:
                return False
            path.chmod(0o700)
            return True
        except OSError:
            return False

    def _ensure_wrapper_ready(self) -> None:
        if self.managed_wrapper_path is None:
            return
        if not self.managed_wrapper_path.exists():
            raise MtProxyApplyError(_MANAGED_RUNTIME_NOT_INITIALIZED)
        if os.name == "posix":
            mode = self.managed_wrapper_path.stat().st_mode
            if mode & 0o111 == 0:
                raise MtProxyApplyError("MTProto managed wrapper is not executable")

    def _line_has_listen_port(self, line: str) -> bool:
        return re.search(rf":{re.escape(str(self.port))}(?:\s|$)", line) is not None

    def _optional_int(self, value: object) -> int | None:
        if value is None:
            return None
        try:
            return int(value)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return None
