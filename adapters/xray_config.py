
import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable
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
from adapters.validation import reject_option_like
from adapters.xray_stats import MACHINE_OUTPUT_LIMIT as STATS_MAX_OUTPUT_CHARS
from adapters.xray_stats import XrayStatsAdapter
from utils.redact import redact


logger = logging.getLogger(__name__)

# Allows printable email-safe characters; leading '-' is forbidden to prevent
# flag injection when email_label is passed as a positional CLI argument.
_EMAIL_SAFE_RE = re.compile(r'^[a-zA-Z0-9@._+][a-zA-Z0-9@._+-]*$')


@dataclass(frozen=True, slots=True)
class XrayClientApplyResult:
    short_id_inserted: bool = False


def _vless_inbound_present(config_path: Path, inbound_tag: str, *, require_reality: bool) -> bool:
    """Return True if *config_path* has a VLESS inbound tagged *inbound_tag*.

    Read once at startup to decide whether to build the optional second (XHTTP)
    adapter from what is *actually* in config.json — independently of any feature
    flag — so already-issued keys on that inbound stay manageable. Any error
    (missing file, broken JSON, unexpected shape) is treated as "absent" so a
    misconfiguration never aborts startup. Mirrors ``_is_vless_reality`` /
    ``_is_vless`` depending on *require_reality*.
    """
    if not inbound_tag:
        return False
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    inbounds = data.get("inbounds")
    if not isinstance(inbounds, list):
        return False
    for inbound in inbounds:
        if isinstance(inbound, dict) and inbound.get("tag") == inbound_tag:
            if not isinstance(inbound.get("settings"), dict) or inbound.get("protocol") != "vless":
                return False
            if not require_reality:
                return True
            stream = inbound.get("streamSettings")
            return isinstance(stream, dict) and stream.get("security") == "reality"
    return False


def vless_reality_inbound_present(config_path: Path, inbound_tag: str) -> bool:
    """Return True if *config_path* has a VLESS/REALITY inbound tagged *inbound_tag*."""
    return _vless_inbound_present(config_path, inbound_tag, require_reality=True)


def vless_inbound_present(config_path: Path, inbound_tag: str) -> bool:
    """Return True if *config_path* has a VLESS inbound tagged *inbound_tag*, REALITY or not.

    Used to build the XHTTP adapter from the inbound's *presence* rather than its
    security: in the fallback topology the XHTTP inbound (``vless-xhttp-reality``)
    is the dest of vless-in's REALITY fallback and itself carries ``security:
    none`` — it holds only ``settings.clients`` for routing, no REALITY.
    """
    return _vless_inbound_present(config_path, inbound_tag, require_reality=False)


# Protocol of the direct-egress outbound that WARP binds to the tunnel IP.
FREEDOM_OUTBOUND_PROTOCOL = "freedom"


def apply_warp_send_through(config: dict[str, Any], tunnel_ip: str | None) -> bool:
    """Bind every ``freedom`` outbound's egress source to the WARP tunnel IP.

    config.json is rewritten by the bot on every client change, so a hand-added
    ``sendThrough`` would be lost; the writer re-asserts it here instead. When
    *tunnel_ip* is a non-empty string, each outbound with ``protocol == "freedom"``
    gets ``"sendThrough": tunnel_ip`` so Xray sources its direct egress from the
    tunnel address (which ``vpnbot-warp-routes`` diverts into the tunnel). When
    *tunnel_ip* is falsy the field is removed again, leaving a disabled/non-WARP
    deploy clean.

    Only OUTBOUNDS are touched — never inbounds — so the hybrid build (REALITY from
    ``vless-in``, transport from the XHTTP inbound) is unaffected. Returns whether
    the config changed.
    """
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return False
    changed = False
    for outbound in outbounds:
        if not isinstance(outbound, dict) or outbound.get("protocol") != FREEDOM_OUTBOUND_PROTOCOL:
            continue
        if tunnel_ip:
            if outbound.get("sendThrough") != tunnel_ip:
                outbound["sendThrough"] = tunnel_ip
                changed = True
        elif "sendThrough" in outbound:
            del outbound["sendThrough"]
            changed = True
    return changed


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
        require_reality: bool = True,
        warp_send_through: Callable[[], str | None] | None = None,
    ) -> None:
        if config_path.is_symlink():
            raise XrayConfigError("Xray config path не должен быть symlink. Укажите реальный путь к config.json.")
        self.config_path = config_path
        # Reject option-like service/tag names: both reach a subprocess argv slot
        # (systemctl <service>, xray api rmi ... <tag>) where a leading '-' would be
        # parsed as a flag.
        reject_option_like(service_name, "XRAY_SERVICE_NAME", error=XrayConfigError)
        if inbound_tag:
            reject_option_like(inbound_tag, "XRAY_INBOUND_TAG", error=XrayConfigError)
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
        # When False the target inbound is a plain VLESS inbound without REALITY
        # (the XHTTP fallback dest): accept it by tag and never touch REALITY-only
        # state (shortIds), which does not exist there.
        self.require_reality = require_reality
        self.allow_restart_on_rollback = allow_restart_on_rollback
        self.backup = backup
        self.systemctl = systemctl
        self.shell = shell
        self.stats_server = stats_server
        self.helper_runner = helper_runner
        self.helper_path = helper_path or Path("/usr/local/sbin/vpnbot-xray-apply")
        self.helper_staging_dir = helper_staging_dir or Path("/run/vpn-bot/xray")
        # Optional provider of the WARP tunnel IP. When set, every config write binds
        # the freedom outbound's egress source to it (sendThrough); when it yields
        # None the field is stripped. Left None on non-WARP deploys (outbounds are
        # then never touched). See ``apply_warp_send_through``.
        self._warp_send_through = warp_send_through
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
                    # Pure client add: reload the inbound via the API. A shortId insert
                    # instead takes the systemctl path (below), so it is excluded here.
                    await self._install_candidate_api(temp_path, snapshot, backup_path, action="add")
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
                    # Pure client remove: reload the inbound via the API. A shortId removal
                    # instead takes the systemctl path (below).
                    await self._install_candidate_api(temp_path, snapshot, backup_path, action="remove")
                else:
                    await self._install_candidate(temp_path, snapshot, backup_path)
            finally:
                self._cleanup_temp(temp_path)

    async def rename_clients(self, renames: dict[str, str], *, prefer_restart: bool = False) -> int:
        """Rename clients (matched by UUID) to new email labels and apply once.

        *renames* maps client UUID -> desired email label. Only clients present on
        THIS inbound whose email actually differs are changed; the UUID — the
        client's identity — is never touched. Returns how many clients were
        renamed. A no-op (nothing to change) returns 0 without writing the config
        or restarting Xray, so this is safe to run on every startup. Applies
        through the standard install path (snapshot + backup + ``xray -test`` +
        helper/reload/restart): the live config is never edited in place.

        When *prefer_restart* is True the direct (non-helper) apply is routed
        through ``systemctl restart`` instead of ``reload`` — used by the startup
        reconcile because a plain ``reload`` does not rebuild this unit's runtime
        client table, so renamed labels would never reach the live inbound. The
        restart resets Xray's per-email stats (accepted trade-off). After a
        restart-applied rename the runtime is verified best-effort against
        ``xray api statsquery`` (logged, never raised). It has no effect when a
        privileged helper performs the apply.
        """
        if not renames:
            return 0
        # Defence-in-depth: every target label is server-generated, but enforce the
        # safe charset at the adapter boundary so a malformed label can never reach
        # the config (mirrors add_client). Leading '-' is rejected (flag injection).
        for new_email in renames.values():
            if not new_email or _EMAIL_SAFE_RE.match(new_email) is None:
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
                renamed = 0
                # Labels of clients that actually exist on this inbound (matched by
                # UUID) — what the running Xray should expose after the apply. Unknown
                # UUIDs in *renames* are not collected, so verification stays quiet.
                present_labels: set[str] = set()
                for client in clients:
                    if not isinstance(client, dict):
                        continue
                    uuid_value = client.get("id")
                    if not isinstance(uuid_value, str):
                        continue
                    desired = renames.get(uuid_value)
                    if not desired:
                        continue
                    present_labels.add(desired)
                    if client.get("email") != desired:
                        client["email"] = desired
                        renamed += 1
                if renamed == 0:
                    return 0

                temp_path = await self._write_temp_config(config, self.config_path)
                await self._install_candidate(temp_path, snapshot, backup_path, prefer_restart=prefer_restart)
                if prefer_restart:
                    await self._verify_runtime_labels(present_labels)
                return renamed
            finally:
                self._cleanup_temp(temp_path)

    async def ensure_short_id(self, short_id: str) -> bool:
        """Add the short id to the inbound if missing and apply the config."""
        if not short_id or not self.require_reality:
            # No REALITY shortIds to manage on the XHTTP fallback dest.
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
        if not self.require_reality:
            # The XHTTP fallback dest carries no REALITY/shortIds of its own.
            return set()
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
            return stat.st_mtime_ns, stat.st_size, hashlib.blake2b(raw).digest()
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
            # mtime+size match: verify a hash of the WHOLE file to catch same-size
            # same-mtime substitutions anywhere in the config (not just the first 64 KiB).
            try:
                current_raw = self.config_path.read_bytes()
            except FileNotFoundError as exc:
                raise XrayConfigError(f"Xray config не найден: {self.config_path}") from exc
            if hashlib.blake2b(current_raw).digest() != expected_hash:
                raise XrayConfigError("Xray config изменился во время операции. Изменения не применены.")

        await asyncio.to_thread(_do)

    def _target_inbound(self, config: dict[str, Any]) -> dict[str, Any]:
        inbounds = config.get("inbounds")
        if not isinstance(inbounds, list):
            raise XrayInboundNotFoundError("В Xray config не найден список inbounds")

        if self.inbound_tag:
            for inbound in inbounds:
                if isinstance(inbound, dict) and inbound.get("tag") == self.inbound_tag:
                    if not self._is_target_inbound(inbound):
                        kind = "VLESS/REALITY" if self.require_reality else "VLESS"
                        raise XrayInboundNotFoundError(
                            f"Xray inbound tag={self.inbound_tag!r} найден, но это не {kind} inbound"
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

    def _is_target_inbound(self, inbound: dict[str, Any]) -> bool:
        return self._is_vless_reality(inbound) if self.require_reality else self._is_vless(inbound)

    def _is_vless(self, inbound: dict[str, Any]) -> bool:
        return inbound.get("protocol") == "vless" and isinstance(inbound.get("settings"), dict)

    def _is_vless_reality(self, inbound: dict[str, Any]) -> bool:
        stream = inbound.get("streamSettings")
        return (
            self._is_vless(inbound)
            and isinstance(stream, dict)
            and stream.get("security") == "reality"
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
        # Re-assert (or strip) the WARP egress source-bind on the freedom outbound so
        # it survives the bot's config rewrites. No-op on non-WARP deploys.
        if self._warp_send_through is not None:
            try:
                tunnel_ip = self._warp_send_through()
            except Exception:
                logger.warning(
                    "WARP sendThrough provider raised; leaving freedom outbound egress unchanged",
                    exc_info=True,
                )
            else:
                apply_warp_send_through(config, tunnel_ip)
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
        *,
        prefer_restart: bool = False,
    ) -> None:
        if self._using_helper():
            # The privileged helper owns the apply (and its own reload/restart);
            # prefer_restart never crosses the privilege boundary.
            await self._assert_config_unchanged(snapshot)
            await self._apply_helper(temp_path, snapshot)
            return
        if backup_path is None:
            raise XrayApplyError("Xray backup is not available for direct apply")
        await self._test_config(temp_path)
        await self._assert_config_unchanged(snapshot)
        await self._replace_main_config(temp_path, self.config_path)
        await self._apply_or_restore(backup_path, prefer_restart=prefer_restart)

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

    async def _apply_or_restore(self, backup_path: Path, *, prefer_restart: bool = False) -> None:
        # prefer_restart lets a caller (the startup reconcile) force the restart path
        # for a unit whose `reload` does not rebuild the runtime client table.
        if self.apply_mode == "restart" or prefer_restart:
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

    async def _verify_runtime_labels(self, email_labels: set[str]) -> None:
        """Log whether the restarted runtime exposes a traffic stat per renamed label.

        After a restart-applied rename the running Xray should expose a per-user
        counter (``user>>>{email_label}>>>traffic>>>...``) for every client we
        renamed. This is a best-effort diagnostic only: a missing counter (e.g. an
        idle user whose counter Xray has not created yet, or no stats API on this
        deploy) is logged, never raised, so a stats hiccup can't undo a rename that
        already applied successfully.
        """
        if not email_labels:
            return
        if self.shell is None or not self.stats_server:
            logger.debug("Xray rename applied via restart; stats API not configured, skipping verification")
            return
        try:
            result = await self.shell.run(
                ["xray", "api", "statsquery", f"--server={self.stats_server}"],
                timeout=15,
                max_output_chars=STATS_MAX_OUTPUT_CHARS,
            )
            if not result.ok:
                logger.warning(
                    "Xray rename applied via restart, but stats verification query failed: %s",
                    result.stderr or result.stdout,
                )
                return
            counters = XrayStatsAdapter.parse_statsquery_output(result.stdout)
        except Exception:
            logger.warning("Xray rename applied via restart, but stats verification raised", exc_info=True)
            return
        present = {
            label
            for label in email_labels
            if any(name.startswith(f"user>>>{label}>>>traffic>>>") for name in counters)
        }
        missing = sorted(email_labels - present)
        if missing:
            logger.warning(
                "Xray rename verified via statsquery: %d/%d labels present in runtime; missing=%s",
                len(present), len(email_labels), missing,
            )
        else:
            logger.info(
                "Xray rename verified via statsquery: all %d labels present in runtime",
                len(email_labels),
            )

    async def _install_candidate_api(
        self,
        temp_path: Path,
        snapshot: tuple[int, int, bytes],
        backup_path: Path | None,
        *,
        action: str,
    ) -> None:
        """Apply a pure client add/remove in ``api`` mode by rebuilding the inbound.

        Only client-list edits reach here: shortId changes and renames deliberately take
        the ``systemctl`` reload/restart path (see the call sites), because a live
        ``rmi`` + ``adi`` would disrupt REALITY state for what are rare structural edits.
        So this just replaces config.json and reloads the inbound via ``_api_reload_inbound``
        (rmi + adi). ``action`` ("add"/"remove") only labels the error on failure.
        """
        if backup_path is None:
            raise XrayApplyError("Xray backup is not available for API apply")
        await self._test_config(temp_path)
        await self._assert_config_unchanged(snapshot)
        await self._replace_main_config(temp_path, self.config_path)
        try:
            await self._api_reload_inbound()
        except Exception as exc:
            await asyncio.to_thread(self.backup.restore, backup_path, self.config_path, mode_from=self.config_path)
            # After rmi+adi failure the inbound may be absent from runtime; adi with the
            # just-restored disk config brings it back.
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
                raise XrayApplyError(f"xray api adi failed: {redact(adi_result.stderr or adi_result.stdout)}")
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    def _cleanup_temp(self, temp_path: Path | None) -> None:
        cleanup_staging_path(temp_path)

    def _using_helper(self) -> bool:
        return self.helper_runner is not None
