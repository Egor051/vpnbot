"""SSH from the main server to a relay's agent (docs/relay.md).

* :class:`RelayKeyStore` — the bot's ONE key for every relay,
  ``/etc/vpn-bot/relay_ssh/id_ed25519`` (0600, owned by the bot's user), generated
  once with ``cryptography`` and never replaced. Read with the checks of the TOTP
  key: a regular file, no symlink, private to the bot's uid. In the helper-nonroot
  model, where the bot cannot write ``/etc/vpn-bot``, create it once as root
  (docs/relay.md).
* :class:`RelayAgentClient` — one call = one ``ssh`` process (OpenSSH client) with
  every option pinned on the command line (``-F /dev/null``: no user or system
  config), the bot's key only, no agent, no forwarding, no tty, batch mode. The
  relay's authorized_keys forces ``vpn-relay-agent`` anyway; the request is one of
  its whitelisted command lines, built here from validated values only.

Host keys: trust on first use. The pairing's first call runs with an empty
known_hosts and ``StrictHostKeyChecking=accept-new`` under ``HostKeyAlias``; the key
it learned is returned and pinned in ``relay_agents.host_key``. Every later call
writes that one key to a private temporary known_hosts and runs with
``StrictHostKeyChecking=yes`` — a relay that shows another key is refused
(:class:`RelayHostKeyMismatch`). The alias makes the pin independent of the address
(a relay re-addressed by DNS keeps its key).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.shell_runner import COMMAND_NOT_FOUND_RETURNCODE, TIMEOUT_RETURNCODE, ShellRunner
from config import validators
from services.errors import ServiceError

logger = logging.getLogger(__name__)

RELAY_SSH_DIR = Path("/etc/vpn-bot/relay_ssh")
KEY_COMMENT = "vpn-bot-relay"
_MAX_KEY_BYTES = 16 * 1024
_HOST_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) ([A-Za-z0-9+/]+={0,2})")
_ALIAS = re.compile(r"vpn-relay-[a-z0-9-]{1,40}")
# The whitelist of scripts/vpn-relay-agent, again: nothing else is ever sent.
_REQUEST = re.compile(
    r"hello [A-Za-z0-9_-]{43}|status|update|uninstall"
    r"|apply target=[A-Za-z0-9.-]{1,253} tcp=[0-9]{1,5}(?:,[0-9]{1,5}){0,7} udp=[0-9]{1,5}(?:,[0-9]{1,5}){0,7}"
)


class RelayKeyUnavailable(ServiceError):
    """The bot's relay key cannot be read or created."""


class RelaySshError(ServiceError):
    """The relay could not be reached over SSH (network, auth, host key)."""


class RelayHostKeyMismatch(RelaySshError):
    """The relay presented another host key than the one pinned at pairing."""


class RelayKeyStore:
    """The bot's ed25519 key for the relays (generated once, 0600)."""

    def __init__(self, directory: Path = RELAY_SSH_DIR) -> None:
        self.directory = directory
        self.key_path = directory / "id_ed25519"
        self.pub_path = directory / "id_ed25519.pub"

    def exists(self) -> bool:
        return os.path.lexists(self.key_path)

    def _read_private(self) -> bytes:
        try:
            fd = os.open(self.key_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise RelayKeyUnavailable("нет ключа relay", key="relay_key_missing") from None
        except OSError as exc:
            raise RelayKeyUnavailable("ключ relay недоступен", key="relay_key_unusable") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_KEY_BYTES:
                raise RelayKeyUnavailable("ключ relay не обычный файл", key="relay_key_unusable")
            if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
                logger.warning(
                    "Relay key %s: owner %s mode %o is not private to uid %s",
                    self.key_path, st.st_uid, st.st_mode & 0o777, os.geteuid(),
                )
                raise RelayKeyUnavailable("ключ relay не приватный", key="relay_key_unusable")
            return os.read(fd, _MAX_KEY_BYTES + 1)
        finally:
            os.close(fd)

    def public_key(self) -> str:
        """``ssh-ed25519 AAAA…`` of the existing key (derived from the private key)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        try:
            key = serialization.load_ssh_private_key(self._read_private(), password=None)
        except (ValueError, TypeError) as exc:
            raise RelayKeyUnavailable("ключ relay повреждён", key="relay_key_unusable") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise RelayKeyUnavailable("ключ relay не ed25519", key="relay_key_unusable")
        return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()

    def ensure(self) -> str:
        """The public key; the key pair is generated first if there is none (never replaced)."""
        if self.exists():
            return self.public_key()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return self.public_key()
        except OSError as exc:
            logger.warning("Relay key %s cannot be created: %s", self.key_path, exc)
            raise RelayKeyUnavailable("не удалось создать ключ relay", key="relay_key_create_failed") from exc
        try:
            os.write(fd, private)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            self.pub_path.write_bytes(public + f" {KEY_COMMENT}\n".encode())
            os.chmod(self.pub_path, 0o644)
        except OSError:
            logger.warning("Relay public key %s could not be written (the private key is fine)", self.pub_path)
        logger.info("Relay SSH key created at %s", self.key_path)
        return public.decode()


@dataclass(frozen=True, slots=True)
class AgentReply:
    """One answer of the agent: its exit code and JSON (``{}`` when there was none)."""

    returncode: int
    payload: dict[str, Any]
    # The host key learned on a trust-on-first-use call: "<type> <base64>".
    learned_host_key: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.payload.get("ok") is True

    @property
    def error(self) -> str:
        value = self.payload.get("error")
        return str(value) if value else f"agent exit {self.returncode}"


def valid_ssh_host(host: str) -> bool:
    """A DNS name or an IPv4 address — never something ssh could read as an option."""
    try:
        return bool(validators.dns_name_or_ipv4("host", host)) and not host.startswith("-")
    except validators.InvalidValue:
        return False


def parse_host_key(value: str) -> str:
    match = _HOST_KEY.fullmatch((value or "").strip())
    if match is None:
        raise RelaySshError("непонятный ключ хоста", key="relay_ssh_bad_host_key")
    return f"{match[1]} {match[2]}"


class RelayAgentClient:
    """Runs one whitelisted agent request on a relay over ssh."""

    def __init__(
        self,
        runner: ShellRunner,
        keys: RelayKeyStore,
        *,
        ssh_binary: str = "ssh",
        work_dir: Path | None = None,
        connect_timeout: int = 10,
    ) -> None:
        self.runner = runner
        self.keys = keys
        self.ssh_binary = ssh_binary
        self.work_dir = work_dir
        self.connect_timeout = connect_timeout

    def argv(self, host: str, port: int, request: str, *, alias: str, known_hosts: Path, pinned: bool) -> list[str]:
        if not valid_ssh_host(host):
            raise RelaySshError(f"{host!r} — не DNS-имя и не IPv4", key="relay_ssh_bad_host")
        if not 1 <= port <= 65535:
            raise RelaySshError("порт ssh вне 1..65535", key="relay_ssh_bad_host")
        if _REQUEST.fullmatch(request) is None:
            raise RelaySshError("запрос не из списка агента", key="relay_ssh_bad_request")
        if _ALIAS.fullmatch(alias) is None:
            raise RelaySshError("плохой alias", key="relay_ssh_bad_request")
        options = {
            "BatchMode": "yes",
            "IdentitiesOnly": "yes",
            "IdentityAgent": "none",
            "PubkeyAuthentication": "yes",
            "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no",
            "UserKnownHostsFile": str(known_hosts),
            "GlobalKnownHostsFile": "/dev/null",
            "HostKeyAlias": alias,
            "StrictHostKeyChecking": "yes" if pinned else "accept-new",
            "CheckHostIP": "no",
            "UpdateHostKeys": "no",
            "HashKnownHosts": "no",
            "ConnectTimeout": str(self.connect_timeout),
            "ServerAliveInterval": "10",
            "ServerAliveCountMax": "3",
            "ForwardAgent": "no",
            "ForwardX11": "no",
            "ClearAllForwardings": "yes",
            "RequestTTY": "no",
            "ControlMaster": "no",
            "ControlPath": "none",
            "LogLevel": "ERROR",
        }
        argv = [self.ssh_binary, "-F", "/dev/null", "-i", str(self.keys.key_path), "-p", str(port), "-l", "root"]
        for name, value in options.items():
            argv += ["-o", f"{name}={value}"]
        return [*argv, "--", host, request]

    async def call(
        self,
        host: str,
        port: int,
        request: str,
        *,
        alias: str,
        host_key: str | None,
        timeout: float = 60.0,
        sensitive: Sequence[str] = (),
    ) -> AgentReply:
        """Run *request*; ``host_key=None`` = the trust-on-first-use call of a pairing."""
        self.keys.public_key()  # fails early, with a clear reason, without a usable key
        work = Path(tempfile.mkdtemp(prefix="relay-ssh-", dir=self.work_dir))
        try:
            os.chmod(work, 0o700)
            known_hosts = work / "known_hosts"
            if host_key is None:
                known_hosts.write_text("", encoding="utf-8")
            else:
                pinned_key = parse_host_key(host_key)
                known_hosts.write_text(f"{alias} {pinned_key}\n[{alias}]:{port} {pinned_key}\n", encoding="utf-8")
            argv = self.argv(host, port, request, alias=alias, known_hosts=known_hosts, pinned=host_key is not None)
            result = await self.runner.run(argv, timeout=timeout, sensitive_values=sensitive, max_output_chars=200_000)
            learned = None
            if host_key is None:
                learned = _learned_key(known_hosts.read_text(encoding="utf-8"), alias)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if result.returncode == COMMAND_NOT_FOUND_RETURNCODE:
            raise RelaySshError("нет ssh-клиента на сервере (apt install openssh-client)", key="relay_ssh_no_client")
        if result.returncode == TIMEOUT_RETURNCODE:
            raise RelaySshError("relay не ответил вовремя", key="relay_ssh_timeout")
        if result.returncode == 255:
            stderr = result.stderr.strip()
            if "Host key verification failed" in stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
                raise RelayHostKeyMismatch(
                    "ключ хоста relay не совпадает с закреплённым", key="relay_ssh_host_key_changed"
                )
            raise RelaySshError(
                f"ssh: {stderr.splitlines()[-1] if stderr else 'ошибка соединения'}",
                key="relay_ssh_failed",
                params={"error": stderr.splitlines()[-1][:300] if stderr else "—"},
            )
        payload = _last_json(result.stdout)
        return AgentReply(returncode=result.returncode, payload=payload, learned_host_key=learned)


def _learned_key(text: str, alias: str) -> str | None:
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and (fields[0] == alias or fields[0].startswith(f"[{alias}]:")):
            try:
                return parse_host_key(f"{fields[1]} {fields[2]}")
            except RelaySshError:
                return None
    return None


def _last_json(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            return data if isinstance(data, dict) else {}
    return {}
