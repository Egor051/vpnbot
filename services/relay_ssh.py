"""SSH from the main server to a relay's agent (docs/relay.md).

* :class:`RelayKeyStore` — the bot's ONE key for every relay,
  ``/etc/vpn-bot/relay_ssh/id_ed25519`` (0600, owned by the bot's user), generated
  once with ``cryptography`` and never replaced. Read with the checks of the TOTP
  key: a regular file, no symlink, private to the bot's uid. In the helper-nonroot
  model, where the bot cannot write ``/etc/vpn-bot``, create it once as root
  (docs/relay.md). The JUMP key (:func:`jump_key_store`,
  ``/etc/vpn-bot/relay_ssh/id_ed25519_jump``) is a second key of the same model:
  it only opens the way THROUGH the hub (below) and never reaches an agent.
* :class:`RelayAgentClient` — one call = one ``ssh`` process (OpenSSH client) with
  every option pinned on the command line (``-F /dev/null``: no user or system
  config), the bot's key only, no agent, no forwarding, no tty, batch mode. The
  relay's authorized_keys forces ``vpn-relay-agent`` anyway; the request is one of
  its whitelisted command lines, built here from validated values only.

Host keys: trust on first use. The pairing's first call runs with an empty
known_hosts and ``StrictHostKeyChecking=accept-new`` under ``HostKeyAlias``; the key
it learned is returned and pinned in ``relays.host_key``. Every later call
writes that one key to a private temporary known_hosts and runs with
``StrictHostKeyChecking=yes`` — a relay that shows another key is refused
(:class:`RelayHostKeyMismatch`). The alias makes the pin independent of the address
(a relay re-addressed by DNS keeps its key).

THROUGH THE HUB (:class:`JumpHost`). The TSPU cuts SSH from the main server to the
RU relays in the fallback mode; the hub still reaches both. A call ``via`` a hub is
the same ssh to the relay with a ``ProxyCommand`` — a second, fully pinned ``ssh``
(``-F /dev/null``, the SAME option set, the JUMP key, the hub's own alias and pinned
host key, ``StrictHostKeyChecking=yes`` always) that only runs ``-W <relay>:<port>``.
Not ``-J``: ProxyJump starts the jump ssh with defaults (``~/.ssh``, any identity)
that cannot be pinned. The relay's hop keeps its own alias, key and known_hosts:
the session on the relay is an ordinary agent session (a NEW one — the proof
``vpn-relay-apply input-confirm`` wants). On the hub the jump key's ONE line is

    restrict,port-forwarding,permitopen="<relay>:<port>"[,...],command="/bin/false" ssh-ed25519 …

written by the hub's agent (``jump key=… open=…``): no shell, no pty, forwarding
only to the relays the bot lists — and the client refuses a target that is not in
that list (:attr:`JumpHost.opens`) before any process starts.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import stat
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.shell_runner import COMMAND_NOT_FOUND_RETURNCODE, TIMEOUT_RETURNCODE, ShellRunner
from config import validators
from services.errors import ServiceError

logger = logging.getLogger(__name__)

RELAY_SSH_DIR = Path("/etc/vpn-bot/relay_ssh")
KEY_NAME = "id_ed25519"
KEY_COMMENT = "vpn-bot-relay"
# The jump key: the hub lets it forward to the relays behind it, nothing else.
JUMP_KEY_NAME = "id_ed25519_jump"
JUMP_KEY_COMMENT = "vpn-bot-relay-jump"
_MAX_KEY_BYTES = 16 * 1024
_HOST_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) ([A-Za-z0-9+/]+={0,2})")
_ALIAS = re.compile(r"vpn-relay-[a-z0-9-]{1,40}")
# What ProxyCommand runs in: ssh hands it to $SHELL -c, and the bot's own $SHELL may
# be /usr/sbin/nologin (deploy/create-vpn-bot-user.sh).
PROXY_SHELL = "/bin/sh"
# The longest request (MAX_REQUEST of scripts/vpn-relay-agent): a `jump` list.
MAX_REQUEST = 4096
# At most this many relays behind one hub (MAX_JUMP_OPEN of scripts/vpn-relay-agent).
MAX_JUMP_OPEN = 32
# An ed25519 public key's base64 blob: "ssh-ed25519" + 32 bytes, always 68 characters.
_ED25519_BLOB = r"AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}"
_JUMP_OPEN = r"[A-Za-z0-9.-]{1,253}:[0-9]{1,5}"
# The whitelist of scripts/vpn-relay-agent, again: nothing else is ever sent.
# tests/test_relay_jump.py runs both on the same requests.
_REQUEST = re.compile(
    r"hello [A-Za-z0-9_-]{43}|status|update|uninstall|input-confirm|jump-off"
    r"|ssh-port-finish port=[0-9]{1,5} since=[0-9]{1,12}|ssh-port-keep since=[0-9]{1,12}"
    r"|ssh-port-resume since=[0-9]{1,12}|ssh-port-set port=[0-9]{1,5}"
    r"|apply target=[A-Za-z0-9.-]{1,253} tcp=[0-9]{1,5}(?:,[0-9]{1,5}){0,7} udp=[0-9]{1,5}(?:,[0-9]{1,5}){0,7}"
    rf"|jump key={_ED25519_BLOB} open={_JUMP_OPEN}(?:,{_JUMP_OPEN}){{0,{MAX_JUMP_OPEN - 1}}}"
)


class RelayKeyUnavailable(ServiceError):
    """The bot's relay key cannot be read or created."""


class RelaySshError(ServiceError):
    """The relay could not be reached over SSH (network, auth, host key)."""


class RelayHostKeyMismatch(RelaySshError):
    """The relay presented another host key than the one pinned at pairing."""


class RelayKeyStore:
    """An ed25519 key of the bot for the relays (generated once, 0600).

    The agent key by default; :func:`jump_key_store` is the jump key, the same model
    next to it.
    """

    def __init__(self, directory: Path = RELAY_SSH_DIR, *, name: str = KEY_NAME, comment: str = KEY_COMMENT) -> None:
        self.directory = directory
        self.comment = comment
        self.key_path = directory / name
        self.pub_path = directory / f"{name}.pub"

    def _unavailable(self, message: str, key: str) -> RelayKeyUnavailable:
        return RelayKeyUnavailable(message, key=key, params={"path": str(self.key_path)})

    def exists(self) -> bool:
        return os.path.lexists(self.key_path)

    def _read_private(self) -> bytes:
        try:
            fd = os.open(self.key_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise self._unavailable("нет ключа relay", "relay_key_missing") from None
        except OSError as exc:
            raise self._unavailable("ключ relay недоступен", "relay_key_unusable") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_KEY_BYTES:
                raise self._unavailable("ключ relay не обычный файл", "relay_key_unusable")
            if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
                logger.warning(
                    "Relay key %s: owner %s mode %o is not private to uid %s",
                    self.key_path, st.st_uid, st.st_mode & 0o777, os.geteuid(),
                )
                raise self._unavailable("ключ relay не приватный", "relay_key_unusable")
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
            raise self._unavailable("ключ relay повреждён", "relay_key_unusable") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise self._unavailable("ключ relay не ed25519", "relay_key_unusable")
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
            raise self._unavailable("не удалось создать ключ relay", "relay_key_create_failed") from exc
        try:
            os.write(fd, private)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            self.pub_path.write_bytes(public + f" {self.comment}\n".encode())
            os.chmod(self.pub_path, 0o644)
        except OSError:
            logger.warning("Relay public key %s could not be written (the private key is fine)", self.pub_path)
        logger.info("Relay SSH key created at %s", self.key_path)
        return public.decode()


def jump_key_store(directory: Path = RELAY_SSH_DIR) -> RelayKeyStore:
    """The bot's jump key: ``<directory>/id_ed25519_jump``, the agent key's model."""
    return RelayKeyStore(directory, name=JUMP_KEY_NAME, comment=JUMP_KEY_COMMENT)


@dataclass(frozen=True, slots=True)
class JumpHost:
    """The hub a call goes through: where its sshd answers, its pinned host key (it
    is a relay with an agent — the same TOFU pin), and the relays its jump line
    opens. The client refuses a target outside *opens* before any process starts."""

    host: str
    port: int
    alias: str
    host_key: str
    opens: frozenset[tuple[str, int]]


def jump_request(public_key: str, opens: Iterable[tuple[str, int]]) -> str:
    """The hub agent's request for the jump line: ``jump key=<blob> open=<h:p>,…``
    (sorted, unique) — or ``jump-off`` when nothing is behind the hub."""
    fields = (public_key or "").split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519" or re.fullmatch(_ED25519_BLOB, fields[1]) is None:
        raise RelaySshError("jump-ключ не ssh-ed25519", key="relay_ssh_bad_request")
    entries = sorted({(host.lower(), int(port)) for host, port in opens})
    if not entries:
        return "jump-off"
    if len(entries) > MAX_JUMP_OPEN:
        raise RelaySshError(
            f"за hub больше {MAX_JUMP_OPEN} relay", key="relay_jump_too_many", params={"count": len(entries)}
        )
    for host, port in entries:
        if not valid_ssh_host(host) or not 1 <= port <= 65535:
            raise RelaySshError(f"{host}:{port} — не адрес relay", key="relay_ssh_bad_host")
    request = f"jump key={fields[1]} open=" + ",".join(f"{host}:{port}" for host, port in entries)
    if len(request) > MAX_REQUEST or _REQUEST.fullmatch(request) is None:
        raise RelaySshError("список jump не помещается в запрос", key="relay_jump_too_many",
                            params={"count": len(entries)})
    return request


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
    """Runs one whitelisted agent request on a relay over ssh (directly, or via a hub)."""

    def __init__(
        self,
        runner: ShellRunner,
        keys: RelayKeyStore,
        *,
        jump_keys: RelayKeyStore | None = None,
        ssh_binary: str = "ssh",
        work_dir: Path | None = None,
        connect_timeout: int = 10,
    ) -> None:
        self.runner = runner
        self.keys = keys
        self.jump_keys = jump_keys
        self.ssh_binary = ssh_binary
        self.work_dir = work_dir
        self.connect_timeout = connect_timeout

    def _options(self, *, known_hosts: Path, alias: str, strict: bool) -> dict[str, str]:
        """THE option set of every hop (the relay's and the hub's alike)."""
        return {
            "BatchMode": "yes",
            "IdentitiesOnly": "yes",
            "IdentityAgent": "none",
            "PubkeyAuthentication": "yes",
            "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no",
            "UserKnownHostsFile": str(known_hosts),
            "GlobalKnownHostsFile": "/dev/null",
            "HostKeyAlias": alias,
            "StrictHostKeyChecking": "yes" if strict else "accept-new",
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

    @staticmethod
    def _check_target(host: str, port: int) -> None:
        if not valid_ssh_host(host):
            raise RelaySshError(f"{host!r} — не DNS-имя и не IPv4", key="relay_ssh_bad_host")
        if not 1 <= port <= 65535:
            raise RelaySshError("порт ssh вне 1..65535", key="relay_ssh_bad_host")

    def jump_argv(self, jump: JumpHost, host: str, port: int, *, known_hosts: Path) -> list[str]:
        """The hub's hop: ``ssh … -W <relay>:<port> -- <hub>`` with the jump key, the
        hub's alias and pinned key — strict, always (the hub was paired long ago)."""
        self._check_target(jump.host, jump.port)
        self._check_target(host, port)
        if _ALIAS.fullmatch(jump.alias) is None:
            raise RelaySshError("плохой alias", key="relay_ssh_bad_request")
        if (host.lower(), port) not in jump.opens:
            raise RelaySshError(
                f"{host}:{port} не за hub {jump.host}", key="relay_ssh_not_behind_hub",
                params={"value": f"{host}:{port}", "hub": jump.host},
            )
        if self.jump_keys is None:
            raise RelaySshError("нет jump-ключа", key="relay_agent_unavailable")
        options = self._options(known_hosts=known_hosts, alias=jump.alias, strict=True)
        # The one value that differs: at ERROR the hop says only "stdio forwarding
        # failed"; at INFO it says why ("administratively prohibited" — not in the
        # hub's permitopen; "connect failed" — the hub cannot reach the relay).
        options["LogLevel"] = "INFO"
        argv = [self.ssh_binary, "-F", "/dev/null", "-i", str(self.jump_keys.key_path), "-p", str(jump.port), "-l", "root"]
        for name, value in options.items():
            argv += ["-o", f"{name}={value}"]
        # Lower case, like the hub's list: sshd compares a permitopen host with strcmp.
        return [*argv, "-W", f"{host.lower()}:{port}", "--", jump.host]

    @staticmethod
    def proxy_command(argv: Sequence[str]) -> str:
        """*argv* as ONE ProxyCommand value: ssh runs it as ``$SHELL -c "exec …"`` and
        expands ``%`` tokens first — every word is shell-quoted, every ``%`` doubled."""
        return " ".join(shlex.quote(word) for word in argv).replace("%", "%%")

    def argv(
        self,
        host: str,
        port: int,
        request: str,
        *,
        alias: str,
        known_hosts: Path,
        pinned: bool,
        jump: JumpHost | None = None,
        jump_known_hosts: Path | None = None,
    ) -> list[str]:
        self._check_target(host, port)
        if len(request) > MAX_REQUEST or _REQUEST.fullmatch(request) is None:
            raise RelaySshError("запрос не из списка агента", key="relay_ssh_bad_request")
        if _ALIAS.fullmatch(alias) is None:
            raise RelaySshError("плохой alias", key="relay_ssh_bad_request")
        options = self._options(known_hosts=known_hosts, alias=alias, strict=pinned)
        if jump is not None:
            if jump_known_hosts is None or jump.alias == alias:
                raise RelaySshError("hub и relay — один alias", key="relay_ssh_bad_request")
            options["ProxyCommand"] = self.proxy_command(self.jump_argv(jump, host, port, known_hosts=jump_known_hosts))
            options["ProxyUseFdpass"] = "no"
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
        via: JumpHost | None = None,
    ) -> AgentReply:
        """Run *request*; ``host_key=None`` = the trust-on-first-use call of a pairing
        (the relay's hop only: a hub's hop is always pinned)."""
        self.keys.public_key()  # fails early, with a clear reason, without a usable key
        if via is not None:
            if self.jump_keys is None:
                raise RelaySshError("нет jump-ключа", key="relay_agent_unavailable")
            self.jump_keys.public_key()
        work = Path(tempfile.mkdtemp(prefix="relay-ssh-", dir=self.work_dir))
        try:
            os.chmod(work, 0o700)
            known_hosts = work / "known_hosts"
            if host_key is None:
                known_hosts.write_text("", encoding="utf-8")
            else:
                known_hosts.write_text(_pin_lines(alias, port, host_key), encoding="utf-8")
            jump_known: Path | None = None
            if via is not None:
                jump_known = work / "known_hosts.hub"
                jump_known.write_text(_pin_lines(via.alias, via.port, via.host_key), encoding="utf-8")
            argv = self.argv(
                host, port, request, alias=alias, known_hosts=known_hosts, pinned=host_key is not None,
                jump=via, jump_known_hosts=jump_known,
            )
            if via is None:
                result = await self.runner.run(argv, timeout=timeout, sensitive_values=sensitive, max_output_chars=200_000)
            else:
                result = await self.runner.run(
                    argv, timeout=timeout, sensitive_values=sensitive, max_output_chars=200_000,
                    env={**os.environ, "SHELL": PROXY_SHELL},
                )
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
            raise _ssh_failure(result.stderr.strip(), via=via, target=f"{host}:{port}")
        payload = _last_json(result.stdout)
        return AgentReply(returncode=result.returncode, payload=payload, learned_host_key=learned)


def _pin_lines(alias: str, port: int, host_key: str) -> str:
    pinned_key = parse_host_key(host_key)
    return f"{alias} {pinned_key}\n[{alias}]:{port} {pinned_key}\n"


def _ssh_failure(stderr: str, *, via: JumpHost | None, target: str) -> RelaySshError:
    """What an ssh exit 255 means, in one error (the hub's hop prints to the same stderr)."""
    last = stderr.splitlines()[-1][:300] if stderr else "—"
    if via is not None:
        if "administratively prohibited" in stderr:
            return RelaySshError(
                f"hub {via.host} не пускает к {target}", key="relay_ssh_jump_refused",
                params={"hub": via.host, "value": target},
            )
        if f"@{via.host}: Permission denied" in stderr:
            # The HUB refused the jump key (ssh names the host it was given): its jump
            # line is gone or holds another key — the hub's agent can write it again.
            return RelaySshError(
                f"hub {via.host} не принял jump-ключ", key="relay_ssh_jump_denied", params={"hub": via.host},
            )
        if "open failed: connect failed" in stderr or "stdio forwarding failed" in stderr:
            return RelaySshError(
                f"hub {via.host} не достучался до {target}", key="relay_ssh_jump_connect",
                params={"hub": via.host, "value": target, "error": last},
            )
    if "Host key verification failed" in stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
        if via is not None:
            return RelayHostKeyMismatch(
                "ключ хоста hub или relay не совпадает с закреплённым", key="relay_ssh_host_key_changed_hub",
                params={"hub": via.host},
            )
        return RelayHostKeyMismatch("ключ хоста relay не совпадает с закреплённым", key="relay_ssh_host_key_changed")
    return RelaySshError(
        f"ssh: {last if stderr else 'ошибка соединения'}",
        key="relay_ssh_failed",
        params={"error": last},
    )


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
