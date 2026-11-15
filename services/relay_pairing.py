"""The relay pairing code and the one-line relay install command (docs/relay.md).

Pure functions, except :func:`installer_source`, which reads this checkout's own
``.git`` (files only, no subprocess). The bot issues a code from admin panel →
«🛰 Relay» (a new relay, or an agent for an existing one); the operator pastes
the command it renders on the relay, where
``scripts/install.sh --relay`` decodes the code with the SAME rules
(``parse_pairing_code`` there; tests/test_install_relay.py feeds codes made here
through it). The relay agent (``scripts/vpn-relay-agent``) validates the targets and
ports of a later ``apply`` with the same rules too.

The code is ``base64url(JSON)`` without padding, exactly these fields::

    {"v": 1, "target_host": "<main DNS name>", "ports": ["443/tcp", "443/udp"],
     "main_pubkey": "ssh-ed25519 AAAA…", "one_time_token": "<43 chars>", "exp": <unix>}

``target_host`` is a DNS NAME, never an address: the relay re-resolves it every 5
minutes (vpn-relay-resolve.timer), so a new IP of the main server is an A-record
change and nothing on the relay.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from services.errors import InvalidOperation

PAIRING_VERSION = 1
PAIRING_TTL_SECONDS = 30 * 60
# How long after ``exp`` the bot still completes a pairing (the relay's agent accepts
# its first ``hello`` for as long: scripts/vpn-relay-agent HELLO_GRACE_SECONDS).
COMPLETION_GRACE_SECONDS = 15 * 60
# The installer accepts a code this far past ``exp`` (clock skew between the hosts).
INSTALL_CLOCK_SKEW_SECONDS = 300
MAX_PORTS_PER_PROTOCOL = 8
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
_PORT_ITEM = re.compile(r"([1-9][0-9]{0,4})/(tcp|udp)")
_PUBKEY = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/]{68})(?: [!-~]{1,64})?")
_FIELDS = frozenset({"v", "target_host", "ports", "main_pubkey", "one_time_token", "exp"})
_GITHUB_REMOTE = re.compile(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?")
_SHA = re.compile(r"[0-9a-f]{40}")
_GITFILE = re.compile(r"gitdir: (?P<path>[^\r\n\x00]+)\n?")
_COMMONDIR = re.compile(r"(?P<path>[^\r\n\x00]+)\n?")
_GITFILE_MAX_BYTES = 4096


class PairingCodeError(ValueError):
    """A code (or a part of one) that does not follow the format."""


def valid_dns_name(value: str) -> bool:
    """A DNS name with at least two labels whose last label is not numeric (no IPv4)."""
    if not value or len(value) > 253 or value.endswith(".") or "." not in value:
        return False
    labels = value.split(".")
    return all(_LABEL.fullmatch(label) for label in labels) and not labels[-1].isdigit()


def parse_target_host(value: str) -> str:
    host = (value or "").strip().lower()
    if not valid_dns_name(host):
        raise PairingCodeError(f"{value!r} — не DNS-имя")
    return host


def parse_ports(raw: str) -> tuple[int, ...]:
    """``"443,8443"`` -> (443, 8443): 1..8 distinct ports in 1..65535, no leading zeros."""
    items = [item.strip() for item in (raw or "").split(",")]
    if not raw or not raw.strip() or len(items) > MAX_PORTS_PER_PROTOCOL:
        raise PairingCodeError("нужно 1–8 портов через запятую")
    ports: list[int] = []
    for item in items:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", item) or int(item) > 65535:
            raise PairingCodeError(f"{item!r} — не порт 1..65535")
        if int(item) in ports:
            raise PairingCodeError(f"порт {item} указан дважды")
        ports.append(int(item))
    return tuple(sorted(ports))


def format_ports(ports: Iterable[int]) -> str:
    return ",".join(str(p) for p in sorted(ports))


def validate_main_pubkey(value: str) -> str:
    """``ssh-ed25519 <blob>`` (a comment is dropped); the blob must be a real ed25519 key."""
    match = _PUBKEY.fullmatch(value or "")
    if match is None:
        raise PairingCodeError("main_pubkey — не ssh-ed25519")
    blob = base64.b64decode(match[1])
    if (
        len(blob) != 51
        or blob[:4] != struct.pack(">I", 11)
        or blob[4:15] != b"ssh-ed25519"
        or blob[15:19] != struct.pack(">I", 32)
    ):
        raise PairingCodeError("main_pubkey повреждён")
    return f"ssh-ed25519 {match[1]}"


def new_token() -> str:
    """A fresh one-time token: 32 random bytes, base64url, 43 characters."""
    token = secrets.token_urlsafe(32)
    assert TOKEN_PATTERN.fullmatch(token)
    return token


@dataclass(frozen=True, slots=True)
class PairingCode:
    target_host: str
    tcp_ports: tuple[int, ...]
    udp_ports: tuple[int, ...]
    main_pubkey: str
    token: str
    exp: int

    def __post_init__(self) -> None:
        if not valid_dns_name(self.target_host):
            raise PairingCodeError("target_host — не DNS-имя")
        for ports in (self.tcp_ports, self.udp_ports):
            if not 1 <= len(ports) <= MAX_PORTS_PER_PROTOCOL or len(set(ports)) != len(ports):
                raise PairingCodeError("нужно 1–8 разных портов на протокол")
            if any(not 1 <= p <= 65535 for p in ports):
                raise PairingCodeError("порт вне 1..65535")
        validate_main_pubkey(self.main_pubkey)
        if TOKEN_PATTERN.fullmatch(self.token) is None:
            raise PairingCodeError("one_time_token")


def encode_pairing_code(code: PairingCode) -> str:
    payload = {
        "v": PAIRING_VERSION,
        "target_host": code.target_host,
        "ports": [f"{p}/tcp" for p in sorted(code.tcp_ports)] + [f"{p}/udp" for p in sorted(code.udp_ports)],
        "main_pubkey": validate_main_pubkey(code.main_pubkey),
        "one_time_token": code.token,
        "exp": int(code.exp),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_pairing_code(raw: str, *, now: int, skew: int = INSTALL_CLOCK_SKEW_SECONDS) -> PairingCode:
    """The installer's rules (scripts/install.sh parse_pairing_code), for the tests and the UI."""
    text = (raw or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,4096}", text):
        raise PairingCodeError("это не pairing-код")
    try:
        data = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise PairingCodeError("не декодируется") from exc
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise PairingCodeError("неизвестный формат")
    if data["v"] != PAIRING_VERSION:
        raise PairingCodeError("версия не поддерживается")
    ports = data["ports"]
    if not isinstance(ports, list) or len({str(p) for p in ports}) != len(ports):
        raise PairingCodeError("ports")
    tcp: list[int] = []
    udp: list[int] = []
    for item in ports:
        match = _PORT_ITEM.fullmatch(item) if isinstance(item, str) else None
        if match is None or int(match[1]) > 65535:
            raise PairingCodeError(f"ports: {item!r}")
        (tcp if match[2] == "tcp" else udp).append(int(match[1]))
    exp = data["exp"]
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise PairingCodeError("exp")
    if now > exp + skew:
        raise PairingCodeError("истёк")
    if exp > now + 2 * 3600:
        raise PairingCodeError("exp слишком далеко")
    if not isinstance(data["target_host"], str) or not isinstance(data["main_pubkey"], str):
        raise PairingCodeError("поля")
    if not isinstance(data["one_time_token"], str):
        raise PairingCodeError("one_time_token")
    return PairingCode(
        target_host=data["target_host"],
        tcp_ports=tuple(sorted(tcp)),
        udp_ports=tuple(sorted(udp)),
        main_pubkey=data["main_pubkey"],
        token=data["one_time_token"],
        exp=exp,
    )


# ── the command the bot shows ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Source:
    """Where the relay fetches the installer: the main server's own commit."""

    owner: str
    repo: str
    commit: str
    installer_sha256: str

    @property
    def raw_url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.commit}/scripts/install.sh"

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"


DEFAULT_OWNER, DEFAULT_REPO = "Egor051", "vpnbot"


def github_remote(url: str) -> tuple[str, str] | None:
    match = _GITHUB_REMOTE.fullmatch((url or "").strip())
    return (match[1], match[2]) if match else None


def relay_command(code: str, source: Source) -> str:
    """One line for the relay: download the installer of THIS commit, check its
    sha256, run it in relay mode with the code on stdin (a shell builtin prints it:
    never an argv)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,4096}", code):
        raise PairingCodeError("это не pairing-код")
    if _SHA.fullmatch(source.commit) is None or re.fullmatch(r"[0-9a-f]{64}", source.installer_sha256) is None:
        raise PairingCodeError("источник установщика")
    env = f"INSTALL_REF={source.commit}"
    if (source.owner, source.repo) != (DEFAULT_OWNER, DEFAULT_REPO):
        env += f" INSTALL_REPO={source.repo_url}"
    return (
        f"curl -fsSL -o install.sh {source.raw_url}"
        f" && echo '{source.installer_sha256}  install.sh' | sha256sum -c --quiet -"
        f" && printf '%s\\n' '{code}' | sudo env {env} bash install.sh --relay"
    )


def format_port_specs(tcp: Sequence[int], udp: Sequence[int]) -> str:
    return " ".join([*(f"{p}/tcp" for p in sorted(tcp)), *(f"{p}/udp" for p in sorted(udp))])


# ── where the relay gets the installer: this checkout's own commit ────────────


def _small_text(path: Path) -> str | None:
    """A small regular file's UTF-8 text; a symlink, a non-regular or a larger file is None.

    O_NOFOLLOW refuses a symlink, O_NONBLOCK keeps a FIFO from blocking the open, and
    the type and size are checked through the open descriptor.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _GITFILE_MAX_BYTES:
            return None
        raw = os.read(fd, _GITFILE_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > _GITFILE_MAX_BYTES:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _git_dirs(repo_root: Path) -> tuple[Path, Path] | None:
    """``(gitdir, commondir)`` of the checkout at ``repo_root``; anything unexpected is None.

    A plain checkout: ``.git`` is the directory and both are it. A linked worktree
    (``git worktree add`` — deploy.sh Phase 1 runs pytest in one): ``.git`` is a FILE,
    one line ``gitdir: <path>`` (relative to ``repo_root``). That per-worktree
    directory holds HEAD and per-worktree refs; its ``commondir`` file (relative to it,
    usually ``../..``) names the shared directory with refs/*, packed-refs and config.
    Without a ``commondir`` file (``--separate-git-dir``) the gitdir is the common dir.
    """
    dot_git = repo_root / ".git"
    if dot_git.is_dir():
        return dot_git, dot_git
    gitfile = _small_text(dot_git)
    match = _GITFILE.fullmatch(gitfile) if gitfile is not None else None
    if match is None:
        return None
    gitdir = repo_root / match.group("path")
    if not gitdir.is_dir():
        return None
    commondir_file = gitdir / "commondir"
    if not os.path.lexists(commondir_file):
        return gitdir, gitdir
    content = _small_text(commondir_file)
    common = _COMMONDIR.fullmatch(content) if content is not None else None
    if common is None:
        return None
    commondir = gitdir / common.group("path")
    if not commondir.is_dir():
        return None
    return gitdir, commondir


def _read_head(gitdir: Path, commondir: Path) -> str | None:
    try:
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref) or ".." in ref:
        return None
    # A per-worktree ref (refs/bisect, refs/worktree) lives in the gitdir, a branch in
    # the common dir; in a plain checkout the two are one directory, read once.
    for refs_dir in (gitdir,) if gitdir == commondir else (gitdir, commondir):
        try:
            value = (refs_dir / ref).read_text(encoding="utf-8").strip()
            return value if _SHA.fullmatch(value) else None
        except OSError:
            pass
    try:
        for line in (commondir / "packed-refs").read_text(encoding="utf-8").splitlines():
            sha, _, name = line.partition(" ")
            if name.strip() == ref and _SHA.fullmatch(sha):
                return sha
    except OSError:
        return None
    return None


def _origin_url(commondir: Path) -> str:
    try:
        text = (commondir / "config").read_text(encoding="utf-8")
    except OSError:
        return ""
    section = re.search(r'\[remote "origin"\](.*?)(?:\n\[|\Z)', text, re.S)
    if section is None:
        return ""
    url = re.search(r"^\s*url\s*=\s*(\S+)\s*$", section.group(1), re.M)
    return url.group(1) if url else ""


def installer_source(repo_root: Path) -> Source:
    """The installer the relay runs: this checkout's commit (its file's sha256).

    The checkout is read from its files (no ``git`` subprocess) — a plain one or a
    linked worktree alike (:func:`_git_dirs`).
    """
    dirs = _git_dirs(repo_root)
    commit = None if dirs is None else _read_head(*dirs)
    if dirs is None or commit is None:
        raise InvalidOperation("не удалось определить коммит бота (.git)", key="relay_pair_no_commit")
    _, commondir = dirs
    try:
        digest = hashlib.sha256((repo_root / "scripts" / "install.sh").read_bytes()).hexdigest()
    except OSError as exc:
        raise InvalidOperation("нет scripts/install.sh в checkout бота", key="relay_pair_no_installer") from exc
    owner, repo = github_remote(_origin_url(commondir)) or (DEFAULT_OWNER, DEFAULT_REPO)
    return Source(owner=owner, repo=repo, commit=commit, installer_sha256=digest)
