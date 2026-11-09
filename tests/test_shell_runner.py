"""ShellRunner: the single choke point every privileged/system command goes through.

Real child processes are used where the behaviour lives in the OS boundary
(exit codes, pipes, decoding), and the child is always the test interpreter
itself (``sys.executable -c ...``) — never systemctl/sudo/id or anything that
touches the host or the network. Kill/reap edge cases that cannot be produced
deterministically with a real process (EPERM from killpg, a vanished pid) are
driven through small fakes.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import adapters.shell_runner as shell_runner_module
from adapters.shell_runner import (
    COMMAND_NOT_FOUND_RETURNCODE,
    COMMAND_NOT_FOUND_STDERR,
    TIMEOUT_RETURNCODE,
    TIMEOUT_STDERR,
    ShellRunner,
)

LOGGER = "adapters.shell_runner"
SECRET = "hunter2-SECRET"
PY = sys.executable
# A child that blocks forever without sleeping: it waits on an Event nobody sets.
BLOCK_FOREVER = "import threading; threading.Event().wait()"


def _reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


# Invariant: an empty argv is a programming error and is rejected before any
# process is spawned.
async def test_empty_args_raise_value_error() -> None:
    # Arrange
    runner = ShellRunner()

    # Act / Assert
    with pytest.raises(ValueError, match="must not be empty"):
        await runner.run([])


# Invariant: a successful command returns rc 0, stripped stdout and empty
# stderr, and logs nothing at WARNING or above.
async def test_success_returns_output_and_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    # Act
    result = await runner.run([PY, "-c", "print('  hello  ')"])

    # Assert
    assert result.ok and result.returncode == 0
    assert result.stdout == "hello"
    assert result.stderr == ""
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# Invariant: a missing binary maps to the rc-127 sentinel with the sentinel
# stderr, and the warning names the (redacted) program, not a traceback.
async def test_missing_binary_returns_sentinel(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    missing = str(tmp_path / f"no-such-{SECRET}")
    runner = ShellRunner()
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    result = await runner.run([missing, "--flag"], sensitive_values=[SECRET])

    # Assert
    assert result.returncode == COMMAND_NOT_FOUND_RETURNCODE
    assert result.stderr == COMMAND_NOT_FOUND_STDERR
    assert result.stdout == ""
    assert SECRET not in " ".join(result.args)
    assert result.args[1] == "--flag"
    assert SECRET not in caplog.text
    assert "***" in caplog.text


# Invariant: a non-zero exit is returned as-is (not raised), and the WARNING it
# logs carries the rc and the stderr with every sensitive value redacted — in
# args and in stderr alike.
async def test_nonzero_rc_is_logged_with_redaction(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.WARNING, logger=LOGGER)
    code = f"import sys; sys.stderr.write('bad token {SECRET}\\n'); sys.exit(3)"

    # Act
    result = await runner.run([PY, "-c", code, SECRET], sensitive_values=[SECRET])

    # Assert
    assert result.returncode == 3 and not result.ok
    assert result.stderr == "bad token ***"
    assert result.args[-1] == "***"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "rc=3" in warnings[0].getMessage()
    assert SECRET not in caplog.text


# Invariant: stdout is returned verbatim even when it contains a sensitive value
# (callers such as `wg genkey` consume it) — redaction applies only to args and
# stderr, and stdout is never written to the log.
async def test_stdout_is_not_redacted_and_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    code = f"import sys; print('{SECRET}'); sys.exit(1)"

    # Act
    result = await runner.run([PY, "-c", code], sensitive_values=[SECRET])

    # Assert
    assert result.stdout == SECRET
    assert SECRET not in caplog.text


# Invariant: an empty string in sensitive_values is ignored — it must not turn
# every character boundary into "***".
async def test_empty_sensitive_value_is_ignored() -> None:
    # Arrange
    runner = ShellRunner()
    code = "import sys; sys.stderr.write('plain'); sys.exit(1)"

    # Act
    result = await runner.run([PY, "-c", code], sensitive_values=["", SECRET])

    # Assert
    assert result.stderr == "plain"
    assert result.args == (PY, "-c", code)


# Invariant: every occurrence of every sensitive value is redacted, not just the
# first one.
async def test_all_occurrences_of_all_secrets_are_redacted() -> None:
    # Arrange
    runner = ShellRunner()
    other = "second-secret"
    code = f"import sys; sys.stderr.write('{SECRET} {other} {SECRET}'); sys.exit(2)"

    # Act
    result = await runner.run([PY, "-c", code], sensitive_values=[SECRET, other])

    # Assert
    assert result.stderr == "*** *** ***"


# Invariant: undecodable bytes on stdout/stderr never raise — they are decoded
# with U+FFFD replacement characters.
async def test_invalid_utf8_is_replaced_not_raised() -> None:
    # Arrange
    runner = ShellRunner()
    code = (
        "import sys; sys.stdout.buffer.write(b'ok\\xff\\xfeend'); "
        "sys.stderr.buffer.write(b'err\\xc3'); sys.exit(1)"
    )

    # Act
    result = await runner.run([PY, "-c", code])

    # Assert
    assert result.stdout == "ok��end"
    assert result.stderr == "err�"


# Invariant: the output cap is applied in BYTES; a multibyte character cut at the
# boundary decodes to U+FFFD and the result is marked truncated.
async def test_multibyte_char_cut_at_limit_is_replaced() -> None:
    # Arrange
    runner = ShellRunner(max_output_chars=3)
    code = "import sys; sys.stdout.buffer.write('aaя'.encode())"  # 'я' is 2 bytes

    # Act
    result = await runner.run([PY, "-c", code])

    # Assert
    assert result.stdout == "aa�...[truncated]"


# Invariant: a per-call max_output_chars overrides the instance default for
# that call only.
async def test_per_call_output_limit_overrides_default() -> None:
    # Arrange
    runner = ShellRunner(max_output_chars=4096)
    code = "print('x' * 100)"

    # Act
    limited = await runner.run([PY, "-c", code], max_output_chars=10)
    default = await runner.run([PY, "-c", code])

    # Assert
    assert limited.stdout == "x" * 10 + "...[truncated]"
    assert default.stdout == "x" * 100


# Invariant: stderr is redacted BEFORE it is truncated, so a secret straddling
# the truncation boundary cannot leave a recognisable prefix behind.
#
# KNOWN BUG — this invariant does not hold today. _read_stream_limited() keeps
# only the first `max_output_chars` BYTES of the pipe, so the redaction in run()
# sees an already-cut secret, cannot match it, and its prefix survives in
# result.stderr and in the WARNING log ("abhunt...[truncated]" for the secret
# "hunter2-SECRET" at a limit of 6). Affects every caller that passes
# sensitive_values: the SOCKS5 password (adapters/dante_users.py) and the AWG
# private key / preshared key (adapters/awg_config.py). strict=True makes this
# test fail as soon as the fix lands, forcing the marker to be removed.
@pytest.mark.xfail(
    strict=True,
    reason="shell_runner truncates stderr before redaction: a secret on the cut leaks its prefix",
)
async def test_secret_straddling_truncation_boundary_is_redacted(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.WARNING, logger=LOGGER)
    code = f"import sys; sys.stderr.write('ab{SECRET}'); sys.exit(1)"
    fragments = [SECRET[:k] for k in range(3, len(SECRET) + 1)]

    # Act
    result = await runner.run([PY, "-c", code], sensitive_values=[SECRET], max_output_chars=6)

    # Assert
    assert result.stderr.startswith("ab")
    assert not [f for f in fragments if f in result.stderr], result.stderr
    assert not [f for f in fragments if f in caplog.text], caplog.text


# Invariant: input_text is delivered on stdin (UTF-8) and stdin is closed, so a
# child that reads to EOF terminates.
async def test_input_text_is_written_to_stdin() -> None:
    # Arrange
    runner = ShellRunner()
    code = "import sys; data = sys.stdin.read(); print(data.upper())"

    # Act
    result = await runner.run([PY, "-c", code], input_text="привет wg")

    # Assert
    assert result.ok
    assert result.stdout == "ПРИВЕТ WG"


# Invariant: a command that outlives its timeout is killed and reported with
# the rc-124 sentinel; the ERROR log carries redacted args only.
async def test_timeout_kills_child_and_returns_sentinel(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.ERROR, logger=LOGGER)

    # Act
    result = await runner.run([PY, "-c", BLOCK_FOREVER, SECRET], timeout=0.5, sensitive_values=[SECRET])

    # Assert
    assert result.returncode == TIMEOUT_RETURNCODE
    assert result.stderr == TIMEOUT_STDERR
    assert result.stdout == ""
    assert result.args[-1] == "***"
    assert "timeout" in caplog.text
    assert SECRET not in caplog.text


# Invariant: on timeout the WHOLE process group is SIGKILLed (grandchildren such
# as awg spawned by awg-quick included), not just the direct child.
async def test_timeout_kills_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    calls: list[tuple[int, int]] = []
    real_killpg = shell_runner_module.os.killpg

    def recording_killpg(pgid: int, sig: int) -> None:
        calls.append((pgid, sig))
        real_killpg(pgid, sig)

    monkeypatch.setattr(shell_runner_module.os, "killpg", recording_killpg)
    runner = ShellRunner()

    # Act
    result = await runner.run([PY, "-c", BLOCK_FOREVER], timeout=0.5)

    # Assert
    assert result.returncode == TIMEOUT_RETURNCODE
    assert len(calls) == 1
    assert calls[0][1] == signal.SIGKILL


class _FakeProcess:
    """Just enough of asyncio.subprocess.Process for _terminate()."""

    def __init__(self, *, kill_exc: BaseException | None = None, wait_exc: BaseException | None = None) -> None:
        self.pid = 999_999
        self.kill_calls = 0
        self.wait_calls = 0
        self._kill_exc = kill_exc
        self._wait_exc = wait_exc

    def kill(self) -> None:
        self.kill_calls += 1
        if self._kill_exc is not None:
            raise self._kill_exc

    async def wait(self) -> int:
        self.wait_calls += 1
        if self._wait_exc is not None:
            raise self._wait_exc
        return -9


def _posix_os(**overrides: Any) -> SimpleNamespace:
    def getpgid(pid: int) -> int:
        return pid

    def killpg(pgid: int, sig: int) -> None:
        raise PermissionError("EPERM: root child of sudo")

    base: dict[str, Any] = {"name": "posix", "getpgid": getpgid, "killpg": killpg}
    base.update(overrides)
    return SimpleNamespace(**base)


# Invariant: when killpg is refused (a root helper under sudo), _terminate falls
# back to killing the direct child and still reaps it.
async def test_terminate_falls_back_to_kill_on_eperm(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(shell_runner_module, "os", _posix_os())
    process = _FakeProcess()

    # Act
    await ShellRunner()._terminate(process)  # type: ignore[arg-type]

    # Assert
    assert process.kill_calls == 1
    assert process.wait_calls == 1


# Invariant: if even the direct kill is refused, the error is swallowed so run()
# still returns a TIMEOUT ShellResult instead of raising.
@pytest.mark.parametrize("exc", [PermissionError("EPERM"), ProcessLookupError("gone"), OSError("other")])
async def test_terminate_swallows_kill_errors(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    # Arrange
    monkeypatch.setattr(shell_runner_module, "os", _posix_os())
    process = _FakeProcess(kill_exc=exc)

    # Act
    await ShellRunner()._terminate(process)  # type: ignore[arg-type]

    # Assert
    assert process.kill_calls == 1
    assert process.wait_calls == 1


# Invariant: a process that already vanished (ProcessLookupError from getpgid
# AND from wait) does not make _terminate raise.
async def test_terminate_tolerates_vanished_process(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    def getpgid(pid: int) -> int:
        raise ProcessLookupError("no such process")

    monkeypatch.setattr(shell_runner_module, "os", _posix_os(getpgid=getpgid))
    process = _FakeProcess(wait_exc=ProcessLookupError("reaped"))

    # Act
    await ShellRunner()._terminate(process)  # type: ignore[arg-type]

    # Assert
    assert process.kill_calls == 1
    assert process.wait_calls == 1


# Invariant: on a non-POSIX platform (no process groups) _terminate kills the
# direct child only and never touches killpg.
async def test_terminate_non_posix_kills_child_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    def killpg(pgid: int, sig: int) -> None:
        raise AssertionError("killpg must not be used off POSIX")

    monkeypatch.setattr(shell_runner_module, "os", _posix_os(name="nt", killpg=killpg))
    process = _FakeProcess()

    # Act
    await ShellRunner()._terminate(process)  # type: ignore[arg-type]

    # Assert
    assert process.kill_calls == 1


# Invariant: a ProcessLookupError escaping the platform kill branch itself is
# swallowed by the outer guard.
async def test_terminate_swallows_lookup_error_from_kill_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    process = _FakeProcess()

    def safe_kill(proc: object) -> None:
        raise ProcessLookupError("raced with exit")

    monkeypatch.setattr(shell_runner_module, "os", _posix_os(name="nt"))
    monkeypatch.setattr(ShellRunner, "_safe_kill", staticmethod(safe_kill))

    # Act
    await ShellRunner()._terminate(process)  # type: ignore[arg-type]

    # Assert
    assert process.wait_calls == 1


class _FakeStdin:
    def __init__(self, drain_exc: BaseException | None = None) -> None:
        self.written = b""
        self.closed = False
        self.wait_closed_calls = 0
        self._drain_exc = drain_exc

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        if self._drain_exc is not None:
            raise self._drain_exc

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1


# Invariant: a child that exits without reading its stdin (broken pipe /
# connection reset on drain) is not an error — stdin is still closed.
@pytest.mark.parametrize("exc", [BrokenPipeError(), ConnectionResetError()])
async def test_write_stdin_tolerates_closed_pipe(exc: BaseException) -> None:
    # Arrange
    stdin = _FakeStdin(drain_exc=exc)
    process = SimpleNamespace(stdin=stdin)

    # Act
    await ShellRunner()._write_stdin(process, "data")  # type: ignore[arg-type]

    # Assert
    assert stdin.written == b"data"
    assert stdin.closed is True
    assert stdin.wait_closed_calls == 0


# Invariant: the happy path closes stdin and waits for it to be closed.
async def test_write_stdin_closes_and_waits() -> None:
    # Arrange
    stdin = _FakeStdin()
    process = SimpleNamespace(stdin=stdin)

    # Act
    await ShellRunner()._write_stdin(process, "ключ")  # type: ignore[arg-type]

    # Assert
    assert stdin.written == "ключ".encode()
    assert stdin.closed is True
    assert stdin.wait_closed_calls == 1


# Invariant: no input_text, or no stdin pipe, means nothing is written.
@pytest.mark.parametrize(("stdin", "text"), [(_FakeStdin(), None), (None, "x")])
async def test_write_stdin_noop_without_text_or_pipe(stdin: _FakeStdin | None, text: str | None) -> None:
    # Arrange
    process = SimpleNamespace(stdin=stdin)

    # Act
    await ShellRunner()._write_stdin(process, text)  # type: ignore[arg-type]

    # Assert
    if stdin is not None:
        assert stdin.written == b"" and stdin.closed is False


# Invariant: a missing stream reads as empty and not truncated.
async def test_read_stream_none_is_empty() -> None:
    # Arrange
    runner = ShellRunner()

    # Act
    result = await runner._read_stream_limited(None, 10)

    # Assert
    assert result == (b"", False)


# Invariant: output of exactly the limit is NOT truncated; one byte over is.
@pytest.mark.parametrize(("size", "truncated"), [(10, False), (11, True)])
async def test_read_stream_limit_boundary(size: int, truncated: bool) -> None:
    # Arrange
    reader = _reader(b"x" * size)

    # Act
    data, was_truncated = await ShellRunner()._read_stream_limited(reader, 10)

    # Assert
    assert data == b"x" * min(size, 10)
    assert was_truncated is truncated


# Invariant: output far beyond the limit (many chunks) is still fully drained —
# so the child never blocks on a full pipe — but only `limit` bytes are kept.
async def test_read_stream_drains_beyond_limit() -> None:
    # Arrange
    reader = _reader(b"y" * 5000)

    # Act
    data, was_truncated = await ShellRunner()._read_stream_limited(reader, 100)

    # Assert
    assert data == b"y" * 100
    assert was_truncated is True
    assert reader.at_eof()


# Invariant: a large child output does not deadlock the runner (the reader
# keeps draining past the cap while the child is still writing).
async def test_large_output_does_not_deadlock() -> None:
    # Arrange
    runner = ShellRunner(max_output_chars=16)
    code = "import sys; sys.stdout.write('z' * 1_000_000); sys.stderr.write('e' * 1_000_000)"

    # Act
    result = await runner.run([PY, "-c", code], timeout=30)

    # Assert
    assert result.ok
    assert result.stdout == "z" * 16 + "...[truncated]"
    assert result.stderr == "e" * 16 + "...[truncated]"
