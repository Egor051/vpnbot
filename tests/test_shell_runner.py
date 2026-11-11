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
import time
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import adapters.shell_runner as shell_runner_module
from adapters.shell_runner import (
    CAPTURE_CAP_BYTES,
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


# Invariant: stdout is redacted like stderr (a sensitive value never comes back
# on the result), and stdout is never written to the log. A caller that needs a
# generated secret from stdout (`wg genkey`) simply does not list it.
async def test_stdout_is_redacted_and_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    code = "import sys; sys.stdout.write(sys.stdin.read()); sys.exit(1)"

    # Act
    result = await runner.run([PY, "-c", code], input_text=f"key={SECRET}", sensitive_values=[SECRET])

    # Assert
    assert result.stdout == "key=***"
    assert SECRET not in caplog.text
    assert "key=" not in caplog.text  # stdout is never logged, redacted or not


# Invariant: when one sensitive value contains another, the longer one is
# replaced whole — redacting the shorter first would leave the rest of the
# longer one behind.
async def test_overlapping_secrets_are_redacted_whole() -> None:
    # Arrange
    runner = ShellRunner()
    short, long = "abc", "abcdef-XYZ"
    code = f"import sys; sys.stderr.write('{long}'); sys.exit(1)"

    # Act
    result = await runner.run([PY, "-c", code], sensitive_values=[short, long])

    # Assert
    assert result.stderr == "***"


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


# Invariant: the output limit counts CHARACTERS of the decoded text, so a
# multibyte character is never cut in half by it: 'aaя' fits a limit of 3, and
# 'aaяb' is cut after the whole 'я'.
@pytest.mark.parametrize(("payload", "expected"), [("aaя", "aaя"), ("aaяb", "aaя...[truncated]")])
async def test_output_limit_counts_characters(payload: str, expected: str) -> None:
    # Arrange
    runner = ShellRunner(max_output_chars=3)
    code = f"import sys; sys.stdout.buffer.write({payload!r}.encode())"

    # Act
    result = await runner.run([PY, "-c", code])

    # Assert
    assert result.stdout == expected


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


# The boundary harness. The secret is built from characters that appear nowhere
# else in the output (filler '.', marker '*', suffix '...[truncated]'), so "not a
# single character of the secret in the result" can be asserted literally. The
# payload reaches the child on stdin, so the argv (which IS logged) never holds
# the secret in the first place; only the output path is under test.
BOUNDARY_SECRET = "XQ7Z-9KWB"
BOUNDARY_LIMIT = 16
ECHO_STDIN = "import sys; data = sys.stdin.read(); sys.{stream}.write(data); sys.exit(1)"


def _secret_offsets(limit: int, secret: str) -> list[pytest.param]:
    """Secret wholly before the cut, across it at every offset 1..len-1, right after it."""
    cases = [pytest.param(limit - len(secret) - 2, id="before")]
    cases += [pytest.param(limit - inside, id=f"across-{inside}") for inside in range(1, len(secret))]
    cases.append(pytest.param(limit, id="after"))
    return cases


def _fragments(secret: str) -> list[str]:
    return [secret[i:j] for i in range(len(secret)) for j in range(i + 2, len(secret) + 1)]


# Invariant: the output limit is applied AFTER redaction, so wherever the
# secret sits relative to the cut — before it, across it at any offset, or just
# after it — not one character of it reaches result.stdout / result.stderr, and
# no fragment of it reaches the log.
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("start", _secret_offsets(BOUNDARY_LIMIT, BOUNDARY_SECRET))
async def test_secret_at_output_limit_never_leaks(
    caplog: pytest.LogCaptureFixture, stream: str, start: int
) -> None:
    # Arrange
    runner = ShellRunner()
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    payload = "." * start + BOUNDARY_SECRET + "." * 20

    # Act
    result = await runner.run(
        [PY, "-c", ECHO_STDIN.format(stream=stream)],
        input_text=payload,
        sensitive_values=[BOUNDARY_SECRET],
        max_output_chars=BOUNDARY_LIMIT,
    )

    # Assert
    output = getattr(result, stream)
    assert output.endswith("...[truncated]")
    assert not set(BOUNDARY_SECRET) & set(result.stdout + result.stderr), (result.stdout, result.stderr)
    assert not [f for f in _fragments(BOUNDARY_SECRET) if f in caplog.text], caplog.text


# Invariant: the memory cap (the one cut that happens before redaction) cannot
# leak a secret either — a secret cut by the cap, at any offset, is dropped from
# the tail instead of surviving as a prefix. Checked on the finaliser directly,
# with an output limit far above the cut, so nothing else can hide a leak.
@pytest.mark.parametrize("inside", range(1, len(BOUNDARY_SECRET)))
def test_secret_cut_by_memory_cap_is_dropped(inside: int) -> None:
    # Arrange
    captured = ("." * 40 + BOUNDARY_SECRET[:inside]).encode()

    # Act
    text = ShellRunner()._finalize_output(captured, True, [BOUNDARY_SECRET], 10_000)

    # Assert
    assert text == "." * 40 + "...[truncated]"


# Invariant: a multibyte secret cut by the cap mid-character is dropped too —
# the incomplete UTF-8 tail is discarded instead of decoding to U+FFFD, which
# would otherwise shield the secret prefix in front of it from the tail check.
@pytest.mark.parametrize("cut_bytes", range(1, len("КЛЮЧ-ЖЁСТКИЙ".encode())))
def test_multibyte_secret_cut_by_memory_cap_is_dropped(cut_bytes: int) -> None:
    # Arrange
    secret = "КЛЮЧ-ЖЁСТКИЙ"
    captured = b"." * 40 + secret.encode()[:cut_bytes]

    # Act
    text = ShellRunner()._finalize_output(captured, True, [secret], 10_000)

    # Assert
    assert text == "." * 40 + "...[truncated]"


# Invariant: end to end, the cap cut is reachable inside the output limit —
# redaction shrinks each long secret to "***", pulling the cut point forward —
# and still nothing of the cut secret is returned or logged.
@pytest.mark.parametrize("inside", [1, 2, 3, 4])
async def test_secret_cut_by_memory_cap_end_to_end(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, inside: int
) -> None:
    # Arrange: two 30-char secrets (60 bytes) then the third cut by a 64-byte cap;
    # redacted, the cut lands at char 6 + inside, well inside a 16-char limit.
    secret = (BOUNDARY_SECRET * 4)[:30]
    monkeypatch.setattr(shell_runner_module, "CAPTURE_CAP_BYTES", 64)
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    payload = secret * 2 + "." * (4 - inside) + secret + "." * 100

    # Act
    result = await ShellRunner().run(
        [PY, "-c", ECHO_STDIN.format(stream="stderr")],
        input_text=payload,
        sensitive_values=[secret],
        max_output_chars=16,
    )

    # Assert
    assert result.stderr == "******" + "." * (4 - inside) + "...[truncated]"
    assert not [f for f in _fragments(secret) if f in caplog.text], caplog.text


# Invariant: a capped stream whose tail merely RESEMBLES nothing secret keeps
# all of it; the tail clean-up only removes the start of a sensitive value.
def test_partial_tail_cleanup_only_removes_secret_prefixes() -> None:
    # Arrange
    values = ["SECRET", "TOKEN"]

    # Act
    kept = ShellRunner._drop_partial_secret_tail("abc..SEC", values)
    stacked = ShellRunner._drop_partial_secret_tail("abc..TOK", values)
    untouched = ShellRunner._drop_partial_secret_tail("abc..xyz", values)

    # Assert
    assert (kept, stacked, untouched) == ("abc..", "abc..", "abc..xyz")


# Invariant: wherever the cap splits a secret (every offset 1..len-1), not one
# character of it survives the clean-up. The cut is the LONGEST matching prefix
# across all values: a shorter value that also matches the tail and is listed
# first must not win, or the rest of the cut secret would stay. Empty values are
# skipped.
TAIL_SECRET = "Kq7Zw2Xn9RtB4mVy8LpC3sHd6FjG1aEu5NcT0oWiYb+="


@pytest.mark.parametrize("inside", range(1, len(TAIL_SECRET)))
def test_tail_cleanup_drops_secret_cut_at_every_offset(inside: int) -> None:
    # Arrange: the decoy's one-char prefix is the last char of the cut secret.
    filler = "." * 40
    decoy = TAIL_SECRET[inside - 1] + "!"

    # Act
    result = ShellRunner._drop_partial_secret_tail(filler + TAIL_SECRET[:inside], ["", decoy, TAIL_SECRET])

    # Assert
    assert result == filler
    assert not set(TAIL_SECRET) & set(result), result


# Invariant: with no value that can leave a proper prefix behind (none at all,
# an empty one, a one-char one), a capped tail is kept as is and nothing raises.
@pytest.mark.parametrize("values", [pytest.param([], id="none"), pytest.param(["", "a"], id="empty-and-1-char")])
def test_tail_cleanup_without_multichar_values_keeps_text(values: list[str]) -> None:
    # Arrange
    text = "abc..a"

    # Act
    result = ShellRunner._drop_partial_secret_tail(text, values)

    # Assert
    assert result == text


# Invariant: the cap cuts once, so the clean-up cuts once. A full capture that
# merely repeats a secret's first character loses only the fragment one cut can
# leave (len - 1 at most), never the whole text, and the cost does not grow with
# the output: the looping version spent minutes on this input, blocking the
# event loop.
@pytest.mark.parametrize(
    ("secret", "dropped"),
    [pytest.param("aZ", 1, id="2-char"), pytest.param("a" * 47 + "Z", 47, id="48-char")],
)
def test_tail_cleanup_cuts_once_in_bounded_time(secret: str, dropped: int) -> None:
    # Arrange
    text = "a" * CAPTURE_CAP_BYTES

    # Act
    started = time.perf_counter()
    result = ShellRunner._drop_partial_secret_tail(text, [secret])
    elapsed = time.perf_counter() - started

    # Assert
    assert elapsed < 0.5, f"{elapsed:.3f}s"
    assert len(text) - len(result) == dropped
    assert text.startswith(result)


# Invariant: the clean-up repairs the cap's cut, so it runs only when the cap
# actually cut. An uncapped stream ended where the child ended it: a tail that
# looks like the start of a secret is real output and comes back unchanged. The
# capped row is the control that proves the spy is wired.
@pytest.mark.parametrize(
    ("capped", "calls", "expected"),
    [
        pytest.param(False, 0, "." * 40 + BOUNDARY_SECRET[:4], id="uncapped"),
        pytest.param(True, 1, "." * 40 + "...[truncated]", id="capped"),
    ],
)
def test_tail_cleanup_runs_only_on_capped_stream(
    monkeypatch: pytest.MonkeyPatch, capped: bool, calls: int, expected: str
) -> None:
    # Arrange
    seen: list[str] = []
    real = ShellRunner._drop_partial_secret_tail

    def spy(text: str, values: Sequence[str]) -> str:
        seen.append(text)
        return real(text, values)

    monkeypatch.setattr(ShellRunner, "_drop_partial_secret_tail", staticmethod(spy))
    captured = ("." * 40 + BOUNDARY_SECRET[:4]).encode()

    # Act
    text = ShellRunner()._finalize_output(captured, capped, [BOUNDARY_SECRET], 10_000)

    # Assert
    assert len(seen) == calls
    assert text == expected


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


# Invariant: a missing stream reads as empty and not capped.
async def test_read_stream_none_is_empty() -> None:
    # Arrange
    runner = ShellRunner()

    # Act
    result = await runner._read_stream_capped(None, 10)

    # Assert
    assert result == (b"", False)


# Invariant: output of exactly the memory cap is kept whole and NOT reported as
# capped; one byte over is.
@pytest.mark.parametrize(("size", "capped"), [(10, False), (11, True)])
async def test_read_stream_cap_boundary(size: int, capped: bool) -> None:
    # Arrange
    reader = _reader(b"x" * size)

    # Act
    data, was_capped = await ShellRunner()._read_stream_capped(reader, 10)

    # Assert
    assert data == b"x" * min(size, 10)
    assert was_capped is capped


# Invariant: output far beyond the cap (many chunks) is still fully drained —
# so the child never blocks on a full pipe — but only `cap` bytes are kept.
async def test_read_stream_drains_beyond_cap() -> None:
    # Arrange
    reader = _reader(b"y" * 300_000)

    # Act
    data, was_capped = await ShellRunner()._read_stream_capped(reader, 100)

    # Assert
    assert data == b"y" * 100
    assert was_capped is True
    assert reader.at_eof()


# Invariant: the memory cap follows large requested limits (4 bytes per
# character), so a caller asking for 2M characters is never cut by the 8 MiB
# default first.
async def test_capture_cap_scales_with_requested_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    caps: list[int] = []
    real = ShellRunner._read_stream_capped

    async def spy(self: ShellRunner, stream: Any, cap_bytes: int) -> tuple[bytes, bool]:
        caps.append(cap_bytes)
        return await real(self, stream, cap_bytes)

    monkeypatch.setattr(ShellRunner, "_read_stream_capped", spy)

    # Act
    await ShellRunner().run([PY, "-c", "pass"], max_output_chars=16)
    await ShellRunner().run([PY, "-c", "pass"], max_output_chars=3_000_000)

    # Assert
    assert caps == [shell_runner_module.CAPTURE_CAP_BYTES] * 2 + [12_000_000] * 2


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
