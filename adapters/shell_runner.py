
import asyncio
import codecs
import logging
import os
import signal
from collections.abc import Sequence

from models.dto import ShellResult

logger = logging.getLogger(__name__)

# Sentinel return codes / stderr set by ShellRunner itself (not by the child).
# Callers use these to distinguish "binary missing" and "timed out" from a real
# non-zero exit of the child process.
COMMAND_NOT_FOUND_RETURNCODE = 127
COMMAND_NOT_FOUND_STDERR = "command not found"
TIMEOUT_RETURNCODE = 124
TIMEOUT_STDERR = "timeout"

# Memory ceiling for one captured stream, in bytes. It is NOT the output limit:
# a stream is captured whole (up to this ceiling), redacted, and only then cut to
# the caller's max_output_chars — so a secret is always seen complete by the
# redaction, wherever the output limit falls. The ceiling only stops a runaway
# child from exhausting memory; it is raised to 4 bytes per requested character
# (the UTF-8 worst case) for callers that ask for very large outputs.
CAPTURE_CAP_BYTES = 8 * 1024 * 1024
_READ_CHUNK = 64 * 1024


class ShellRunner:
    """Runs shell commands asynchronously, redacting sensitive values from logs and error output."""

    def __init__(self, max_output_chars: int = 4096) -> None:
        self.max_output_chars = max_output_chars

    async def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = 15.0,
        sensitive_values: Sequence[str] = (),
        max_output_chars: int | None = None,
    ) -> ShellResult:
        """Execute a subprocess; redact sensitive_values from its args, stdout and stderr.

        ``result.args``, ``result.stdout`` and ``result.stderr`` are all redacted, and the
        redaction runs on the COMPLETE captured output before it is cut to the output
        limit — so no fragment of a value passed in ``sensitive_values`` can reach the
        result or the log, wherever the limit falls. Pass in ``sensitive_values`` only
        what must never come back: a caller that needs a generated secret from stdout
        (``wg genkey``) does not list it there. stdout is never logged.
        """
        if not args:
            raise ValueError("args must not be empty")

        output_limit = self.max_output_chars if max_output_chars is None else max_output_chars
        capture_cap = max(CAPTURE_CAP_BYTES, 4 * output_limit)
        safe_args = self._redact_args(args, sensitive_values)
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if input_text is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # New session/process group so a timeout can SIGKILL the whole tree
                # (e.g. awg-quick -> awg), not just the immediate child.
                start_new_session=True,
            )
        except FileNotFoundError:
            logger.warning("Команда не найдена: %s", safe_args[0])
            return ShellResult(tuple(safe_args), COMMAND_NOT_FOUND_RETURNCODE, "", COMMAND_NOT_FOUND_STDERR)

        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stdin_task: asyncio.Task[None] | None = None
        try:
            stdout_task = asyncio.create_task(self._read_stream_capped(process.stdout, capture_cap))
            stderr_task = asyncio.create_task(self._read_stream_capped(process.stderr, capture_cap))
            stdin_task = asyncio.create_task(self._write_stdin(process, input_text))
            await asyncio.wait_for(process.wait(), timeout=timeout)
            await stdin_task
            stdout_raw, stdout_capped = await stdout_task
            stderr_raw, stderr_capped = await stderr_task
        except asyncio.TimeoutError:
            await self._terminate(process)
            await self._drain_tasks(stdout_task, stderr_task, stdin_task)
            logger.error("Команда превысила timeout: %s", " ".join(safe_args))
            return ShellResult(tuple(safe_args), TIMEOUT_RETURNCODE, "", TIMEOUT_STDERR)

        stdout = self._finalize_output(stdout_raw, stdout_capped, sensitive_values, output_limit)
        stderr = self._finalize_output(stderr_raw, stderr_capped, sensitive_values, output_limit)
        if process.returncode != 0:
            logger.warning(
                "Команда завершилась с ошибкой rc=%s: %s; stderr=%s",
                process.returncode,
                " ".join(safe_args),
                stderr,
            )
        return ShellResult(tuple(safe_args), int(process.returncode or 0), stdout, stderr)

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        """Kill the timed-out child and its process group, then reap it.

        Killing the whole group reaches grandchildren (e.g. awg spawned by awg-quick).
        When the child is ``sudo``, the privileged helper it spawned runs as root and
        cannot be signalled by the unprivileged bot; ``killpg`` still terminates every
        process it is permitted to, and callers must not retry on a timeout (the helper
        may still be applying).
        """
        try:
            if os.name == "posix":
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    self._safe_kill(process)
            else:
                self._safe_kill(process)
        except ProcessLookupError:
            pass
        try:
            await process.wait()
        except ProcessLookupError:
            pass

    @staticmethod
    def _safe_kill(process: asyncio.subprocess.Process) -> None:
        """SIGKILL the child, swallowing errors.

        On a timed-out ``sudo`` helper the root child may be unsignalable by the
        unprivileged bot; ``process.kill()`` then raises ``PermissionError``. That must
        not escape ``_terminate`` (and thus ``run()``), or callers would see a raw
        exception instead of a ``ShellResult`` with ``TIMEOUT_RETURNCODE``.
        """
        try:
            process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass

    async def _drain_tasks(self, *tasks: asyncio.Task[object] | None) -> None:
        pending = [task for task in tasks if task is not None]
        for task in pending:
            if not task.done():
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _write_stdin(self, process: asyncio.subprocess.Process, input_text: str | None) -> None:
        if input_text is None or process.stdin is None:
            return
        process.stdin.write(input_text.encode("utf-8"))
        try:
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            process.stdin.close()
        await process.stdin.wait_closed()

    async def _read_stream_capped(self, stream: asyncio.StreamReader | None, cap_bytes: int) -> tuple[bytes, bool]:
        """Read the stream to EOF, keeping at most ``cap_bytes``; report whether it hit the cap.

        The cap bounds memory only — it is not the output limit (see
        ``_finalize_output``). Bytes past it are still read and dropped, so the child
        never blocks on a full pipe.
        """
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        capped = False
        while True:
            chunk = await stream.read(_READ_CHUNK)
            if not chunk:
                break
            room = cap_bytes - total
            if room > 0:
                chunks.append(chunk[:room])
                total += min(len(chunk), room)
            if len(chunk) > room:
                capped = True
        return b"".join(chunks), capped

    def _finalize_output(
        self,
        data: bytes,
        capped: bool,
        sensitive_values: Sequence[str],
        max_output_chars: int,
    ) -> str:
        """Decode → redact → cut to the output limit, in exactly that order.

        Redacting the whole captured text first is what guarantees that a secret
        crossing the output limit is replaced as a whole instead of leaving its
        prefix behind. The only cut that happens before redaction is the memory cap,
        and a capture that hit it is cleaned up before redaction can be fooled by it:
        an incomplete trailing UTF-8 sequence is dropped (it could be half of a
        secret's character), and after redaction any tail that is the beginning of a
        sensitive value is dropped too — that tail is a secret cut by the cap.
        """
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        text = decoder.decode(data, final=not capped)
        text = self._redact(text, sensitive_values)
        if capped:
            text = self._drop_partial_secret_tail(text, sensitive_values)
        return self._compact_text(text, capped, max_output_chars)

    @staticmethod
    def _drop_partial_secret_tail(text: str, sensitive_values: Sequence[str]) -> str:
        """Remove a trailing fragment that is the start of any sensitive value."""
        changed = True
        while changed and text:
            changed = False
            for value in sensitive_values:
                for size in range(min(len(value) - 1, len(text)), 0, -1):
                    if text.endswith(value[:size]):
                        text = text[:-size]
                        changed = True
                        break
        return text

    def _compact_text(self, text: str, truncated: bool, max_output_chars: int) -> str:
        text = text.strip()
        if not truncated and len(text) <= max_output_chars:
            return text
        return text[:max_output_chars] + "...[truncated]"

    def _redact_args(self, args: Sequence[str], sensitive_values: Sequence[str]) -> list[str]:
        return [self._redact(item, sensitive_values) for item in args]

    def _redact(self, text: str, sensitive_values: Sequence[str]) -> str:
        # Longest first: when one sensitive value contains another, replacing the
        # shorter one first would split the longer one and leave its remainder.
        redacted = text
        for value in sorted((v for v in sensitive_values if v), key=len, reverse=True):
            redacted = redacted.replace(value, "***")
        return redacted
