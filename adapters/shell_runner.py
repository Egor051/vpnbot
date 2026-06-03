
import asyncio
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
        """Execute a subprocess; redact sensitive_values from all logged and returned stderr.

        Note: stdout is returned verbatim because some callers consume it (e.g. ``wg genkey``
        writes the generated key to stdout). stderr stored on the result is redacted, so
        surfacing ``result.stderr`` in an error message cannot leak a secret.
        """
        if not args:
            raise ValueError("args must not be empty")

        output_limit = self.max_output_chars if max_output_chars is None else max_output_chars
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
            return ShellResult(tuple(args), COMMAND_NOT_FOUND_RETURNCODE, "", COMMAND_NOT_FOUND_STDERR)

        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stdin_task: asyncio.Task[None] | None = None
        try:
            stdout_task = asyncio.create_task(self._read_stream_limited(process.stdout, output_limit))
            stderr_task = asyncio.create_task(self._read_stream_limited(process.stderr, output_limit))
            stdin_task = asyncio.create_task(self._write_stdin(process, input_text))
            await asyncio.wait_for(process.wait(), timeout=timeout)
            await stdin_task
            stdout_raw, stdout_truncated = await stdout_task
            stderr_raw, stderr_truncated = await stderr_task
        except asyncio.TimeoutError:
            await self._terminate(process)
            await self._drain_tasks(stdout_task, stderr_task, stdin_task)
            logger.error("Команда превысила timeout: %s", " ".join(safe_args))
            return ShellResult(tuple(args), TIMEOUT_RETURNCODE, "", TIMEOUT_STDERR)

        stdout = self._compact(stdout_raw, stdout_truncated, output_limit)
        # Redact secrets from the full decoded stderr BEFORE truncating, so a value that
        # straddles the truncation boundary cannot survive in logs or on the result.
        stderr_text = self._redact(stderr_raw.decode("utf-8", errors="replace"), sensitive_values)
        stderr = self._compact_text(stderr_text, stderr_truncated, output_limit)
        if process.returncode != 0:
            logger.warning(
                "Команда завершилась с ошибкой rc=%s: %s; stderr=%s",
                process.returncode,
                " ".join(safe_args),
                stderr,
            )
        return ShellResult(tuple(args), int(process.returncode or 0), stdout, stderr)

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
                    process.kill()
            else:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            await process.wait()
        except ProcessLookupError:
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

    async def _read_stream_limited(self, stream: asyncio.StreamReader | None, max_output_bytes: int) -> tuple[bytes, bool]:
        """Read up to max_output_bytes from the stream, draining the rest.

        The cap is applied in bytes; a multibyte UTF-8 sequence cut at the boundary is
        rendered safe later by ``decode(errors="replace")``. The remainder of the stream
        is still consumed so the child does not block on a full pipe.
        """
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        truncated = False
        while True:
            chunk = await stream.read(1024)
            if not chunk:
                break
            remaining = max_output_bytes - total
            if remaining > 0:
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
        return b"".join(chunks), truncated

    def _compact(self, data: bytes, truncated: bool = False, max_output_chars: int | None = None) -> str:
        output_limit = self.max_output_chars if max_output_chars is None else max_output_chars
        return self._compact_text(data.decode("utf-8", errors="replace"), truncated, output_limit)

    def _compact_text(self, text: str, truncated: bool, max_output_chars: int) -> str:
        text = text.strip()
        if not truncated and len(text) <= max_output_chars:
            return text
        return text[:max_output_chars] + "...[truncated]"

    def _redact_args(self, args: Sequence[str], sensitive_values: Sequence[str]) -> list[str]:
        return [self._redact(item, sensitive_values) for item in args]

    def _redact(self, text: str, sensitive_values: Sequence[str]) -> str:
        redacted = text
        for value in sensitive_values:
            if value:
                redacted = redacted.replace(value, "***")
        return redacted
