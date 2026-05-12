from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from models.dto import ShellResult

logger = logging.getLogger(__name__)


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
        """Execute a subprocess; redact sensitive_values from all logged output."""
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
            )
        except FileNotFoundError:
            logger.warning("Команда не найдена: %s", safe_args[0])
            return ShellResult(tuple(args), 127, "", "command not found")

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
            process.kill()
            await process.wait()
            for task in (stdout_task, stderr_task, stdin_task):
                if task is not None and not task.done():
                    task.cancel()
            logger.error("Команда превысила timeout: %s", " ".join(safe_args))
            return ShellResult(tuple(args), 124, "", "timeout")

        stdout = self._compact(stdout_raw, stdout_truncated, output_limit)
        stderr = self._compact(stderr_raw, stderr_truncated, output_limit)
        if process.returncode != 0:
            logger.warning(
                "Команда завершилась с ошибкой rc=%s: %s; stderr=%s",
                process.returncode,
                " ".join(safe_args),
                self._redact(stderr, sensitive_values),
            )
        return ShellResult(tuple(args), int(process.returncode or 0), stdout, stderr)

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

    async def _read_stream_limited(self, stream: asyncio.StreamReader | None, max_output_chars: int) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        truncated = False
        while True:
            chunk = await stream.read(1024)
            if not chunk:
                break
            remaining = max_output_chars - total
            if remaining > 0:
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
        return b"".join(chunks), truncated

    def _compact(self, data: bytes, truncated: bool = False, max_output_chars: int | None = None) -> str:
        output_limit = self.max_output_chars if max_output_chars is None else max_output_chars
        text = data.decode("utf-8", errors="replace").strip()
        if not truncated and len(text) <= output_limit:
            return text
        return text[:output_limit] + "...[truncated]"

    def _redact_args(self, args: Sequence[str], sensitive_values: Sequence[str]) -> list[str]:
        return [self._redact(item, sensitive_values) for item in args]

    def _redact(self, text: str, sensitive_values: Sequence[str]) -> str:
        redacted = text
        for value in sensitive_values:
            if value:
                redacted = redacted.replace(value, "***")
        return redacted
