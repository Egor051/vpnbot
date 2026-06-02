
import logging
import os
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path

from utils.redact import redact_text


class _RedactingFormatter(logging.Formatter):
    """Formatter that masks secret-like patterns in every emitted record.

    Redaction is enforced centrally here so a forgotten ``redact()`` call at an
    individual log site cannot leak a token/key/password into the logs.
    """

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


class _SecureRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that re-applies 0600 on every (re)open.

    The base handler creates each rotated/new log file with ``open()`` using the
    process umask (typically 0644). Overriding ``_open`` chmods the freshly
    opened file so log files stay private after a rollover, not just at startup.
    """

    def _open(self) -> TextIOWrapper:
        stream = super()._open()
        if os.name == "posix":
            try:
                os.chmod(self.baseFilename, 0o600)
            except OSError:
                pass
        return stream


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            log_dir.chmod(0o700)
        except OSError:
            pass
    formatter = _RedactingFormatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    log_path = log_dir / "bot.log"
    if os.name == "posix":
        try:
            # Pre-create the active log file privately so there is no window in
            # which it exists with umask-derived permissions before first write.
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
            for path in log_dir.glob("bot.log*"):
                path.chmod(0o600)
        except OSError:
            pass

    file_handler = _SecureRotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    logging.getLogger("aiogram.event").setLevel(logging.WARNING)
