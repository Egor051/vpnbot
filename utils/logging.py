
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            log_dir.chmod(0o700)
        except OSError:
            pass
    formatter = logging.Formatter(
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
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
            for path in log_dir.glob("bot.log*"):
                path.chmod(0o600)
        except OSError:
            pass

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    if os.name == "posix":
        try:
            (log_dir / "bot.log").chmod(0o600)
        except OSError:
            pass
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    logging.getLogger("aiogram.event").setLevel(logging.WARNING)
