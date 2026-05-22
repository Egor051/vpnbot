
import asyncio
import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def fsync_parent(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(path.parent, flags)
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


async def async_fsync_parent(path: Path) -> None:
    await asyncio.to_thread(fsync_parent, path)


def copy_stat(source: Path, target: Path, *, suppress_chown_warning: bool = False) -> None:
    shutil.copystat(source, target)
    if os.name != "posix":
        return
    stat = source.stat()
    try:
        os.chown(target, stat.st_uid, stat.st_gid)
    except OSError as exc:
        if not suppress_chown_warning:
            logger.warning(
                "chown(%s, uid=%d, gid=%d) failed: %s",
                target, stat.st_uid, stat.st_gid, exc,
            )


async def async_copy_stat(source: Path, target: Path, *, suppress_chown_warning: bool = False) -> None:
    await asyncio.to_thread(copy_stat, source, target, suppress_chown_warning=suppress_chown_warning)
