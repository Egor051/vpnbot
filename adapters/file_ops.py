
import os
import shutil
from pathlib import Path


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


def copy_stat(source: Path, target: Path) -> None:
    shutil.copystat(source, target)
    if os.name != "posix":
        return
    stat = source.stat()
    try:
        os.chown(target, stat.st_uid, stat.st_gid)
    except OSError:
        pass
