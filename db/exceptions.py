

class ConcurrentModificationError(RuntimeError):
    """Raised when a DB row was modified or transitioned concurrently.

    Indicates that a status-guarded UPDATE matched 0 rows because the row's
    status changed between the caller's read and write.
    """
