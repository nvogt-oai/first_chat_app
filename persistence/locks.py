from __future__ import annotations

import threading
from pathlib import Path


class PathLockRegistry:
    """
    Provides a stable lock per normalized file path to avoid global contention.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def lock_for(self, path: Path) -> threading.Lock:
        key = str(path.resolve())
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock


GLOBAL_PATH_LOCKS = PathLockRegistry()


