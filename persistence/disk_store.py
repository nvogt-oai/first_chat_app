from __future__ import annotations

from pathlib import Path
from typing import Any

from json_store import atomic_write_json, read_json

from .interfaces import KeyValueDocumentStore
from .locks import GLOBAL_PATH_LOCKS


class DiskJsonDocumentStore(KeyValueDocumentStore):
    """
    Stores a single JSON document on disk at a fixed path.

    - Always returns a dict (empty dict on missing/invalid JSON).
    - Writes atomically.
    """

    def __init__(self, path: Path):
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> dict[str, Any]:
        lock = GLOBAL_PATH_LOCKS.lock_for(self._path)
        with lock:
            raw = read_json(self._path)
            return raw if isinstance(raw, dict) else {}

    def save(self, doc: dict[str, Any]) -> None:
        lock = GLOBAL_PATH_LOCKS.lock_for(self._path)
        with lock:
            atomic_write_json(self._path, doc)


