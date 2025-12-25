from __future__ import annotations

from typing import Any, Protocol


class KeyValueDocumentStore(Protocol):
    """
    Minimal DB-friendly interface: a single JSON-like document persisted under a key.
    """

    def load(self) -> dict[str, Any]:
        """Load and return the full document (never None)."""
        ...

    def save(self, doc: dict[str, Any]) -> None:
        """Persist the full document atomically."""
        ...


