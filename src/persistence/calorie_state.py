from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

from .disk_store import DiskJsonDocumentStore


class CalorieDataDoc(BaseModel):
    """
    Mirrors the on-disk DATA.json schema:
      { "users": { "<user_id>": { "entries": [...], "next_id": 1, "daily_goal_calories": 2000 | null } } }
    """

    users: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @classmethod
    def from_disk_doc(cls, doc: Mapping[str, Any]) -> "CalorieDataDoc":
        # Legacy migration: { "entries": [...], "next_id": 1, "daily_goal_calories": ... }
        if "users" not in doc and any(k in doc for k in ("entries", "next_id", "daily_goal_calories")):
            legacy_user = {
                "entries": doc.get("entries", []),
                "next_id": doc.get("next_id", 1),
                "daily_goal_calories": doc.get("daily_goal_calories", None),
            }
            return cls.model_validate({"users": {"default": legacy_user}})
        return cls.model_validate(doc)

    def to_disk_doc(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class CalorieStateRepository:
    def get_user_state(self, user_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def save_user_state(self, user_id: str, state: dict[str, Any]) -> None:
        raise NotImplementedError


class DiskCalorieStateRepository(CalorieStateRepository):
    def __init__(self, *, path: Path):
        self._lock = threading.Lock()
        self._store = DiskJsonDocumentStore(path)
        self._doc = self._load()

    def _load(self) -> CalorieDataDoc:
        raw = self._store.load()
        doc = CalorieDataDoc.from_disk_doc(raw)
        # Persist any legacy migration immediately.
        self._store.save(doc.to_disk_doc())
        return doc

    def _persist(self) -> None:
        self._store.save(self._doc.to_disk_doc())

    def get_user_state(self, user_id: str) -> dict[str, Any]:
        uid = user_id.strip() or "anonymous"
        with self._lock:
            st = self._doc.users.get(uid)
            if not isinstance(st, dict):
                st = {"entries": [], "next_id": 1, "daily_goal_calories": None}
                self._doc.users[uid] = st
                self._persist()
            return dict(st)

    def save_user_state(self, user_id: str, state: dict[str, Any]) -> None:
        uid = user_id.strip() or "anonymous"
        if not isinstance(state, dict):
            raise TypeError("state must be a dict")
        with self._lock:
            self._doc.users[uid] = state
            self._persist()


