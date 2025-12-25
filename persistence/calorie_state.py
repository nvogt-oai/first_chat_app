from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

from .disk_store import DiskJsonDocumentStore
from .paths import calories_users_dir, data_dir, project_root


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
    def __init__(self):
        self._users_dir = calories_users_dir(data_dir())

        # One-time migration from legacy DATA.json if present.
        legacy = project_root() / "DATA.json"
        if legacy.exists() and not any(self._users_dir.glob("*.json")):
            raw = DiskJsonDocumentStore(legacy).load()
            if isinstance(raw, dict):
                doc = CalorieDataDoc.from_disk_doc(raw)
                for uid, state in doc.users.items():
                    if isinstance(uid, str) and isinstance(state, dict):
                        DiskJsonDocumentStore(self._user_path(uid)).save(state)

    def get_user_state(self, user_id: str) -> dict[str, Any]:
        uid = (user_id.strip() or "anonymous").replace("/", "_")
        store = DiskJsonDocumentStore(self._user_path(uid))
        st = store.load()
        if not isinstance(st, dict) or "entries" not in st:
            st = {"entries": [], "next_id": 1, "daily_goal_calories": None}
            store.save(st)
        return dict(st)

    def save_user_state(self, user_id: str, state: dict[str, Any]) -> None:
        uid = (user_id.strip() or "anonymous").replace("/", "_")
        if not isinstance(state, dict):
            raise TypeError("state must be a dict")
        # minimal shape validation
        if "entries" not in state:
            raise ValueError("state must include 'entries'")
        DiskJsonDocumentStore(self._user_path(uid)).save(state)

    def _user_path(self, user_id: str) -> Path:
        return self._users_dir / f"{user_id}.json"


