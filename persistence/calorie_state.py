from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Protocol

from pydantic import BaseModel, Field

from .disk_store import DiskJsonDocumentStore
from .paths import calories_users_dir, data_dir, project_root


class CalorieEntryRecord(BaseModel):
    id: str | None = None
    food: str | None = None
    calories: int | None = None
    date: str | None = None
    meal: str | None = None
    notes: str | None = None
    createdAt: str | None = None

class UserCalorieStateRecord(BaseModel):
    entries: list[CalorieEntryRecord] = Field(default_factory=list)
    next_id: int = 1
    daily_goal_calories: int | None = None


class CalorieDataDoc(BaseModel):
    """
    Mirrors the on-disk calorie schema:
      { "users": { "<user_id>": { "entries": [...], "next_id": 1, "daily_goal_calories": 2000 | null } } }
    """

    users: dict[str, UserCalorieStateRecord] = Field(default_factory=dict)

    @classmethod
    def from_disk_doc(cls, doc: Mapping[str, Any]) -> "CalorieDataDoc":
        return cls.model_validate(doc)

    def to_disk_doc(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class CalorieStateRepository(Protocol):
    def get_user_state(self, user_id: str) -> UserCalorieStateRecord:
        ...

    def save_user_state(self, user_id: str, state: UserCalorieStateRecord) -> None:
        ...


class DiskCalorieStateRepository(CalorieStateRepository):
    def __init__(self):
        self._users_dir = calories_users_dir(data_dir())

    def get_user_state(self, user_id: str) -> UserCalorieStateRecord:
        uid = (user_id.strip() or "anonymous").replace("/", "_")
        store = DiskJsonDocumentStore(self._user_path(uid))
        st = store.load()
        if not isinstance(st, dict):
            st = {}
        # Validate/normalize on read. If missing/invalid, write normalized doc.
        record = UserCalorieStateRecord.model_validate(st)
        normalized = record.model_dump(mode="json", exclude_none=True)
        if ("entries" not in st) or (st != normalized):
            store.save(normalized)
        return record

    def save_user_state(self, user_id: str, state: UserCalorieStateRecord) -> None:
        uid = (user_id.strip() or "anonymous").replace("/", "_")
        DiskJsonDocumentStore(self._user_path(uid)).save(state.model_dump(mode="json", exclude_none=True))

    def _user_path(self, user_id: str) -> Path:
        return self._users_dir / f"{user_id}.json"


