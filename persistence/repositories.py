from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .auth_state import AuthCodeRecord, DiskAuthStateRepository, RegisteredClientRecord, SessionRecord
from .calorie_state import CalorieEntryRecord, DiskCalorieStateRepository, UserCalorieStateRecord


class AuthRepository(Protocol):
    def get_registered_client(self, client_id: str) -> RegisteredClientRecord | None: ...
    def put_registered_client(self, client_id: str, record: RegisteredClientRecord) -> None: ...

    def get_auth_code(self, code: str) -> AuthCodeRecord | None: ...
    def put_auth_code(self, code: str, record: AuthCodeRecord) -> None: ...
    def pop_auth_code(self, code: str) -> AuthCodeRecord | None: ...

    def get_session(self, session_id: str) -> SessionRecord | None: ...
    def put_session(self, session_id: str, record: SessionRecord) -> None: ...
    def delete_session(self, session_id: str) -> None: ...


class CalorieRepository(Protocol):
    """
    Domain-level calorie persistence interface.
    Intentionally granular: mirrors how a real DB would be used.
    """

    def list_entries(self, user_id: str, *, date: str | None = None) -> list[CalorieEntryRecord]: ...

    def add_entry(
        self,
        user_id: str,
        *,
        food: str,
        calories: int,
        date: str | None = None,
        meal: str | None = None,
        notes: str | None = None,
        created_at: str | None = None,
    ) -> CalorieEntryRecord: ...

    def delete_entry(self, user_id: str, entry_id: str) -> bool: ...

    def get_daily_goal(self, user_id: str) -> int | None: ...
    def set_daily_goal(self, user_id: str, calories: int | None) -> None: ...


class DiskAuthRepository(DiskAuthStateRepository):
    """Disk-backed AuthRepository (already granular)."""


class DiskCalorieRepository(CalorieRepository):
    """
    Disk-backed CalorieRepository.

    Implementation detail: we still load/modify/save a per-user JSON document.
    The interface stays granular so we can swap in a real DB later without
    rewriting endpoints.
    """

    def __init__(self) -> None:
        self._state_repo = DiskCalorieStateRepository()

    def _load(self, user_id: str) -> UserCalorieStateRecord:
        return self._state_repo.get_user_state(user_id)

    def _save(self, user_id: str, state: UserCalorieStateRecord) -> None:
        self._state_repo.save_user_state(user_id, state)

    def list_entries(self, user_id: str, *, date: str | None = None) -> list[CalorieEntryRecord]:
        st = self._load(user_id)
        if date is None:
            return list(st.entries)
        return [e for e in st.entries if e.date == date]

    def add_entry(
        self,
        user_id: str,
        *,
        food: str,
        calories: int,
        date: str | None = None,
        meal: str | None = None,
        notes: str | None = None,
        created_at: str | None = None,
    ) -> CalorieEntryRecord:
        st = self._load(user_id)

        yyyy_mm_dd = date or datetime.now().date().isoformat()
        created = created_at or datetime.now().isoformat()

        entry_id = f"entry-{st.next_id}"
        st.next_id += 1

        entry = CalorieEntryRecord(
            id=entry_id,
            food=food,
            calories=int(calories),
            date=yyyy_mm_dd,
            meal=meal,
            notes=notes,
            createdAt=created,
        )
        st.entries.append(entry)
        self._save(user_id, st)
        return entry

    def delete_entry(self, user_id: str, entry_id: str) -> bool:
        st = self._load(user_id)
        before = len(st.entries)
        st.entries = [e for e in st.entries if e.id != entry_id]
        after = len(st.entries)
        if after == before:
            return False
        self._save(user_id, st)
        return True

    def get_daily_goal(self, user_id: str) -> int | None:
        st = self._load(user_id)
        return st.daily_goal_calories

    def set_daily_goal(self, user_id: str, calories: int | None) -> None:
        st = self._load(user_id)
        st.daily_goal_calories = calories
        self._save(user_id, st)


