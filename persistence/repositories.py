from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Protocol

from .auth_state import AuthCodeRecord, DiskAuthStateRepository, RegisteredClientRecord, SessionRecord
from .calorie_state import CalorieEntryRecord, DiskCalorieStateRepository, UserCalorieStateRecord


class AsyncAuthRepository(Protocol):
    async def get_registered_client(self, client_id: str) -> RegisteredClientRecord | None: ...
    async def put_registered_client(self, client_id: str, record: RegisteredClientRecord) -> None: ...

    async def get_auth_code(self, code: str) -> AuthCodeRecord | None: ...
    async def put_auth_code(self, code: str, record: AuthCodeRecord) -> None: ...
    async def pop_auth_code(self, code: str) -> AuthCodeRecord | None: ...

    async def get_session(self, session_id: str) -> SessionRecord | None: ...
    async def put_session(self, session_id: str, record: SessionRecord) -> None: ...
    async def delete_session(self, session_id: str) -> None: ...


class AsyncCalorieRepository(Protocol):
    """
    Domain-level calorie persistence interface.
    Intentionally granular: mirrors how a real DB would be used.
    """

    async def list_entries(self, user_id: str, *, date: str | None = None) -> list[CalorieEntryRecord]: ...

    async def add_entry(
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

    async def delete_entry(self, user_id: str, entry_id: str) -> bool: ...

    async def get_daily_goal(self, user_id: str) -> int | None: ...
    async def set_daily_goal(self, user_id: str, calories: int | None) -> None: ...


class AsyncDiskAuthRepository(AsyncAuthRepository):
    """
    Async wrapper around the disk-backed auth repository.
    Uses asyncio.to_thread to avoid blocking the event loop on file I/O.
    """

    def __init__(self) -> None:
        self._repo = DiskAuthStateRepository()

    async def get_registered_client(self, client_id: str) -> RegisteredClientRecord | None:
        return await asyncio.to_thread(self._repo.get_registered_client, client_id)

    async def put_registered_client(self, client_id: str, record: RegisteredClientRecord) -> None:
        await asyncio.to_thread(self._repo.put_registered_client, client_id, record)

    async def get_auth_code(self, code: str) -> AuthCodeRecord | None:
        return await asyncio.to_thread(self._repo.get_auth_code, code)

    async def put_auth_code(self, code: str, record: AuthCodeRecord) -> None:
        await asyncio.to_thread(self._repo.put_auth_code, code, record)

    async def pop_auth_code(self, code: str) -> AuthCodeRecord | None:
        return await asyncio.to_thread(self._repo.pop_auth_code, code)

    async def get_session(self, session_id: str) -> SessionRecord | None:
        return await asyncio.to_thread(self._repo.get_session, session_id)

    async def put_session(self, session_id: str, record: SessionRecord) -> None:
        await asyncio.to_thread(self._repo.put_session, session_id, record)

    async def delete_session(self, session_id: str) -> None:
        await asyncio.to_thread(self._repo.delete_session, session_id)


class AsyncDiskCalorieRepository(AsyncCalorieRepository):
    """
    Disk-backed CalorieRepository.

    Implementation detail: we still load/modify/save a per-user JSON document.
    The interface stays granular so we can swap in a real DB later without
    rewriting endpoints.
    """

    def __init__(self) -> None:
        self._state_repo = DiskCalorieStateRepository()

    async def _load(self, user_id: str) -> UserCalorieStateRecord:
        return await asyncio.to_thread(self._state_repo.get_user_state, user_id)

    async def _save(self, user_id: str, state: UserCalorieStateRecord) -> None:
        await asyncio.to_thread(self._state_repo.save_user_state, user_id, state)

    async def list_entries(self, user_id: str, *, date: str | None = None) -> list[CalorieEntryRecord]:
        st = await self._load(user_id)
        if date is None:
            return list(st.entries)
        return [e for e in st.entries if e.date == date]

    async def add_entry(
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
        st = await self._load(user_id)

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
        await self._save(user_id, st)
        return entry

    async def delete_entry(self, user_id: str, entry_id: str) -> bool:
        st = await self._load(user_id)
        before = len(st.entries)
        st.entries = [e for e in st.entries if e.id != entry_id]
        after = len(st.entries)
        if after == before:
            return False
        await self._save(user_id, st)
        return True

    async def get_daily_goal(self, user_id: str) -> int | None:
        st = await self._load(user_id)
        return st.daily_goal_calories

    async def set_daily_goal(self, user_id: str, calories: int | None) -> None:
        st = await self._load(user_id)
        st.daily_goal_calories = calories
        await self._save(user_id, st)


