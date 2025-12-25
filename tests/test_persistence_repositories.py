from __future__ import annotations

import asyncio

import pytest

from persistence.auth_state import AuthCodeRecord, RegisteredClientRecord, SessionRecord
from persistence.repositories import AsyncDiskAuthRepository, AsyncDiskCalorieRepository


def test_async_disk_auth_repository_roundtrip(sandbox_project):
    async def _run():
        repo = AsyncDiskAuthRepository()

        # sessions
        await repo.put_session("s1", SessionRecord(username="alice", created_at=123))
        sess = await repo.get_session("s1")
        assert sess is not None
        assert sess.username == "alice"
        await repo.delete_session("s1")
        assert await repo.get_session("s1") is None

        # registered clients
        rc = RegisteredClientRecord(
            redirect_uris=["https://example.com/cb"],
            token_endpoint_auth_method="none",
            client_secret=None,
            created_at=123,
        )
        await repo.put_registered_client("c1", rc)
        got = await repo.get_registered_client("c1")
        assert got is not None
        assert got.redirect_uris == ["https://example.com/cb"]

        # auth codes (get + pop)
        code = AuthCodeRecord(
            client_id="c1",
            redirect_uri="https://example.com/cb",
            username="alice",
            scopes=["toy.read"],
            code_challenge=None,
            code_challenge_method=None,
            expires_at=9999999999,
            resource=None,
        )
        await repo.put_auth_code("code1", code)
        got_code = await repo.get_auth_code("code1")
        assert got_code is not None
        assert got_code.username == "alice"
        popped = await repo.pop_auth_code("code1")
        assert popped is not None
        assert await repo.get_auth_code("code1") is None

    asyncio.run(_run())

def test_async_disk_calorie_repository_basic_flow(sandbox_project):
    async def _run():
        repo = AsyncDiskCalorieRepository()

        # default date
        e1 = await repo.add_entry("u1", food="banana", calories=105)
        assert e1.id is not None
        assert e1.date is not None

        # explicit date
        e2 = await repo.add_entry("u1", food="toast", calories=200, date="2025-01-01")
        assert e2.date == "2025-01-01"

        all_entries = await repo.list_entries("u1")
        assert len(all_entries) == 2

        jan1 = await repo.list_entries("u1", date="2025-01-01")
        assert [e.food for e in jan1] == ["toast"]

        ok = await repo.delete_entry("u1", e2.id or "")
        assert ok is True
        assert len(await repo.list_entries("u1", date="2025-01-01")) == 0

        # goals
        assert await repo.get_daily_goal("u1") is None
        await repo.set_daily_goal("u1", 2000)
        assert await repo.get_daily_goal("u1") == 2000

    asyncio.run(_run())


