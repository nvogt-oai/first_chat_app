from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

from .disk_store import DiskJsonDocumentStore


class AuthCodeRecord(BaseModel):
    client_id: str
    redirect_uri: str
    username: str
    scopes: list[str] = Field(default_factory=list)
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    expires_at: int
    resource: str | None = None


class RegisteredClientRecord(BaseModel):
    redirect_uris: list[str] = Field(default_factory=list)
    token_endpoint_auth_method: str = "none"
    client_secret: str | None = None
    created_at: int


class SessionRecord(BaseModel):
    username: str
    created_at: int


class AuthState(BaseModel):
    """
    Mirrors the on-disk AUTH_STATE.json schema exactly:
      {
        "registered_clients": { "<client_id>": {...} },
        "auth_codes": { "<code>": {...} },
        "sessions": { "<session_id>": {...} }
      }
    """

    registered_clients: dict[str, RegisteredClientRecord] = Field(default_factory=dict)
    auth_codes: dict[str, AuthCodeRecord] = Field(default_factory=dict)
    sessions: dict[str, SessionRecord] = Field(default_factory=dict)

    @classmethod
    def from_disk_doc(cls, doc: Mapping[str, Any]) -> "AuthState":
        return cls.model_validate(doc)

    def to_disk_doc(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def drop_expired_auth_codes(self, now: int | None = None) -> None:
        ts = int(time.time()) if now is None else int(now)
        expired = [k for k, v in self.auth_codes.items() if int(v.expires_at) < ts]
        for k in expired:
            self.auth_codes.pop(k, None)


class AuthStateRepository:
    def get_registered_client(self, client_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def put_registered_client(self, client_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    def get_auth_code(self, code: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def put_auth_code(self, code: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    def pop_auth_code(self, code: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def put_session(self, session_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    def delete_session(self, session_id: str) -> None:
        raise NotImplementedError


class DiskAuthStateRepository(AuthStateRepository):
    def __init__(self, *, path: Path):
        self._lock = threading.Lock()
        self._store = DiskJsonDocumentStore(path)
        self._state = self._load()

    def _load(self) -> AuthState:
        doc = self._store.load()
        st = AuthState.from_disk_doc(doc)
        st.drop_expired_auth_codes()
        self._store.save(st.to_disk_doc())
        return st

    def _persist(self) -> None:
        self._store.save(self._state.to_disk_doc())

    def get_registered_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._state.registered_clients.get(client_id)
            return rec.model_dump(mode="json") if rec is not None else None

    def put_registered_client(self, client_id: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._state.registered_clients[client_id] = RegisteredClientRecord.model_validate(record)
            self._persist()

    def get_auth_code(self, code: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._state.auth_codes.get(code)
            if rec is None:
                return None
            if int(time.time()) > int(rec.expires_at):
                self._state.auth_codes.pop(code, None)
                self._persist()
                return None
            return rec.model_dump(mode="json")

    def put_auth_code(self, code: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._state.auth_codes[code] = AuthCodeRecord.model_validate(record)
            self._persist()

    def pop_auth_code(self, code: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._state.auth_codes.pop(code, None)
            self._persist()
            return rec.model_dump(mode="json") if rec is not None else None

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._state.sessions.get(session_id)
            return rec.model_dump(mode="json") if rec is not None else None

    def put_session(self, session_id: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._state.sessions[session_id] = SessionRecord.model_validate(record)
            self._persist()

    def delete_session(self, session_id: str) -> None:
        with self._lock:
            self._state.sessions.pop(session_id, None)
            self._persist()


