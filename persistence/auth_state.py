from __future__ import annotations

import time
from typing import Any, Mapping, Protocol

from pydantic import BaseModel, Field

from .disk_store import DiskJsonDocumentStore
from .paths import auth_dir, data_dir, project_root


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


class AuthStateRepository(Protocol):
    def get_registered_client(self, client_id: str) -> RegisteredClientRecord | None:
        ...

    def put_registered_client(self, client_id: str, record: RegisteredClientRecord) -> None:
        ...

    def get_auth_code(self, code: str) -> AuthCodeRecord | None:
        ...

    def put_auth_code(self, code: str, record: AuthCodeRecord) -> None:
        ...

    def pop_auth_code(self, code: str) -> AuthCodeRecord | None:
        ...

    def get_session(self, session_id: str) -> SessionRecord | None:
        ...

    def put_session(self, session_id: str, record: SessionRecord) -> None:
        ...

    def delete_session(self, session_id: str) -> None:
        ...


class DiskAuthStateRepository(AuthStateRepository):
    """
    Stores auth state split across multiple files to reduce write amplification / contention:

    - data/auth/registered_clients.json
    - data/auth/auth_codes.json
    - data/auth/sessions.json
    """

    def __init__(self):
        base = auth_dir(data_dir())
        self._clients = DiskJsonDocumentStore(base / "registered_clients.json")
        self._codes = DiskJsonDocumentStore(base / "auth_codes.json")
        self._sessions = DiskJsonDocumentStore(base / "sessions.json")

        # One-time migration from legacy AUTH_STATE.json if present.
        legacy = project_root() / "AUTH_STATE.json"
        if legacy.exists() and not (base / "registered_clients.json").exists():
            raw = DiskJsonDocumentStore(legacy).load()
            if isinstance(raw, dict):
                rc = raw.get("registered_clients")
                ac = raw.get("auth_codes")
                ss = raw.get("sessions")
                self._clients.save(rc if isinstance(rc, dict) else {})
                self._codes.save(ac if isinstance(ac, dict) else {})
                self._sessions.save(ss if isinstance(ss, dict) else {})

        # Drop expired codes on startup.
        self._drop_expired_codes()

    def _drop_expired_codes(self) -> None:
        data = self._codes.load()
        if not isinstance(data, dict):
            self._codes.save({})
            return
        now = int(time.time())
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            if not isinstance(v, dict):
                continue
            exp = v.get("expires_at")
            if isinstance(exp, int) and now > exp:
                continue
            cleaned[str(k)] = v
        self._codes.save(cleaned)

    def get_registered_client(self, client_id: str) -> RegisteredClientRecord | None:
        data = self._clients.load()
        rec = data.get(client_id) if isinstance(data, dict) else None
        if not isinstance(rec, dict):
            return None
        return RegisteredClientRecord.model_validate(rec)

    def put_registered_client(self, client_id: str, record: RegisteredClientRecord) -> None:
        validated = record.model_dump(mode="json")
        data = self._clients.load()
        if not isinstance(data, dict):
            data = {}
        data[client_id] = validated
        self._clients.save(data)

    def get_auth_code(self, code: str) -> AuthCodeRecord | None:
        data = self._codes.load()
        rec = data.get(code) if isinstance(data, dict) else None
        if not isinstance(rec, dict):
            return None
        exp = rec.get("expires_at")
        if isinstance(exp, int) and int(time.time()) > exp:
            # expire eagerly
            self.pop_auth_code(code)
            return None
        return AuthCodeRecord.model_validate(rec)

    def put_auth_code(self, code: str, record: AuthCodeRecord) -> None:
        validated = record.model_dump(mode="json")
        data = self._codes.load()
        if not isinstance(data, dict):
            data = {}
        data[code] = validated
        self._codes.save(data)

    def pop_auth_code(self, code: str) -> AuthCodeRecord | None:
        data = self._codes.load()
        if not isinstance(data, dict):
            return None
        rec = data.pop(code, None)
        self._codes.save(data)
        if not isinstance(rec, dict):
            return None
        return AuthCodeRecord.model_validate(rec)

    def get_session(self, session_id: str) -> SessionRecord | None:
        data = self._sessions.load()
        rec = data.get(session_id) if isinstance(data, dict) else None
        if not isinstance(rec, dict):
            return None
        return SessionRecord.model_validate(rec)

    def put_session(self, session_id: str, record: SessionRecord) -> None:
        validated = record.model_dump(mode="json")
        data = self._sessions.load()
        if not isinstance(data, dict):
            data = {}
        data[session_id] = validated
        self._sessions.save(data)

    def delete_session(self, session_id: str) -> None:
        data = self._sessions.load()
        if not isinstance(data, dict):
            return
        data.pop(session_id, None)
        self._sessions.save(data)


