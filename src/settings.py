from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Deployment / URLs
    public_base_url: str
    local_base_url: str
    issuer: str
    resource_server_url: str

    # JWT
    jwt_secret: str
    jwt_alg: str

    # Debug
    debug_log_tokens: bool
    debug_log_requests: bool

    # Optional static client for client_credentials
    static_client_id: str
    static_client_secret: str

    # Persistence (serverless-friendly default: off)
    persist_to_disk: bool


def get_settings() -> Settings:
    public_base_url = (os.getenv("PUBLIC_BASE_URL", "")).rstrip("/")
    local_base_url = (os.getenv("LOCAL_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
    issuer = public_base_url or local_base_url

    resource_server_url = (os.getenv("RESOURCE_SERVER_URL", f"{issuer}/mcp")).rstrip("/")

    # NOTE: default is insecure; set JWT_SECRET in production
    jwt_secret = os.getenv("JWT_SECRET", "dev-only-super-secret")
    jwt_alg = os.getenv("JWT_ALG", "HS256")

    debug_log_tokens = _env_bool("DEBUG_LOG_TOKENS", False)
    debug_log_requests = _env_bool("DEBUG_LOG_REQUESTS", True)

    static_client_id = os.getenv("STATIC_CLIENT_ID", "toy-client")
    static_client_secret = os.getenv("STATIC_CLIENT_SECRET", "toy-secret")

    # Serverless filesystems are ephemeral; default off unless explicitly enabled.
    persist_to_disk = _env_bool("PERSIST_TO_DISK", False)

    return Settings(
        public_base_url=public_base_url,
        local_base_url=local_base_url,
        issuer=issuer,
        resource_server_url=resource_server_url,
        jwt_secret=jwt_secret,
        jwt_alg=jwt_alg,
        debug_log_tokens=debug_log_tokens,
        debug_log_requests=debug_log_requests,
        static_client_id=static_client_id,
        static_client_secret=static_client_secret,
        persist_to_disk=persist_to_disk,
    )


