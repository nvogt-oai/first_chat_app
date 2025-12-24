# auth_endpoints.py
from __future__ import annotations
from urllib.parse import urlparse, parse_qs

import base64
import hashlib
import logging
import threading
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlencode
from pathlib import Path

import jwt
from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from json_store import atomic_write_json, read_json  # type: ignore[import-not-found]
from settings import get_settings

router = APIRouter(tags=["auth"])
logger = logging.getLogger(__name__)

# Centralized settings
SETTINGS = get_settings()

# -------------------------------------------------------------------
# CONFIG (toy)
# -------------------------------------------------------------------
JWT_SECRET = SETTINGS.jwt_secret
JWT_ALG = SETTINGS.jwt_alg
DEBUG_LOG_TOKENS = SETTINGS.debug_log_tokens
DEBUG_LOG_REQUESTS = SETTINGS.debug_log_requests

# Set this when using ngrok:
#   export PUBLIC_BASE_URL="https://harsh-jordy-horribly.ngrok-free.dev"
PUBLIC_BASE_URL = SETTINGS.public_base_url

# ✅ Exported constant: other files can import this
DEFAULT_LOCAL_BASE_URL = SETTINGS.local_base_url
ISSUER = SETTINGS.issuer

SCOPES_SUPPORTED = ["toy.read"]

# -------------------------------------------------------------------
# Toy "user login" (username only) with in-memory sessions
# -------------------------------------------------------------------
SESSION_COOKIE_NAME = "toy_session"
SESSIONS: dict[str, dict[str, Any]] = {}  # session_id -> { "username": str, "created_at": int }

AUTH_STATE_LOCK = threading.Lock()
# Persist toy auth state to a separate JSON file in the project directory.
AUTH_STATE_FILE = Path(__file__).with_name("AUTH_STATE.json")


def _persist_auth_state_to_disk() -> None:
    """
    Atomically write auth state to AUTH_STATE.json (toy persistence).

    Schema:
      {
        "registered_clients": { ... },
        "auth_codes": { ... },
        "sessions": { ... }
      }
    """
    with AUTH_STATE_LOCK:
        if not SETTINGS.persist_to_disk:
            return
        payload = {
            "registered_clients": REGISTERED_CLIENTS,
            "auth_codes": AUTH_CODES,
            "sessions": SESSIONS,
        }
        try:
            atomic_write_json(AUTH_STATE_FILE, payload)
        except Exception as e:
            logger.warning("AUTH STATE SAVE: failed to write %s: %r", AUTH_STATE_FILE, e)


def _load_auth_state_from_disk() -> None:
    """
    Load auth state from AUTH_STATE.json if it exists and is valid JSON.
    Drops expired auth codes on load.
    """
    with AUTH_STATE_LOCK:
        try:
            if not SETTINGS.persist_to_disk:
                return
            data = read_json(AUTH_STATE_FILE)
            if not isinstance(data, dict):
                return

            rc = data.get("registered_clients")
            ac = data.get("auth_codes")
            ss = data.get("sessions")

            if isinstance(rc, dict):
                REGISTERED_CLIENTS.clear()
                REGISTERED_CLIENTS.update({str(k): v for k, v in rc.items() if isinstance(v, dict)})

            if isinstance(ss, dict):
                SESSIONS.clear()
                SESSIONS.update({str(k): v for k, v in ss.items() if isinstance(v, dict)})

            # Auth codes are short-lived; drop expired on load.
            if isinstance(ac, dict):
                AUTH_CODES.clear()
                now = int(time.time())
                for k, v in ac.items():
                    if not isinstance(v, dict):
                        continue
                    exp = v.get("expires_at")
                    if isinstance(exp, int) and now > exp:
                        continue
                    AUTH_CODES[str(k)] = v
        except Exception as e:
            logger.warning("AUTH STATE LOAD: failed to load %s: %r", AUTH_STATE_FILE, e)


# Initialize auth state on import
_load_auth_state_from_disk()


def _safe_next_path(next_path: Any) -> str:
    """
    Only allow relative paths (prevent open redirects).
    """
    if not isinstance(next_path, str):
        return "/"
    s = next_path.strip()
    if not s:
        return "/"
    if s.startswith("/") and not s.startswith("//"):
        return s
    return "/"


def _get_username_from_session(request: Request) -> str | None:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        return None
    with AUTH_STATE_LOCK:
        rec = SESSIONS.get(sid)
    if not rec:
        return None
    username = rec.get("username")
    if isinstance(username, str) and username.strip():
        return username.strip()
    return None


@router.get("/login")
async def login_page(request: Request, next: str = "/") -> HTMLResponse:
    next_path = _safe_next_path(next)
    username = _get_username_from_session(request)
    if username:
        return HTMLResponse(
            f"""
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Toy Login</title></head>
  <body>
    <h2>Toy Login</h2>
    <p>Already logged in as <strong>{username}</strong>.</p>
    <p><a href="{next_path}">Continue</a></p>
    <form method="post" action="/logout">
      <button type="submit">Log out</button>
    </form>
  </body>
</html>
""".strip(),
            status_code=200,
        )
    return HTMLResponse(
        f"""
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Toy Login</title></head>
  <body>
    <h2>Toy Login</h2>
    <p>This is a toy app: enter any username; no password.</p>
    <form method="post" action="/login">
      <input type="hidden" name="next" value="{next_path}" />
      <label>Username <input name="username" /></label>
      <button type="submit">Log in</button>
    </form>
  </body>
</html>
""".strip(),
        status_code=200,
    )


@router.post("/login")
async def login_submit(
    response: Response,
    username: str = Form(...),
    next: str = Form("/"),
) -> RedirectResponse:
    uname = username.strip()
    if not uname:
        raise HTTPException(status_code=400, detail="username is required")
    next_path = _safe_next_path(next)

    sid = f"sess_{uuid.uuid4().hex}"
    with AUTH_STATE_LOCK:
        SESSIONS[sid] = {"username": uname, "created_at": int(time.time())}
    _persist_auth_state_to_disk()

    resp = RedirectResponse(url=next_path, status_code=302)
    # Toy cookie (in production you’d set Secure=True behind HTTPS, and consider SameSite).
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return resp


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid:
        with AUTH_STATE_LOCK:
            SESSIONS.pop(sid, None)
        _persist_auth_state_to_disk()
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return resp

# -------------------------------------------------------------------
# In-memory stores (toy; resets on restart)
# -------------------------------------------------------------------
REGISTERED_CLIENTS: dict[str, dict[str, Any]] = {}
AUTH_CODES: dict[str, dict[str, Any]] = {}

# Optional manual client (for curl client_credentials)
STATIC_CLIENT_ID = SETTINGS.static_client_id
STATIC_CLIENT_SECRET = SETTINGS.static_client_secret


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _base_url_from_request(request: Request) -> str:
    # Use public URL when present; otherwise whatever host the request used.
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    return str(request.base_url).rstrip("/")


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _issue_access_token(*, subject: str, scopes: list[str], client_id: str | None = None) -> dict[str, Any]:
    now = int(time.time())
    exp = now + 60 * 60  # 1 hour

    payload = {
        "iss": ISSUER,   # ✅ stable issuer
        "sub": subject,
        "iat": now,
        "exp": exp,
        "scp": scopes,
    }
    if client_id:
        # Useful for tracing which OAuth client obtained the token.
        payload["client_id"] = client_id
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    if DEBUG_LOG_TOKENS:
        # WARNING: This logs bearer tokens. Use only for local debugging.
        logger.debug("ISSUED JWT: sub=%s client_id=%s scopes=%s", subject, client_id, scopes)
        logger.debug("ISSUED JWT (masked): %s", _mask_token(token))
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": exp - now,
        "scope": " ".join(scopes),
    }


def _get_client_auth(request: Request) -> tuple[Optional[str], Optional[str]]:
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("basic "):
        return None, None

    b64 = auth.split(" ", 1)[1].strip()
    try:
        raw = base64.b64decode(b64).decode("utf-8")
        client_id, client_secret = raw.split(":", 1)
        return client_id, client_secret
    except Exception:
        return None, None


def _dbg_len(value: Any) -> str:
    if value is None:
        return "none"
    try:
        s = str(value)
    except Exception:
        return "unprintable"
    return str(len(s))


def _dbg_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _mask_token(token: str, *, head: int = 16, tail: int = 8) -> str:
    if not token:
        return ""
    if len(token) <= head + tail + 3:
        return token
    return f"{token[:head]}...{token[-tail:]}"


# -------------------------------------------------------------------
# WELL-KNOWN METADATA (ChatGPT probes these at ROOT)
# -------------------------------------------------------------------
@router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata(request: Request):
    base = _base_url_from_request(request)

    return JSONResponse(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",  # ✅ DCR
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": SCOPES_SUPPORTED,
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        }
    )


@router.get("/.well-known/openid-configuration")
async def openid_configuration_alias(request: Request):
    return await oauth_authorization_server_metadata(request)


# -------------------------------------------------------------------
# RFC 7591-ish DYNAMIC CLIENT REGISTRATION
# -------------------------------------------------------------------
@router.post("/oauth/register")
async def register_client(body: dict[str, Any]):
    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris):
        raise HTTPException(status_code=400, detail="redirect_uris (list[str]) is required")

    requested_auth_method = body.get("token_endpoint_auth_method") or "none"
    if requested_auth_method not in ("none", "client_secret_post", "client_secret_basic"):
        raise HTTPException(status_code=400, detail="unsupported token_endpoint_auth_method")

    client_id = f"client_{uuid.uuid4().hex}"
    client_secret = None
    if requested_auth_method != "none":
        client_secret = f"secret_{uuid.uuid4().hex}"

    with AUTH_STATE_LOCK:
        REGISTERED_CLIENTS[client_id] = {
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": requested_auth_method,
            "client_secret": client_secret,
            "created_at": int(time.time()),
        }
    _persist_auth_state_to_disk()

    resp: dict[str, Any] = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": requested_auth_method,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }
    if client_secret:
        resp["client_secret"] = client_secret
        resp["client_secret_expires_at"] = 0

    return JSONResponse(resp)


# -------------------------------------------------------------------
# AUTHORIZATION ENDPOINT (toy: auto-approve)
# -------------------------------------------------------------------
@router.get("/oauth/authorize")
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    resource: Optional[str] = None,
):
    # Require a toy "logged in" user (username-only session).
    username = _get_username_from_session(request)
    if not username:
        # Preserve the full authorize URL as a relative path for a post-login redirect.
        next_path = _safe_next_path(str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))
        return RedirectResponse(url=f"/login?{urlencode({'next': next_path})}", status_code=302)

    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported_response_type")

    with AUTH_STATE_LOCK:
        client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="unknown_client")

    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="invalid_redirect_uri")

    scopes = (scope or "toy.read").split()
    for s in scopes:
        if s not in SCOPES_SUPPORTED:
            raise HTTPException(status_code=400, detail=f"unsupported_scope: {s}")

    if code_challenge is not None:
        method = code_challenge_method or "plain"
        if method not in ("plain", "S256"):
            raise HTTPException(status_code=400, detail="unsupported_code_challenge_method")

    code = f"code_{uuid.uuid4().hex}"
    with AUTH_STATE_LOCK:
        AUTH_CODES[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "username": username,
            "scopes": scopes,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method or ("plain" if code_challenge else None),
            "expires_at": int(time.time()) + 5 * 60,
            "resource": resource,
        }
    _persist_auth_state_to_disk()

    params = {"code": code}
    if state:
        params["state"] = state

    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


# -------------------------------------------------------------------
# TOKEN ENDPOINT
# -------------------------------------------------------------------

@router.post("/oauth/token")
async def token(request: Request):
    # Parse either x-www-form-urlencoded or JSON
    content_type = (request.headers.get("content-type") or "").lower()
    data: dict[str, Any] = {}

    if DEBUG_LOG_REQUESTS:
        logger.info(
            "TOKEN REQUEST: url=%s content_type=%s xff=%s ua=%s origin=%s accept=%s",
            str(request.url),
            content_type,
            request.headers.get("x-forwarded-for"),
            request.headers.get("user-agent"),
            request.headers.get("origin"),
            request.headers.get("accept"),
        )

    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        form = await request.form()
        # Starlette forms can include repeated keys; log counts before coercing.
        if DEBUG_LOG_REQUESTS:
            try:
                # type: ignore[attr-defined]
                multi = form.multi_items()
                counts: dict[str, int] = {}
                for k, _v in multi:
                    counts[k] = counts.get(k, 0) + 1
                logger.info("TOKEN REQUEST form key counts: %s", counts)
            except Exception:
                logger.debug("TOKEN REQUEST: failed to inspect multipart form", exc_info=True)
        data = dict(form)

    # SAFE debug: show only keys (not secrets)
    if DEBUG_LOG_REQUESTS:
        logger.info("TOKEN REQUEST keys: %s", sorted(list(data.keys())))
    # If you need more debugging, print selected fields only:
    for k in ("grant_type", "client_id", "redirect_uri", "resource", "scope"):
        if k in data:
            if DEBUG_LOG_REQUESTS:
                logger.info("TOKEN %s: %s", k, data.get(k))
    # Sensitive-ish fields: log presence/length only
    for k in ("code", "code_verifier", "client_secret", "refresh_token"):
        if k in data:
            if DEBUG_LOG_REQUESTS:
                logger.info(
                    "TOKEN %s: present=%s len=%s", k, _dbg_present(data.get(k)), _dbg_len(data.get(k))
                )

    grant_type = data.get("grant_type")

    # Some systems send a full redirect URL; if ever present, extract code/state for debugging
    full_redirect_url = data.get("full_redirect_url")
    if (not data.get("code")) and isinstance(full_redirect_url, str):
        try:
            qs = parse_qs(urlparse(full_redirect_url).query)
            if "code" in qs:
                data["code"] = qs["code"][0]
        except Exception:
            pass

    # Optional client authentication (Basic)
    basic_id, basic_secret = _get_client_auth(request)
    if basic_id:
        data["client_id"] = basic_id
        # only set secret if not already provided
        data.setdefault("client_secret", basic_secret)

    if grant_type == "authorization_code":
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
        code_verifier = data.get("code_verifier")
        resource = data.get("resource")

        if not code or not redirect_uri or not client_id:
            raise HTTPException(status_code=400, detail="missing code/redirect_uri/client_id")

        with AUTH_STATE_LOCK:
            client = REGISTERED_CLIENTS.get(client_id)
        if not client:
            raise HTTPException(status_code=400, detail="unknown_client")

        # Enforce client auth method if applicable
        auth_method = client.get("token_endpoint_auth_method", "none")
        if auth_method in ("client_secret_post", "client_secret_basic"):
            expected = client.get("client_secret")
            if not expected or not client_secret or client_secret != expected:
                raise HTTPException(status_code=401, detail="invalid_client")

        with AUTH_STATE_LOCK:
            record = AUTH_CODES.get(code)
        if not record:
            raise HTTPException(status_code=400, detail="invalid_code")

        if int(time.time()) > int(record["expires_at"]):
            with AUTH_STATE_LOCK:
                AUTH_CODES.pop(code, None)
            _persist_auth_state_to_disk()
            raise HTTPException(status_code=400, detail="expired_code")

        if record["client_id"] != client_id or record["redirect_uri"] != redirect_uri:
            raise HTTPException(status_code=400, detail="code_mismatch")

        # ✅ resource echo (ChatGPT may send it; spec expects it to be echoed) :contentReference[oaicite:3]{index=3}
        expected_resource = record.get("resource")
        if expected_resource and resource and resource != expected_resource:
            raise HTTPException(status_code=400, detail="resource_mismatch")

        # PKCE verification if used
        cc = record.get("code_challenge")
        if cc is not None:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="missing_code_verifier")

            method = record.get("code_challenge_method") or "plain"
            if method == "plain":
                derived = code_verifier
            else:  # S256
                derived = _b64url_no_pad(hashlib.sha256(code_verifier.encode("utf-8")).digest())

            if derived != cc:
                raise HTTPException(status_code=400, detail="invalid_code_verifier")

        # one-time use
        with AUTH_STATE_LOCK:
            AUTH_CODES.pop(code, None)
        _persist_auth_state_to_disk()

        # Include resource as audience if present (nice-to-have)
        username = record.get("username")
        if not isinstance(username, str) or not username.strip():
            raise HTTPException(status_code=400, detail="invalid_code_user")
        token_payload = _issue_access_token(subject=username.strip(), scopes=record["scopes"], client_id=client_id)
        # If you want aud, change _issue_access_token to accept aud/resource and include it.

        return JSONResponse(token_payload)

    if grant_type == "client_credentials":
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
        scope = data.get("scope")

        if client_id != STATIC_CLIENT_ID or client_secret != STATIC_CLIENT_SECRET:
            raise HTTPException(status_code=401, detail="invalid_client")

        scopes = (scope or "toy.read").split()
        for s in scopes:
            if s not in SCOPES_SUPPORTED:
                raise HTTPException(status_code=400, detail=f"unsupported_scope: {s}")

        # client_credentials is client-only (no user)
        return JSONResponse(_issue_access_token(subject=client_id, scopes=scopes, client_id=client_id))

    raise HTTPException(status_code=400, detail="unsupported_grant_type")
