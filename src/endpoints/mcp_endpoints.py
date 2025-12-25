from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import date as Date
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

import jwt
from pydantic import AnyHttpUrl

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Context
from mcp.server.transport_security import TransportSecuritySettings

from src.endpoints.auth_endpoints import JWT_ALG, JWT_SECRET, ISSUER
from src.settings import get_settings
from src.persistence.calorie_state import DiskCalorieStateRepository

REQUIRED_SCOPES = ["toy.read"]
SETTINGS = get_settings()
DEBUG_LOG_TOKENS = SETTINGS.debug_log_tokens

logger = logging.getLogger(__name__)

ISSUER_URL = AnyHttpUrl(ISSUER)
RESOURCE_SERVER_URL = AnyHttpUrl(SETTINGS.resource_server_url)

YYYY_MM_DD_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
Meal = Literal["breakfast", "lunch", "dinner", "snack"]


class ToolTextContent(TypedDict):
    type: Literal["text"]
    text: str


class DailySummary(TypedDict, total=False):
    date: str
    totalCalories: int
    entriesCount: int
    goalCalories: int
    remainingCalories: int


class CalorieEntry(TypedDict, total=False):
    id: str
    food: str
    calories: int
    date: str  # YYYY-MM-DD (local)
    meal: Meal
    notes: str
    createdAt: str  # ISO timestamp


class CalorieToolResponse(TypedDict, total=False):
    content: list[ToolTextContent]
    structuredContent: dict[str, Any]


@dataclass
class _State:
    entries: list[CalorieEntry]
    next_id: int
    daily_goal_calories: int | None


STATE_LOCK = threading.Lock()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CALORIE_REPO = DiskCalorieStateRepository()


def _empty_state() -> _State:
    return _State(entries=[], next_id=1, daily_goal_calories=None)


def _get_user_id(ctx: Context | None) -> str:
    """
    Return the authenticated user identifier for this request.

    For Streamable HTTP, the MCP bearer auth backend attaches an AuthenticatedUser
    to the underlying Starlette request (request.user.access_token.client_id).
    FastMCP's Context.client_id reads from request meta and may be unset, so we
    prefer the Starlette auth user when available.
    """
    if ctx is None:
        return "anonymous"

    # Prefer Starlette AuthenticationMiddleware user if present
    try:
        req = ctx.request_context.request
        user = getattr(req, "user", None) if req is not None else None
        access_token = getattr(user, "access_token", None) if user is not None else None
        principal = getattr(access_token, "client_id", None) if access_token is not None else None
        if isinstance(principal, str) and principal.strip():
            return principal.strip()
    except Exception:
        pass

    # Fallback: FastMCP-provided client_id (may be None depending on transport)
    cid = getattr(ctx, "client_id", None)
    if isinstance(cid, str) and cid.strip():
        return cid.strip()

    return "anonymous"


def _load_state_for_user_locked(user_id: str) -> _State:
    raw = CALORIE_REPO.get_user_state(user_id)
    state = _empty_state()
    entries = raw.get("entries")
    next_id = raw.get("next_id")
    daily_goal = raw.get("daily_goal_calories")
    if isinstance(entries, list):
        cleaned_entries: list[CalorieEntry] = []
        for e in entries:
            if isinstance(e, dict):
                cleaned_entries.append(cast(CalorieEntry, e))
        state.entries = cleaned_entries
    if isinstance(next_id, int) and next_id >= 1:
        state.next_id = next_id
    if daily_goal is None or (isinstance(daily_goal, int) and daily_goal >= 1):
        state.daily_goal_calories = daily_goal
    return state


def _save_state_for_user_locked(user_id: str, state: _State) -> None:
    CALORIE_REPO.save_user_state(
        user_id,
        {
            "entries": state.entries,
            "next_id": state.next_id,
            "daily_goal_calories": state.daily_goal_calories,
        },
    )


def _format_local_date_yyyy_mm_dd(dt: datetime) -> str:
    # Using local time, matching the TS example’s intent.
    return dt.date().isoformat()


def _parse_date_yyyy_mm_dd(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or not YYYY_MM_DD_RE.match(s):
        return None
    try:
        # Validate calendar correctness (e.g. 2025-02-30 should fail)
        Date.fromisoformat(s)
    except ValueError:
        return None
    return s


def _parse_int_nonneg(value: Any) -> int | None:
    if isinstance(value, bool):  # bool is subclass of int in Python
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip() != "":
        try:
            n = int(value)
        except ValueError:
            return None
        return n if n >= 0 else None
    return None


def _parse_goal_int_pos(value: Any) -> int | None:
    n = _parse_int_nonneg(value)
    if n is None or n < 1:
        return None
    return n


def _summarize_for_date(state: _State, yyyy_mm_dd: str) -> DailySummary:
    day_entries = [e for e in state.entries if e.get("date") == yyyy_mm_dd]
    total = sum(int(e.get("calories") or 0) for e in day_entries)
    summary: DailySummary = {
        "date": yyyy_mm_dd,
        "totalCalories": int(total),
        "entriesCount": len(day_entries),
    }
    daily_goal = state.daily_goal_calories
    if isinstance(daily_goal, int):
        goal = daily_goal
        summary["goalCalories"] = goal
        summary["remainingCalories"] = max(0, goal - int(total))
    return summary


def _reply(
    message: str | None = None,
    *,
    entries: list[CalorieEntry] | None = None,
    summary: DailySummary | None = None,
) -> CalorieToolResponse:
    payload_entries = entries if entries is not None else []
    structured: dict[str, Any] = {"entries": payload_entries}
    if summary is not None:
        structured["summary"] = summary
    return {
        "content": ([{"type": "text", "text": message}] if message else []),
        "structuredContent": structured,
    }


class JwtTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALG],
                options={"require": ["exp", "sub", "iss"]},
            )
        except jwt.PyJWTError as e:
            logger.info("MCP VERIFY: jwt decode failed: %r", e)
            return None

        iss = payload.get("iss")
        sub = payload.get("sub")
        scopes = payload.get("scp")
        client_id_claim = payload.get("client_id")

        if DEBUG_LOG_TOKENS:
            # WARNING: Logging bearer tokens is sensitive. Use only for local debugging.
            masked = (token[:16] + "...") if isinstance(token, str) else str(token)
            logger.debug(
                "MCP VERIFY: token=%s iss=%s sub=%s client_id=%s scp=%s",
                masked,
                iss,
                sub,
                client_id_claim,
                scopes,
            )
        logger.debug("MCP VERIFY: iss=%s expected=%s sub=%s scopes=%s", iss, ISSUER, sub, scopes)

        if iss != ISSUER:
            logger.info("MCP VERIFY: issuer mismatch (got=%s expected=%s)", iss, ISSUER)
            return None

        if not isinstance(sub, str) or not sub:
            logger.info("MCP VERIFY: bad sub")
            return None

        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            logger.info("MCP VERIFY: bad scopes")
            return None

        if any(req not in scopes for req in REQUIRED_SCOPES):
            logger.info("MCP VERIFY: missing required scopes %s", REQUIRED_SCOPES)
            return None

        exp = payload.get("exp")
        expires_at = int(exp) if isinstance(exp, int) else None

        return AccessToken(
            token=token,
            client_id=sub,
            scopes=scopes,
            expires_at=expires_at,
            resource=None,
        )



mcp = FastMCP(
    "Toy MCP (OAuth + JWT)",
    stateless_http=True,
    json_response=True,
    token_verifier=JwtTokenVerifier(),
    auth=AuthSettings(
        issuer_url=ISSUER_URL,
        resource_server_url=RESOURCE_SERVER_URL,
        required_scopes=REQUIRED_SCOPES,
    ),
    # Toy / ngrok friendly: FastMCP auto-enables DNS rebinding protection when it thinks it's running
    # on localhost, which rejects ngrok Host headers and returns 421. Disable for this toy app.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
def log_food(
    food: str,
    calories: int | str,
    date: str | None = None,
    meal: Meal | None = None,
    notes: str | None = None,
    ctx: Context | None = None,
) -> CalorieToolResponse:
    """
    Logs a food entry with calories (optionally for a specific date/meal).
    """
    if not isinstance(food, str) or not food.strip():
        return _reply("Invalid input: `food` must be a non-empty string.")
    parsed_calories = _parse_int_nonneg(calories)
    if parsed_calories is None:
        return _reply("Invalid input: `calories` must be an integer >= 0.")

    parsed_date = _parse_date_yyyy_mm_dd(date)
    now = datetime.now()
    yyyy_mm_dd = parsed_date or _format_local_date_yyyy_mm_dd(now)
    user_id = _get_user_id(ctx)
    with STATE_LOCK:
        state = _load_state_for_user_locked(user_id)

    if meal is not None and meal not in ("breakfast", "lunch", "dinner", "snack"):
        return _reply("Invalid input: `meal` must be one of breakfast/lunch/dinner/snack.")
    if notes is not None:
        if not isinstance(notes, str) or not notes.strip():
            return _reply("Invalid input: `notes` must be a non-empty string if provided.")
        if len(notes) > 500:
            return _reply("Invalid input: `notes` must be <= 500 characters.")

    with STATE_LOCK:
        entry_id = f"entry-{state.next_id}"
        state.next_id += 1
    entry: CalorieEntry = {
        "id": entry_id,
        "food": food.strip(),
        "calories": int(parsed_calories),
        "date": yyyy_mm_dd,
        "createdAt": now.isoformat(),
    }
    if meal is not None:
        entry["meal"] = meal
    if notes is not None:
        entry["notes"] = notes

    with STATE_LOCK:
        state.entries = [*state.entries, entry]
        _save_state_for_user_locked(user_id, state)
    summary = _summarize_for_date(state, yyyy_mm_dd)
    return _reply(
        f'Logged {entry["calories"]} calories for "{entry["food"]}" on {yyyy_mm_dd}.',
        entries=list(state.entries),
        summary=summary,
    )


@mcp.tool()
def delete_entry(id: str, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Deletes a logged food entry by id.
    """
    if not isinstance(id, str) or not id.strip():
        return _reply("Missing entry id.")
    user_id = _get_user_id(ctx)
    with STATE_LOCK:
        state = _load_state_for_user_locked(user_id)
        entry = next((e for e in state.entries if e.get("id") == id), None)
    if entry is None:
        return _reply(f"Entry {id} was not found.", entries=list(state.entries))
    with STATE_LOCK:
        state.entries = [e for e in state.entries if e.get("id") != id]
        _save_state_for_user_locked(user_id, state)
    entry_date = str(entry.get("date") or _format_local_date_yyyy_mm_dd(datetime.now()))
    summary = _summarize_for_date(state, entry_date)
    food = entry.get("food") or "unknown"
    return _reply(f'Deleted entry "{food}" ({id}).', entries=list(state.entries), summary=summary)


@mcp.tool()
def list_entries(date: str | None = None, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Lists logged food entries (optionally filtered by date).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        user_id = _get_user_id(ctx)
        with STATE_LOCK:
            state = _load_state_for_user_locked(user_id)
        return _reply("Invalid input: `date` must be YYYY-MM-DD.", entries=list(state.entries))
    user_id = _get_user_id(ctx)
    with STATE_LOCK:
        state = _load_state_for_user_locked(user_id)
    if not parsed_date:
        return _reply("All entries:", entries=list(state.entries))
    with STATE_LOCK:
        filtered = [e for e in state.entries if e.get("date") == parsed_date]
    return _reply(
        f"Entries for {parsed_date}:",
        entries=filtered,
        summary=_summarize_for_date(state, parsed_date),
    )


@mcp.tool()
def get_daily_summary(date: str | None = None, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Returns total calories and entry count for a date (defaults to today).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        user_id = _get_user_id(ctx)
        with STATE_LOCK:
            state = _load_state_for_user_locked(user_id)
        return _reply("Invalid input: `date` must be YYYY-MM-DD.", entries=list(state.entries))
    yyyy_mm_dd = parsed_date or _format_local_date_yyyy_mm_dd(datetime.now())
    user_id = _get_user_id(ctx)
    with STATE_LOCK:
        state = _load_state_for_user_locked(user_id)
    summary = _summarize_for_date(state, yyyy_mm_dd)
    goal_text = (
        f' Goal {summary.get("goalCalories")}, remaining {summary.get("remainingCalories")}.'
        if "goalCalories" in summary
        else ""
    )
    with STATE_LOCK:
        day_entries = [e for e in state.entries if e.get("date") == yyyy_mm_dd]
    return _reply(
        f'Total for {yyyy_mm_dd}: {summary["totalCalories"]} calories across {summary["entriesCount"]} entries.{goal_text}',
        entries=day_entries,
        summary=summary,
    )


@mcp.tool()
def set_daily_goal(calories: int | str, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Sets a daily calorie goal (used by daily summaries).
    """
    goal = _parse_goal_int_pos(calories)
    if goal is None:
        user_id = _get_user_id(ctx)
        with STATE_LOCK:
            state = _load_state_for_user_locked(user_id)
        return _reply("Invalid goal calories.", entries=list(state.entries))
    user_id = _get_user_id(ctx)
    with STATE_LOCK:
        state = _load_state_for_user_locked(user_id)
        state.daily_goal_calories = int(goal)
        _save_state_for_user_locked(user_id, state)
    today = _format_local_date_yyyy_mm_dd(datetime.now())
    return _reply(
        f"Set daily goal to {goal} calories.",
        entries=list(state.entries),
        summary=_summarize_for_date(state, today),
    )
