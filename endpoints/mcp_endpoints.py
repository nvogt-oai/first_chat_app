from __future__ import annotations

import logging
import re
from datetime import date as Date
from datetime import datetime
from typing import Any, Literal, NotRequired, TypedDict

import jwt
from pydantic import AnyHttpUrl

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Context
from mcp.server.transport_security import TransportSecuritySettings

from endpoints.auth_endpoints import ISSUER, JWT_ALG, JWT_SECRET
from persistence.calorie_state import CalorieEntryRecord
from persistence import repositories as persistence_repositories
from settings import get_settings

REQUIRED_SCOPES = ["toy.read"]
SETTINGS = get_settings()
DEBUG_LOG_TOKENS = SETTINGS.debug_log_tokens

logger = logging.getLogger(__name__)

ISSUER_URL = AnyHttpUrl(ISSUER)
RESOURCE_SERVER_URL = AnyHttpUrl(SETTINGS.resource_server_url)

YYYY_MM_DD_RE = re.compile(r"^\\d{4}-\\d{2}-\\d{2}$")
Meal = Literal["breakfast", "lunch", "dinner", "snack"]


class ToolTextContent(TypedDict):
    type: Literal["text"]
    text: str


class DailySummary(TypedDict):
    date: str
    totalCalories: int
    entriesCount: int
    goalCalories: NotRequired[int]
    remainingCalories: NotRequired[int]


class CalorieToolResponse(TypedDict, total=False):
    content: list[ToolTextContent]
    structuredContent: dict[str, Any]


CALORIE_REPO = persistence_repositories.AsyncDiskCalorieRepository()


def _get_user_id(ctx: Context | None) -> str:
    if ctx is None:
        raise ValueError("Context is required")

    req = ctx.request_context.request
    if req is None:
        raise ValueError("Missing request on MCP context")

    try:
        user_id = req.user.access_token.client_id
    except AttributeError as e:
        raise ValueError("Missing authenticated user id on MCP context") from e

    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("Invalid authenticated user id on MCP context")

    return user_id.strip()


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


def _summarize_for_entries(entries: list[CalorieEntryRecord], *, yyyy_mm_dd: str, goal: int | None) -> DailySummary:
    day_entries = [e for e in entries if e.date == yyyy_mm_dd]
    total = sum(int(e.calories or 0) for e in day_entries)
    summary: DailySummary = {
        "date": yyyy_mm_dd,
        "totalCalories": int(total),
        "entriesCount": len(day_entries),
    }
    if isinstance(goal, int):
        summary["goalCalories"] = goal
        summary["remainingCalories"] = max(0, goal - int(total))
    return summary


def _reply(
    message: str | None = None,
    *,
    entries: list[CalorieEntryRecord] | None = None,
    summary: DailySummary | None = None,
) -> CalorieToolResponse:
    payload_entries = [
        e.model_dump(mode="json", exclude_none=True) for e in (entries if entries is not None else [])
    ]
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
async def log_food(
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

    if notes is not None:
        if not isinstance(notes, str) or not notes.strip():
            return _reply("Invalid input: `notes` must be a non-empty string if provided.")
        if len(notes) > 500:
            return _reply("Invalid input: `notes` must be <= 500 characters.")

    entry = await CALORIE_REPO.add_entry(
        user_id,
        food=food.strip(),
        calories=int(parsed_calories),
        date=yyyy_mm_dd,
        meal=meal,
        notes=notes,
        created_at=now.isoformat(),
    )
    day_entries = await CALORIE_REPO.list_entries(user_id, date=yyyy_mm_dd)
    summary = _summarize_for_entries(
        day_entries, yyyy_mm_dd=yyyy_mm_dd, goal=await CALORIE_REPO.get_daily_goal(user_id)
    )
    return _reply(
        f'Logged {int(entry.calories or 0)} calories for "{entry.food or ""}" on {yyyy_mm_dd}.',
        entries=day_entries,
        summary=summary,
    )


@mcp.tool()
async def delete_entry(id: str, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Deletes a logged food entry by id.
    """
    if not isinstance(id, str) or not id.strip():
        return _reply("Missing entry id.")
    user_id = _get_user_id(ctx)
    all_entries = await CALORIE_REPO.list_entries(user_id)
    entry = next((e for e in all_entries if e.id == id), None)
    if entry is None:
        return _reply(f"Entry {id} was not found.", entries=all_entries)
    ok = await CALORIE_REPO.delete_entry(user_id, id)
    remaining = await CALORIE_REPO.list_entries(user_id)
    entry_date = str(entry.date or _format_local_date_yyyy_mm_dd(datetime.now()))
    summary = _summarize_for_entries(
        [e for e in remaining if e.date == entry_date],
        yyyy_mm_dd=entry_date,
        goal=await CALORIE_REPO.get_daily_goal(user_id),
    )
    food = entry.food or "unknown"
    msg = f'Deleted entry "{food}" ({id}).' if ok else f'Entry {id} was not found.'
    return _reply(msg, entries=remaining, summary=summary)


@mcp.tool()
async def list_entries(date: str | None = None, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Lists logged food entries (optionally filtered by date).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        user_id = _get_user_id(ctx)
        return _reply(
            "Invalid input: `date` must be YYYY-MM-DD.",
            entries=await CALORIE_REPO.list_entries(user_id),
        )
    user_id = _get_user_id(ctx)
    if not parsed_date:
        return _reply("All entries:", entries=await CALORIE_REPO.list_entries(user_id))
    filtered = await CALORIE_REPO.list_entries(user_id, date=parsed_date)
    return _reply(
        f"Entries for {parsed_date}:",
        entries=filtered,
        summary=_summarize_for_entries(
            filtered, yyyy_mm_dd=parsed_date, goal=await CALORIE_REPO.get_daily_goal(user_id)
        ),
    )


@mcp.tool()
async def get_daily_summary(date: str | None = None, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Returns total calories and entry count for a date (defaults to today).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        user_id = _get_user_id(ctx)
        return _reply(
            "Invalid input: `date` must be YYYY-MM-DD.",
            entries=await CALORIE_REPO.list_entries(user_id),
        )
    yyyy_mm_dd = parsed_date or _format_local_date_yyyy_mm_dd(datetime.now())
    user_id = _get_user_id(ctx)
    day_entries = await CALORIE_REPO.list_entries(user_id, date=yyyy_mm_dd)
    summary = _summarize_for_entries(
        day_entries, yyyy_mm_dd=yyyy_mm_dd, goal=await CALORIE_REPO.get_daily_goal(user_id)
    )
    goal_text = (
        f' Goal {summary.get("goalCalories")}, remaining {summary.get("remainingCalories")}.'
        if "goalCalories" in summary
        else ""
    )
    return _reply(
        f'Total for {yyyy_mm_dd}: {summary["totalCalories"]} calories across {summary["entriesCount"]} entries.{goal_text}',
        entries=day_entries,
        summary=summary,
    )


@mcp.tool()
async def set_daily_goal(calories: int | str, ctx: Context | None = None) -> CalorieToolResponse:
    """
    Sets a daily calorie goal (used by daily summaries).
    """
    goal = _parse_goal_int_pos(calories)
    if goal is None:
        user_id = _get_user_id(ctx)
        return _reply("Invalid goal calories.", entries=await CALORIE_REPO.list_entries(user_id))
    user_id = _get_user_id(ctx)
    await CALORIE_REPO.set_daily_goal(user_id, int(goal))
    today = _format_local_date_yyyy_mm_dd(datetime.now())
    entries = await CALORIE_REPO.list_entries(user_id, date=today)
    return _reply(
        f"Set daily goal to {goal} calories.",
        entries=entries,
        summary=_summarize_for_entries(entries, yyyy_mm_dd=today, goal=await CALORIE_REPO.get_daily_goal(user_id)),
    )


