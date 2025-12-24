# mcp_endpoints.py
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date as Date
from datetime import datetime
from typing import Any, Literal, TypedDict

import jwt
from pydantic import AnyHttpUrl

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from auth_endpoints import JWT_ALG, JWT_SECRET, ISSUER

REQUIRED_SCOPES = ["toy.read"]

ISSUER_URL = AnyHttpUrl(ISSUER)
RESOURCE_SERVER_URL = AnyHttpUrl("http://localhost:8000/mcp")

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


STATE = _State(entries=[], next_id=1, daily_goal_calories=None)


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


def _summarize_for_date(yyyy_mm_dd: str) -> DailySummary:
    day_entries = [e for e in STATE.entries if e.get("date") == yyyy_mm_dd]
    total = sum(int(e.get("calories") or 0) for e in day_entries)
    summary: DailySummary = {
        "date": yyyy_mm_dd,
        "totalCalories": int(total),
        "entriesCount": len(day_entries),
    }
    if isinstance(STATE.daily_goal_calories, int):
        goal = STATE.daily_goal_calories
        summary["goalCalories"] = goal
        summary["remainingCalories"] = max(0, goal - int(total))
    return summary


def _reply(
    message: str | None = None,
    *,
    entries: list[CalorieEntry] | None = None,
    summary: DailySummary | None = None,
) -> CalorieToolResponse:
    payload_entries = entries if entries is not None else STATE.entries
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
            print("MCP VERIFY: jwt decode failed:", repr(e))
            return None

        iss = payload.get("iss")
        sub = payload.get("sub")
        scopes = payload.get("scp")

        print("MCP VERIFY: iss=", iss, " expected=", ISSUER)
        print("MCP VERIFY: sub=", sub)
        print("MCP VERIFY: scopes=", scopes)

        if iss != ISSUER:
            print("MCP VERIFY: issuer mismatch")
            return None

        if not isinstance(sub, str) or not sub:
            print("MCP VERIFY: bad sub")
            return None

        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            print("MCP VERIFY: bad scopes")
            return None

        if any(req not in scopes for req in REQUIRED_SCOPES):
            print("MCP VERIFY: missing required scopes", REQUIRED_SCOPES)
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

    if meal is not None and meal not in ("breakfast", "lunch", "dinner", "snack"):
        return _reply("Invalid input: `meal` must be one of breakfast/lunch/dinner/snack.")
    if notes is not None:
        if not isinstance(notes, str) or not notes.strip():
            return _reply("Invalid input: `notes` must be a non-empty string if provided.")
        if len(notes) > 500:
            return _reply("Invalid input: `notes` must be <= 500 characters.")

    entry_id = f"entry-{STATE.next_id}"
    STATE.next_id += 1
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

    STATE.entries = [*STATE.entries, entry]
    summary = _summarize_for_date(yyyy_mm_dd)
    return _reply(f'Logged {entry["calories"]} calories for "{entry["food"]}" on {yyyy_mm_dd}.', summary=summary)


@mcp.tool()
def delete_entry(id: str) -> CalorieToolResponse:
    """
    Deletes a logged food entry by id.
    """
    if not isinstance(id, str) or not id.strip():
        return _reply("Missing entry id.")
    entry = next((e for e in STATE.entries if e.get("id") == id), None)
    if entry is None:
        return _reply(f"Entry {id} was not found.")
    STATE.entries = [e for e in STATE.entries if e.get("id") != id]
    entry_date = str(entry.get("date") or _format_local_date_yyyy_mm_dd(datetime.now()))
    summary = _summarize_for_date(entry_date)
    food = entry.get("food") or "unknown"
    return _reply(f'Deleted entry "{food}" ({id}).', summary=summary)


@mcp.tool()
def list_entries(date: str | None = None) -> CalorieToolResponse:
    """
    Lists logged food entries (optionally filtered by date).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        return _reply("Invalid input: `date` must be YYYY-MM-DD.")
    if not parsed_date:
        return _reply("All entries:")
    filtered = [e for e in STATE.entries if e.get("date") == parsed_date]
    return _reply(
        f"Entries for {parsed_date}:",
        entries=filtered,
        summary=_summarize_for_date(parsed_date),
    )


@mcp.tool()
def get_daily_summary(date: str | None = None) -> CalorieToolResponse:
    """
    Returns total calories and entry count for a date (defaults to today).
    """
    parsed_date = _parse_date_yyyy_mm_dd(date)
    if date is not None and parsed_date is None:
        return _reply("Invalid input: `date` must be YYYY-MM-DD.")
    yyyy_mm_dd = parsed_date or _format_local_date_yyyy_mm_dd(datetime.now())
    summary = _summarize_for_date(yyyy_mm_dd)
    goal_text = (
        f' Goal {summary.get("goalCalories")}, remaining {summary.get("remainingCalories")}.'
        if "goalCalories" in summary
        else ""
    )
    day_entries = [e for e in STATE.entries if e.get("date") == yyyy_mm_dd]
    return _reply(
        f'Total for {yyyy_mm_dd}: {summary["totalCalories"]} calories across {summary["entriesCount"]} entries.{goal_text}',
        entries=day_entries,
        summary=summary,
    )


@mcp.tool()
def set_daily_goal(calories: int | str) -> CalorieToolResponse:
    """
    Sets a daily calorie goal (used by daily summaries).
    """
    goal = _parse_goal_int_pos(calories)
    if goal is None:
        return _reply("Invalid goal calories.")
    STATE.daily_goal_calories = int(goal)
    today = _format_local_date_yyyy_mm_dd(datetime.now())
    return _reply(f"Set daily goal to {goal} calories.", summary=_summarize_for_date(today))
