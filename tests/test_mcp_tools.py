from __future__ import annotations

import asyncio
from types import SimpleNamespace


def _fake_ctx(client_id: str):
    # minimal shape for _get_user_id: ctx.request_context.request.user.access_token.client_id
    access_token = SimpleNamespace(client_id=client_id)
    user = SimpleNamespace(access_token=access_token)
    request = SimpleNamespace(user=user)
    request_context = SimpleNamespace(request=request)
    return SimpleNamespace(request_context=request_context)


def test_mcp_tools_basic_flow(reload_endpoints):
    async def _run():
        import endpoints.mcp_endpoints as mcp

        ctx = _fake_ctx("u1")

        r = await mcp.log_food(food="banana", calories=105, ctx=ctx)
        assert "structuredContent" in r
        assert len(r["structuredContent"]["entries"]) == 1

        r2 = await mcp.get_daily_summary(ctx=ctx)
        assert "Total for" in (r2["content"][0]["text"] if r2.get("content") else "")

        r3 = await mcp.set_daily_goal(2000, ctx=ctx)
        assert "Set daily goal" in (r3["content"][0]["text"] if r3.get("content") else "")

    asyncio.run(_run())


