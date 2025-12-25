from __future__ import annotations

from fastapi.testclient import TestClient


def test_app_smoke_routes(reload_endpoints):
    import app as app_module

    client = TestClient(app_module.create_app())

    r = client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    assert "authorization_endpoint" in r.json()

    # mcp redirect helpers
    r = client.get("/mcp", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/mcp/"


