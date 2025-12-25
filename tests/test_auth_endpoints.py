from __future__ import annotations

from fastapi.testclient import TestClient


def test_login_sets_cookie_and_authorize_redirects(reload_endpoints):
    import app as app_module

    client = TestClient(app_module.create_app())

    # Register client (DCR)
    r = client.post(
        "/oauth/register",
        json={
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 200
    client_id = r.json()["client_id"]

    # Log in
    r = client.post("/login", data={"username": "alice", "next": "/"}, follow_redirects=False)
    assert r.status_code == 302
    assert "toy_session=" in r.headers.get("set-cookie", "")

    # Authorize should redirect to redirect_uri with a code
    r = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://example.com/cb",
            "scope": "toy.read",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://example.com/cb?")
    assert "code=" in r.headers["location"]


