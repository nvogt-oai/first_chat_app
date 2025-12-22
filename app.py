# app.py
from __future__ import annotations

import contextlib
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from auth_endpoints import ISSUER, router as auth_router
from mcp_endpoints import mcp

# MCP lives at /mcp/ (note the trailing slash matters for some clients)
mcp.settings.streamable_http_path = "/"

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield

app = FastAPI(lifespan=lifespan)

# CORS for Inspector (browser)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # toy only
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
from fastapi.responses import RedirectResponse

@app.post("/mcp")
async def mcp_redirect_post():
    return RedirectResponse(url="/mcp/", status_code=307)

@app.get("/mcp")
async def mcp_redirect_get():
    return RedirectResponse(url="/mcp/", status_code=307)

# ---- OAuth Protected Resource Metadata (use public ISSUER, not localhost) ----
@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata():
    return JSONResponse(
        {
            "resource": f"{ISSUER}/mcp/",
            "authorization_servers": [ISSUER],
            "scopes_supported": ["toy.read"],
            "bearer_methods_supported": ["header"],
        }
    )

# Some clients request a suffixed variant (you saw "/.../mcp")
@app.get("/.well-known/oauth-protected-resource/{rest:path}")
async def oauth_protected_resource_metadata_alias(rest: str):
    return await oauth_protected_resource_metadata()

# ---- Authorization Server metadata at ROOT (use public ISSUER) ----
@app.get("/.well-known/oauth-authorization-server")
async def oauth_as_metadata_root():
    return JSONResponse(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oauth/authorize",
            "token_endpoint": f"{ISSUER}/oauth/token",
            "registration_endpoint": f"{ISSUER}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": ["toy.read"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        }
    )

@app.get("/.well-known/openid-configuration")
async def openid_config_root():
    return await oauth_as_metadata_root()

# Include auth routes (this router already defines /oauth/* and /.well-known/* paths)
app.include_router(auth_router)

# MCP server
app.mount("/mcp", mcp.streamable_http_app())
