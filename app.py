# app.py
from __future__ import annotations

import contextlib
import logging

# Load local environment variables early (before importing modules that read env vars).
from dotenv import load_dotenv

load_dotenv("local.env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from auth_endpoints import ISSUER, router as auth_router
from mcp_endpoints import mcp

logger = logging.getLogger(__name__)

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

# Include auth routes (this router already defines /oauth/* and /.well-known/* paths)
app.include_router(auth_router)

# MCP server
app.mount("/mcp", mcp.streamable_http_app())
