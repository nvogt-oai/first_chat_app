from __future__ import annotations

import contextlib
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    from endpoints.mcp_endpoints import mcp

    async with mcp.session_manager.run():
        yield


def create_app() -> FastAPI:
    load_dotenv("local.env")

    from endpoints.auth_endpoints import ISSUER, router as auth_router
    from endpoints.mcp_endpoints import mcp

    mcp.settings.streamable_http_path = "/"

    app = FastAPI(lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
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

    @app.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource_metadata():
        return JSONResponse(
            {
                # Keep resource URL stable (no trailing slash) to avoid strict URL mismatch in clients.
                "resource": f"{ISSUER}/mcp",
                "authorization_servers": [ISSUER],
                "scopes_supported": ["toy.read"],
                "bearer_methods_supported": ["header"],
            }
        )

    @app.get("/.well-known/oauth-protected-resource/{rest:path}")
    async def oauth_protected_resource_metadata_alias(rest: str):
        return await oauth_protected_resource_metadata()

    app.include_router(auth_router)

    app.mount("/mcp", mcp.streamable_http_app())

    return app


app = create_app()
