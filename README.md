## first_chat_app

Toy FastAPI app that exposes an MCP server protected by a minimal OAuth2 (authorization code + optional PKCE) flow.

### What’s in here

- **`app.py`**: FastAPI entrypoint, CORS, mounts MCP at `/mcp/`
- **`auth_endpoints.py`**: toy login + OAuth endpoints (`/oauth/*`) and auth metadata (`/.well-known/*`)
- **`mcp_endpoints.py`**: MCP tools (calorie logging) + JWT bearer verification
- **`AUTH_STATE.json`**: persisted toy auth state (registered clients, auth codes, sessions)
- **`DATA.json`**: persisted toy per-user calorie data

### Run locally

Install deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run:

```bash
uvicorn app:app --reload
```

### Local env file

This repo uses `python-dotenv` to load `local.env` automatically when you import `app.py`.

### Env vars (optional)

- **`PUBLIC_BASE_URL`**: public URL (e.g. ngrok) used as OAuth issuer
- **`LOCAL_BASE_URL`**: local issuer fallback (default `http://127.0.0.1:8000`)
- **`JWT_SECRET`**: JWT signing secret (toy default is insecure)
- **`JWT_ALG`**: JWT algorithm (default `HS256`)
- **`DEBUG_LOG_TOKENS`**: `1` to log masked token details
- **`DEBUG_LOG_REQUESTS`**: `1` to log token request envelopes (no secrets)
- **`RESOURCE_SERVER_URL`**: overrides the OAuth resource server URL (defaults to `${ISSUER}/mcp`)
- **`PERSIST_TO_DISK`**: `1` to persist `AUTH_STATE.json` / `DATA.json` (defaults **off**, recommended off on Vercel)

### Vercel notes

- This repo includes **`api/index.py`** and **`vercel.json`** so Vercel can import the ASGI app.
- **Do not rely on `AUTH_STATE.json` / `DATA.json` on Vercel**. Serverless filesystems are ephemeral.
  - For persistence, use Vercel KV/Redis, Postgres, or Blob storage instead.
  - If you still enable `PERSIST_TO_DISK=1`, expect data loss across deploys/instances.
- In Vercel project settings, set **`PUBLIC_BASE_URL`** to your deployed domain (no trailing slash) and set a strong **`JWT_SECRET`**.


