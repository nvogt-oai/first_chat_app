#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  echo "Missing .venv. Run ./scripts/setup.sh first."
  exit 1
fi

# Load local env by default, but allow opting out (useful for forcing localhost URLs in tooling).
if [ "${SKIP_LOCAL_ENV:-0}" != "1" ] && [ -f "local.env" ]; then
  set -a
  source local.env
  set +a
fi

. .venv/bin/activate

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
RELOAD="${RELOAD:-1}"

UVICORN_ARGS=(app:app --host "$HOST" --port "$PORT")
if [ "$RELOAD" = "1" ]; then
  UVICORN_ARGS+=(--reload)
fi

cleanup() {
  if [ -n "${NGROK_PID:-}" ] && kill -0 "$NGROK_PID" 2>/dev/null; then
    kill "$NGROK_PID" 2>/dev/null || true
  fi
  if [ -n "${UVICORN_PID:-}" ] && kill -0 "$UVICORN_PID" 2>/dev/null; then
    kill "$UVICORN_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# If NGROK_AUTHTOKEN is set and ngrok is installed, start an ngrok tunnel too.
if [ -n "${NGROK_AUTHTOKEN:-}" ]; then
  if command -v npx >/dev/null 2>&1; then
    # Use npx so we don't require a globally-installed ngrok binary and we avoid writing config files.
    npx --yes ngrok http "$PORT" --log=stdout &
    NGROK_PID=$!
    echo "ngrok started via npx (tunneling :$PORT)."
  else
    echo "NGROK_AUTHTOKEN is set but npx is not available; skipping ngrok."
    echo "Install Node.js (for npx) or unset NGROK_AUTHTOKEN."
  fi
fi

uvicorn "${UVICORN_ARGS[@]}" &
UVICORN_PID=$!

wait "$UVICORN_PID"


