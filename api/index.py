"""
Vercel Python entrypoint.

Vercel expects an importable ASGI app from the `api/` directory by default.
"""

from __future__ import annotations

from app import app


