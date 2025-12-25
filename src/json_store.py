from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any | None:
    """
    Read JSON from disk.

    Returns None for missing files, empty files, or invalid JSON.
    """
    try:
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return None
        return json.loads(raw)
    except Exception:
        return None


def atomic_write_json(path: Path, payload: Any, *, indent: int = 2, sort_keys: bool = True) -> None:
    """
    Atomically write JSON to disk by writing to a temp file then replacing.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=indent, sort_keys=sort_keys)
        f.write("\n")
    tmp_path.replace(path)


