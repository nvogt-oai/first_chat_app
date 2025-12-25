from __future__ import annotations

import importlib
from pathlib import Path
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    # Ensure top-level imports like `import persistence` work even when pytest
    # is invoked in an environment that doesn't add the repo root to sys.path.
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sandbox_project(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """
    Redirect persistence paths to a temp project directory so tests never touch real ./data.
    """
    import persistence.paths as paths

    def _project_root() -> Path:
        return tmp_path

    def _data_dir() -> Path:
        p = tmp_path / "data"
        p.mkdir(parents=True, exist_ok=True)
        return p

    monkeypatch.setattr(paths, "project_root", _project_root)
    monkeypatch.setattr(paths, "data_dir", _data_dir)
    return tmp_path


@pytest.fixture
def reload_endpoints(sandbox_project: Path) -> None:
    """
    Endpoints create repo singletons at import time; reload after sandboxing paths.
    """
    import endpoints.auth_endpoints as auth_endpoints
    import endpoints.mcp_endpoints as mcp_endpoints

    importlib.reload(auth_endpoints)
    importlib.reload(mcp_endpoints)


