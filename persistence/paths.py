from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    # persistence/paths.py -> persistence -> project root
    return Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    return ensure_dir(project_root() / "data")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def auth_dir(data_dir: Path) -> Path:
    return ensure_dir(data_dir / "auth")


def calories_dir(data_dir: Path) -> Path:
    return ensure_dir(data_dir / "calories")


def calories_users_dir(data_dir: Path) -> Path:
    return ensure_dir(calories_dir(data_dir) / "users")


