"""Absolute, private paths independent of the caller's current directory."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]


def private_dir(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("Runtime paths must be absolute")
    # Refuse directory symlinks before creating or chmod-ing anything.
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError(f"Symlink directory is not permitted: {part}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


@dataclass(frozen=True)
class Settings:
    root: Path
    state_dir: Path
    profile_dir: Path
    proxy_url: str
    egress_mode: str
    model: str
    base_url: str
    api_key: str
    chrome_path: str
    display: str = ":99"

    @classmethod
    def load(cls) -> "Settings":
        root = Path(os.environ.get("BROCODE_ROOT", str(ROOT))).expanduser().resolve()
        values = {**dotenv_values(root / ".env"), **os.environ}

        def absolute(name: str, default: Path) -> Path:
            p = Path(values.get(name) or default).expanduser()
            if not p.is_absolute():
                raise ValueError(f"{name} must be absolute")
            return p

        return cls(
            root=root,
            state_dir=absolute("BROCODE_STATE_DIR", root / "var"),
            profile_dir=absolute("CHROME_USER_DATA_DIR", root / ".chrome_profile"),
            proxy_url=values.get("BROCODE_PROXY_URL") or "",
            egress_mode=values.get("BROCODE_EGRESS_MODE") or "tailscale",
            model=values.get("VISION_MODEL") or values.get("DEFAULT_MODEL") or "gpt-4.1",
            base_url=values.get("OPENAI_BASE_URL") or "https://api.openai.com/v1",
            api_key=values.get("OPENAI_API_KEY") or "",
            chrome_path=values.get("BROCODE_CHROME_PATH") or "/usr/bin/google-chrome",
            display=values.get("DISPLAY") or values.get("BROCODE_DISPLAY") or ":99",
        )
