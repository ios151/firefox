"""Config file handling (JSON)."""
from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_PATH = Path(
    os.environ.get("FXPROXY_CONFIG", Path.home() / ".config" / "fxproxy" / "config.json")
)

DEFAULTS = {
    "refresh_token": "",
    "country": "",        # "" = any; else ISO code like "US", "GB", "DE"
    "host": "127.0.0.1",
    "http_port": 8080,
    "socks_port": 1080,
    "failover": 3,        # nodes to try per connection before giving up
}


def load(path: Path | None = None) -> dict:
    path = Path(path) if path else DEFAULT_PATH
    cfg = dict(DEFAULTS)
    if path.exists():
        cfg.update(json.loads(path.read_text()))
    # env override for the secret
    if os.environ.get("FXPROXY_REFRESH_TOKEN"):
        cfg["refresh_token"] = os.environ["FXPROXY_REFRESH_TOKEN"]
    return cfg


def save(cfg: dict, path: Path | None = None) -> Path:
    path = Path(path) if path else DEFAULT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    os.chmod(path, 0o600)
    return path
