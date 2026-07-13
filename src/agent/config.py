"""Optional local configuration.

Lets an operator supply an ANTHROPIC_API_KEY (or other env vars) via a local
`.env` file without hardcoding secrets. This is opt-in: if no `.env` exists, or
it doesn't set the key, the agent falls back to the existing Claude Code login.
Existing environment variables are never overridden.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: Path) -> list[str]:
    """Load simple KEY=VALUE lines from `path` into os.environ.

    - A missing file is a no-op (returns []).
    - Blank lines and `#` comments are ignored.
    - A variable already present in the environment is NOT overridden.
    - Returns the names of the variables that were set (never the values).
    """
    if not path.is_file():
        return []
    loaded: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key or key in os.environ:
            continue
        os.environ[key] = value
        loaded.append(key)
    return loaded
