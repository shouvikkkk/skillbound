"""Bundle inventory: walk a skill directory and classify its files.

SKILL.md itself is inventoried but NOT capability-scanned: its code
fences are documentation and examples, and scanning them would turn
every worked example into a false finding. Code files, hook configs and
package/MCP manifests are scanned.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

CODE_EXTS = {".sh", ".py", ".js", ".ts", ".rb", ".pl"}
CONFIG_NAMES = {"hooks.json", ".mcp.json", "package.json"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


@dataclass
class BundleFile:
    """One file in the skill bundle."""

    path: str  # path relative to the skill root
    kind: str  # "skill-doc" | "code" | "hooks" | "mcp" | "package" | "other"


def inventory(skill_dir: str) -> list[BundleFile]:
    """Walk skill_dir, skipping VCS/venv noise, and classify each file."""
    files: list[BundleFile] = []
    for root, dirs, names in os.walk(skill_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, skill_dir)
            if name == "SKILL.md":
                kind = "skill-doc"
            elif name in CONFIG_NAMES:
                kind = {"hooks.json": "hooks", ".mcp.json": "mcp", "package.json": "package"}[name]
            elif os.path.splitext(name)[1].lower() in CODE_EXTS:
                kind = "code"
            else:
                kind = "other"
            files.append(BundleFile(path=rel, kind=kind))
    return files


def read_text(path: str) -> str | None:
    """Read a file as UTF-8, tolerating undecodable bytes. None on error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None
