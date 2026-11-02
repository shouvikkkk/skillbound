"""Cross-file ask-first guard graph.

v0.1 asked: does the file that performs a sensitive capability itself
contain a confirmation prompt? Real skills rarely work that way: a
thin entry script prompts ("Send the report?") and then calls a helper
that does the curl, or a hooks.json entry invokes the script that
prompts. v0.1 flagged those helpers as contradictions — a false
positive on the most common honest layout.

This module builds a small reference graph over the bundle and answers
the question the checker actually needs: is this capability file
*guarded* by a prompt somewhere on the path that reaches it?

Guarding rule (deliberately conservative):
- A file guards itself if it contains a prompt (the v0.1 behaviour).
- A prompting file P guards a file F it references, but only when the
  prompt appears BEFORE the reference in P — a prompt after the call
  cannot have authorised the call.
- Guarding is transitive past that first hop: once P has prompted and
  called F, anything F itself calls runs after the prompt too, so
  F's references are guarded as well (their own ordering is not
  re-checked — that is a documented over-approximation).
- An unrelated prompting file guards nothing: the prompt must reach
  the capability through references, not merely coexist in the bundle.

References are recognised textually, per file kind:
- Python: `import helper`, `from helper import ...` (module stem).
- JS/TS: `import ... from './helper'`, `require('./helper')`.
- Shell: `source helper.sh`, `. helper.sh`, `bash helper.sh`,
  `python helper.py`, `node helper.js`, `./helper.sh`.
- JSON (hooks.json, .mcp.json, package.json): any quoted string whose
  basename is a bundle file — hook commands are usually just paths.

Resolution is by basename (or, for extensionless imports, by stem):
`import helper` resolves to `scripts/helper.py`. If two bundle files
share a basename, a reference resolves to all of them — ambiguous
references over-guard rather than under-guard, and the ambiguity is
inherent in the textual signal, so it is documented, not hidden.
"""

from __future__ import annotations

import os
import re
from collections import deque

# Same prompt vocabulary as crosscheck.CONFIRM_PROMPT_RE, kept here so
# guardgraph does not import crosscheck (which imports guardgraph).
PROMPT_RE = re.compile(
    r"(read\s+-p|input\s*\(|confirm|are you sure|press\s+enter\s+to\s+continue|yes/no)",
    re.I,
)

_PY_IMPORT = re.compile(
    r"^\s*(?:import\s+([A-Za-z0-9_\.]+)|from\s+([A-Za-z0-9_\.]+)\s+import\s)",
    re.M,
)
_JS_IMPORT = re.compile(r"""(?:from\s+|require\s*\(\s*)['"]([^'"]+)['"]""")
_SHELL_CALL = re.compile(
    r"(?:^|[;\s&|])(?:source\s+|\.\s+|bash\s+|sh\s+|python3?\s+|node\s+|ruby\s+|perl\s+)([^\s;'\"|&]+)"
)
_DIRECT_EXEC = re.compile(r"(?:^|[\s;\|&])(\./[^\s;'\"|&]+)")
_JSON_STRING = re.compile(r'"([^"]+)"')


def _resolve(raw: str, by_basename: dict[str, list[str]], by_stem: dict[str, list[str]]) -> list[str]:
    """Resolve a referenced path/module to bundle files (possibly none)."""
    base = raw.replace("\\", "/").rstrip("/").split("/")[-1]
    if not base or base in (".", ".."):
        return []
    if base in by_basename:
        return list(by_basename[base])
    stem = base.rsplit(".", 1)[0] if "." in base else base
    # Extensionless imports (import helper, require('./helper')) match
    # by stem; dotted Python modules match on their last component.
    last = raw.replace("\\", "/").split("/")[-1].split(".")[-1]
    for key in (stem, last):
        if key in by_stem:
            return list(by_stem[key])
    return []


def references(text: str, filename: str, files: list[str]) -> list[tuple[int, str]]:
    """Return [(position, resolved_bundle_file)] referenced by this file.

    `files` is the full list of bundle file paths; the file itself is
    never returned as its own reference.
    """
    by_basename: dict[str, list[str]] = {}
    by_stem: dict[str, list[str]] = {}
    for f in files:
        if f == filename:
            continue
        by_basename.setdefault(os.path.basename(f), []).append(f)
        stem = os.path.splitext(os.path.basename(f))[0]
        by_stem.setdefault(stem, []).append(f)

    found: dict[str, int] = {}  # resolved file -> earliest position

    def _add(raw: str, pos: int) -> None:
        for target in _resolve(raw, by_basename, by_stem):
            if target not in found or pos < found[target]:
                found[target] = pos

    if filename.endswith(".json"):
        for m in _JSON_STRING.finditer(text):
            _add(m.group(1), m.start(1))
        return sorted(((pos, f) for f, pos in found.items()), key=lambda t: t[0])

    for m in _PY_IMPORT.finditer(text):
        raw = m.group(1) or m.group(2)
        _add(raw, m.start())
    for m in _JS_IMPORT.finditer(text):
        _add(m.group(1), m.start(1))
    for m in _SHELL_CALL.finditer(text):
        _add(m.group(1), m.start(1))
    for m in _DIRECT_EXEC.finditer(text):
        _add(m.group(1), m.start(1))
    return sorted(((pos, f) for f, pos in found.items()), key=lambda t: t[0])


def guarded_files(file_texts: dict[str, str]) -> set[str]:
    """Return the set of bundle files guarded by a confirmation prompt.

    A file is guarded if it contains a prompt itself, or if it is
    reachable through references from a prompting file where the
    prompt precedes the first-hop reference (see module docstring).
    """
    files = sorted(file_texts)
    adjacency: dict[str, list[tuple[int, str]]] = {
        f: references(text, f, files) for f, text in file_texts.items()
    }
    prompt_positions: dict[str, list[int]] = {
        f: [m.start() for m in PROMPT_RE.finditer(text)]
        for f, text in file_texts.items()
    }

    prompting = {f for f, positions in prompt_positions.items() if positions}
    guarded: set[str] = set(prompting)

    # First hops out of a prompting file are order-checked: only
    # references after (at least one) prompt in that file count, since
    # a prompt after the call cannot have authorised the call.
    frontier: deque[str] = deque()
    for source in sorted(prompting):
        for pos, target in adjacency.get(source, []):
            if any(p < pos for p in prompt_positions[source]):
                if target not in guarded:
                    guarded.add(target)
                frontier.append(target)

    # Transitive closure from those first hops, unconditional: code in
    # a guarded file only runs after the root prompt, so anything it
    # calls is guarded too — including files that are themselves
    # prompting files (their own prompt position is then irrelevant).
    seen: set[str] = set(frontier)
    while frontier:
        current = frontier.popleft()
        for _pos, target in adjacency.get(current, []):
            if target in seen:
                continue
            seen.add(target)
            guarded.add(target)
            frontier.append(target)
    return guarded
