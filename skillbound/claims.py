"""Boundary-claim extraction from SKILL.md.

A *claim* is a sentence in SKILL.md (frontmatter or body) that states a
boundary: something the skill promises NOT to do, or promises to ask
about first. Each claim maps to the capability categories it forbids.

Code fences never produce claims: example commands inside a fenced block
are documentation, not promises. Lines that look like examples
("e.g.", "for instance") are kept but demoted to low confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Capability categories a claim can forbid.
NETWORK = "NETWORK_EGRESS"
WRITE = "FILE_WRITE"
DELETE = "FILE_DELETE"
SECRET = "SECRET_ACCESS"
EXEC = "INSTALL_EXEC"
CONFIG = "CONFIG_EDIT"
CONFIRM = "CONFIRM_FIRST"  # not a capability; a "ask before acting" promise

# Negation lead-ins shared by most patterns.
_NEG = r"(?:never|does\s+not|doesn'?t|do\s+not|don'?t|won'?t|will\s+not|cannot|can'?t|must\s+not|no)"

# (pattern, forbidden categories, short label)
_CLAIM_PATTERNS: list[tuple[re.Pattern, list[str], str]] = [
    # Read-only family: forbids every mutating capability.
    (
        re.compile(
            r"\b(read[- ]only|only\s+reads?|analysis[- ]only|never\s+modif\w*)\b",
            re.I,
        ),
        [WRITE, DELETE, EXEC, CONFIG],
        "read-only",
    ),
    # Network: never sends / uploads / posts / phones home ...
    (
        re.compile(
            _NEG + r"\b[^.;]{0,60}?\b(send\w*|upload\w*|post\w*|transmit\w*|shar\w*|phone\s+home)\b",
            re.I,
        ),
        [NETWORK],
        "does-not-send",
    ),
    # Network: never calls / contacts / fetches from the network.
    (
        re.compile(
            _NEG + r"\b[^.;]{0,60}?\b(call\w*|contact\w*|fetch\w*|download\w*|connect\w*)\b",
            re.I,
        ),
        [NETWORK],
        "does-not-call-out",
    ),
    # Network: local-only / offline / no network.
    (
        re.compile(r"\b(local[- ]only|offline|no\s+(network|internet|external)\s+(access|calls?|requests?|services?|servers?|endpoints?)?)\b", re.I),
        [NETWORK],
        "local-only",
    ),
    # Network, paraphrased (no negation marker): nothing leaves the
    # machine, data stays local, runs entirely locally, on-device only.
    # These are the promises the README's Limitations used to admit
    # were missed; they are real boundary statements, not marketing.
    (
        re.compile(
            r"\b((nothing|no\s+data)\s+leaves?\s+(this\s+|your\s+|the\s+)?(machine|computer|system|box|device))\b",
            re.I,
        ),
        [NETWORK],
        "nothing-leaves",
    ),
    (
        re.compile(
            r"\b((stays?|remains?)\s+(local|on\s+(your\s+|this\s+)?(machine|computer|device))|keeps?\s+(everything\s+)?on\s+(your\s+|this\s+)?(machine|computer|device)|runs?\s+(entirely\s+|fully\s+)?locally|on[- ]device(\s+only)?)\b",
            re.I,
        ),
        [NETWORK],
        "stays-local",
    ),
    (
        re.compile(r"\bno\s+third[- ]party\s+(services?|servers?|calls?|requests?)?\b", re.I),
        [NETWORK],
        "no-external",
    ),
    # File writes: never modifies / writes / edits.
    (
        re.compile(
            _NEG + r"\b[^.;]{0,60}?\b(modif\w*|chang\w*|writ\w*|edit\w*|alter\w*|overwrit\w*)\b",
            re.I,
        ),
        [WRITE],
        "does-not-modify",
    ),
    # Deletes: never deletes / removes.
    (
        re.compile(_NEG + r"\b[^.;]{0,60}?\b(delet\w*|remov\w*|eras\w*)\b", re.I),
        [DELETE],
        "does-not-delete",
    ),
    # Secrets: never accesses / reads / stores credentials, keys, tokens.
    (
        re.compile(
            _NEG
            + r"\b[^.;]{0,50}?\b(access\w*|read\w*|us\w*|stor\w*|collect\w*|see\w*|touch\w*)\b[^.;]{0,50}?\b(credential\w*|secret\w*|private\s+key\w*|api\s+key\w*|token\w*|password\w*|\.env|\.ssh)\b",
            re.I,
        ),
        [SECRET],
        "does-not-touch-secrets",
    ),
    # Secrets, paraphrased: "stores nothing" keeps no data at all, so
    # it cannot retain a credential; "never uploads your keys" is a
    # secret-exposure promise even though the verb (upload) is not in
    # the access-verb list above.
    (
        re.compile(r"\bstor\w*\s+(nothing|no\s+(data|information|credentials|keys))\b", re.I),
        [SECRET],
        "stores-nothing",
    ),
    (
        re.compile(
            _NEG
            + r"\b[^.;]{0,60}?\b(upload\w*|send\w*|shar\w*|transmit\w*|post\w*|expos\w*)\b[^.;]{0,50}?\b(credential\w*|secret\w*|private\s+key\w*|api\s+key\w*|token\w*|password\w*)\b",
            re.I,
        ),
        [SECRET],
        "does-not-upload-secret",
    ),
    # Writes, paraphrased: "writes nothing to disk" / "saves nothing".
    (
        re.compile(r"\b(writ\w*|sav\w*|persist\w*)\s+(nothing|no\s+(data|files?))\b", re.I),
        [WRITE],
        "writes-nothing",
    ),
    # Install/exec: never installs / runs / executes.
    (
        re.compile(
            _NEG + r"\b[^.;]{0,60}?\b(install\w*|run\w*|execut\w*|launch\w*|invoke\w*)\b",
            re.I,
        ),
        [EXEC],
        "does-not-execute",
    ),
    # Config edits: never changes settings / config.
    (
        re.compile(
            _NEG
            + r"\b[^.;]{0,60}?\b(chang\w*|edit\w*|modif\w*)\b[^.;]{0,40}?\b(settings|config\w*|preferences)\b",
            re.I,
        ),
        [CONFIG],
        "does-not-edit-config",
    ),
    # Ask-first: promises to ask / confirm before acting.
    (
        re.compile(
            r"\b(ask\w*\s+(first|before)|confirm\w*\s+before|only\s+with\s+(your\s+)?(permission|approval|consent|confirmation|asking)|only\s+after\s+(your\s+)?(approval|permission|consent|confirmation|asking)|without\s+(your\s+)?(approval|permission|consent|confirmation|asking)|never\s+acts?\s+without|will\s+ask)\b",
            re.I,
        ),
        [CONFIRM],
        "ask-first",
    ),
]

# A line qualified by approval ("nothing leaves this machine WITHOUT
# your approval", "never sends data ONLY after your approval") is an
# ask-first promise, not an absolute one: the sentence permits the
# action once approved. So on approval-qualified lines, absolute claims
# are suppressed and only the ask-first claim fires — otherwise a
# properly guarded skill would read as a contradiction. This also
# covers the paraphrase patterns, which have no negation marker to
# distinguish them from absolute promises.
_APPROVAL_QUALIFIER = re.compile(
    r"\b(without\s+(your\s+)?(approval|permission|consent|confirmation|asking)|only\s+(with|after)\s+(your\s+)?(approval|permission|consent|confirmation|asking))\b",
    re.I,
)

_EXAMPLE_HINT = re.compile(r"\b(e\.g\.|for example|for instance|sample|example)\b", re.I)


@dataclass
class Claim:
    """One boundary promise found in SKILL.md."""

    text: str
    forbids: list[str]
    label: str
    line: int
    confidence: str = "high"  # "high" or "low"

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "forbids": list(self.forbids),
            "label": self.label,
            "line": self.line,
            "confidence": self.confidence,
        }


@dataclass
class SkillDoc:
    """Parsed SKILL.md: frontmatter name/description plus claims."""

    name: str | None
    description: str | None
    claims: list[Claim] = field(default_factory=list)


def parse_frontmatter(lines: list[str]) -> tuple[dict[str, str], int]:
    """Parse a YAML-ish --- frontmatter block. Returns (fields, body_start).

    Only simple `key: value` lines are understood; anything else is
    ignored rather than mis-parsed. No frontmatter -> ({}, 0).
    """
    if not lines or lines[0].strip() != "---":
        return {}, 0
    fields: dict[str, str] = {}
    for idx, line in enumerate(lines[1:], start=1):
        if line.strip() in ("---", "..."):
            return fields, idx + 1
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip().strip("\"'")
    return fields, len(lines)


def _strip_fences(lines: list[str]) -> list[tuple[int, str]]:
    """Yield (line_number, line) for lines outside fenced code blocks."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for lineno, line in enumerate(lines, start=1):
        if line.strip().startswith("```") or line.strip().startswith("~~~"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append((lineno, line))
    return out


def extract_claims(text: str) -> SkillDoc:
    """Extract boundary claims from SKILL.md source text."""
    lines = text.splitlines()
    fields, _body_start = parse_frontmatter(lines)
    claims: list[Claim] = []
    seen: set[tuple[int, str]] = set()
    for lineno, line in _strip_fences(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        low_conf = bool(_EXAMPLE_HINT.search(stripped))
        approval_qualified = bool(_APPROVAL_QUALIFIER.search(stripped))
        for pattern, forbids, label in _CLAIM_PATTERNS:
            if approval_qualified and CONFIRM not in forbids:
                continue
            if pattern.search(stripped):
                key = (lineno, label)
                if key in seen:
                    continue
                seen.add(key)
                claims.append(
                    Claim(
                        text=stripped,
                        forbids=list(forbids),
                        label=label,
                        line=lineno,
                        confidence="low" if low_conf else "high",
                    )
                )
    return SkillDoc(
        name=fields.get("name"),
        description=fields.get("description"),
        claims=claims,
    )
