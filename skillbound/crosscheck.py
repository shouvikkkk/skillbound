"""Cross-check: claims vs capabilities.

- CONTRADICTION: a claim forbids a capability the bundle actually has.
  Severity: high.
- UNCLAIMED: a sensitive capability (network / delete / secret) exists
  with no boundary statement about it either way. Informational, not a
  contradiction. Severity: medium for sensitive categories, low for the
  rest.
- PASS: no contradictions and no unclaimed capabilities.

Ask-first claims are special: they forbid *silent* action. A sensitive
capability in a file that itself asks for confirmation (a `read -p`,
`input(`, or "are you sure" prompt) satisfies the claim; the same
capability in a file with no prompt contradicts it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .capabilities import SENSITIVE, Capability
from .claims import CONFIRM, Claim

CONFIRM_PROMPT_RE = re.compile(
    r"(read\s+-p|input\s*\(|confirm|are you sure|press\s+enter\s+to\s+continue|yes/no)",
    re.I,
)


@dataclass
class Finding:
    """One cross-check result."""

    kind: str  # "CONTRADICTION" | "UNCLAIMED"
    severity: str  # "high" | "medium" | "low"
    category: str
    message: str
    claim: Claim | None = None
    capability: Capability | None = None

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "claim": self.claim.to_dict() if self.claim else None,
            "capability": self.capability.to_dict() if self.capability else None,
        }


def crosscheck(
    claims: list[Claim],
    capabilities: list[Capability],
    file_texts: dict[str, str],
) -> list[Finding]:
    """Compare claims against capabilities. Returns findings."""
    findings: list[Finding] = []
    claimed_categories: set[str] = set()
    for claim in claims:
        claimed_categories.update(claim.forbids)

    # --- contradictions: forbidden capability present
    for claim in claims:
        for forbidden in claim.forbids:
            if forbidden == CONFIRM:
                continue  # handled below
            for cap in capabilities:
                if cap.category == forbidden:
                    findings.append(
                        Finding(
                            kind="CONTRADICTION",
                            severity="high",
                            category=cap.category,
                            message=(
                                f"SKILL.md line {claim.line} promises '{claim.label}' "
                                f"but {cap.file}:{cap.line} has {cap.category} ({cap.detail})"
                            ),
                            claim=claim,
                            capability=cap,
                        )
                    )

    # --- ask-first: silent sensitive capability contradicts the promise
    already_contradicted = {
        (f.capability.file, f.capability.line, f.capability.category)
        for f in findings
        if f.capability
    }
    ask_first_honoured: set[tuple[str, int, str]] = set()
    for claim in claims:
        if CONFIRM not in claim.forbids:
            continue
        for cap in capabilities:
            if cap.category not in SENSITIVE:
                continue
            if (cap.file, cap.line, cap.category) in already_contradicted:
                continue
            text = file_texts.get(cap.file, "")
            if CONFIRM_PROMPT_RE.search(text):
                # The file asks before acting: claim honoured, and the
                # capability is accounted for (not UNCLAIMED either).
                ask_first_honoured.add((cap.file, cap.line, cap.category))
                continue
            findings.append(
                Finding(
                    kind="CONTRADICTION",
                    severity="high",
                    category=cap.category,
                    message=(
                        f"SKILL.md line {claim.line} promises to ask first, but "
                        f"{cap.file}:{cap.line} performs {cap.category} ({cap.detail}) "
                        "with no confirmation prompt in the file"
                    ),
                    claim=claim,
                    capability=cap,
                )
            )

    # --- unclaimed: sensitive capability with no statement either way
    contradicted = {(f.capability.file, f.capability.line, f.capability.category)
                    for f in findings if f.capability}
    for cap in capabilities:
        if cap.category in claimed_categories:
            continue
        if (cap.file, cap.line, cap.category) in contradicted:
            continue
        if (cap.file, cap.line, cap.category) in ask_first_honoured:
            continue
        findings.append(
            Finding(
                kind="UNCLAIMED",
                severity="medium" if cap.category in SENSITIVE else "low",
                category=cap.category,
                message=(
                    f"{cap.file}:{cap.line} has {cap.category} ({cap.detail}) "
                    "and SKILL.md says nothing about it either way"
                ),
                capability=cap,
            )
        )
    return findings


def verdict(findings: list[Finding]) -> str:
    """Overall verdict string."""
    if any(f.kind == "CONTRADICTION" for f in findings):
        return "CONTRADICTION"
    if any(f.kind == "UNCLAIMED" for f in findings):
        return "UNCLAIMED"
    return "PASS"


def exit_code(findings: list[Finding], strict: bool = False) -> int:
    """0 PASS, 1 UNCLAIMED-only, 2 CONTRADICTION found.

    --strict upgrades UNCLAIMED *sensitive* capabilities to exit 2.
    """
    if any(f.kind == "CONTRADICTION" for f in findings):
        return 2
    if strict and any(
        f.kind == "UNCLAIMED" and f.severity == "medium" for f in findings
    ):
        return 2
    if any(f.kind == "UNCLAIMED" for f in findings):
        return 1
    return 0
