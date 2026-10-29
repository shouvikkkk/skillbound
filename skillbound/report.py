"""Report rendering: human-readable text and machine-readable JSON."""

from __future__ import annotations

import json

from .capabilities import Capability
from .claims import Claim
from .crosscheck import Finding


def render_text(
    skill_dir: str,
    name: str | None,
    claims: list[Claim],
    capabilities: list[Capability],
    findings: list[Finding],
    verdict_text: str,
    code: int,
) -> str:
    """Human-readable report."""
    lines: list[str] = []
    lines.append(f"skillbound report: {name or skill_dir}")
    lines.append("")
    lines.append(f"Claims ({len(claims)}):")
    if claims:
        for c in claims:
            lines.append(
                f"  - [{','.join(c.forbids)}] SKILL.md:{c.line} ({c.confidence}): {c.text}"
            )
    else:
        lines.append("  (none found)")
    lines.append("")
    lines.append(f"Capabilities ({len(capabilities)}):")
    if capabilities:
        for cap in capabilities:
            lines.append(f"  - [{cap.category}] {cap.file}:{cap.line}: {cap.detail}")
    else:
        lines.append("  (none found)")
    lines.append("")
    lines.append(f"Findings ({len(findings)}):")
    if findings:
        for f in findings:
            mark = "!" if f.kind == "CONTRADICTION" else "~"
            lines.append(f"  {mark} {f.kind} ({f.severity}): {f.message}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"Verdict: {verdict_text} (exit {code})")
    return "\n".join(lines) + "\n"


def render_json(
    skill_dir: str,
    name: str | None,
    claims: list[Claim],
    capabilities: list[Capability],
    findings: list[Finding],
    verdict_text: str,
    code: int,
) -> str:
    """Machine-readable report (stable key order, sorted lists)."""
    payload = {
        "skill": skill_dir,
        "name": name,
        "claims": [c.to_dict() for c in claims],
        "capabilities": [c.to_dict() for c in capabilities],
        "findings": [f.to_dict() for f in findings],
        "verdict": verdict_text,
        "exit_code": code,
    }
    return json.dumps(payload, indent=2) + "\n"
