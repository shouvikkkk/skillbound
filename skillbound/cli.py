"""CLI: `skillbound check <skill-dir> [--format text|json] [--strict]`.

Exit codes: 0 PASS, 1 UNCLAIMED-only, 2 CONTRADICTION found
(and, with --strict, UNCLAIMED sensitive capabilities also exit 2).
Exit 3: usage error (missing directory or missing SKILL.md).
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .capabilities import analyze_file
from .claims import extract_claims
from .crosscheck import crosscheck, exit_code, verdict
from .inventory import inventory, read_text
from .report import render_json, render_text


def run_check(skill_dir: str, fmt: str, strict: bool) -> tuple[str, int]:
    """Run the full check. Returns (report_text, exit_code)."""
    if not os.path.isdir(skill_dir):
        return f"skillbound: no such directory: {skill_dir}\n", 3
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(skill_md):
        return f"skillbound: no SKILL.md in {skill_dir}\n", 3

    doc_text = read_text(skill_md) or ""
    doc = extract_claims(doc_text)

    files = inventory(skill_dir)
    capabilities = []
    file_texts: dict[str, str] = {}
    for bundle_file in files:
        if bundle_file.kind in ("skill-doc", "other"):
            continue
        text = read_text(os.path.join(skill_dir, bundle_file.path))
        if text is None:
            continue
        file_texts[bundle_file.path] = text
        capabilities.extend(analyze_file(bundle_file.path, bundle_file.kind, text))
    capabilities.sort(key=lambda c: (c.file, c.line, c.category))

    findings = crosscheck(doc.claims, capabilities, file_texts)
    v = verdict(findings)
    code = exit_code(findings, strict=strict)
    if fmt == "json":
        report = render_json(skill_dir, doc.name, doc.claims, capabilities, findings, v, code)
    else:
        report = render_text(skill_dir, doc.name, doc.claims, capabilities, findings, v, code)
    return report, code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillbound",
        description="Static scope checker for agent skills: does the bundle "
        "stay inside what SKILL.md promises?",
    )
    parser.add_argument("--version", action="version", version=f"skillbound {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check one skill directory")
    check.add_argument("skill_dir", help="directory containing SKILL.md")
    check.add_argument("--format", choices=["text", "json"], default="text",
                       help="report format (default: text)")
    check.add_argument("--strict", action="store_true",
                       help="treat UNCLAIMED sensitive capabilities as failures (exit 2)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        report, code = run_check(args.skill_dir, args.format, args.strict)
        sys.stdout.write(report)
        return code
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
