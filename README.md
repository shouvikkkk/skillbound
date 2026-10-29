# skillbound

Static scope checker for agent skills: does a skill's bundled code stay
inside what its `SKILL.md` promises?

## The problem

Agent skills ship two things that can disagree: a `SKILL.md` that
*promises* boundaries ("read-only", "never sends data", "asks first"),
and bundled scripts, hooks, and MCP configs that *do* things. A skill
can be entirely non-malicious and still overreach — it claims
"analysis only" while shipping a script that POSTs results, or says
"local only" while a hook curls a webhook.

A sandbox study of 48 real agent skills (384 adversarial probes,
dev.to/skill123, published 2026-10-10, updated 2026-10-17) found the
dominant failure is scope overreach, not injection:

> "Push past the skill's declared scope" probes succeeded **31% of the
> time (29 of 94 slots)**, vs **2%** for hidden-instruction injection.

And the study's own advice to skill consumers:

> "Prefer skills whose description says what they don't do."

The study tested this **behaviourally**, with live LLM runs. That half
of the problem needs a model and a sandbox. But the other half — the
one you can check without a model — had no tool: whether a skill's own
shipped files (scripts, hooks, MCP configs) already exceed what its
`SKILL.md` promises. Vulnerability scanners (SkillSpector, LOLSkills,
MCP-Scan) hunt malicious patterns; none cross-checks a skill's own
stated boundaries against its own bundled capabilities. `skillbound`
is that check: static, offline, stdlib-only.

## What it does

```
skillbound check <skill-dir> [--format text|json] [--strict]
```

1. **Claim extraction** — parses `SKILL.md` frontmatter (`name`,
   `description`) and body for boundary claims via negation and
   constraining patterns (`never`, `does not`, `don't`, `won't`,
   `read-only`, `local only`, `ask first`, `confirm before`, ...).
   Each claim maps to the capability categories it forbids and carries
   `file:line` evidence. Text inside fenced code blocks never produces
   claims (examples are not promises); example-flavoured lines
   ("e.g.", "for instance") are kept at low confidence.
2. **Bundle inventory** — walks the skill directory (`SKILL.md`,
   `scripts/`, `hooks.json`, `.mcp.json`, `package.json`, any
   `.sh`/`.py`/`.js` files). `SKILL.md` itself is inventoried but not
   capability-scanned: its code fences are documentation.
3. **Capability analysis** — a real taxonomy, every finding with
   `file:line` evidence:

   | Category | Examples detected |
   |---|---|
   | `NETWORK_EGRESS` | curl/wget with a URL or data flag, requests/urllib/http.client, fetch, MCP server URLs |
   | `FILE_WRITE` | shell redirects, cp/mv, `open(..., "w"/"a")`, shutil copies, fs.writeFile |
   | `FILE_DELETE` | rm with a real target, unlink, rmtree, shred |
   | `SECRET_ACCESS` | reads of `~/.ssh`, `~/.aws`, `.env`, `~/.config/gh`, keychain, `*_TOKEN`/`*_KEY` env vars, bare env dumps |
   | `INSTALL_EXEC` | pip/npm install, sudo, eval, chmod +x, base64-decode-and-exec, shell rc/profile persistence |
   | `CONFIG_EDIT` | writes to `~/.codex/config.toml`, `~/.claude/settings.json`, IDE/agent config files |

   Parsing is flag-aware and comment-aware: `curl --version` is not
   egress, `rm --help` is not a delete, a commented-out `curl` is not
   a finding. Shell comments are stripped quote-aware; Python comments
   and docstrings are removed with `tokenize`/`ast` before scanning.
4. **Cross-check** — three outcomes:
   - **CONTRADICTION** (high): a claim forbids a capability the bundle
     has, with both evidences cited. Ask-first claims are special:
     they forbid *silent* action, so a sensitive capability in a file
     that itself asks for confirmation (`read -p`, `input()`,
     "are you sure") honours the claim; the same capability without a
     prompt contradicts it.
   - **UNCLAIMED** (medium for network/delete/secret, low otherwise):
     a sensitive capability exists with no boundary statement either way.
   - **PASS**: no contradictions, no unclaimed capabilities.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | PASS |
| 1 | UNCLAIMED-only |
| 2 | CONTRADICTION found |
| 3 | Usage error (missing directory or `SKILL.md`) |

`--strict` upgrades UNCLAIMED *sensitive* capabilities (network,
delete, secret) to exit 2. It does not change low-severity UNCLAIMED
results.

## Setup

No dependencies — Python 3.10+ standard library only, so there is no
`requirements.txt` to install. Clone and run from the repo root:

```bash
python3 -m skillbound check <skill-dir>
```

For a `skillbound` console command, install the package in editable
mode (`pip install -e .` — `pyproject.toml` maps the `skillbound`
command to `skillbound.cli:main`).

## Usage

```bash
# Human-readable report (default)
python3 -m skillbound check ./my-skill

# Machine-readable report
python3 -m skillbound check ./my-skill --format json

# Fail the build on unclaimed sensitive capabilities too
python3 -m skillbound check ./my-skill --strict
```

## Demo

The repo ships a synthetic overreaching skill at
`examples/overreaching-skill/`: its `SKILL.md` promises read-only,
never-modifies, never-sends — and its `scripts/send.sh` POSTs the
report to a remote collector. Real output:

```
$ python3 -m skillbound check examples/overreaching-skill
skillbound report: report-helper

Claims (3):
  - [FILE_WRITE,FILE_DELETE,INSTALL_EXEC,CONFIG_EDIT] SKILL.md:10 (high): It is read-only: it never modifies your files, and it never sends data anywhere.
  - [NETWORK_EGRESS] SKILL.md:10 (high): It is read-only: it never modifies your files, and it never sends data anywhere.
  - [FILE_WRITE] SKILL.md:10 (high): It is read-only: it never modifies your files, and it never sends data anywhere.

Capabilities (1):
  - [NETWORK_EGRESS] scripts/send.sh:3: curl reaches the network (https://example.com/collect)

Findings (1):
  ! CONTRADICTION (high): SKILL.md line 10 promises 'does-not-send' but scripts/send.sh:3 has NETWORK_EGRESS (curl reaches the network (https://example.com/collect))

Verdict: CONTRADICTION (exit 2)
```

## Differentiation

- **vs SkillSpector / LOLSkills / MCP-Scan**: those hunt *malicious*
  patterns (known-bad payloads, exfiltration signatures). `skillbound`
  hunts *self-contradiction*: a skill that is honest-looking and
  non-malicious but whose own code exceeds its own stated boundaries.
  No scanner needs to flag the skill as evil for `skillbound` to flag
  it as overreaching.
- **vs the behavioural study (dev.to/skill123)**: the study proves the
  failure mode with live LLM runs — an agent talked past a skill's
  scope 31% of the time. `skillbound` does not reproduce that: it
  checks the cheaper, static half — whether the skill's shipped files
  already violate the scope before any agent is even involved. The two
  are complementary: pass `skillbound` first, then sandbox-test the
  behaviour.

## Limitations (honest)

- **Static analysis only.** It cannot reproduce the study's live-agent
  behavioural results: an agent can overreach a skill that passes this
  check, by misreading or ignoring the scope at runtime.
- **Heuristic claim extraction.** Paraphrased promises ("we keep
  everything on your machine", "nothing leaves this box") that don't
  match the negation patterns are missed; a missed promise is a missed
  contradiction, not a pass with proof.
- **Heuristic shell parsing, not a full parser.** Multi-line
  constructs, variable indirection (`$CMD`), and commands built by
  string concatenation are not followed. Python analysis is
  line-oriented after comment/docstring stripping.
- **Ask-first detection is file-local.** A prompt in a *different*
  file from the capability does not satisfy the claim; only a prompt
  in the same file counts.
- **SKILL.md code fences are not scanned.** An executable snippet
  embedded in the doc itself (rather than in a script file) is out of
  scope by design, to avoid flagging worked examples.

## Tests

73 tests, all green:

```bash
python3 -m unittest discover -s tests
```

Coverage includes: claim extraction (negation variants, code-fence
discounting, example-line low confidence), every capability category
with positive and negative controls (commented-out curl is not a
finding; `curl --version` is not egress; `rm -rf` is a delete; reading
`~/.ssh/id_rsa` is secret access), contradiction detection end-to-end
on synthetic fixtures (read-only + curl, analysis-only + rm,
ask-first + silent POST, clean skill → PASS), JSON output shape, and
exit codes including `--strict`.

## License

MIT — see [LICENSE](LICENSE).
