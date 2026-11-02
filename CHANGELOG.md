# Changelog

## 0.2.0 — 2026-11-02

- **Paraphrase promises.** Claim extraction no longer needs a negation
  marker to hear a boundary: "Nothing leaves this machine", "Your data
  stays on your machine", "runs entirely locally", "on-device",
  "no external services", "stores nothing", "writes nothing to disk",
  and "never uploads your API keys" are now claims (NETWORK_EGRESS,
  SECRET_ACCESS, or FILE_WRITE as appropriate). This closes the
  v0.1 limitation that paraphrased promises were missed — a missed
  promise used to read as a pass with proof.
- **Approval-qualified lines are ask-first, not absolute.** "Nothing
  leaves this machine WITHOUT your approval" and "sends data ONLY
  after your approval" now produce a CONFIRM_FIRST claim only; the
  absolute claim is suppressed, so a properly guarded skill no longer
  reads as a contradiction.
- **Cross-file ask-first guards (guardgraph).** A sensitive capability
  is honoured when a prompting file reaches it through the bundle's
  reference graph (Python imports, JS `require`/`import`, shell
  `source`/direct execution, JSON hook commands), provided the prompt
  comes before the call in the prompting file; guarding is transitive
  past that first hop. An unrelated prompting file still guards
  nothing, and a prompt after the call still does not guard. This
  fixes the v0.1 false positive on the common layout where a thin
  entry script prompts and a helper does the sending.
- **Bugfix.** Secret claims with plural keys ("never reads your API
  keys") now match: the trailing word boundary after `key` used to
  reject the plural form.
- New example `examples/guarded-skill/` (ask-first entry script +
  sending helper → PASS). Test suite grows 73 → 103 tests.

## 0.1.0 — 2026-10-29

- Initial release: SKILL.md boundary-claim extraction, bundle
  inventory, six-category capability analysis (flag- and
  comment-aware), claim-vs-capability cross-check with
  CONTRADICTION / UNCLAIMED / PASS verdicts, severity-gated exit
  codes, text + JSON reports.
