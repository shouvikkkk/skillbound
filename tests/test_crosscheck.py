"""Tests for the claim/capability cross-check and exit codes."""

import unittest

from skillbound.capabilities import Capability
from skillbound.claims import Claim
from skillbound.crosscheck import crosscheck, exit_code, verdict


def claim(forbids, line=1, label="test"):
    return Claim(text="test claim", forbids=forbids, label=label, line=line)


def cap(category, file="scripts/run.sh", line=3, detail="test"):
    return Capability(category=category, file=file, line=line, detail=detail)


class TestCrosscheck(unittest.TestCase):
    def test_contradiction_read_only_plus_curl(self):
        findings = crosscheck(
            [claim(["FILE_WRITE", "FILE_DELETE"])],
            [cap("NETWORK_EGRESS")],
            {},
        )
        # NETWORK not forbidden by this claim -> UNCLAIMED, not contradiction
        self.assertEqual([f.kind for f in findings], ["UNCLAIMED"])

    def test_contradiction_forbidden_capability(self):
        findings = crosscheck(
            [claim(["NETWORK_EGRESS"])],
            [cap("NETWORK_EGRESS")],
            {},
        )
        self.assertEqual(findings[0].kind, "CONTRADICTION")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(verdict(findings), "CONTRADICTION")
        self.assertEqual(exit_code(findings), 2)

    def test_unclaimed_sensitive_is_medium(self):
        findings = crosscheck([], [cap("FILE_DELETE")], {})
        self.assertEqual(findings[0].kind, "UNCLAIMED")
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(exit_code(findings), 1)

    def test_unclaimed_non_sensitive_is_low(self):
        findings = crosscheck([], [cap("FILE_WRITE")], {})
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(exit_code(findings), 1)

    def test_strict_upgrades_sensitive_unclaimed(self):
        findings = crosscheck([], [cap("SECRET_ACCESS")], {})
        self.assertEqual(exit_code(findings), 1)
        self.assertEqual(exit_code(findings, strict=True), 2)

    def test_strict_does_not_upgrade_low_unclaimed(self):
        findings = crosscheck([], [cap("FILE_WRITE")], {})
        self.assertEqual(exit_code(findings, strict=True), 1)

    def test_pass_when_nothing_found(self):
        self.assertEqual(crosscheck([], [], {}), [])
        self.assertEqual(verdict([]), "PASS")
        self.assertEqual(exit_code([]), 0)

    def test_claimed_but_absent_capability_is_pass(self):
        findings = crosscheck([claim(["NETWORK_EGRESS"])], [], {})
        self.assertEqual(findings, [])

    def test_ask_first_silent_post_is_contradiction(self):
        findings = crosscheck(
            [claim(["CONFIRM_FIRST"])],
            [cap("NETWORK_EGRESS")],
            {"scripts/run.sh": "curl -d x https://example.com/hook\n"},
        )
        self.assertEqual(findings[0].kind, "CONTRADICTION")

    def test_ask_first_with_prompt_is_not_contradiction(self):
        findings = crosscheck(
            [claim(["CONFIRM_FIRST"])],
            [cap("NETWORK_EGRESS")],
            {"scripts/run.sh": "read -p 'Send report? (y/n) ' ans\ncurl -d x https://example.com/hook\n"},
        )
        self.assertEqual(findings, [])

    def test_finding_carries_both_evidences(self):
        findings = crosscheck(
            [claim(["FILE_DELETE"], line=5)],
            [cap("FILE_DELETE", line=9)],
            {},
        )
        self.assertEqual(findings[0].claim.line, 5)
        self.assertEqual(findings[0].capability.line, 9)


if __name__ == "__main__":
    unittest.main()
