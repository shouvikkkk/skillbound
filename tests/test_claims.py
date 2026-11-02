"""Tests for boundary-claim extraction from SKILL.md."""

import unittest

from skillbound.claims import extract_claims


def forbids_of(doc):
    return {label: c.forbids for c in doc.claims for label in [c.label]}


class TestClaimExtraction(unittest.TestCase):
    def test_read_only_claim(self):
        doc = extract_claims("---\nname: x\n---\n\nThis skill is read-only.\n")
        self.assertEqual(doc.name, "x")
        self.assertTrue(any("FILE_WRITE" in c.forbids for c in doc.claims))

    def test_does_not_send_claim(self):
        doc = extract_claims("It does not send any data anywhere.\n")
        self.assertTrue(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_does_not_delete_claim(self):
        doc = extract_claims("This skill never deletes files.\n")
        self.assertTrue(any("FILE_DELETE" in c.forbids for c in doc.claims))

    def test_does_not_modify_claim(self):
        doc = extract_claims("The tool does not modify your files.\n")
        self.assertTrue(any("FILE_WRITE" in c.forbids for c in doc.claims))

    def test_secret_claim(self):
        doc = extract_claims("It never reads your credentials or API keys.\n")
        self.assertTrue(any("SECRET_ACCESS" in c.forbids for c in doc.claims))

    def test_ask_first_claim(self):
        doc = extract_claims("It always asks first before taking any action.\n")
        self.assertTrue(any("CONFIRM_FIRST" in c.forbids for c in doc.claims))

    def test_confirm_before_claim(self):
        doc = extract_claims("Please confirm before deleting anything.\n")
        self.assertTrue(any("CONFIRM_FIRST" in c.forbids for c in doc.claims))

    def test_local_only_claim(self):
        doc = extract_claims("Runs local only, no network access.\n")
        self.assertTrue(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_negation_variants(self):
        for text in (
            "It doesn't upload results.\n",
            "It won't share data.\n",
            "It does not transmit anything.\n",
        ):
            doc = extract_claims(text)
            self.assertTrue(
                any("NETWORK_EGRESS" in c.forbids for c in doc.claims), text
            )

    def test_code_fence_produces_no_claims(self):
        doc = extract_claims(
            "```bash\n# this skill never deletes files\nrm -rf /tmp/x\n```\n"
        )
        self.assertEqual(doc.claims, [])

    def test_code_fence_does_not_swallow_later_claims(self):
        doc = extract_claims(
            "```\nnever deletes files\n```\nIt never deletes files.\n"
        )
        self.assertEqual(len(doc.claims), 1)
        self.assertEqual(doc.claims[0].line, 4)

    def test_example_line_is_low_confidence(self):
        doc = extract_claims("For example, it never deletes files.\n")
        self.assertEqual(len(doc.claims), 1)
        self.assertEqual(doc.claims[0].confidence, "low")

    def test_plain_statement_produces_no_claim(self):
        doc = extract_claims("This skill analyses your repository.\n")
        self.assertEqual(doc.claims, [])

    def test_frontmatter_description_scanned(self):
        doc = extract_claims(
            "---\nname: x\ndescription: read-only repo analyser\n---\n\nBody.\n"
        )
        self.assertTrue(any("FILE_WRITE" in c.forbids for c in doc.claims))

    def test_claim_line_numbers(self):
        doc = extract_claims("Intro line.\n\nIt never deletes files.\n")
        self.assertEqual(doc.claims[0].line, 3)

    # --- v0.2.0 paraphrase promises ---

    def test_nothing_leaves_machine_claim(self):
        doc = extract_claims("Nothing leaves this machine.\n")
        self.assertTrue(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_no_data_leaves_claim(self):
        doc = extract_claims("No data leaves your computer.\n")
        self.assertTrue(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_stays_local_claims(self):
        for text in (
            "Your data stays on your machine.\n",
            "It keeps everything on your machine.\n",
            "The skill runs entirely locally.\n",
            "Transcription uses an on-device model.\n",
        ):
            doc = extract_claims(text)
            self.assertTrue(
                any("NETWORK_EGRESS" in c.forbids for c in doc.claims), text
            )

    def test_no_external_services_claim(self):
        doc = extract_claims("It uses no external services.\n")
        self.assertTrue(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_stores_nothing_claim(self):
        doc = extract_claims("This skill stores nothing.\n")
        self.assertTrue(any("SECRET_ACCESS" in c.forbids for c in doc.claims))

    def test_never_uploads_keys_claim(self):
        doc = extract_claims("It never uploads your API keys.\n")
        self.assertTrue(any("SECRET_ACCESS" in c.forbids for c in doc.claims))

    def test_writes_nothing_claim(self):
        doc = extract_claims("It writes nothing to disk.\n")
        self.assertTrue(any("FILE_WRITE" in c.forbids for c in doc.claims))

    def test_approval_qualified_line_is_ask_first_only(self):
        # "Nothing leaves ... without your approval" permits sending
        # once approved: it must NOT become a never-sends claim.
        doc = extract_claims("Nothing leaves this machine without your approval.\n")
        self.assertTrue(any("CONFIRM_FIRST" in c.forbids for c in doc.claims))
        self.assertFalse(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_sends_only_after_approval_is_ask_first_only(self):
        doc = extract_claims("It sends the report only after your approval.\n")
        self.assertTrue(any("CONFIRM_FIRST" in c.forbids for c in doc.claims))
        self.assertFalse(any("NETWORK_EGRESS" in c.forbids for c in doc.claims))

    def test_storing_a_key_is_not_a_stores_nothing_claim(self):
        doc = extract_claims("It stores your API key in ~/.config for reuse.\n")
        self.assertFalse(any("SECRET_ACCESS" in c.forbids for c in doc.claims))


if __name__ == "__main__":
    unittest.main()
