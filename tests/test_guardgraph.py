"""Tests for the cross-file ask-first guard graph."""

import unittest

from skillbound.guardgraph import guarded_files, references


class TestReferences(unittest.TestCase):
    def test_shell_source_reference(self):
        refs = references(
            "source scripts/helper.sh\n",
            "scripts/main.sh",
            ["scripts/main.sh", "scripts/helper.sh"],
        )
        self.assertEqual(refs, [(7, "scripts/helper.sh")])

    def test_shell_direct_exec_reference(self):
        refs = references(
            "./helper.sh\n",
            "scripts/main.sh",
            ["scripts/main.sh", "scripts/helper.sh"],
        )
        self.assertEqual(refs, [(0, "scripts/helper.sh")])

    def test_python_import_by_stem(self):
        refs = references(
            "import helper\n",
            "main.py",
            ["main.py", "helper.py"],
        )
        self.assertEqual(refs, [(0, "helper.py")])

    def test_python_from_import(self):
        refs = references(
            "from lib import worker\n",
            "main.py",
            ["main.py", "lib.py"],
        )
        self.assertEqual(refs, [(0, "lib.py")])

    def test_js_require_reference(self):
        refs = references(
            "const h = require('./helper');\n",
            "index.js",
            ["index.js", "helper.js"],
        )
        self.assertEqual([f for _pos, f in refs], ["helper.js"])

    def test_json_hook_reference(self):
        refs = references(
            '{"hooks": [{"command": "scripts/guard.sh"}]}',
            "hooks.json",
            ["hooks.json", "scripts/guard.sh"],
        )
        self.assertEqual([f for _pos, f in refs], ["scripts/guard.sh"])

    def test_unrelated_basename_is_not_a_reference(self):
        refs = references(
            "echo helper\n",
            "scripts/main.sh",
            ["scripts/main.sh", "scripts/helper.sh"],
        )
        self.assertEqual(refs, [])

    def test_self_is_not_a_reference(self):
        refs = references(
            "source main.sh\n",
            "main.sh",
            ["main.sh"],
        )
        self.assertEqual(refs, [])

    def test_ambiguous_basename_resolves_to_all(self):
        refs = references(
            "source helper.sh\n",
            "main.sh",
            ["main.sh", "a/helper.sh", "b/helper.sh"],
        )
        self.assertEqual({f for _pos, f in refs}, {"a/helper.sh", "b/helper.sh"})


class TestGuardedFiles(unittest.TestCase):
    def test_prompt_in_same_file_guards(self):
        guarded = guarded_files({
            "run.sh": "read -p 'Go? ' ans\ncurl https://example.com\n",
        })
        self.assertEqual(guarded, {"run.sh"})

    def test_prompt_before_call_guards_callee(self):
        guarded = guarded_files({
            "main.sh": "read -p 'Send? ' ans\n./helper.sh\n",
            "helper.sh": "curl https://example.com\n",
        })
        self.assertEqual(guarded, {"main.sh", "helper.sh"})

    def test_prompt_after_call_does_not_guard(self):
        guarded = guarded_files({
            "main.sh": "./helper.sh\nread -p 'Send? ' ans\n",
            "helper.sh": "curl https://example.com\n",
        })
        self.assertEqual(guarded, {"main.sh"})

    def test_unrelated_prompt_guards_nothing(self):
        guarded = guarded_files({
            "other.sh": "read -p 'Go? ' ans\n",
            "helper.sh": "curl https://example.com\n",
        })
        self.assertEqual(guarded, {"other.sh"})

    def test_transitive_guard_through_chain(self):
        guarded = guarded_files({
            "main.sh": "read -p 'Send? ' ans\n./mid.sh\n",
            "mid.sh": "./helper.sh\n",
            "helper.sh": "curl https://example.com\n",
        })
        self.assertEqual(guarded, {"main.sh", "mid.sh", "helper.sh"})

    def test_no_prompt_no_guard(self):
        guarded = guarded_files({
            "main.sh": "./helper.sh\n",
            "helper.sh": "curl https://example.com\n",
        })
        self.assertEqual(guarded, set())

    def test_cycle_terminates(self):
        guarded = guarded_files({
            "a.sh": "read -p 'Go? ' ans\n./b.sh\n",
            "b.sh": "./a.sh\n",
        })
        self.assertEqual(guarded, {"a.sh", "b.sh"})


if __name__ == "__main__":
    unittest.main()
