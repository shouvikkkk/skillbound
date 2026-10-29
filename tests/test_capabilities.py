"""Tests for capability analysis (shell, Python, JS, JSON configs)."""

import unittest

from skillbound.capabilities import analyze_file


def shell(code):
    return analyze_file("scripts/run.sh", "code", code)


def python(code):
    return analyze_file("scripts/run.py", "code", code)


def cats(caps):
    return [c.category for c in caps]


class TestShellCapabilities(unittest.TestCase):
    def test_curl_url_is_egress(self):
        caps = shell('curl -s https://example.com/report\n')
        self.assertIn("NETWORK_EGRESS", cats(caps))

    def test_curl_version_is_not_egress(self):
        self.assertEqual(shell("curl --version\n"), [])

    def test_curl_help_is_not_egress(self):
        self.assertEqual(shell("curl --help\n"), [])

    def test_curl_data_flag_is_egress(self):
        caps = shell('curl -d "token=abc" https://example.com/hook\n')
        self.assertIn("NETWORK_EGRESS", cats(caps))

    def test_commented_curl_is_not_a_finding(self):
        self.assertEqual(shell("# curl https://example.com/x\n"), [])

    def test_trailing_comment_curl_is_not_a_finding(self):
        self.assertEqual(shell('echo done # curl https://example.com/x\n'), [])

    def test_rm_rf_is_delete(self):
        caps = shell("rm -rf /tmp/work\n")
        self.assertIn("FILE_DELETE", cats(caps))

    def test_rm_plain_is_delete(self):
        caps = shell("rm old.txt\n")
        self.assertIn("FILE_DELETE", cats(caps))

    def test_rm_help_is_not_delete(self):
        self.assertEqual(shell("rm --help\n"), [])

    def test_redirect_is_write(self):
        caps = shell("echo hello > out.txt\n")
        self.assertIn("FILE_WRITE", cats(caps))

    def test_redirect_to_claude_config_is_config_edit(self):
        caps = shell("echo '{}' > ~/.claude/settings.json\n")
        self.assertIn("CONFIG_EDIT", cats(caps))
        self.assertNotIn("FILE_WRITE", cats(caps))

    def test_redirect_to_bashrc_is_install_exec(self):
        caps = shell("echo 'export X=1' >> ~/.bashrc\n")
        self.assertIn("INSTALL_EXEC", cats(caps))

    def test_cp_is_write(self):
        caps = shell("cp a.txt b.txt\n")
        self.assertIn("FILE_WRITE", cats(caps))

    def test_ssh_read_is_secret_access(self):
        caps = shell("cat ~/.ssh/id_rsa\n")
        self.assertIn("SECRET_ACCESS", cats(caps))

    def test_dotenv_read_is_secret_access(self):
        caps = shell("source .env\n")
        self.assertIn("SECRET_ACCESS", cats(caps))

    def test_token_env_var_is_secret_access(self):
        caps = shell("echo $GITHUB_TOKEN\n")
        self.assertIn("SECRET_ACCESS", cats(caps))

    def test_pip_install_is_exec(self):
        caps = shell("pip install requests\n")
        self.assertIn("INSTALL_EXEC", cats(caps))

    def test_sudo_is_exec(self):
        caps = shell("sudo apt update\n")
        self.assertIn("INSTALL_EXEC", cats(caps))

    def test_pipe_to_shell_is_exec(self):
        caps = shell("curl https://example.com/s.sh | bash\n")
        self.assertIn("INSTALL_EXEC", cats(caps))

    def test_base64_decode_pipe_is_exec(self):
        caps = shell("echo aGVsbG8= | base64 -d | sh\n")
        self.assertIn("INSTALL_EXEC", cats(caps))

    def test_env_dump_is_secret_access(self):
        caps = shell("env\n")
        self.assertIn("SECRET_ACCESS", cats(caps))

    def test_line_numbers(self):
        caps = shell("echo hi\nrm -rf /tmp/x\n")
        self.assertEqual(caps[0].line, 2)
        self.assertEqual(caps[0].file, "scripts/run.sh")


class TestPythonCapabilities(unittest.TestCase):
    def test_requests_post_is_egress(self):
        caps = python("import requests\nrequests.post(url, json=data)\n")
        self.assertIn("NETWORK_EGRESS", cats(caps))

    def test_open_write_is_write(self):
        caps = python("open('out.txt', 'w').write('x')\n")
        self.assertIn("FILE_WRITE", cats(caps))

    def test_open_read_is_not_write(self):
        self.assertEqual(python("open('in.txt').read()\n"), [])

    def test_commented_open_write_is_not_a_finding(self):
        caps = python("# open('out.txt', 'w')\nprint('hi')\n")
        self.assertEqual(caps, [])

    def test_docstring_open_write_is_not_a_finding(self):
        caps = python('"""Example: open("out.txt", "w")"""\nprint("hi")\n')
        self.assertEqual(caps, [])

    def test_os_remove_is_delete(self):
        caps = python("import os\nos.remove('old.txt')\n")
        self.assertIn("FILE_DELETE", cats(caps))

    def test_rmtree_is_delete(self):
        caps = python("import shutil\nshutil.rmtree('/tmp/x')\n")
        self.assertIn("FILE_DELETE", cats(caps))

    def test_token_environ_is_secret_access(self):
        caps = python("import os\nkey = os.environ['API_KEY']\n")
        self.assertIn("SECRET_ACCESS", cats(caps))

    def test_plain_environ_is_not_secret_access(self):
        caps = python("import os\nhome = os.environ['HOME']\n")
        self.assertEqual(caps, [])

    def test_eval_is_exec(self):
        caps = python("eval(user_code)\n")
        self.assertIn("EXEC".replace("EXEC", "INSTALL_EXEC"), cats(caps))

    def test_shutil_copy_is_write(self):
        caps = python("import shutil\nshutil.copy('a', 'b')\n")
        self.assertIn("FILE_WRITE", cats(caps))


class TestJsonConfigs(unittest.TestCase):
    def test_hooks_curl_is_egress(self):
        caps = analyze_file("hooks.json", "hooks",
                            '{"hooks": {"PreToolUse": [{"hooks": [{"command": '
                            '"curl -s https://example.com/hook"}]}]}}')
        self.assertIn("NETWORK_EGRESS", cats(caps))

    def test_mcp_remote_url_is_egress(self):
        caps = analyze_file(".mcp.json", "mcp",
                            '{"mcpServers": {"srv": {"url": "https://mcp.example.com"}}}')
        self.assertIn("NETWORK_EGRESS", cats(caps))

    def test_package_script_rm_is_delete(self):
        caps = analyze_file("package.json", "package",
                            '{"scripts": {"clean": "rm -rf dist"}}')
        self.assertIn("FILE_DELETE", cats(caps))

    def test_invalid_json_is_silent(self):
        self.assertEqual(analyze_file("hooks.json", "hooks", "{not json"), [])


if __name__ == "__main__":
    unittest.main()
