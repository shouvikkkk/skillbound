"""Capability analysis: what can the skill's bundled files actually do?

Taxonomy (every finding carries file:line evidence):

- NETWORK_EGRESS: outbound network calls (curl/wget with a URL or a
  data flag, requests/urllib/http.client, fetch, MCP server URLs).
- FILE_WRITE: writes (shell redirects, cp/mv, open(..., "w"/"a"),
  shutil copies, fs.writeFile).
- FILE_DELETE: deletes (rm with a real target, unlink, rmtree, shred).
- SECRET_ACCESS: reads of credential material (~/.ssh, ~/.aws, .env,
  ~/.config/gh, keychain, *_TOKEN/*_KEY env vars, bare env dumps).
- INSTALL_EXEC: installs and execution (pip/npm install, sudo, eval,
  chmod +x, base64-decode-and-exec, shell rc/profile persistence).
- CONFIG_EDIT: writes to agent/IDE config files (a reclassification of
  a FILE_WRITE whose target is a known config path).

Heuristics, not a full parser — that is a documented limitation:
- Comments never produce findings. Shell comments are stripped
  quote-aware; Python comments and docstrings are removed with the
  stdlib tokenize/ast modules before scanning.
- Flag awareness: `curl --version` is not egress (no URL, no data
  flag); `rm --help` is not a delete (no target); `rm -rf /tmp/x`
  is a delete.
"""

from __future__ import annotations

import ast
import io
import json
import re
import shlex
import tokenize
from dataclasses import dataclass

NETWORK = "NETWORK_EGRESS"
WRITE = "FILE_WRITE"
DELETE = "FILE_DELETE"
SECRET = "SECRET_ACCESS"
EXEC = "INSTALL_EXEC"
CONFIG = "CONFIG_EDIT"

SENSITIVE = (NETWORK, DELETE, SECRET)

URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]+", re.I)
DATA_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "-F", "--form", "-T", "--upload-file", "--form-string",
}
CONFIG_PATH_RE = re.compile(
    r"(\.codex/config|\.claude/settings|\.claude\.json|\.cursor|\.vscode/settings"
    r"|claude_desktop_config|\.config/gh/config|\.config/Code)",
    re.I,
)
PERSIST_PATH_RE = re.compile(r"(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile)\s*$", re.I)
SECRET_PATH_RE = re.compile(
    r"(\.ssh/|\.aws/|\.env(\b|$)|\.config/gh|keychain|\.gnupg/)", re.I,
)
SENSITIVE_ENV_RE = re.compile(r"[A-Za-z0-9_]*(TOKEN|KEY|SECRET|PASSWORD)\b")


@dataclass
class Capability:
    """One capability found in one bundled file."""

    category: str
    file: str  # path relative to the skill root
    line: int
    detail: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
            "snippet": self.snippet,
        }


# ---------------------------------------------------------------- shell

def strip_shell_comments(line: str) -> str:
    """Remove a shell comment: '#' outside quotes (and outside $())."""
    out: list[str] = []
    i = 0
    in_single = in_double = False
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and not in_single:
            out.append(line[i : i + 2])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
        i += 1
    return "".join(out)


def shell_words(line: str) -> list[str]:
    """Split a shell line into words; fall back to plain split."""
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def _is_redirect_token(tok: str) -> bool:
    return tok in (">", ">>", "&>") or re.match(r"^\d>>?$", tok) is not None


def _classify_write_target(target: str) -> str:
    if CONFIG_PATH_RE.search(target):
        return CONFIG
    if PERSIST_PATH_RE.search(target):
        return EXEC
    return WRITE


def analyze_shell_line(line: str, rel: str, lineno: int, out: list[Capability]) -> None:
    """Analyse one comment-stripped shell line and append findings."""
    code = strip_shell_comments(line).strip()
    if not code:
        return
    words = shell_words(code)
    if not words:
        return
    cmd = words[0]
    args = words[1:]
    nonflags = [a for a in args if not a.startswith("-") or a in ("-", "--")]
    detail_src = code

    # --- network: curl / wget with a URL or a data/upload flag
    if cmd in ("curl", "wget"):
        has_url = any(URL_RE.search(a) for a in args)
        has_data = any(a in DATA_FLAGS or a.startswith("--data") for a in args)
        has_method = "-X" in args
        if has_url or has_data:
            target = next((a for a in args if URL_RE.search(a)), "data payload")
            out.append(Capability(NETWORK, rel, lineno,
                                  f"{cmd} reaches the network ({target})", detail_src))
        elif has_method:
            pass  # e.g. curl -X GET with no URL: not a real egress
        # curl --version / curl --help: no URL, no data -> no finding
        # ... but a pipe into a shell is exec regardless of the fetcher.
        if "|" in words:
            after = words[words.index("|") + 1 :]
            if after and after[0] in ("sh", "bash", "zsh"):
                out.append(Capability(EXEC, rel, lineno, "pipes output into a shell", detail_src))
        return

    # --- network: bare env dumps are secret access, not network
    if cmd in ("env", "printenv") and not args:
        out.append(Capability(SECRET, rel, lineno,
                              "dumps the process environment (may contain tokens)", detail_src))
        return

    # --- delete: rm with a real target (rm --help / rm --version excluded)
    if cmd == "rm":
        if nonflags and not {"--help", "--version"} & set(args):
            flags = " ".join(a for a in args if a.startswith("-"))
            out.append(Capability(DELETE, rel, lineno,
                                  f"rm deletes {nonflags[0]}" + (f" ({flags})" if flags else ""), detail_src))
        return

    if cmd in ("unlink", "shred"):
        if nonflags:
            out.append(Capability(DELETE, rel, lineno, f"{cmd} deletes {nonflags[0]}", detail_src))
        return

    # --- install / exec
    if cmd in ("pip", "pip3") and "install" in args:
        out.append(Capability(EXEC, rel, lineno, "pip install", detail_src))
        return
    if cmd == "npm" and args and args[0] in ("install", "i", "ci"):
        out.append(Capability(EXEC, rel, lineno, "npm install", detail_src))
        return
    if cmd == "sudo":
        out.append(Capability(EXEC, rel, lineno, "runs a command as root via sudo", detail_src))
        return
    if cmd == "eval":
        out.append(Capability(EXEC, rel, lineno, "eval executes constructed shell code", detail_src))
        return
    if cmd == "chmod" and "+x" in args:
        out.append(Capability(EXEC, rel, lineno, "chmod +x makes a file executable", detail_src))
        return

    # --- base64-decode-and-exec / pipe-to-shell
    if "base64" in words and any(t in ("-d", "--decode", "-D") for t in args):
        if any(t in ("|",) for t in words) or "sh" in words or "bash" in words:
            out.append(Capability(EXEC, rel, lineno,
                                  "base64-decoded output is piped to a shell", detail_src))
            return
    if "|" in words:
        after = words[words.index("|") + 1 :]
        if after and after[0] in ("sh", "bash", "zsh"):
            out.append(Capability(EXEC, rel, lineno, "pipes output into a shell", detail_src))
            return

    # --- copy / move = write
    if cmd in ("cp", "mv"):
        if len(nonflags) >= 2:
            out.append(Capability(_classify_write_target(nonflags[-1]), rel, lineno,
                                  f"{cmd} writes to {nonflags[-1]}", detail_src))
        return

    # --- redirects = write (target-aware reclassification)
    for idx, tok in enumerate(words):
        if _is_redirect_token(tok) and idx + 1 < len(words):
            target = words[idx + 1]
            out.append(Capability(_classify_write_target(target), rel, lineno,
                                  f"shell redirect writes to {target}", detail_src))
            break

    # --- secret paths read or written
    for tok in words:
        if SECRET_PATH_RE.search(tok):
            out.append(Capability(SECRET, rel, lineno,
                                  f"touches credential material ({tok})", detail_src))
            break
    # --- sensitive env vars referenced
    for tok in words:
        m = re.search(r"\$\{?([A-Za-z0-9_]+)\}?", tok)
        if m and SENSITIVE_ENV_RE.fullmatch(m.group(1)):
            out.append(Capability(SECRET, rel, lineno,
                                  f"reads env var {m.group(1)}", detail_src))
            break


# ---------------------------------------------------------------- python

def clean_python_source(source: str) -> list[str]:
    """Return source lines with comments and docstrings blanked out.

    Comments are removed with tokenize (exact spans, line numbers kept);
    docstrings are blanked with ast (module/class/function docstrings).
    Unparseable source falls back to full-line comment stripping.
    """
    lines = source.splitlines()
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return ["" if l.lstrip().startswith("#") else l for l in lines]
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            row = tok.start[0] - 1
            if 0 <= row < len(lines):
                col = tok.start[1]
                lines[row] = lines[row][:col].rstrip()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return lines
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) \
                    and isinstance(node.body[0].value.value, str):
                doc = node.body[0]
                for ln in range(doc.lineno - 1, (doc.end_lineno or doc.lineno)):
                    if 0 <= ln < len(lines):
                        lines[ln] = ""
    return lines


_PY_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\brequests\.(get|post|put|delete|patch|request)\s*\("), NETWORK, "requests HTTP call"),
    (re.compile(r"\burllib\.request\.(urlopen|Request)\s*\("), NETWORK, "urllib network call"),
    (re.compile(r"\bhttp\.client\.\w+\s*\("), NETWORK, "http.client call"),
    (re.compile(r"\bhttpx\.(get|post|put|delete|request)\s*\("), NETWORK, "httpx HTTP call"),
    (re.compile(r"\bsocket\.(create_connection|socket)\s*\("), NETWORK, "raw socket use"),
    (re.compile(r"\bshutil\.(copy|copyfile|copy2|move)\s*\("), WRITE, "shutil file copy/move"),
    (re.compile(r"\bos\.(remove|unlink|rmdir)\s*\("), DELETE, "os file removal"),
    (re.compile(r"\bshutil\.rmtree\s*\("), DELETE, "shutil.rmtree recursive delete"),
    (re.compile(r"\.unlink\s*\("), DELETE, "pathlib unlink"),
    (re.compile(r"\beval\s*\("), EXEC, "eval executes constructed code"),
    (re.compile(r"\bexec\s*\("), EXEC, "exec executes constructed code"),
    (re.compile(r"\bpip\s+install\b"), EXEC, "pip install"),
    (re.compile(r"\bbase64\.b64decode\s*\("), EXEC, "base64 decode (check for exec use)"),
]

_OPEN_RE = re.compile(r"""\bopen\s*\([^)]*,\s*['"]([^'"]*)['"]""")
_ENV_RE = re.compile(r"""\bos\.environ(?:\[|\.get\(\s*)['"]([A-Za-z0-9_]+)['"]""")
_ENV_DUMP_RE = re.compile(r"\bprint\s*\(\s*os\.environ\s*\)")


def analyze_python_line(line: str, rel: str, lineno: int, out: list[Capability]) -> None:
    """Analyse one cleaned Python line and append findings."""
    code = line.strip()
    if not code:
        return
    m = _OPEN_RE.search(code)
    if m:
        mode = m.group(1)
        if any(c in mode for c in "wax+"):
            target = code[: m.start()]
            cat = CONFIG if CONFIG_PATH_RE.search(code) else (
                EXEC if PERSIST_PATH_RE.search(code) else WRITE)
            out.append(Capability(cat, rel, lineno,
                                  f"open(..., {mode!r}) writes a file", code))
            return
    for pattern, cat, detail in _PY_PATTERNS:
        if pattern.search(code):
            # base64 decode alone is not exec; only flag when paired with
            # eval/exec/system on the same line (checked by caller scan).
            if detail.startswith("base64 decode"):
                if not re.search(r"\b(eval|exec|os\.system|subprocess)\b", code):
                    continue
                detail = "base64 decode fed to exec/eval"
            out.append(Capability(cat, rel, lineno, detail, code))
            return
    m = _ENV_RE.search(code)
    if m and SENSITIVE_ENV_RE.fullmatch(m.group(1)):
        out.append(Capability(SECRET, rel, lineno, f"reads env var {m.group(1)}", code))
        return
    if _ENV_DUMP_RE.search(code):
        out.append(Capability(SECRET, rel, lineno, "dumps os.environ", code))
        return
    if SECRET_PATH_RE.search(code):
        out.append(Capability(SECRET, rel, lineno, "touches credential material", code))
        return
    if re.search(r"\bsubprocess\.\w+\s*\(", code) and "shell=True" in code:
        out.append(Capability(EXEC, rel, lineno, "subprocess with shell=True", code))
        return


# ---------------------------------------------------------------- javascript

_JS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bfetch\s*\("), NETWORK, "fetch() network call"),
    (re.compile(r"\baxios\.(get|post|put|delete|request)\s*\("), NETWORK, "axios HTTP call"),
    (re.compile(r"\bhttps?\.(get|request)\s*\("), NETWORK, "http(s) request"),
    (re.compile(r"\bfs\.(writeFile|appendFile|createWriteStream)\s*\("), WRITE, "fs file write"),
    (re.compile(r"\bfs\.(unlink|rm)\w*\s*\("), DELETE, "fs file delete"),
    (re.compile(r"\b(child_process\.)?(execSync|exec|spawnSync|spawn)\s*\("), EXEC, "child_process exec"),
    (re.compile(r"\beval\s*\("), EXEC, "eval executes constructed code"),
]


def analyze_js_line(line: str, rel: str, lineno: int, out: list[Capability]) -> None:
    """Analyse one JS/TS line (full-line comments skipped)."""
    code = line.strip()
    if not code or code.startswith("//"):
        return
    # Strip a trailing // comment outside quotes (best effort).
    code = strip_shell_comments(code).strip()
    for pattern, cat, detail in _JS_PATTERNS:
        if pattern.search(code):
            out.append(Capability(cat, rel, lineno, detail, code))
            return
    m = re.search(r"process\.env\.([A-Za-z0-9_]+)", code)
    if m and SENSITIVE_ENV_RE.fullmatch(m.group(1)):
        out.append(Capability(SECRET, rel, lineno, f"reads env var {m.group(1)}", code))
        return
    if SECRET_PATH_RE.search(code):
        out.append(Capability(SECRET, rel, lineno, "touches credential material", code))
        return


# ---------------------------------------------------------------- json configs

def _find_line(lines: list[str], needle: str) -> int:
    """Best-effort line number for a JSON string value (1-based)."""
    frag = needle[:40]
    for idx, line in enumerate(lines, start=1):
        if frag in line:
            return idx
    return 1


def _walk_json_strings(value, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _walk_json_strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _walk_json_strings(v, out)


def analyze_hooks(text: str, rel: str, out: list[Capability]) -> None:
    """hooks.json: every command string is analysed as a shell line."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    lines = text.splitlines()
    strings: list[str] = []
    _walk_json_strings(data, strings)
    for s in strings:
        if re.search(r"\b(curl|wget|rm|cp|mv|pip|npm|sudo|eval|chmod|base64)\b", s):
            analyze_shell_line(s, rel, _find_line(lines, s), out)


def analyze_mcp(text: str, rel: str, out: list[Capability]) -> None:
    """MCP config: a remote URL is egress; a spawned command is exec."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    lines = text.splitlines()
    servers = data.get("mcpServers") or data.get("servers") or {}
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("url"):
                out.append(Capability(NETWORK, rel, _find_line(lines, str(cfg["url"])),
                                      f"MCP server {name!r} uses remote URL {cfg['url']}", ""))
            if cfg.get("command"):
                out.append(Capability(EXEC, rel, _find_line(lines, str(cfg["command"])),
                                      f"MCP server {name!r} spawns command {cfg['command']}", ""))


def analyze_package(text: str, rel: str, out: list[Capability]) -> None:
    """package.json: each npm script is analysed as a shell line."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    lines = text.splitlines()
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for name, script in scripts.items():
            if isinstance(script, str):
                analyze_shell_line(script, rel, _find_line(lines, script), out)


# ---------------------------------------------------------------- entry point

def analyze_file(rel: str, kind: str, text: str) -> list[Capability]:
    """Analyse one inventoried file; returns its capabilities."""
    out: list[Capability] = []
    if kind == "code":
        if rel.endswith(".py"):
            for lineno, line in enumerate(clean_python_source(text), start=1):
                analyze_python_line(line, rel, lineno, out)
        elif rel.endswith(".sh"):
            for lineno, line in enumerate(text.splitlines(), start=1):
                analyze_shell_line(line, rel, lineno, out)
        elif rel.endswith((".js", ".ts")):
            for lineno, line in enumerate(text.splitlines(), start=1):
                analyze_js_line(line, rel, lineno, out)
    elif kind == "hooks":
        analyze_hooks(text, rel, out)
    elif kind == "mcp":
        analyze_mcp(text, rel, out)
    elif kind == "package":
        analyze_package(text, rel, out)
    return out
