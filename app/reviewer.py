"""Rule-based code reviewer for Python changes in pull requests.

GitHub gives us a ``patch`` string for every changed file. The patch is
a unified diff, and the interesting lines for a reviewer are the ones
starting with ``+`` (lines the pull request *adds*).

This module:
1. extracts the added lines together with their real line numbers,
2. runs a small set of plain, explainable rules over them,
3. builds one Markdown comment (plus a severity count) that
   ``app/main.py`` posts to the pull-request reviews API.

The output is deterministic: the same PR always produces the same text.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any


# --------------------------------------------------------------------------
# Patch parsing
# --------------------------------------------------------------------------
# Example header: "@@ -12,7 +12,9 @@ def existing_function():"
HUNK_HEADER_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# The first number after the second "@@" set " +12,9 " is where the new
# version's line counter starts for this hunk.


# --------------------------------------------------------------------------
# Rules (regular expressions over single added lines)
# --------------------------------------------------------------------------
SECRET_VALUE_RE = re.compile(
    r"""^\s*[\w.]*(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|token)\s*=\s*["'][^"']{4,}["']""",
    re.IGNORECASE,
)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
FSTRING_RE = re.compile(r"""\bf["']""")
SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
DANGEROUS_EXEC_RE = re.compile(r"\b(?:eval|exec)\s*\(")
SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
PICKLE_LOAD_RE = re.compile(r"\bpickle\.loads?\s*\(")
OS_SYSTEM_RE = re.compile(r"\bos\.(?:system|popen)\s*\(")
MD5_RE = re.compile(r"\bhashlib\.md5\s*\(")
BARE_EXCEPT_RE = re.compile(r"except\s*:")
BROAD_EXCEPT_RE = re.compile(r"except\s+Exception\b")
PRINT_RE = re.compile(r"\bprint\s*\(")
NONE_COMPARE_RE = re.compile(r"[!=]=\s*None\b")
MUTABLE_DEFAULT_RE = re.compile(r"def\s+\w+\s*\(.*=\s*(?:\[\]|\{\})")
TODO_RE = re.compile(r"#\s*(?:TODO|FIXME|HACK|XXX)\b")
ASSERT_RE = re.compile(r"^\s*assert\b")

LONG_LINE_LIMIT = 120
MAX_LONG_LINES_PER_FILE = 1
MAX_FINDINGS = 40

SEVERITY_ORDER = {"security": 0, "warning": 1, "suggestion": 2}
SEVERITY_TITLE = {
    "security": "🔒 Security issues",
    "warning": "⚠️ Warnings",
    "suggestion": "💡 Suggestions",
}
SEVERITY_LABEL = {
    "security": "security issue(s)",
    "warning": "warning(s)",
    "suggestion": "suggestion(s)",
}


@dataclass
class Finding:
    path: str
    line: int
    severity: str
    message: str

    def render(self) -> str:
        return f"- `{self.path}` line {self.line} — {self.message}"


@dataclass
class Review:
    """What main.py needs in order to post a comment."""

    body: str
    security_count: int = 0


# --------------------------------------------------------------------------
# Diff helpers
# --------------------------------------------------------------------------
def added_lines(patch: str) -> list[tuple[int, str]]:
    """Return ``(line_number_in_new_file, text)`` for every ``+`` line.

    Hunk headers (``@@ ... @@``) tell us where the new-side counter
    starts; added (+) and context ( ) lines advance it, deleted (-)
    lines do not.
    """
    result: list[tuple[int, str]] = []
    new_side = 0

    for raw in patch.splitlines():
        header = HUNK_HEADER_RE.match(raw)
        if header:
            new_side = int(header.group(1))
            continue
        if raw.startswith("+"):
            result.append((new_side, raw[1:]))
            new_side += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            # Deleted line or "\ No newline at end of file".
            continue
        else:
            # Context line that exists in the new file.
            new_side += 1

    return result


def is_test_file(path: str) -> bool:
    """True for files that look like tests (tests/… or test_*.py)."""
    base = os.path.basename(path).lower()
    lowered = path.lower().replace("\\", "/")
    return "/tests/" in f"/{lowered}" or lowered.startswith("tests/") or base.startswith("test_")


def file_type(path: str) -> str:
    extension = os.path.splitext(path)[1].lower()
    labels = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".md": "Docs",
        ".html": "HTML",
        ".css": "CSS",
        ".json": "JSON",
        ".yml": "YAML",
        ".yaml": "YAML",
        ".txt": "Text",
    }
    return labels.get(extension, "Data" if extension else "Other")


def _analyze_line(
    path: str, line_number: int, code: str, in_test_file: bool
) -> list[tuple[str, str]]:
    """Run every single-line rule over one added line of code."""
    findings: list[tuple[str, str]] = []
    stripped = code.strip()
    if not stripped:
        return findings

    if DANGEROUS_EXEC_RE.search(code):
        findings.append(
            (
                "security",
                "Avoid `eval`/`exec` — they run any string as code, so a user-supplied "
                "value becomes an arbitrary-code-execution hole. Use explicit functions, "
                "or `ast.literal_eval` when you only need plain data.",
            )
        )

    if SHELL_TRUE_RE.search(code):
        findings.append(
            (
                "security",
                "`shell=True` runs the command through the shell, which lets user input "
                "be interpreted as shell commands. Prefer `subprocess.run([...])` with a "
                "list of arguments and no shell.",
            )
        )

    if FSTRING_RE.search(code) and "{" in code and SQL_KEYWORD_RE.search(code):
        findings.append(
            (
                "security",
                "Building SQL with an f-string lets input become SQL code (SQL injection). "
                "Pass parameters separately, e.g. `cursor.execute(sql, (value,))`.",
            )
        )

    if SECRET_VALUE_RE.match(code):
        findings.append(
            (
                "security",
                "This looks like a hardcoded credential. Load it from the environment "
                "instead (`os.getenv(...)` or `.env`). If it was ever committed, rotate "
                "the key — history cannot be un-pushed safely.",
            )
        )

    if AWS_KEY_RE.search(code):
        findings.append(
            (
                "security",
                "This looks like an AWS access key ID in source code. Remove it and "
                "rotate the key in the AWS console.",
            )
        )

    if PICKLE_LOAD_RE.search(code):
        findings.append(
            (
                "security",
                "`pickle.load` executes code contained in the data it loads. Only do this "
                "for files you created yourself; use JSON for anything untrusted.",
            )
        )

    if OS_SYSTEM_RE.search(code):
        findings.append(
            (
                "warning",
                "`os.system`/`os.popen` is easy to inject into. Prefer the `subprocess` "
                "module with an argument list, and avoid building command strings from "
                "user input.",
            )
        )

    if MD5_RE.search(code):
        findings.append(
            (
                "warning",
                "MD5 is collision-broken and unsuitable for security purposes. Use "
                "`hashlib.sha256`, or `bcrypt`/`argon2` for passwords.",
            )
        )

    if BARE_EXCEPT_RE.search(code) or BROAD_EXCEPT_RE.search(code):
        findings.append(
            (
                "warning",
                "Catching every exception hides real bugs (typos, `KeyboardInterrupt`, "
                "BrokenPipeError, …). Catch the specific exception types this call can "
                "raise and handle or log them.",
            )
        )

    if MUTABLE_DEFAULT_RE.search(code):
        findings.append(
            (
                "warning",
                "Mutable default arguments (`[]`, `{}`) are created once and shared "
                "between calls, so mutations persist. Default to `None` and create "
                "the list/dict inside the function body.",
            )
        )

    if TODO_RE.search(code):
        findings.append(
            (
                "suggestion",
                "A TODO/FIXME in merged code tends to be forgotten. Resolve it before "
                "merging, or open an issue so it stays tracked.",
            )
        )

    if PRINT_RE.search(code) and not in_test_file:
        findings.append(
            (
                "suggestion",
                "`print` is hard to control in production. Prefer the `logging` module "
                "so levels and destinations can be configured in one place.",
            )
        )

    if NONE_COMPARE_RE.search(code):
        findings.append(
            (
                "suggestion",
                "Use `is None` / `is not None` — `== None` calls `__eq__`, which can "
                "give surprising results for objects that customise equality.",
            )
        )

    if not in_test_file and ASSERT_RE.match(stripped):
        findings.append(
            (
                "suggestion",
                "`assert` disappears when Python runs with `-O`, so it must never be "
                "the only runtime check. If this matters, use a real `if`/`raise`.",
            )
        )

    return findings


def _format_file_table(files: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in files[:10]:
        path = item.get("filename", "unknown")
        status = item.get("status", "modified")
        add = item.get("additions", 0) or 0
        dele = item.get("deletions", 0) or 0
        rows.append(f"| `{path}` | {file_type(path)} | {status} | **+{add} / -{dele}** |")

    table = "| File | Type | Status | Changes |\n|---|---|---|---|\n" + "\n".join(rows)
    if len(files) > 10:
        table += f"\n*(…and {len(files) - 10} more files)*"
    return table


def fallback_review(repo_full_name: str, pr_number: int, pr_title: str) -> Review:
    """A minimal, still-useful comment for when the reviewer itself fails."""
    body = (
        "## 🤖 AI Code Review\n\n"
        f"Something went wrong while I analyzed **{repo_full_name} PR #{pr_number}** "
        f"(`{pr_title}`), so this is only a placeholder. Please review this pull "
        "request manually — the checker logs in the bot's console show the reason.\n\n"
        "---\n"
        "<sub>Automated comment by <code>ai-code-review-bot</code>.</sub>"
    )
    return Review(body=body)


def review_pull_request(
    repo_full_name: str,
    pr_number: int,
    pr_title: str,
    files: list[dict[str, Any]],
) -> Review:
    """Build the one general review comment for a pull request."""
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    total_additions = total_deletions = 0
    files_with_inline_diff = 0
    python_source_files = 0
    python_test_files = 0

    def add_finding(finding: Finding) -> None:
        key = (finding.path, finding.line, finding.message)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for item in files:
        path = item.get("filename", "<unknown>")
        total_additions += item.get("additions", 0) or 0
        total_deletions += item.get("deletions", 0) or 0

        is_python = path.lower().endswith(".py")
        in_test = is_test_file(path) if is_python else False
        if is_python:
            if in_test:
                python_test_files += 1
            else:
                python_source_files += 1

        patch = item.get("patch")
        if not patch:
            # Binary files, huge diffs, and renames come without a patch.
            continue
        files_with_inline_diff += 1

        parsed = added_lines(patch)

        for line_number, text in parsed:
            for severity, message in _analyze_line(path, line_number, text, in_test):
                add_finding(Finding(path, line_number, severity, message))

        long_lines = [(n, t) for n, t in parsed if len(t.rstrip()) > LONG_LINE_LIMIT]
        if long_lines:
            first_line, first_text = long_lines[0]
            extra = ""
            if len(long_lines) > MAX_LONG_LINES_PER_FILE:
                extra = f" (and {len(long_lines) - 1} more in this file)"
            add_finding(
                Finding(
                    path,
                    first_line,
                    "suggestion",
                    f"This line is {len(first_text.rstrip())} characters long — "
                    f"keep lines under {LONG_LINE_LIMIT} characters for readability.{extra}",
                )
            )

    # Pull-request level check: do new tests accompany the changes?
    if python_source_files and not python_test_files:
        add_finding(
            Finding(
                "<pull request>",
                0,
                "suggestion",
                f"None of the changed files is a test, while "
                f"{python_source_files} Python source file(s) were modified. "
                "Consider adding or updating a test for the new behaviour.",
            )
        )

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line))

    truncated = len(findings) > MAX_FINDINGS
    if truncated:
        findings = findings[:MAX_FINDINGS]

    counts = Counter(f.severity for f in findings)
    if truncated:
        counts[findings[-1].severity] += 1

    # ------------------------------------------------------------------
    # Compose the Markdown comment
    # ------------------------------------------------------------------
    type_counts = Counter(file_type(item.get("filename", "unknown")) for item in files)
    touched = ", ".join(f"{count} {label}" for label, count in type_counts.most_common())

    parts = [f"**{counts[sev]}** {SEVERITY_LABEL[sev]}" for sev in ("security", "warning", "suggestion") if counts[sev]]
    if parts:
        if len(parts) == 1:
            summary = parts[0]
        else:
            summary = ", ".join(parts[:-1]) + " and " + parts[-1]
        overview = (
            f"I analyzed the lines this pull request adds and noticed {summary}. "
            "Details below — the 🔒 items deserve a look before merging."
        )
    else:
        overview = (
            "✅ I analyzed the added code and found no issues with my checks "
            "(dangerous calls, hardcoded secrets, broad exception handling, "
            f"style, long lines, and test coverage). Reviewed {touched}."
        )

    sections: list[str] = [
        "## 🤖 AI Code Review",
        "",
        f"**PR:** #{pr_number} — {pr_title}",
        f"**Repository:** `{repo_full_name}`",
        f"**Changes:** {len(files)} file(s) · **+{total_additions} / -{total_deletions}** lines · {touched}",
        "",
        overview,
    ]

    if len(files) > files_with_inline_diff:
        sections.append(
            f"\n*({len(files) - files_with_inline_diff} file(s) had no inline diff — "
            "binary or very large — and were skipped by the line rules.)*"
        )

    if touched and files:
        sections.append("\n" + _format_file_table(files))

    for severity in ("security", "warning", "suggestion"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        title = SEVERITY_TITLE[severity]
        sections.append(f"\n### {title} ({len(group)})\n")
        sections.extend(finding.render() for finding in group)

    if truncated:
        sections.append(f"\n*…findings were truncated at {MAX_FINDINGS} items.*")

    if not counts["security"] and not counts["warning"] and counts["suggestion"]:
        sections.append("\n👍 Only suggestions left — nothing looks dangerous.")

    footer_note = (
        "⚠️ This is an automated, rule-based check of the **added lines only** — "
        "it can miss context that a human reviewer would catch. Verify anything "
        "tagged 🔒 yourself."
    )
    sections.append(f"\n---\n<sub>{footer_note} · `ai-code-review-bot`</sub>")

    body = "\n".join(sections)
    return Review(body=body, security_count=counts["security"])
