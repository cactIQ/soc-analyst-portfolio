#!/usr/bin/env python3
"""Small secret scanner for SOCVerse repositories.

Usage:
  python3 tools/secret_scan.py --staged     scan what is about to be committed
  python3 tools/secret_scan.py --all        scan every tracked file
  python3 tools/secret_scan.py FILE [...]   scan specific files

Exit codes: 0 clean, 1 findings, 2 usage or git error.

Private terms (employer name, work domain, real IP prefixes) go in
.secretscan-local, one per line. That file is gitignored, so the terms
themselves are never committed.

A line containing "secretscan:allow" is skipped. Use it rarely and say why.
This tool is a safety net, not a guarantee. Review what you commit.
"""
import re
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
ALLOW_MARK = "secretscan:allow"
LOCAL_TERMS_FILE = ".secretscan-local"

RULES = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# key = value style assignments, e.g. DB_PASSWORD=..., "api_key": "..."
ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token)[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']?([^\s\"'#,;]{8,})"
)
# Values that are obviously placeholders or code references, not secrets.
PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\$\{.*\}|\{.*\}|x{4,}|\*{4,}|changeme|example\S*|your[_-]\S*|none|null|true|false|redacted)$"
)
CODE_REFERENCE = re.compile(r"^[A-Za-z_]\w*(\.\w+)+(\(\))?$")


def mask(value):
    """Show only enough of a match to locate it, never the whole secret."""
    return value[:4] + "***" if len(value) > 4 else "***"


def load_local_terms(root):
    path = Path(root) / LOCAL_TERMS_FILE
    if not path.is_file():
        return []
    terms = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line.lower())
    return terms


def scan_text(name, text, local_terms=()):
    """Return a list of (name, line_number, rule, masked_match)."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARK in line:
            continue
        for rule, pattern in RULES:
            for match in pattern.finditer(line):
                findings.append((name, number, rule, mask(match.group(0))))
        for match in ASSIGNMENT.finditer(line):
            value = match.group(2)
            if PLACEHOLDER.match(value) or CODE_REFERENCE.match(value):
                continue
            findings.append((name, number, "assignment:" + match.group(1).lower(), mask(value)))
        lowered = line.lower()
        for term in local_terms:
            if term in lowered:
                findings.append((name, number, "local_term", mask(term)))
    return findings


def decode(data):
    """Return text, or None for binary or oversized content."""
    if len(data) > MAX_BYTES or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def staged_files():
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [p for p in out.decode().split("\0") if p]


def tracked_files():
    out = git("ls-files", "-z")
    return [p for p in out.decode().split("\0") if p]


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    try:
        root = git("rev-parse", "--show-toplevel").decode().strip() if argv[0] in ("--staged", "--all") else "."
        local_terms = load_local_terms(root)
        findings = []
        if argv[0] == "--staged":
            for path in staged_files():
                text = decode(git("show", ":" + path))  # the staged version, not the working copy
                if text is not None:
                    findings += scan_text(path, text, local_terms)
        else:
            paths = tracked_files() if argv[0] == "--all" else argv
            for path in paths:
                file = Path(root) / path
                if file.is_file():
                    text = decode(file.read_bytes())
                    if text is not None:
                        findings += scan_text(path, text, local_terms)
    except subprocess.CalledProcessError as error:
        print("secret_scan: git error: " + error.stderr.decode().strip(), file=sys.stderr)
        return 2

    for name, number, rule, shown in findings:
        print(f"{name}:{number}: {rule} ({shown})")
    if findings:
        print(f"secret_scan: {len(findings)} finding(s). Remove them, or mark a false positive with {ALLOW_MARK}.")
        return 1
    print("secret_scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
