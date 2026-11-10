# Local Log Sanitizer

A command-line tool that scans local log files and redacts sensitive data
before you share them. It uses only the Python 3 standard library.

It finds and replaces:

| Kind     | Examples                                                    | Placeholder         |
|----------|-------------------------------------------------------------|---------------------|
| `email`  | `user@example.com`                                          | `[REDACTED_EMAIL]`  |
| `ipv4`   | `192.0.2.10`                                                | `[REDACTED_IPV4]`   |
| `ipv6`   | `2001:db8::1`, `::ffff:192.0.2.1`                           | `[REDACTED_IPV6]`   |
| `secret` | `api_key=...`, `password: ...`, `Bearer ...`, well-known token prefixes, long mixed letter/digit tokens | `[REDACTED_SECRET]` |

For `key=value` secrets only the value is replaced, so `api_key=abc123def456`
becomes `api_key=[REDACTED_SECRET]`. IPv6 candidates are checked with
`ipaddress`, so timestamps (`12:34:56`) and MAC addresses are left alone.

## Usage

Requires Python 3.10 or newer. Run from this folder:

```sh
# See what would be redacted, without changing anything
python -m log_sanitizer /path/to/logs --dry-run

# Redact files in place
python -m log_sanitizer /path/to/logs

# Write redacted copies to another folder, keeping the originals
python -m log_sanitizer /path/to/logs --output-dir sanitized/

# A single file works too, whatever its extension
python -m log_sanitizer app.log -n
```

Options:

- `-n, --dry-run` — print match counts per file; nothing gets written.
- `-o, --output-dir DIR` — write redacted copies into `DIR`, with the same folder layout as the source.
- `-a, --allow TERM` — never redact this term, IP or CIDR range (can be repeated).
- `-w, --whitelist FILE` — load safe terms from a file (can be repeated).
- `-e, --ext EXT` — file extensions to scan in directories (can be repeated; default `.log .txt .out .err`).
- `--all-files` — scan every non-binary file in a directory.
- `-q, --quiet` — print only the summary line.

Binary files are skipped. Files with no matches are not rewritten. Line
endings and bytes that are not valid UTF-8 are kept exactly as they were.

### Whitelist file

Put one entry per line. Blank lines and `#` comments are ignored. Matching
ignores case. IP ranges in CIDR form cover every address inside them.

```text
# internal ranges
10.0.0.0/8
2001:db8::/32
127.0.0.1
noreply@example.com
```

### Using it from Python

```python
from log_sanitizer import Whitelist, sanitize_text

text, counts = sanitize_text("login from 192.0.2.1", Whitelist(["10.0.0.0/8"]))
# text == "login from [REDACTED_IPV4]", counts == {"ipv4": 1}
```

## Running the tests

```sh
python -m pytest -q
```

The tests cover each pattern, the edge cases and look-alikes it should
ignore, whitelisting, dry-run safety, in-place and output-dir writes,
binary-file skipping, byte-exact preservation, and the CLI.

Built with Claude Code, picked by VERONICA.
