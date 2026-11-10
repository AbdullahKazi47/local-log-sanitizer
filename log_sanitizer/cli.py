"""Command-line interface for the log sanitizer."""

import argparse
import sys
from collections import Counter
from typing import Sequence

from .sanitizer import DEFAULT_EXTENSIONS, Whitelist, sanitize_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_sanitizer",
        description="Redact IP addresses, emails and secret tokens from local log files.",
    )
    parser.add_argument("target", help="log file or directory to scan (directories are scanned recursively)")
    parser.add_argument(
        "-n", "--dry-run", action="store_true",
        help="only report match counts; never modify or write files",
    )
    parser.add_argument(
        "-o", "--output-dir",
        help="write redacted copies here instead of overwriting the originals",
    )
    parser.add_argument(
        "-w", "--whitelist", action="append", default=[], metavar="FILE",
        help="file of safe terms, IPs or CIDR ranges, one per line (repeatable)",
    )
    parser.add_argument(
        "-a", "--allow", action="append", default=[], metavar="TERM",
        help="a single safe term, IP or CIDR range to never redact (repeatable)",
    )
    parser.add_argument(
        "-e", "--ext", action="append", metavar="EXT",
        help=f"file extension to include when scanning directories (repeatable; default: {' '.join(DEFAULT_EXTENSIONS)})",
    )
    parser.add_argument(
        "--all-files", action="store_true",
        help="scan every non-binary file in a directory regardless of extension",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the summary line")
    return parser


def _format_counts(counts: Counter) -> str:
    return ", ".join(f"{name}={counts[name]}" for name in sorted(counts)) or "no matches"


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    whitelist = Whitelist(args.allow)
    try:
        for path in args.whitelist:
            whitelist.load_file(path)
    except OSError as exc:
        print(f"error: cannot read whitelist: {exc}", file=sys.stderr)
        return 2

    extensions = () if args.all_files else (args.ext or DEFAULT_EXTENSIONS)
    try:
        results = sanitize_path(args.target, whitelist, args.dry_run, args.output_dir, extensions)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    totals: Counter = Counter()
    for result in results:
        totals.update(result.counts)
        if args.quiet:
            continue
        if result.error:
            print(f"{result.path}: {result.error}")
        elif result.total:
            action = f" -> {result.written_to}" if result.written_to else ""
            print(f"{result.path}: {_format_counts(result.counts)}{action}")

    mode = "dry run" if args.dry_run else "redacted"
    print(f"{mode}: {sum(totals.values())} match(es) in {len(results)} file(s) [{_format_counts(totals)}]")
    return 0
