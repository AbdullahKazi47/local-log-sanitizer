"""Core redaction logic: text sanitizing, whitelisting and file handling."""

import ipaddress
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .patterns import DEFAULT_RULES, Rule

DEFAULT_EXTENSIONS = (".log", ".txt", ".out", ".err")
_BINARY_SNIFF_BYTES = 8192


class Whitelist:
    """Terms that must never be redacted.

    Entries are compared case-insensitively. Entries that parse as an IP
    address or CIDR network (e.g. ``10.0.0.0/8``) also cover every address
    inside that network.
    """

    def __init__(self, entries: Iterable[str] = ()):
        self._terms: set[str] = set()
        self._networks: list = []
        for entry in entries:
            self.add(entry)

    def add(self, entry: str) -> None:
        entry = entry.strip()
        if not entry:
            return
        self._terms.add(entry.lower())
        if "/" in entry:
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass

    def __contains__(self, value: str) -> bool:
        if value.lower() in self._terms:
            return True
        if not self._networks:
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address.version == net.version and address in net for net in self._networks)

    def __len__(self) -> int:
        return len(self._terms)

    def load_file(self, path: str | os.PathLike) -> None:
        """Add one entry per line; blank lines and ``#`` comments are ignored."""
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                self.add(line.split("#", 1)[0])

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Whitelist":
        whitelist = cls()
        whitelist.load_file(path)
        return whitelist


def sanitize_text(
    text: str,
    whitelist: Whitelist | None = None,
    rules: Sequence[Rule] = DEFAULT_RULES,
) -> tuple[str, Counter]:
    """Return ``(redacted_text, counts)`` where counts maps rule name to hits."""
    whitelist = whitelist or Whitelist()
    counts: Counter = Counter()

    for rule in rules:

        def replace(match, rule=rule):
            value = match.group(rule.group)
            if rule.validator and not rule.validator(value):
                return match.group(0)
            if value in whitelist:
                return match.group(0)
            counts[rule.name] += 1
            start, end = match.span(rule.group)
            offset = match.start()
            whole = match.group(0)
            return whole[: start - offset] + rule.placeholder + whole[end - offset :]

        text = rule.regex.sub(replace, text)

    return text, counts


@dataclass
class FileResult:
    path: Path
    counts: Counter = field(default_factory=Counter)
    written_to: Path | None = None
    error: str | None = None

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def is_binary(path: Path) -> bool:
    with open(path, "rb") as handle:
        return b"\0" in handle.read(_BINARY_SNIFF_BYTES)


def iter_files(target: str | os.PathLike, extensions: Sequence[str] = DEFAULT_EXTENSIONS) -> Iterator[Path]:
    """Yield files to scan.

    A single file is always yielded. Directories are walked recursively and
    only files with a matching extension are yielded (all files if
    ``extensions`` is empty), in sorted order for stable output.
    """
    target = Path(target)
    if target.is_file():
        yield target
        return
    if not target.is_dir():
        raise FileNotFoundError(f"No such file or directory: {target}")
    wanted = {ext.lower() if ext.startswith(".") else "." + ext.lower() for ext in extensions}
    for root, dirs, files in os.walk(target):
        dirs.sort()
        for name in sorted(files):
            path = Path(root) / name
            if not wanted or path.suffix.lower() in wanted:
                yield path


def sanitize_file(
    path: Path,
    whitelist: Whitelist | None = None,
    dry_run: bool = False,
    output_path: Path | None = None,
) -> FileResult:
    """Scan one file and, unless ``dry_run``, write the redacted version.

    The file is overwritten in place unless ``output_path`` is given. Files
    with no matches are left untouched. Line endings and undecodable bytes
    are preserved exactly.
    """
    result = FileResult(path=path)
    try:
        if is_binary(path):
            result.error = "skipped binary file"
            return result
        with open(path, encoding="utf-8", errors="surrogateescape", newline="") as handle:
            original = handle.read()
    except OSError as exc:
        result.error = str(exc)
        return result

    redacted, result.counts = sanitize_text(original, whitelist)

    if dry_run or (output_path is None and redacted == original):
        return result

    destination = output_path or path
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", errors="surrogateescape", newline="") as handle:
        handle.write(redacted)
    result.written_to = destination
    return result


def sanitize_path(
    target: str | os.PathLike,
    whitelist: Whitelist | None = None,
    dry_run: bool = False,
    output_dir: str | os.PathLike | None = None,
    extensions: Sequence[str] = DEFAULT_EXTENSIONS,
) -> list[FileResult]:
    """Sanitize a file or directory tree and return one result per file.

    With ``output_dir``, redacted copies are written there (mirroring the
    directory layout) and the originals are left untouched.
    """
    target = Path(target)
    base = target if target.is_dir() else target.parent
    out_root = Path(output_dir).resolve() if output_dir is not None else None
    # Collect up front so copies written into an output dir that lives inside
    # the target tree are never picked up and re-scanned.
    paths = [
        path
        for path in iter_files(target, extensions)
        if out_root is None or not path.resolve().is_relative_to(out_root)
    ]
    results = []
    for path in paths:
        output_path = out_root / path.relative_to(base) if out_root is not None else None
        results.append(sanitize_file(path, whitelist, dry_run, output_path))
    return results
