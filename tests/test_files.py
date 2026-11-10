"""File scanning, writing and command-line behaviour."""

from pathlib import Path

import pytest

from log_sanitizer import Whitelist, iter_files, sanitize_file, sanitize_path
from log_sanitizer.cli import main

SAMPLE = "start\nuser@example.com logged in from 192.0.2.10\napi_key=abcdef123456\n"
REDACTED = "start\n[REDACTED_EMAIL] logged in from [REDACTED_IPV4]\napi_key=[REDACTED_SECRET]\n"


@pytest.fixture
def log_tree(tmp_path):
    (tmp_path / "nested" / "deeper").mkdir(parents=True)
    (tmp_path / "app.log").write_text(SAMPLE, encoding="utf-8")
    (tmp_path / "nested" / "worker.txt").write_text("peer 2001:db8::7\n", encoding="utf-8")
    (tmp_path / "nested" / "deeper" / "clean.log").write_text("all good\n", encoding="utf-8")
    (tmp_path / "nested" / "config.ini").write_text("host=192.0.2.1\n", encoding="utf-8")
    return tmp_path


def test_iter_files_recurses_and_filters_extensions(log_tree):
    found = [p.relative_to(log_tree).as_posix() for p in iter_files(log_tree)]
    assert found == ["app.log", "nested/worker.txt", "nested/deeper/clean.log"]


def test_iter_files_empty_extensions_means_all(log_tree):
    found = {p.name for p in iter_files(log_tree, extensions=())}
    assert "config.ini" in found


def test_iter_files_single_file_ignores_extension(log_tree):
    target = log_tree / "nested" / "config.ini"
    assert list(iter_files(target)) == [target]


def test_iter_files_missing_target(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_files(tmp_path / "nope"))


def test_dry_run_reports_counts_without_changing_files(log_tree):
    before = {p: p.read_bytes() for p in log_tree.rglob("*") if p.is_file()}
    results = sanitize_path(log_tree, dry_run=True)
    after = {p: p.read_bytes() for p in log_tree.rglob("*") if p.is_file()}

    assert before == after
    by_name = {r.path.name: r for r in results}
    assert by_name["app.log"].counts == {"email": 1, "ipv4": 1, "secret": 1}
    assert by_name["worker.txt"].counts == {"ipv6": 1}
    assert by_name["clean.log"].total == 0
    assert all(r.written_to is None for r in results)


def test_in_place_redaction(log_tree):
    sanitize_path(log_tree)
    assert (log_tree / "app.log").read_text(encoding="utf-8") == REDACTED
    assert (log_tree / "nested" / "worker.txt").read_text(encoding="utf-8") == "peer [REDACTED_IPV6]\n"
    # Files outside the extension filter are not touched.
    assert (log_tree / "nested" / "config.ini").read_text(encoding="utf-8") == "host=192.0.2.1\n"


def test_clean_files_are_not_rewritten(log_tree):
    clean = log_tree / "nested" / "deeper" / "clean.log"
    result = sanitize_file(clean)
    assert result.written_to is None


def test_output_dir_mirrors_tree_and_keeps_originals(log_tree, tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    sanitize_path(log_tree, output_dir=out)

    assert (log_tree / "app.log").read_text(encoding="utf-8") == SAMPLE
    assert (out / "app.log").read_text(encoding="utf-8") == REDACTED
    assert (out / "nested" / "worker.txt").exists()
    assert (out / "nested" / "deeper" / "clean.log").read_text(encoding="utf-8") == "all good\n"


def test_output_dir_inside_target_is_not_rescanned(log_tree):
    out = log_tree / "sanitized"
    sanitize_path(log_tree, output_dir=out)
    results = sanitize_path(log_tree, output_dir=out)
    assert not any("sanitized" in r.path.parts for r in results)
    assert not (out / "sanitized").exists()


def test_single_file_with_output_dir(log_tree, tmp_path_factory):
    out = tmp_path_factory.mktemp("single")
    sanitize_path(log_tree / "app.log", output_dir=out)
    assert (out / "app.log").read_text(encoding="utf-8") == REDACTED


def test_preserves_line_endings_and_undecodable_bytes(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_bytes(b"caf\xe9 192.0.2.1\r\nnext\n")
    sanitize_file(path)
    assert path.read_bytes() == b"caf\xe9 [REDACTED_IPV4]\r\nnext\n"


def test_binary_files_are_skipped(tmp_path):
    path = tmp_path / "blob.log"
    data = b"\x00\x01192.0.2.1"
    path.write_bytes(data)
    result = sanitize_file(path)
    assert result.error == "skipped binary file"
    assert path.read_bytes() == data


def test_whitelist_file(tmp_path):
    wl = tmp_path / "allow.txt"
    wl.write_text("# trusted\n192.0.2.0/24\n\nops@example.com  # team inbox\n", encoding="utf-8")
    whitelist = Whitelist.from_file(wl)
    assert "192.0.2.77" in whitelist
    assert "ops@example.com" in whitelist
    assert "# trusted" not in whitelist


# --- CLI --------------------------------------------------------------------

def test_cli_dry_run(log_tree, capsys):
    original = (log_tree / "app.log").read_text(encoding="utf-8")
    assert main([str(log_tree), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "app.log: email=1, ipv4=1, secret=1" in out
    assert "dry run: 4 match(es) in 3 file(s)" in out
    assert (log_tree / "app.log").read_text(encoding="utf-8") == original


def test_cli_redacts_with_allow_and_whitelist(log_tree, capsys):
    wl = log_tree / "allow.cfg"
    wl.write_text("2001:db8::/32\n", encoding="utf-8")
    code = main([str(log_tree), "--allow", "192.0.2.10", "--whitelist", str(wl), "-q"])
    assert code == 0
    assert "redacted: 2 match(es)" in capsys.readouterr().out
    text = (log_tree / "app.log").read_text(encoding="utf-8")
    assert "192.0.2.10" in text and "[REDACTED_EMAIL]" in text
    assert "2001:db8::7" in (log_tree / "nested" / "worker.txt").read_text(encoding="utf-8")


def test_cli_extension_options(log_tree, capsys):
    main([str(log_tree), "-n", "--ext", "ini"])
    assert "in 1 file(s)" in capsys.readouterr().out
    main([str(log_tree), "-n", "--all-files"])
    assert "in 4 file(s)" in capsys.readouterr().out


def test_cli_missing_target(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_missing_whitelist(log_tree, capsys):
    assert main([str(log_tree), "-w", str(log_tree / "none.txt")]) == 2
    assert "whitelist" in capsys.readouterr().err
