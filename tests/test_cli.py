"""
Tests for CLI interface, arguments, outputs, and exit codes.
"""
import os
import sys
import tempfile
import pytest
from analyzer import main

def test_cli_missing_file(capsys):
    rc = main(["non_existent_file_xyz.py"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err


def test_cli_syntax_error(tmp_path, capsys):
    bad_syntax_file = tmp_path / "bad.py"
    bad_syntax_file.write_text("def invalid syntax here !@@#")
    rc = main([str(bad_syntax_file)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "Syntax error" in captured.err


def test_cli_fail_on_vulnerable_flag(tmp_path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import os\ncmd = input()\nos.system(cmd)\n")
    # Without --fail-on-vulnerable: exit 0
    assert main([str(vuln_file)]) == 0
    # With --fail-on-vulnerable: exit 1
    assert main([str(vuln_file), "--fail-on-vulnerable"]) == 1


def test_cli_clean_file_fail_on_vulnerable(tmp_path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("x = 1 + 2\nprint(x)\n")
    assert main([str(safe_file), "--fail-on-vulnerable"]) == 0


def test_cli_output_file_argument(tmp_path):
    src_file = tmp_path / "src.py"
    src_file.write_text("import os\ncmd = input()\nos.system(cmd)\n")
    out_file = tmp_path / "findings.json"
    rc = main([str(src_file), "--format", "json", "--output", str(out_file)])
    assert rc == 0
    assert out_file.exists()
    content = out_file.read_text()
    assert '"schema_version": "1.1"' in content
    assert '"SYM001"' in content


def test_cli_format_sarif_argument(tmp_path):
    src_file = tmp_path / "src.py"
    src_file.write_text("import os\ncmd = input()\nos.system(cmd)\n")
    sarif_file = tmp_path / "findings.sarif"
    rc = main([str(src_file), "--format", "sarif", "--output", str(sarif_file)])
    assert rc == 0
    assert sarif_file.exists()
    content = sarif_file.read_text()
    assert '"version": "2.1.0"' in content
    assert '"SymGuard"' in content
