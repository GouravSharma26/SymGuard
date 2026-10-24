"""
Tests for structured JSON report generation and schema stability.
"""
import json
from analyzer import Analyzer, findings_to_json

def test_json_output_schema_and_fields():
    code = """
import os
cmd = input()
os.system(cmd)
"""
    analyzer = Analyzer("test_sample.py")
    findings = analyzer.analyze_source(code)
    report = findings_to_json("test_sample.py", findings)

    # Validate top-level schema
    assert report["schema_version"] == "1.1"
    assert report["tool"] == "SymGuard"
    assert "test_sample.py" in report["target"]
    assert "generated_at" in report
    assert "summary" in report
    assert report["summary"]["vulnerable"] == 1
    assert report["summary"]["safe"] == 0

    # Validate findings list
    assert len(report["findings"]) == 1
    f = report["findings"][0]

    # Required backwards-compatible fields
    assert f["vuln_type"] == "OS Command Injection"
    assert "line 4" in f["location"]
    assert f["line"] == 4
    assert f["sink"] == "os.system(...)"
    assert "input()" in f["tainted_source"]
    assert "path_condition" in f
    assert "VULNERABLE" in f["verdict"]
    assert f["severity"] == "high"
    assert "z3_counterexample" in f

    # Enhanced fields
    assert f["rule_id"] == "SYM001"
    assert f["rule_name"] == "OS Command Injection"
    assert f["column"] is not None
    assert "message" in f

    # Verify JSON serializability
    dumped = json.dumps(report)
    loaded = json.loads(dumped)
    assert loaded["schema_version"] == "1.1"
