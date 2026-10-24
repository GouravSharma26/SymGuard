"""
Tests for SARIF 2.1.0 output formatting, schema compliance, and policy.
"""
import json
from analyzer import Analyzer, findings_to_sarif

def test_sarif_output_structure():
    code = """
import os
cmd = input()
os.system(cmd)
"""
    analyzer = Analyzer("sample.py")
    findings = analyzer.analyze_source(code)
    sarif = findings_to_sarif("sample.py", findings)

    # Core SARIF 2.1.0 root properties
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "https://raw.githubusercontent.com/oasis-tcs/sarif-spec" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    # Tool driver metadata
    driver = run["tool"]["driver"]
    assert driver["name"] == "SymGuard"
    assert len(driver["rules"]) >= 4

    rule_ids = [r["id"] for r in driver["rules"]]
    assert "SYM001" in rule_ids
    assert "SYM002" in rule_ids
    assert "SYM003" in rule_ids
    assert "SYM004" in rule_ids

    # Results check
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "SYM001"
    assert res["level"] == "error"
    assert "locations" in res
    loc = res["locations"][0]["physicalLocation"]
    assert "sample.py" in loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] == 4
    assert loc["region"]["startColumn"] is not None

    # Properties
    assert "properties" in res
    assert "VULNERABLE" in res["properties"]["verdict"]
    assert res["properties"]["sink"] == "os.system(...)"


def test_sarif_safe_omitted_by_default_included_opt_in():
    code = """
items = [1, 2, 3]
idx = int(input())
if idx >= 0:
    if idx < len(items):
        val = items[idx]
"""
    analyzer = Analyzer("safe_sample.py")
    findings = analyzer.analyze_source(code)

    # Default: safe findings should NOT create alerts in SARIF
    sarif_default = findings_to_sarif("safe_sample.py", findings, include_safe=False)
    assert len(sarif_default["runs"][0]["results"]) == 0

    # Opt-in: include_safe=True will emit note-level results
    sarif_opt_in = findings_to_sarif("safe_sample.py", findings, include_safe=True)
    assert len(sarif_opt_in["runs"][0]["results"]) >= 1
    assert sarif_opt_in["runs"][0]["results"][0]["level"] == "note"


def test_sarif_empty_findings_produces_valid_structure():
    sarif = findings_to_sarif("empty.py", [])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []
