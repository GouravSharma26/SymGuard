"""
Tests for Finding data model, rule catalog, and schema integrity.
"""
from analyzer import Finding, RULE_CATALOG, VULN_TYPE_TO_RULE, severity_for

def test_rule_catalog_contains_expected_rules():
    expected_rules = ["SYM001", "SYM002", "SYM003", "SYM004", "SYM901"]
    for r in expected_rules:
        assert r in RULE_CATALOG
        assert "name" in RULE_CATALOG[r]
        assert "short_description" in RULE_CATALOG[r]
        assert "default_severity" in RULE_CATALOG[r]


def test_finding_initialization_defaults():
    f = Finding(
        vuln_type="OS Command Injection",
        location="module:line 10",
        sink="os.system(...)",
        tainted_source="stdin (input())",
        path_constraints_desc="(no branch conditions)",
        verdict="VULNERABLE (proven reachable by Z3)",
        line=10,
        severity="high",
    )
    assert f.rule_id == "SYM001"
    assert f.rule_name == "OS Command Injection"
    assert f.line == 10
    assert f.severity == "high"


def test_severity_mapping():
    assert severity_for("VULNERABLE (proven reachable by Z3)") == "high"
    assert severity_for("SAFE (Z3 proved infeasible)") == "safe"
    assert severity_for("NOTE: bounded unroll") == "info"
    assert severity_for("UNKNOWN (timeout)") == "unknown"
