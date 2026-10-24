"""
Tests for bounded loop unrolling behavior in SymGuard.
"""
from analyzer import UNROLL_DEPTH

def test_vulnerability_inside_loop_detected(analyze_snippet):
    code = """
import os
for i in range(2):
    cmd = input()
    os.system(cmd)
"""
    findings = analyze_snippet(code)
    vulns = [f for f in findings if f.severity == "high"]
    assert len(vulns) >= 1
    for v in vulns:
        assert v.rule_id == "SYM001"
        assert v.sink == "os.system(...)"


def test_loop_generates_bounded_analysis_note(analyze_snippet):
    code = """
for i in range(5):
    x = 1
"""
    findings = analyze_snippet(code)
    notes = [f for f in findings if f.severity == "info"]
    assert len(notes) == 1
    assert notes[0].rule_id == "SYM901"
    assert f"{UNROLL_DEPTH} iterations" in notes[0].path_constraints_desc
    assert "NOTE:" in notes[0].verdict


def test_loop_bounds_safe_inside_iterations(analyze_snippet):
    code = """
items = ["a", "b", "c", "d"]
idx = int(input())
for i in range(2):
    if idx >= 0:
        if idx < len(items):
            val = items[idx]
"""
    findings = analyze_snippet(code)
    vulns = [f for f in findings if f.severity == "high"]
    safes = [f for f in findings if f.severity == "safe"]
    assert len(vulns) == 0
    assert len(safes) >= 1
