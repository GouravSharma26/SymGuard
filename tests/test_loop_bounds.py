"""
Tests for bounded loop unrolling behavior in SymGuard.
Ensures loop-bound notes are reported separately from definitive results,
and that bounded results are never presented as proofs of unbounded safety.
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


def test_deep_loop_reports_bound_note_not_misleading_definitive_safety(analyze_snippet):
    """
    Ensure a loop where a dangerous sink is guarded by iteration count beyond UNROLL_DEPTH
    produces explicit bounded notes and does not present the program as definitively proven safe.
    """
    code = """
import os
for i in range(20):
    if i == 12:
        cmd = input()
        os.system(cmd)
"""
    findings = analyze_snippet(code)
    notes = [f for f in findings if f.severity == "info" and f.rule_id == "SYM901"]
    assert len(notes) >= 1
    # Bound note explicitly warns that absence of findings is not an unbounded proof
    assert f"first {UNROLL_DEPTH} iterations" in notes[0].verdict
    assert "not a proof for arbitrarily many iterations" in notes[0].verdict

    # Check path condition descriptors on any unrolled path
    for f in findings:
        if f.severity == "safe":
            assert "unrolled iteration" in f.path_constraints_desc


def test_unmodeled_condition_explored_conservatively(analyze_snippet):
    """
    Conditions that cannot be modeled in Z3 theory (e.g. unknown external checks)
    must fork paths with an explicit unmodeled descriptor rather than silently assuming safety.
    """
    code = """
import os
cmd = input()
if unknown_validator(cmd):
    os.system(cmd)
else:
    os.system(cmd)
"""
    findings = analyze_snippet(code)
    # Both paths should be explored conservatively
    vulns = [f for f in findings if f.severity == "high"]
    assert len(vulns) >= 1
    # Check that unmodeled annotation is preserved in path description
    has_unmodeled_desc = any("unmodeled" in f.path_constraints_desc for f in vulns)
    assert has_unmodeled_desc
