"""
Tests for path constraint reasoning with Z3:
- Distinguishing safe vs vulnerable branches
- Infeasible paths proven SAFE via UNSAT
- Restrictive-looking guards that fail to protect the sink
- Parameterized SQL handling
- Safe subprocess list invocation
"""

def test_proper_bounds_guard_proves_safe(analyze_snippet):
    code = """
items = [1, 2, 3, 4]
idx = int(input())
if idx >= 0:
    if idx < len(items):
        val = items[idx]
"""
    findings = analyze_snippet(code)
    # The guarded access must be proven SAFE
    safe_findings = [f for f in findings if f.severity == "safe"]
    vuln_findings = [f for f in findings if f.severity == "high"]
    assert len(vuln_findings) == 0
    assert len(safe_findings) >= 1
    assert safe_findings[0].rule_id == "SYM004"
    assert "SAFE" in safe_findings[0].verdict


def test_infeasible_branch_cannot_reach_sink(analyze_snippet):
    code = """
import os
x = int(input())
if x > 10:
    if x < 5:
        os.system("echo unreachable")
"""
    # Untainted string "echo unreachable" reaches os.system, or even if tainted string:
    # Let's test with tainted argument:
    code_tainted = """
import os
x = int(input())
cmd = input()
if x > 10:
    if x < 5:
        os.system(cmd)
"""
    findings = analyze_snippet(code_tainted)
    vuln_findings = [f for f in findings if f.severity == "high"]
    safe_findings = [f for f in findings if f.severity == "safe"]
    assert len(vuln_findings) == 0
    assert len(safe_findings) == 1
    assert "SAFE" in safe_findings[0].verdict


def test_restrictive_looking_guard_still_vulnerable(analyze_snippet):
    code = """
import os
user_input = input()
if user_input == "admin":
    os.system(user_input)
else:
    os.system(user_input)
"""
    findings = analyze_snippet(code)
    vuln_findings = [f for f in findings if f.severity == "high"]
    # Both paths are reachable with specific inputs ("admin" on true path, anything else on false path)
    assert len(vuln_findings) == 2
    for f in vuln_findings:
        assert f.rule_id == "SYM001"
        assert "VULNERABLE" in f.verdict
        assert f.model is not None


def test_parameterized_sql_is_not_flagged(analyze_snippet):
    code = """
user_id = input()
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 0


def test_subprocess_list_without_shell_is_safe(analyze_snippet):
    code = """
import subprocess
arg = input()
subprocess.run(["ping", "-c", "1", arg])
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 0
