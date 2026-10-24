"""
Regression tests for all supported taint sources and sinks.
Ensures tainted data reaching sinks is proven reachable (or safe),
and untainted data is never falsely flagged.
"""

def test_source_input_reaches_os_system(analyze_snippet):
    code = """
import os
cmd = input()
os.system(cmd)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM001"
    assert vuln[0].vuln_type == "OS Command Injection"
    assert "input()" in vuln[0].tainted_source
    assert vuln[0].sink == "os.system(...)"
    assert vuln[0].line == 4


def test_source_sys_argv_reaches_eval(analyze_snippet):
    code = """
import sys
code_to_run = sys.argv[1]
eval(code_to_run)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM002"
    assert vuln[0].vuln_type == "Code Injection"
    assert "sys.argv" in vuln[0].tainted_source
    assert vuln[0].line == 4


def test_source_environ_reaches_subprocess_shell_true(analyze_snippet):
    code = """
import os
import subprocess
val = os.environ.get("TARGET")
subprocess.run(val, shell=True)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM001"
    assert "environment variable" in vuln[0].tainted_source
    assert vuln[0].line == 5


def test_source_flask_request_args_reaches_sql(analyze_snippet):
    code = """
query = "SELECT * FROM users WHERE name = '" + request.args.get("name") + "'"
cursor.execute(query)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM003"
    assert vuln[0].vuln_type == "SQL Injection"
    assert "request.args.get" in vuln[0].tainted_source
    assert vuln[0].line == 3


def test_source_flask_request_form_reaches_exec(analyze_snippet):
    code = """
payload = request.form.get("script")
exec(payload)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM002"
    assert vuln[0].line == 3


def test_source_flask_request_values_reaches_os_popen(analyze_snippet):
    code = """
import os
target = request.values.get("ip")
os.popen("ping " + target)
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM001"
    assert vuln[0].line == 4


def test_source_tainted_annotation_function_entrypoint(analyze_snippet):
    code = """
def handler(user_id: Tainted):
    cursor.execute("DELETE FROM sessions WHERE uid = '" + user_id + "'")
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM003"
    assert "Tainted" in vuln[0].tainted_source
    assert vuln[0].line == 3


def test_source_int_input_reaches_out_of_bounds(analyze_snippet):
    code = """
items = [10, 20, 30]
idx = int(input())
val = items[idx]
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 1
    assert vuln[0].rule_id == "SYM004"
    assert vuln[0].vuln_type == "Out-of-Bounds Index (buffer-overflow analog)"
    assert vuln[0].line == 4


def test_untainted_data_at_sinks_is_safe(analyze_snippet):
    code = """
import os
import subprocess
safe_cmd = "echo hello"
os.system(safe_cmd)
subprocess.run(["ls", "-la"], shell=False)
eval("1 + 1")
items = [1, 2, 3]
first = items[0]
"""
    findings = analyze_snippet(code)
    vuln = [f for f in findings if f.severity == "high"]
    assert len(vuln) == 0
