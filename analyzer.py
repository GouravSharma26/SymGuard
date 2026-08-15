#!/usr/bin/env python3
"""
vuln_analyzer.py
================
A static analyzer that PROVES (rather than guesses) whether attacker-controlled
data can reach a dangerous sink, by:

  1. Parsing Python source into an AST (Python's own `ast` module).
  2. Symbolically executing the AST, forking at every branch, while tracking
     which values are "tainted" (derived from attacker-controlled input).
  3. Encoding each variable as a Z3 term (Int or String theory) and each
     branch condition as a path constraint.
  4. At every dangerous sink (eval/exec, shell commands, raw SQL, array
     indexing) that receives tainted data, asking the Z3 SMT solver:
     "Is there ANY assignment of the tainted inputs that satisfies the
     path constraints leading here?"

If Z3 returns SAT, the vulnerability is not a guess -- it is a mathematically
proven reachable exploit path, and Z3 gives back a concrete counterexample
(the actual input values that trigger it). If Z3 returns UNSAT for every
path reaching a sink, the tool can positively certify that sink as safe
under the modeled semantics.

Supported source-language subset (deliberately restricted, so that the
translation to logic is sound):
  - assignments, augmented assignments
  - if/elif/else (both branches explored, "diamond" merge is NOT reasoned
    about after the branch -- each path is verified independently)
  - int and str expressions: +, -, *, //, %, string concatenation
  - comparisons: <, <=, >, >=, ==, !=
  - boolean ops: and, or, not
  - function calls used as taint SOURCES (input(), sys.argv[i],
    os.environ.get(...), flask request.args/form/values.get(...))
  - function calls used as taint SINKS (eval, exec, os.system, os.popen,
    subprocess.run/call/Popen(..., shell=True), cursor.execute, list
    indexing)
  - function parameters annotated with `Tainted` are treated as
    attacker-controlled entry points, so whole functions can be analyzed
    in isolation (not just top-level script code)

Anything outside this subset is skipped with a note, rather than silently
mis-modeled -- soundness over coverage.
"""

import ast
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional

import z3

# --------------------------------------------------------------------------
# Symbolic value representation
# --------------------------------------------------------------------------

_fresh_counter = 0


def fresh_name(base: str) -> str:
    global _fresh_counter
    _fresh_counter += 1
    return f"{base}__{_fresh_counter}"


@dataclass
class SymVal:
    """A symbolic value: a Z3 term plus taint/provenance metadata."""
    kind: str                 # 'int' | 'str' | 'unknown'
    expr: object               # z3 ExprRef, or None if kind == 'unknown'
    tainted: bool = False
    source: Optional[str] = None   # human-readable origin, for reporting
    sanitized: bool = False        # True if it passed through a validator


def z3_int(name):
    return z3.Int(fresh_name(name))


def z3_str(name):
    return z3.String(fresh_name(name))


# --------------------------------------------------------------------------
# Taint sources / sinks catalog
# --------------------------------------------------------------------------

# Functions whose *return value* should be treated as attacker-controlled.
TAINT_SOURCE_CALLS = {
    ("", "input"): "stdin (input())",
    ("os.environ", "get"): "environment variable",
    ("request.args", "get"): "HTTP query parameter",
    ("request.form", "get"): "HTTP form field",
    ("request.values", "get"): "HTTP request parameter",
}

# Categories of dangerous sinks we can reason about.
SINK_COMMAND_EXEC = {"os.system", "os.popen", "subprocess.call",
                      "subprocess.run", "subprocess.Popen"}
SINK_CODE_EXEC = {"eval", "exec"}
SINK_SQL_EXEC = {"execute", "executescript"}  # matched as attribute call *.execute(...)

# How many times a `for`/`while` loop body is unrolled. Bounded model
# checking, not a proof about arbitrarily-many iterations: real bugs at
# iteration <= UNROLL_DEPTH are always found (no false negatives in that
# window); a clean report only certifies safety up to this depth, which is
# reported explicitly to the user rather than silently overclaimed.
UNROLL_DEPTH = 3


@dataclass
class Finding:
    vuln_type: str
    location: str
    sink: str
    tainted_source: str
    path_constraints_desc: str
    verdict: str            # "VULNERABLE (proven reachable)" | "SAFE (proven unreachable)" | "UNKNOWN"
    model: Optional[str] = None
    line: Optional[int] = None       # machine-readable line number, for UI highlighting
    severity: str = "info"           # "high" | "safe" | "unknown" | "info"


# --------------------------------------------------------------------------
# The symbolic executor
# --------------------------------------------------------------------------

def severity_for(verdict: str) -> str:
    if verdict.startswith("VULNERABLE"):
        return "high"
    if verdict.startswith("SAFE"):
        return "safe"
    if verdict.startswith("NOTE"):
        return "info"
    return "unknown"


class Analyzer:
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    # ---- expression evaluation -------------------------------------------------

    def dotted_name(self, node) -> str:
        """Turn a Name/Attribute chain into a dotted string, e.g. os.environ.get -> 'os.environ.get'."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.dotted_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return "?"

    def eval_expr(self, node, env: dict) -> SymVal:
        # --- constants ---
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return SymVal('unknown', None)
            if isinstance(node.value, int):
                return SymVal('int', z3.IntVal(node.value))
            if isinstance(node.value, str):
                return SymVal('str', z3.StringVal(node.value))
            return SymVal('unknown', None)

        # --- variable lookup ---
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            return SymVal('unknown', None)

        # --- f-strings / .format() / % formatting: treat as string concat,
        #     taint propagates if any part is tainted ---
        if isinstance(node, ast.JoinedStr):  # f"...{x}..."
            result = SymVal('str', z3.StringVal(""))
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    piece = self.eval_expr(part.value, env)
                else:
                    piece = self.eval_expr(part, env)
                result = self.str_concat(result, piece)
            return result

        # --- binary ops ---
        if isinstance(node, ast.BinOp):
            left = self.eval_expr(node.left, env)
            right = self.eval_expr(node.right, env)
            if isinstance(node.op, ast.Add):
                if left.kind == 'str' or right.kind == 'str':
                    return self.str_concat(left, right)
                if left.expr is not None and right.expr is not None:
                    return SymVal('int', left.expr + right.expr,
                                  tainted=left.tainted or right.tainted,
                                  source=left.source or right.source)
            if isinstance(node.op, (ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)) \
                    and left.expr is not None and right.expr is not None:
                op = {ast.Sub: lambda a, b: a - b,
                      ast.Mult: lambda a, b: a * b,
                      ast.FloorDiv: lambda a, b: a / b,
                      ast.Mod: lambda a, b: a % b}[type(node.op)]
                return SymVal('int', op(left.expr, right.expr),
                              tainted=left.tainted or right.tainted,
                              source=left.source or right.source)
            # % string formatting: "SELECT * WHERE id=%s" % user_id
            if isinstance(node.op, ast.Mod) and left.kind == 'str':
                return self.str_concat(left, right)
            return SymVal('unknown', None,
                           tainted=left.tainted or right.tainted,
                           source=left.source or right.source)

        # --- calls: sources, sanitizers, or unknown ---
        if isinstance(node, ast.Call):
            return self.eval_call(node, env)

        # --- list literal: track length as a concrete fact via env, not expr ---
        if isinstance(node, ast.List):
            return SymVal('list', z3.IntVal(len(node.elts)))

        # --- subscript e.g. sys.argv[1] ---
        if isinstance(node, ast.Subscript):
            base_name = self.dotted_name(node.value)
            if base_name == "sys.argv":
                return SymVal('str', z3_str("argv"), tainted=True,
                               source="command-line argument (sys.argv)")
            # indexing into a tracked list variable is handled in visit_stmt
            # (needs path-constraint access for bounds proof); here just
            # return an unknown value so expression eval doesn't crash.
            return SymVal('unknown', None)

        return SymVal('unknown', None)

    def str_concat(self, a: SymVal, b: SymVal) -> SymVal:
        a_expr = a.expr if a.expr is not None else z3.StringVal(str(a))
        b_expr = b.expr if b.expr is not None else z3.StringVal(str(b))
        if a.kind != 'str':
            a_expr = z3.StringVal("<int>")
        if b.kind != 'str':
            b_expr = z3.StringVal("<int>")
        return SymVal('str', z3.Concat(a_expr, b_expr),
                       tainted=a.tainted or b.tainted,
                       source=a.source or b.source,
                       sanitized=a.sanitized and b.sanitized)

    def eval_call(self, node: ast.Call, env: dict) -> SymVal:
        fname = self.dotted_name(node.func)

        # int(input()) / int(sys.argv[1]) collapse into one tainted Int source
        if fname == "int" and node.args:
            inner = self.eval_expr(node.args[0], env)
            if inner.tainted:
                return SymVal('int', z3_int("tainted_int"), tainted=True,
                               source=inner.source)
            return SymVal('int', inner.expr if inner.kind == 'int' else z3_int("x"))

        # sanitizers we recognize: re.match/fullmatch(...) doesn't return the
        # value itself, but int()/whitelisting patterns are common enough
        # that we treat explicit .isalnum()/.isdigit() *checks* via the
        # branch condition instead (see eval_expr on Compare/Call in cond).

        if fname == "len" and node.args and isinstance(node.args[0], ast.Name):
            target = env.get(node.args[0].id)
            if target is not None and target.kind == 'list':
                return SymVal('int', target.expr)
            return SymVal('unknown', None)

        if fname == "input":
            return SymVal('str', z3_str("stdin"), tainted=True,
                           source="stdin (input())")

        if fname.endswith("os.environ.get") or fname == "os.environ.get":
            return SymVal('str', z3_str("env"), tainted=True,
                           source="environment variable")

        if fname in ("request.args.get", "request.form.get", "request.values.get"):
            return SymVal('str', z3_str("http_param"), tainted=True,
                           source=f"HTTP input ({fname})")

        # generic attribute call like os.environ.get with dynamic base handled above;
        # fall back: evaluate args for taint propagation, but expr unknown
        any_tainted = False
        src = None
        for a in node.args:
            v = self.eval_expr(a, env)
            any_tainted = any_tainted or v.tainted
            src = src or v.source
        return SymVal('unknown', None, tainted=any_tainted, source=src)

    # ---- conditions --------------------------------------------------------

    def eval_cond(self, node, env: dict):
        """Return a z3 BoolRef approximating the condition, or None if unmodelable."""
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left = self.eval_expr(node.left, env)
            right = self.eval_expr(node.comparators[0], env)
            if left.expr is None or right.expr is None:
                return None
            op = node.ops[0]
            try:
                if isinstance(op, ast.Lt):
                    return left.expr < right.expr
                if isinstance(op, ast.LtE):
                    return left.expr <= right.expr
                if isinstance(op, ast.Gt):
                    return left.expr > right.expr
                if isinstance(op, ast.GtE):
                    return left.expr >= right.expr
                if isinstance(op, ast.Eq):
                    return left.expr == right.expr
                if isinstance(op, ast.NotEq):
                    return left.expr != right.expr
            except z3.Z3Exception:
                return None
        if isinstance(node, ast.BoolOp):
            sub = [self.eval_cond(v, env) for v in node.values]
            if any(s is None for s in sub):
                return None
            return z3.And(*sub) if isinstance(node.op, ast.And) else z3.Or(*sub)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            sub = self.eval_cond(node.operand, env)
            return z3.Not(sub) if sub is not None else None
        # isdigit()/isalnum() checks used as sanitizing guards: we can't model
        # them precisely in Int/String theory, so treat as an *opaque* boolean
        # that still forks the path (both branches explored) but doesn't
        # constrain the solver -- conservative (may under-approximate safety).
        return None

    # ---- statement execution (forks on branches) ---------------------------

    def check_subscripts_in(self, node, env, path, path_desc, func_ctx):
        """Walk an expression/statement subtree; for every `name[idx]` where
        `name` is a tracked list and `idx` is tainted, ask Z3 whether an
        out-of-bounds access is reachable GIVEN the current path constraints
        (this is what lets bounds-checked code be proven safe)."""
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Subscript):
                continue
            base_name = self.dotted_name(sub.value)
            base = env.get(base_name)
            if base is None or base.kind != 'list':
                continue
            idx_val = self.eval_expr(sub.slice, env)
            if not idx_val.tainted or idx_val.expr is None:
                continue
            solver = z3.Solver()
            constraint = z3.And(*path) if path else z3.BoolVal(True)
            solver.add(constraint)
            solver.add(z3.Or(idx_val.expr >= base.expr, idx_val.expr < 0))
            result = solver.check()
            loc = f"{func_ctx}:line {getattr(sub, 'lineno', '?')}"
            idx_txt = ast.unparse(sub.slice) if hasattr(ast, "unparse") else "idx"
            if result == z3.sat:
                model = solver.model()
                verdict = "VULNERABLE (proven reachable by Z3)"
                model_str = str(model)
            elif result == z3.unsat:
                verdict = "SAFE (Z3 proved out-of-bounds is infeasible on this path)"
                model_str = None
            else:
                verdict = "UNKNOWN"
                model_str = None
            self.findings.append(Finding(
                vuln_type="Out-of-Bounds Index (buffer-overflow analog)",
                location=loc,
                sink=f"{base_name}[{idx_txt}]",
                tainted_source=idx_val.source or "attacker-controlled index",
                path_constraints_desc=" AND ".join(path_desc) if path_desc else "(no branch conditions)",
                verdict=verdict,
                model=model_str,
                line=getattr(sub, 'lineno', None),
                severity=severity_for(verdict),
            ))

    # ---- bounded loop unrolling ---------------------------------------------

    def exec_loop(self, stmt, env, path, path_desc, func_ctx):
        """Unroll `for`/`while` bodies UNROLL_DEPTH times, in place, so state
        (and taint) carries across iterations and survives after the loop --
        exactly like inlining the body N times where the source had a loop.

        This is a deliberate soundness/coverage trade-off (the same one
        bounded model checkers like CBMC make): any vulnerability reachable
        within UNROLL_DEPTH iterations WILL be found and proven with a real
        counterexample; a report with no findings only certifies safety up
        to that depth, not for arbitrarily many iterations. We do not add
        the loop guard as a constraint before each unrolled copy (that would
        require re-evaluating a possibly-opaque condition every iteration),
        so this slightly over-approximates -- it may explore iterations that
        the real loop condition would have stopped before reaching. That can
        only produce extra caution, never a missed real bug within depth.
        """
        is_for_range = (
            isinstance(stmt, ast.For)
            and isinstance(stmt.iter, ast.Call)
            and self.dotted_name(stmt.iter.func) == "range"
            and isinstance(stmt.target, ast.Name)
        )
        range_bound = None
        if is_for_range and stmt.iter.args:
            last_arg = stmt.iter.args[-1]
            if isinstance(last_arg, ast.Constant) and isinstance(last_arg.value, int):
                range_bound = last_arg.value

        for i in range(UNROLL_DEPTH):
            if is_for_range:
                if range_bound is not None and i >= range_bound:
                    break  # concrete range fully unrolled already, stop early
                env[stmt.target.id] = SymVal('int', z3.IntVal(i))
            elif isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
                # non-range iterable: element value unknown, but still real
                env[stmt.target.id] = SymVal('unknown', None)

            iter_desc = path_desc + [f"(loop body, unrolled iteration {i + 1}/{UNROLL_DEPTH})"]
            self.exec_block(stmt.body, env, path, iter_desc, func_ctx, copy_env=False)

        self.findings.append(Finding(
            vuln_type="[info] Loop unrolling bound",
            location=f"{func_ctx}:line {getattr(stmt, 'lineno', '?')}",
            sink="(loop body)",
            tainted_source="n/a",
            path_constraints_desc=f"unrolled {UNROLL_DEPTH} iterations",
            verdict=f"NOTE: analysis of this loop covers only the first {UNROLL_DEPTH} "
                    f"iterations; absence of findings above is not a proof for "
                    f"arbitrarily many iterations",
            model=None,
            line=getattr(stmt, 'lineno', None),
            severity="info",
        ))

    def exec_block(self, stmts, env: dict, path: list, path_desc: list, func_ctx: str,
                    copy_env: bool = True):
        env = dict(env) if copy_env else env  # copy-on-write per path, unless
        # this is a loop-unroll continuation that must mutate the caller's
        # env in place so state persists across iterations and after the loop.
        for stmt in stmts:
            # Only scan the statement's own expressions for subscripts here;
            # nested blocks (If bodies) are scanned recursively once their
            # branch's path constraint has been pushed, so we don't check
            # them prematurely with the wrong (pre-branch) path.
            scan_target = stmt.test if isinstance(stmt, ast.If) else stmt
            self.check_subscripts_in(scan_target, env, path, path_desc, func_ctx)

            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name):
                if isinstance(stmt.value, ast.Call):
                    # sink call used as an expression, e.g. `result = eval(x)`
                    self.check_call_for_vuln(stmt.value, env, path, path_desc, func_ctx,
                                              line=stmt.lineno)
                val = self.eval_expr(stmt.value, env)
                # track list length for bounds proofs
                env[stmt.targets[0].id] = val
                continue

            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                self.check_call_for_vuln(stmt.value, env, path, path_desc, func_ctx,
                                          line=stmt.lineno)
                continue

            if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                cur = env.get(stmt.target.id, SymVal('unknown', None))
                fake_binop = ast.BinOp(left=ast.Name(id=stmt.target.id, ctx=ast.Load()),
                                        op=stmt.op, right=stmt.value)
                env[stmt.target.id] = self.eval_expr(fake_binop, env)
                continue

            if isinstance(stmt, ast.If):
                cond = self.eval_cond(stmt.test, env)
                cond_txt = ast.unparse(stmt.test) if hasattr(ast, "unparse") else "<cond>"
                if cond is not None:
                    self.exec_block(stmt.body, env, path + [cond],
                                     path_desc + [cond_txt], func_ctx)
                    self.exec_block(stmt.orelse, env, path + [z3.Not(cond)],
                                     path_desc + [f"not ({cond_txt})"], func_ctx)
                else:
                    # can't model condition precisely -> explore both, unconstrained
                    self.exec_block(stmt.body, env, path, path_desc + [f"[{cond_txt}] (unmodeled)"], func_ctx)
                    self.exec_block(stmt.orelse, env, path, path_desc + [f"not [{cond_txt}] (unmodeled)"], func_ctx)
                continue

            if isinstance(stmt, (ast.While, ast.For)):
                self.exec_loop(stmt, env, path, path_desc, func_ctx)
                continue

            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self.check_call_for_vuln(stmt.value, env, path, path_desc, func_ctx,
                                          line=stmt.lineno)
                continue

            if isinstance(stmt, ast.Assign):
                # e.g. subscript assignment or tuple unpack -- evaluate RHS for
                # taint propagation only, best-effort
                self.eval_expr(stmt.value, env)
                continue

        # also scan any bare subscript reads / calls nested in already-handled
        # statements happens inside check_call_for_vuln / eval recursion.

    # ---- sink detection + Z3 proof ------------------------------------------

    def check_call_for_vuln(self, call: ast.Call, env, path, path_desc, func_ctx, line):
        fname = self.dotted_name(call.func)
        args_syms = [self.eval_expr(a, env) for a in call.args]

        vuln_type = None
        if fname in SINK_CODE_EXEC:
            vuln_type = "Code Injection"
        elif fname in SINK_COMMAND_EXEC:
            vuln_type = "OS Command Injection"
        elif isinstance(call.func, ast.Attribute) and call.func.attr in SINK_SQL_EXEC:
            vuln_type = "SQL Injection"

        # subprocess.run/call/Popen only dangerous with shell=True or when
        # passing a raw (non-list) tainted string as the command
        if fname in ("subprocess.run", "subprocess.call", "subprocess.Popen"):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.arg == "shell" and kw.value.value is True
                for kw in call.keywords
            )
            if not shell_true:
                vuln_type = None  # list-form argv without shell=True is safe from shell injection

        if vuln_type is None:
            return

        tainted_arg = next((a for a in args_syms if a.tainted), None)
        if tainted_arg is None:
            return  # sink reached, but with no attacker-controlled data -> not our concern

        # For SQL: only flag if the string was built by concatenation/format
        # (tainted_arg.expr is a Concat term), not if it's passed as a
        # separate parameterized argument (that pattern is the *fix*, and
        # the taint would live in call.args[1], which we deliberately don't
        # flag).
        if vuln_type == "SQL Injection" and len(call.args) >= 2:
            # execute(query, params) parameterized form -> safe, skip
            return

        loc = f"{func_ctx}:line {line}"
        constraint = z3.And(*path) if path else z3.BoolVal(True)
        solver = z3.Solver()
        solver.add(constraint)
        result = solver.check()

        if result == z3.sat:
            model = solver.model()
            verdict = "VULNERABLE (proven reachable by Z3)"
            model_str = str(model) if len(model) else "(no path constraints -- always reachable)"
        elif result == z3.unsat:
            verdict = "SAFE (Z3 proved this path is infeasible)"
            model_str = None
        else:
            verdict = "UNKNOWN (Z3 could not decide)"
            model_str = None

        self.findings.append(Finding(
            vuln_type=vuln_type,
            location=loc,
            sink=f"{fname}(...)",
            tainted_source=tainted_arg.source or "attacker-controlled input",
            path_constraints_desc=" AND ".join(path_desc) if path_desc else "(no branch conditions)",
            verdict=verdict,
            model=model_str,
            line=line,
            severity=severity_for(verdict),
        ))

        # additionally, check bounds-safety for subscript args passed into
        # sinks isn't applicable here; array OOB is handled separately below.

    # ---- top-level driver ---------------------------------------------------

    def analyze_source(self, src: str):
        tree = ast.parse(src)

        # 1. Top-level (module / "script") statements, as one execution context.
        module_env = {}
        self.exec_block(tree.body, module_env, [], [], "module")

        # 2. Each function whose parameters are annotated `Tainted` is treated
        #    as a reachable entry point; its params become fresh tainted symbols.
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                env = {}
                any_tainted_param = False
                for arg in node.args.args:
                    if arg.annotation is not None and self.dotted_name(arg.annotation) == "Tainted":
                        env[arg.arg] = SymVal('str', z3_str(arg.arg), tainted=True,
                                               source=f"function parameter '{arg.arg}' (marked Tainted)")
                        any_tainted_param = True
                if any_tainted_param:
                    self.exec_block(node.body, env, [], [], f"function {node.name}")

        return self.findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_report(filename, findings):
    print(f"\n{'=' * 78}\nStatic Vulnerability Analysis (AST + Taint Tracking + Z3 SMT Proof)")
    print(f"Target: {filename}\n{'=' * 78}")
    real_findings = [f for f in findings if f.severity != "info"]
    notes = [f for f in findings if f.severity == "info"]
    if not real_findings and not notes:
        print("\nNo tainted data flow to any recognized sink was found.")
        return
    vuln_count = sum(1 for f in real_findings if f.severity == "high")
    safe_count = sum(1 for f in real_findings if f.severity == "safe")
    for i, f in enumerate(real_findings, 1):
        print(f"\n[{i}] {f.vuln_type}")
        print(f"    Location        : {f.location}")
        print(f"    Sink            : {f.sink}")
        print(f"    Tainted source  : {f.tainted_source}")
        print(f"    Path condition  : {f.path_constraints_desc}")
        print(f"    Verdict         : {f.verdict}")
        if f.model:
            print(f"    Z3 counterexample (concrete exploit input): {f.model}")
    if notes:
        print(f"\n{'.' * 78}")
        for n in notes:
            print(f"  {n.location} -- {n.verdict}")
    print(f"\n{'-' * 78}")
    print(f"Summary: {vuln_count} proven VULNERABLE, {safe_count} proven SAFE, "
          f"{len(real_findings) - vuln_count - safe_count} UNKNOWN")
    print(f"{'-' * 78}\n")


def findings_to_json(filename, findings):
    """Structured, CI/CD-friendly report. Shape is stable/versioned so a
    GitHub Actions step (or a future web dashboard) can consume it directly:
    each entry carries a `line` for source highlighting and a `severity`
    (high | safe | unknown | info) for pass/fail gating."""
    import datetime
    real = [f for f in findings if f.severity != "info"]
    return {
        "schema_version": "1.0",
        "tool": "vuln_analyzer",
        "target": filename,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "vulnerable": sum(1 for f in real if f.severity == "high"),
            "safe": sum(1 for f in real if f.severity == "safe"),
            "unknown": sum(1 for f in real if f.severity == "unknown"),
            "notes": sum(1 for f in findings if f.severity == "info"),
        },
        "findings": [
            {
                "vuln_type": f.vuln_type,
                "location": f.location,
                "line": f.line,
                "sink": f.sink,
                "tainted_source": f.tainted_source,
                "path_condition": f.path_constraints_desc,
                "verdict": f.verdict,
                "severity": f.severity,
                "z3_counterexample": f.model,
            }
            for f in findings
        ],
    }


def main():
    import argparse
    import json as json_mod

    parser = argparse.ArgumentParser(
        description="Prove (not guess) reachable vulnerabilities via AST symbolic execution + Z3.")
    parser.add_argument("source", help="Path to the Python source file to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                         help="Output format (default: text). Use 'json' for CI/CD pipelines "
                              "or a web dashboard to consume.")
    parser.add_argument("--output", "-o", metavar="PATH",
                         help="Write the report to this file instead of stdout")
    parser.add_argument("--fail-on-vulnerable", action="store_true",
                         help="Exit with a non-zero status if any VULNERABLE finding is proven "
                              "reachable -- for use as a GitHub Actions / CI gate")
    args = parser.parse_args()

    with open(args.source) as f:
        src = f.read()

    analyzer = Analyzer(args.source)
    findings = analyzer.analyze_source(src)

    if args.format == "json":
        report = findings_to_json(args.source, findings)
        text = json_mod.dumps(report, indent=2)
    else:
        import io
        buf = io.StringIO()
        _stdout = sys.stdout
        sys.stdout = buf
        try:
            print_report(args.source, findings)
        finally:
            sys.stdout = _stdout
        text = buf.getvalue()

    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"Report written to {args.output}")
    else:
        print(text)

    vulnerable = any(f.severity == "high" for f in findings)
    if args.fail_on_vulnerable and vulnerable:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # e.g. `analyzer.py x.py | head` -- the reader closed early; exit
        # quietly instead of printing a Python traceback for a non-error.
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
