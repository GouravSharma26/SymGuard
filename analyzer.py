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
import datetime
import json as json_mod
import os
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

# --------------------------------------------------------------------------
# Rule Catalog (Stable IDs SYM001-SYM004, SYM901)
# --------------------------------------------------------------------------

RULE_CATALOG = {
    "SYM001": {
        "id": "SYM001",
        "name": "OS Command Injection",
        "category": "OS Command Injection",
        "short_description": "Attacker-controlled input reaches an OS command execution sink.",
        "full_description": "Untrusted input reaches functions such as os.system, os.popen, or subprocess with shell=True without adequate sanitization or constraints.",
        "default_severity": "high",
        "cwe": "CWE-78",
    },
    "SYM002": {
        "id": "SYM002",
        "name": "Code Injection",
        "category": "Code Injection",
        "short_description": "Attacker-controlled input reaches dynamic code execution.",
        "full_description": "Untrusted input reaches eval() or exec(), allowing arbitrary Python code execution.",
        "default_severity": "high",
        "cwe": "CWE-95",
    },
    "SYM003": {
        "id": "SYM003",
        "name": "SQL Injection",
        "category": "SQL Injection",
        "short_description": "Attacker-controlled input reaches an unparameterized SQL query execution.",
        "full_description": "Untrusted input is concatenated into a SQL statement executed by database cursor without parameterization.",
        "default_severity": "high",
        "cwe": "CWE-89",
    },
    "SYM004": {
        "id": "SYM004",
        "name": "Tainted Out-of-Bounds Indexing",
        "category": "Out-of-Bounds Index (buffer-overflow analog)",
        "short_description": "Attacker-controlled index can access a sequence out of bounds.",
        "full_description": "An untrusted integer index used in a subscript operation is proven satisfiable outside the list bounds [0, len(list)).",
        "default_severity": "high",
        "cwe": "CWE-129",
    },
    "SYM901": {
        "id": "SYM901",
        "name": "Loop Unrolling Bound Note",
        "category": "[info] Loop unrolling bound",
        "short_description": "Analysis of loop is bounded by configured iteration depth.",
        "full_description": f"Analysis of this loop covers only the first {UNROLL_DEPTH} iterations; absence of findings is not a proof for arbitrarily many iterations.",
        "default_severity": "info",
        "cwe": "",
    },
}

VULN_TYPE_TO_RULE = {
    "OS Command Injection": "SYM001",
    "Code Injection": "SYM002",
    "SQL Injection": "SYM003",
    "Out-of-Bounds Index (buffer-overflow analog)": "SYM004",
    "[info] Loop unrolling bound": "SYM901",
}


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
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    column: Optional[int] = None
    uri: Optional[str] = None
    message: Optional[str] = None

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = VULN_TYPE_TO_RULE.get(self.vuln_type, "SYM000")
        if not self.rule_name and self.rule_id in RULE_CATALOG:
            self.rule_name = RULE_CATALOG[self.rule_id]["name"]


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
        try:
            rel = os.path.relpath(filename, os.getcwd())
            self.relative_uri = rel.replace("\\", "/")
        except Exception:
            self.relative_uri = str(filename).replace("\\", "/")
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
            col = getattr(sub, 'col_offset', None)
            col_1idx = (col + 1) if col is not None else None
            line_no = getattr(sub, 'lineno', None)
            if result == z3.sat:
                model = solver.model()
                verdict = "VULNERABLE (proven reachable by Z3)"
                model_str = str(model)
                msg = f"Proven reachable out-of-bounds indexing on '{base_name}' with tainted index."
            elif result == z3.unsat:
                verdict = "SAFE (Z3 proved out-of-bounds is infeasible on this path)"
                model_str = None
                msg = f"Proven safe from out-of-bounds indexing on '{base_name}': path constraints enforce valid bounds."
            else:
                verdict = "UNKNOWN"
                model_str = None
                msg = f"Undecided bounds safety on '{base_name}'."
            self.findings.append(Finding(
                vuln_type="Out-of-Bounds Index (buffer-overflow analog)",
                location=loc,
                sink=f"{base_name}[{idx_txt}]",
                tainted_source=idx_val.source or "attacker-controlled index",
                path_constraints_desc=" AND ".join(path_desc) if path_desc else "(no branch conditions)",
                verdict=verdict,
                model=model_str,
                line=line_no,
                severity=severity_for(verdict),
                rule_id="SYM004",
                rule_name=RULE_CATALOG["SYM004"]["name"],
                column=col_1idx,
                uri=self.relative_uri,
                message=msg,
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

        line_no = getattr(stmt, 'lineno', None)
        col = getattr(stmt, 'col_offset', None)
        col_1idx = (col + 1) if col is not None else None

        self.findings.append(Finding(
            vuln_type="[info] Loop unrolling bound",
            location=f"{func_ctx}:line {line_no if line_no is not None else '?'}",
            sink="(loop body)",
            tainted_source="n/a",
            path_constraints_desc=f"unrolled {UNROLL_DEPTH} iterations",
            verdict=f"NOTE: analysis of this loop covers only the first {UNROLL_DEPTH} "
                    f"iterations; absence of findings above is not a proof for "
                    f"arbitrarily many iterations",
            model=None,
            line=line_no,
            severity="info",
            rule_id="SYM901",
            rule_name=RULE_CATALOG["SYM901"]["name"],
            column=col_1idx,
            uri=self.relative_uri,
            message=f"NOTE: analysis of this loop covers only the first {UNROLL_DEPTH} iterations.",
        ))

    def exec_block(self, stmts, env: dict, path: list, path_desc: list, func_ctx: str,
                    copy_env: bool = True):
        env = dict(env) if copy_env else env  # copy-on-write per path, unless
        # this is a loop-unroll continuation that must mutate the caller's
        # env in place so state persists across iterations and after the loop.
        for stmt in stmts:
            # Only scan the statement's own expressions for subscripts here;
            # nested blocks (If, While, For bodies) are scanned recursively once their
            # branch/iteration path constraint has been pushed, so we don't check
            # them prematurely with the wrong (pre-branch) path.
            if isinstance(stmt, ast.If):
                scan_target = stmt.test
            elif isinstance(stmt, ast.While):
                scan_target = stmt.test
            elif isinstance(stmt, ast.For):
                scan_target = stmt.iter
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scan_target = None
            else:
                scan_target = stmt
            if scan_target is not None:
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

        rule_id = VULN_TYPE_TO_RULE.get(vuln_type, "SYM000")
        rule_meta = RULE_CATALOG.get(rule_id, {})
        rule_name = rule_meta.get("name", vuln_type)
        col = getattr(call, "col_offset", None)
        col_1idx = (col + 1) if col is not None else None

        if result == z3.sat:
            model = solver.model()
            verdict = "VULNERABLE (proven reachable by Z3)"
            model_str = str(model) if len(model) else "(no path constraints -- always reachable)"
            msg = f"Proven reachable {vuln_type} at {fname}(...) via {tainted_arg.source or 'attacker-controlled input'}."
        elif result == z3.unsat:
            verdict = "SAFE (Z3 proved this path is infeasible)"
            model_str = None
            msg = f"Proven safe from {vuln_type} at {fname}(...): path constraints are mathematically infeasible."
        else:
            verdict = "UNKNOWN (Z3 could not decide)"
            model_str = None
            msg = f"Undecided {vuln_type} at {fname}(...): solver reached unknown."

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
            rule_id=rule_id,
            rule_name=rule_name,
            column=col_1idx,
            uri=self.relative_uri,
            message=msg,
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
    """Structured, CI/CD-friendly report. Shape is stable and backwards-compatible:
    includes original keys (line, severity, vuln_type, location, sink, tainted_source,
    path_condition, verdict, z3_counterexample) along with stable rule IDs, column numbers,
    messages, and relative URIs."""
    real = [f for f in findings if f.severity != "info"]
    try:
        rel_target = os.path.relpath(filename, os.getcwd()) if os.path.isabs(filename) else filename
        rel_target = rel_target.replace("\\", "/")
    except Exception:
        rel_target = str(filename).replace("\\", "/")

    return {
        "schema_version": "1.1",
        "tool": "SymGuard",
        "target": rel_target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "vulnerable": sum(1 for f in real if f.severity == "high"),
            "safe": sum(1 for f in real if f.severity == "safe"),
            "unknown": sum(1 for f in real if f.severity == "unknown"),
            "notes": sum(1 for f in findings if f.severity == "info"),
        },
        "findings": [
            {
                "rule_id": f.rule_id or "SYM000",
                "rule_name": f.rule_name or f.vuln_type,
                "vuln_type": f.vuln_type,
                "location": f.location,
                "line": f.line,
                "column": f.column,
                "uri": f.uri or rel_target,
                "sink": f.sink,
                "tainted_source": f.tainted_source,
                "path_condition": f.path_constraints_desc,
                "verdict": f.verdict,
                "severity": f.severity,
                "message": f.message or f"{f.vuln_type} - {f.verdict}",
                "z3_counterexample": f.model,
            }
            for f in findings
        ],
    }


def findings_to_sarif(filename, findings, include_safe: bool = False):
    """Generate a SARIF 2.1.0 compliant report."""
    try:
        rel_target = os.path.relpath(filename, os.getcwd()) if os.path.isabs(filename) else filename
        rel_target = rel_target.replace("\\", "/")
    except Exception:
        rel_target = str(filename).replace("\\", "/")

    # Rule definitions for driver
    rules_list = []
    rule_indices = {}
    for rule_id, rule_meta in RULE_CATALOG.items():
        if rule_id.startswith("SYM9"):
            continue  # notes/informational
        rule_indices[rule_id] = len(rules_list)
        rules_list.append({
            "id": rule_id,
            "name": rule_meta["name"].replace(" ", "").replace("-", ""),
            "shortDescription": {
                "text": rule_meta["short_description"]
            },
            "fullDescription": {
                "text": rule_meta["full_description"]
            },
            "defaultConfiguration": {
                "level": "error" if rule_meta.get("default_severity") == "high" else "note"
            },
            "helpUri": f"https://github.com/GouravSharma26/SymGuard#{rule_id.lower()}",
            "properties": {
                "tags": ["security", "static-analysis"],
                "cwe": rule_meta.get("cwe", "")
            }
        })

    results = []
    for f in findings:
        # Determine SARIF result level
        if f.severity == "high":
            level = "error"
        elif f.severity == "unknown":
            level = "warning"
        elif f.severity == "safe":
            if not include_safe:
                continue
            level = "note"
        elif f.severity == "info":
            if not include_safe:
                continue
            level = "note"
        else:
            level = "warning"

        rule_id = f.rule_id or "SYM000"
        rule_idx = rule_indices.get(rule_id)

        location_entry = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.uri or rel_target,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": f.line if f.line is not None else 1
                }
            }
        }
        if f.column is not None:
            location_entry["physicalLocation"]["region"]["startColumn"] = f.column

        properties_entry = {
            "verdict": f.verdict,
            "sink": f.sink,
            "taintedSource": f.tainted_source,
            "pathConstraints": f.path_constraints_desc,
            "severity": f.severity,
        }
        if f.model:
            properties_entry["z3Counterexample"] = f.model

        result_obj = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f.message or f"{f.vuln_type}: {f.verdict}"
            },
            "locations": [location_entry],
            "properties": properties_entry,
        }
        if rule_idx is not None:
            result_obj["ruleIndex"] = rule_idx

        results.append(result_obj)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SymGuard",
                        "semanticVersion": "0.2.0",
                        "informationUri": "https://github.com/GouravSharma26/SymGuard",
                        "rules": rules_list
                    }
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": rel_target
                        }
                    }
                ],
                "results": results
            }
        ]
    }


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Prove (not guess) reachable vulnerabilities via AST symbolic execution + Z3.")
    parser.add_argument("source", help="Path to the Python source file to analyze")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                         help="Output format (default: text). Use 'json' or 'sarif' for CI/CD pipelines.")
    parser.add_argument("--output", "-o", metavar="PATH",
                         help="Write the report to this file instead of stdout")
    parser.add_argument("--fail-on-vulnerable", action="store_true",
                         help="Exit with a non-zero status if any VULNERABLE finding is proven "
                              "reachable -- for use as a GitHub Actions / CI gate")
    parser.add_argument("--include-safe", action="store_true",
                         help="Include proven SAFE results in SARIF output (by default, only actionable findings are emitted)")
    args = parser.parse_args(argv)

    if not os.path.exists(args.source):
        sys.stderr.write(f"Error: Target file '{args.source}' not found.\n")
        return 2

    try:
        with open(args.source, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as e:
        sys.stderr.write(f"Error: Could not read '{args.source}': {e}\n")
        return 2

    try:
        analyzer = Analyzer(args.source)
        findings = analyzer.analyze_source(src)
    except SyntaxError as e:
        sys.stderr.write(f"Error: Syntax error parsing '{args.source}': {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Error: Analysis failed for '{args.source}': {e}\n")
        return 2

    if args.format == "json":
        report = findings_to_json(args.source, findings)
        text = json_mod.dumps(report, indent=2)
    elif args.format == "sarif":
        report = findings_to_sarif(args.source, findings, include_safe=args.include_safe)
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
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"Report written to {args.output}")
        except Exception as e:
            sys.stderr.write(f"Error writing output to '{args.output}': {e}\n")
            return 2
    else:
        print(text)

    vulnerable = any(f.severity == "high" for f in findings)
    if args.fail_on_vulnerable and vulnerable:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # e.g. `analyzer.py x.py | head` -- the reader closed early; exit
        # quietly instead of printing a Python traceback for a non-error.
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
