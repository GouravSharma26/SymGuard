# SymGuard (AST + Taint Tracking + Z3 SMT Proofs)

A static analyzer that doesn't guess whether code is vulnerable — it
**proves** it, using an SMT solver (Z3).

## How it works

```
source.py --[ast.parse]--> AST --[symbolic execution]--> Z3 formulas --[solver]--> proof
```

1. **Parse.** Python's built-in `ast` module turns source into an Abstract
   Syntax Tree — no custom lexer/parser needed, so effort goes into the
   analysis, not re-implementing a Python front end.
2. **Symbolically execute.** The tool walks the AST and, instead of running
   the code, builds up a *symbolic* environment: every variable maps to a
   Z3 term (`Int` or `String` theory) rather than a concrete value. Every
   `if` **forks** execution into two paths — one with the condition added
   to the path constraint, one with its negation — so both branches are
   verified independently.
3. **Track taint.** Any value derived from `input()`, `sys.argv`,
   `os.environ.get(...)`, Flask's `request.args/form/values.get(...)`, or a
   function parameter annotated `: Tainted`, is marked tainted. Taint
   propagates through string concatenation, f-strings, `%`-formatting, and
   arithmetic.
4. **Prove reachability at sinks.** When a tainted value reaches a
   dangerous sink — `eval`/`exec`, `os.system`/`subprocess(..., shell=True)`,
   `cursor.execute` with a concatenated (non-parameterized) query, or a
   list index — the accumulated path constraint is handed to Z3:

   > "Is there any assignment to the tainted symbols that satisfies every
   > branch condition on the path leading to this sink?"

   - **SAT** → the vulnerability is real and reachable. Z3 also returns a
     concrete **counterexample**: actual input values that trigger it.
   - **UNSAT** → that path is mathematically proven infeasible — the tool
     can positively certify the sink safe on that path, not just "didn't
     find a pattern match."

This is what separates it from grep/regex-based scanners: an `if` that
looks like it blocks an attack (`if user_input == "safe_mode":`) is not
assumed safe — the solver checks whether the *sink itself* is still
reachable with a value that satisfies the guard, catching e.g. exploits
that hide inside an apparently-restrictive branch.

## Vulnerability classes covered

| Class | Sinks recognized | Notes |
|---|---|---|
| OS command injection | `os.system`, `os.popen`, `subprocess.run/call/Popen(..., shell=True)` | list-form `subprocess` args without `shell=True` are correctly treated as safe |
| Code injection | `eval`, `exec` | |
| SQL injection | `*.execute(...)` | flags string-built queries; automatically recognizes parameterized `execute(query, params)` as the fix and does not flag it |
| Out-of-bounds indexing (buffer-overflow analog) | `list_var[tainted_idx]` | list length tracked symbolically; bounds-checking `if` guards are verified to actually constrain the index, inside loops too |

## Loop support (bounded unrolling)

`for`/`while` loop bodies are unrolled a fixed number of times
(`UNROLL_DEPTH = 3` in `analyzer.py`) rather than skipped. This is the same
trade-off bounded model checkers like CBMC make:

- Any vulnerability reachable within `UNROLL_DEPTH` iterations **will** be
  found, with a real Z3 counterexample — no false negatives in that window.
- A clean report only certifies safety **up to that depth**, not for
  arbitrarily many iterations. Every analyzed loop gets an explicit `[info]`
  note saying so in both the console and JSON output, rather than silently
  overclaiming a full proof.

See `examples/loop_unrolling.py` for a vulnerable `for` loop (command
injection reproduced on every unrolled iteration) alongside a `while` loop
that stays proven-safe across all 3 unrolled copies because it re-checks
bounds every iteration.

## CLI usage / CI integration

```bash
# human-readable report (default)
python3 analyzer.py app.py

# machine-readable JSON, printed to stdout (pipeable)
python3 analyzer.py app.py --format json

# JSON written to a file instead of stdout
python3 analyzer.py app.py --format json --output findings.json

# exit 1 if any finding is a PROVEN vulnerability -- the actual CI gate
python3 analyzer.py app.py --format json --output findings.json --fail-on-vulnerable
```

The JSON schema (`schema_version: "1.0"`) is stable so a CI step or a
future web dashboard can consume it directly:

```json
{
  "schema_version": "1.0",
  "tool": "vuln_analyzer",
  "target": "app.py",
  "generated_at": "2026-08-14T11:09:41Z",
  "summary": {"vulnerable": 1, "safe": 1, "unknown": 0, "notes": 0},
  "findings": [
    {
      "vuln_type": "OS Command Injection",
      "location": "module:line 12",
      "line": 12,
      "sink": "os.system(...)",
      "tainted_source": "stdin (input())",
      "path_condition": "not (user_input == 'safe_mode')",
      "verdict": "VULNERABLE (proven reachable by Z3)",
      "severity": "high",
      "z3_counterexample": "[stdin__1 = \"\"]"
    }
  ]
}
```

`severity` (`high` | `safe` | `unknown` | `info`) and `line` exist
specifically so a GitHub Actions annotation or a dashboard's line-highlight
can be driven straight off this file without re-parsing the `verdict`
string. A ready-to-use workflow is in `.github_workflow_example.yml`
(rename to `.github/workflows/analyze.yml` to enable it) — it runs the
analyzer on every push/PR, fails the build on a proven vulnerability, and
uploads `findings.json` as a build artifact regardless of outcome.

## Usage

```bash
python3 analyzer.py path/to/source.py
```

Run it against the bundled examples:

```bash
python3 analyzer.py examples/command_injection.py
python3 analyzer.py examples/sql_injection.py
python3 analyzer.py examples/out_of_bounds.py
python3 analyzer.py examples/function_entrypoint.py
python3 analyzer.py examples/loop_unrolling.py
```

`out_of_bounds.py` is the best demo of the "wow factor": it contains one
unguarded index (proven **vulnerable**, with a concrete exploit value) and
one properly bounds-checked index (proven **safe**, UNSAT) — the same
solver, two opposite, mathematically justified verdicts.

## Supported source subset & honest limitations

This is a research-style prototype, not a production scanner. To keep the
AST→logic translation *sound*, it only fully models:

- assignments, augmented assignments, `if`/`elif`/`else` (forked, not merged)
- int/str arithmetic, comparisons, boolean ops, f-strings
- calls recognized as taint sources/sinks (see table above), plus `len()`
  and `int()` on tracked values
- `for`/`while` loops, via bounded unrolling (see above) — sound *within*
  the unroll depth, explicitly not claimed beyond it

Things it deliberately does **not** attempt to prove (rather than silently
mis-model): unbounded/arbitrary-depth loop behavior beyond `UNROLL_DEPTH`,
classes/objects beyond the simple `Tainted` marker, complex string methods,
exceptions, or inter-procedural calls between two *analyzed* functions
(each `Tainted`-annotated function is checked in isolation). Sanitizer
calls like `.isdigit()`/`re.match()` used as guards are recognized as
branch points (both paths still explored) but aren't modeled precisely in
the theory, so the tool is conservative — it can under-approximate what
counts as "safe" but should never *invent* a safety proof it can't back
with an actual UNSAT result from Z3.

## Files

- `analyzer.py` — the analyzer (parser driver, symbolic executor, Z3
  encoding, sink/source catalog, reporting)
- `examples/` — four annotated sample programs (command injection, SQL
  injection, out-of-bounds indexing, function-entrypoint/`Tainted` mode)
