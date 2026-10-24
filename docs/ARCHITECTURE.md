# SymGuard Architecture

SymGuard is a static analysis tool that verifies whether attacker-controlled data can reach dangerous execution sinks in Python source code by combining:
1. Abstract Syntax Tree (AST) parsing (`ast` module)
2. Path-sensitive symbolic execution with taint tracking
3. Satisfiability Modulo Theories (SMT) constraint solving via Z3

```
Python Source File (.py)
         │
         ▼
[ ast.parse ] ──────────► AST Representation
                                │
                                ▼
                   [ Symbolic Execution & Taint Tracking ]
                     - Fork on branch conditions (If/Elif/Else)
                     - Unroll loops up to UNROLL_DEPTH (3)
                     - Accumulate path constraints
                     - Track provenance of SymVal (Int/Str)
                                │
                                ▼
                       [ Dangerous Sink Reached? ]
                         │               │
                        No              Yes
                         │               │
                      (Ignore)           ▼
                             [ Z3 SMT Solver Query ]
                             "Is there ANY assignment satisfying
                              path constraints leading to this sink?"
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
                     SAT                              UNSAT
              (VULNERABLE)                            (SAFE)
         Counterexample exploit           Mathematically certified
           inputs generated              infeasible on this path
                      │                                 │
                      └────────────────┬────────────────┘
                                       ▼
                             [ Finding Record ]
                                       │
                   ┌───────────────────┼───────────────────┐
                   ▼                   ▼                   ▼
             [ CLI Text ]         [ JSON 1.1 ]      [ SARIF 2.1.0 ]
```

---

## 1. Core Components

### 1.1 Symbolic Values (`SymVal`)
Every tracked variable maps to a `SymVal`:
- `kind`: `'int'`, `'str'`, `'list'`, or `'unknown'`
- `expr`: Z3 term (`z3.Int`, `z3.String`, or composite Z3 expression)
- `tainted`: boolean flag indicating whether the value originated from untrusted user input
- `source`: human-readable origin (e.g. `stdin (input())`, `sys.argv`, `os.environ.get`)

### 1.2 Path Accumulator & Forking
When analyzing branching constructs (`ast.If`):
- The condition expression is converted into a Z3 boolean predicate (`eval_cond`).
- Execution forks into two paths:
  - **True path:** condition added to path constraints.
  - **False path:** negation `z3.Not(condition)` added to path constraints.
- Each branch is evaluated with copy-on-write isolation of the variable environment.

### 1.3 Bounded Loop Unrolling (`UNROLL_DEPTH = 3`)
- `for` and `while` loop bodies are unrolled a fixed number of times in place.
- Taint and state updates carry across iterations.
- An informational finding (`SYM901`) explicitly records that analysis covers up to the configured bound.

### 1.4 Z3 SMT Proof at Sinks
When a dangerous sink is encountered with tainted arguments:
1. Sinks include:
   - `SYM001`: `os.system`, `os.popen`, `subprocess.*(..., shell=True)`
   - `SYM002`: `eval`, `exec`
   - `SYM003`: unparameterized `*.execute(...)`
   - `SYM004`: tainted sequence subscript `buffer[idx]`
2. The solver checks the accumulated conjunction of path constraints:
   - **SAT:** proven reachable vulnerability. Z3 returns a concrete model (counterexample values).
   - **UNSAT:** mathematically proven unreachable on that path. Certified safe.
   - **UNKNOWN:** timeout or undecidable theory.

---

## 2. Reporting Formats

- **Human-Readable Text:** CLI summary highlighting vulnerability locations, path constraints, and exploit models.
- **Structured JSON (Schema 1.1):** Machine-readable report with stable rule IDs, locations, lines, columns, and backwards-compatible field structure.
- **SARIF 2.1.0:** OASIS Static Analysis Results Interchange Format for integration with GitHub Code Scanning and IDEs.
