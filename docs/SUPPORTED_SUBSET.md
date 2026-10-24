# SymGuard Supported Language Subset & Limitations

SymGuard deliberately focuses on a soundly translatable subset of Python to ensure that SMT reachability proofs remain mathematically rigorous.

---

## 1. Supported Language Constructs

### Syntax & Control Flow
- **Assignments:** Simple assignments (`x = y`) and augmented assignments (`x += 1`).
- **Conditionals:** `if`, `elif`, `else` branches. Both branches are explored independently.
- **Loops:** `for` and `while` loops up to `UNROLL_DEPTH = 3` iterations.
- **Function Entrypoints:** Functions where one or more parameters are annotated `: Tainted` are analyzed as reachable entry points.

### Data Types & Operators
- **Integers:** `+`, `-`, `*`, `//`, `%`, unary `-`, bitwise comparisons.
- **Strings:** Literals, string concatenation (`+`), `%` string formatting, and f-strings (`f"..."`).
- **Lists:** Literal lists (symbolically tracking list length).
- **Comparisons:** `<`, `<=`, `>`, `>=`, `==`, `!=`.
- **Boolean Logic:** `and`, `or`, `not`.

### Recognized Taint Sources
- `input()` (stdin)
- `sys.argv[i]` (command-line arguments)
- `os.environ.get(...)` (environment variables)
- `request.args.get(...)` (HTTP query parameters in Flask)
- `request.form.get(...)` (HTTP POST form fields)
- `request.values.get(...)` (HTTP parameters)
- Function parameters annotated with `: Tainted`

### Recognized Dangerous Sinks & Rules
| Rule ID | Category | Sinks | Fix / Safe Variant |
|---|---|---|---|
| `SYM001` | OS Command Injection | `os.system`, `os.popen`, `subprocess.run/call/Popen(..., shell=True)` | List-form argv without `shell=True` |
| `SYM002` | Code Injection | `eval(...)`, `exec(...)` | Safe parsers (e.g., `ast.literal_eval`, `json.loads`) |
| `SYM003` | SQL Injection | `*.execute(query)` with string concatenation | Parameterized query `cursor.execute(query, params)` |
| `SYM004` | Out-of-Bounds Indexing | `list_var[tainted_idx]` | Explicit bounds guards `0 <= idx < len(list_var)` |
| `SYM901` | Loop Bound Note | `(loop body)` | Informational note for bounded loop depth |

---

## 2. Documented Limitations & Out-of-Scope Constructs

To maintain soundness over false certainty, SymGuard does **not** silently invent safety proofs for constructs it cannot model:

1. **Unbounded Loops:** Loops are analyzed up to `UNROLL_DEPTH = 3`. Absence of findings is not an inductive proof for arbitrarily many iterations.
2. **Object-Oriented Dispatch & Classes:** Custom class instantiations and method dispatches are treated as unknown values.
3. **Interprocedural Analysis:** Functions with `: Tainted` parameters are analyzed in isolation. Function call graphs across modules are not traversed.
4. **Regular Expressions:** Checks like `re.match` or `str.isalnum()` fork paths but are not modeled in Z3 string theory; both branches are explored conservatively.
5. **Exceptions & Asynchronous Code:** `try`/`except`/`finally` blocks and `async`/`await` primitives are outside the current symbolic model.
