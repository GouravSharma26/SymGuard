# SymGuard Benchmark Methodology

This document outlines the benchmark design, evaluation criteria, and reproducible measurement protocol for SymGuard.

---

## 1. Objective

Provide a transparent, verifiable corpus to evaluate:
1. Detection of reachable vulnerabilities across supported vulnerability classes (`SYM001`-`SYM004`).
2. Correct verification of safe patterns (UNSAT reachability proofs and parameterized constructs).
3. Graceful handling of out-of-scope code constructs without inventing safety proofs or crashing.

---

## 2. Benchmark Corpus Categories

The benchmark suite (`benchmark/cases/`) comprises three categories declared in `benchmark/manifest.json`:

### 2.1 Vulnerable Cases (`cases/vulnerable/`)
- `vuln_cmd_injection.py`: Direct concatenation into `os.system`.
- `vuln_code_injection.py`: Stdin payload directly passed to `eval`.
- `vuln_sql_injection.py`: Concatenated SQL query passed to `cursor.execute`.
- `vuln_oob_index.py`: Untrusted index accessing a list without bounds guards.

### 2.2 Safe Cases (`cases/safe/`)
- `safe_cmd_subprocess.py`: List-form argv in `subprocess.run` without `shell=True`.
- `safe_sql_parameterized.py`: Parameterized SQL query `cursor.execute(sql, (param,))`.
- `safe_bounds_check.py`: Conditional bounds checks (`idx >= 0 and idx < len(items)`) proven safe by Z3.
- `safe_infeasible_branch.py`: Contradictory branch conditions (`x > 100 AND x < 10`) proven mathematically infeasible.

### 2.3 Out-of-Scope Cases (`cases/out_of_scope/`)
- `out_of_scope_class_dispatch.py`: Class method dispatch outside modeled subset.
- `out_of_scope_regex_sanitizer.py`: Regex guards (`re.fullmatch`) explored conservatively.
- `out_of_scope_deep_loop.py`: Target reachable only on iteration 8 (beyond `UNROLL_DEPTH = 3`).

---

## 3. Evaluation Protocol

1. **Non-Execution Invariant:** Source files are analyzed purely via AST traversal and SMT logic. Fixtures are **never executed as scripts**.
2. **Deterministic Execution:** The runner isolates each case and executes in a single pass.
3. **Metrics Calculation:**
   - **True Positives (TP):** Expected vulnerable, proven vulnerable.
   - **False Positives (FP):** Expected safe, flagged vulnerable.
   - **True Negatives (TN):** Expected safe, proven safe or not flagged.
   - **False Negatives (FN):** Expected vulnerable, missed.
   - **Precision:** $\frac{TP}{TP + FP}$
   - **Recall:** $\frac{TP}{TP + FN}$
   - **F1 Score:** $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
   - **Analysis Coverage:** $\frac{\text{In-Scope Cases}}{\text{Total Cases}}$

---

## 4. Reproducing Results

To execute the benchmark and generate `benchmark/results.json`:

```bash
python benchmark/run_benchmark.py
```
