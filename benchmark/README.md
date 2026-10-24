# SymGuard Benchmark Corpus & Evaluation

This directory contains a small, reproducible, and transparent benchmark corpus evaluating SymGuard's static taint tracking and Z3 reachability analysis against a variety of vulnerable, safe, and out-of-scope Python patterns.

## Corpus Design

The corpus is organized into three distinct groups under `benchmark/cases/`:

1. **`vulnerable/`**: Synthetic fixtures exhibiting proven, directly reachable taint flows to dangerous sinks (`SYM001`-`SYM004`).
2. **`safe/`**: Fixtures implementing recognized secure programming practices:
   - Parameterized SQL queries (`cursor.execute(query, params)`)
   - Safe subprocess execution (`subprocess.run(list_args, shell=False)`)
   - Guarded bounds checking (`0 <= idx < len(buffer)`)
   - Mathematically contradictory path constraints (`x > 100 AND x < 10`)
3. **`out_of_scope/`**: Intentionally unsupported constructs evaluating whether SymGuard communicates uncertainty rather than mis-modeling:
   - Dynamic class/object dispatch
   - Regex guard constraints (not translated into SMT theory)
   - Deep loop iterations beyond bounded unrolling depth (`UNROLL_DEPTH = 3`)

## Safety & Non-Execution Principle

> [!IMPORTANT]
> Benchmark source files are **never executed as code**. They are parsed into ASTs and symbolically analyzed with Z3 within an isolated solver context.

## Running the Benchmark

From the repository root:

```bash
python benchmark/run_benchmark.py
```

The script evaluates all cases in `benchmark/manifest.json`, prints a Markdown summary table, and writes structured metrics to `benchmark/results.json`.

## Evaluated Metrics

- **True Positives (TP):** Reachable vulnerabilities correctly proved and flagged.
- **False Positives (FP):** Safe programming patterns incorrectly flagged as vulnerable.
- **True Negatives (TN):** Safe patterns certified safe (UNSAT) or not flagged.
- **False Negatives (FN):** Vulnerabilities in the supported subset missed by the analyzer.
- **Precision, Recall, F1 Score:** Standard classification metrics computed on in-scope cases.
- **Analysis Coverage:** Proportion of test cases falling within the modeled subset.
