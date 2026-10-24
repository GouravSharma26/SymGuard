# SymGuard Upgrade Plan
## From research prototype to a testable, CI-integrated static-analysis tool

**Repository:** https://github.com/GouravSharma26/SymGuard  
**Plan status:** Proposed implementation plan  
**Suggested location in repository:** `docs/SYMGUARD_UPGRADE_PLAN.md`  
**Scope:** Regression tests, SARIF output, CI integration, line-level findings, and a reproducible benchmark

---

## 1. Objective

Upgrade SymGuard from a research-style Python static analyzer into a more reproducible and reviewer-friendly developer tool. Preserve its existing core idea—AST parsing, taint tracking, symbolic execution, and Z3-backed reachability checks—while adding a regression suite, a reliable CI workflow, interoperable SARIF output, and a benchmark with transparent limitations.

This upgrade must improve **verifiability and reporting**, not overstate what the current analysis can prove. SymGuard supports a restricted Python subset and bounded loop unrolling; all documentation and output must make those limits explicit.

### Definition of success

A new contributor should be able to clone the repository, install the development dependencies, run the test suite, analyze the example programs, produce JSON and SARIF reports, and understand exactly which results are proven, unknown, or outside the modeled subset.

---

## 2. Current baseline and observations

Based on the current public repository structure and README:

- `analyzer.py` implements the analyzer and defines a `Finding` record with vulnerability type, location, sink, tainted source, path constraints, verdict, model, line number, and severity.
- The analyzer supports JSON output and a `--fail-on-vulnerable` exit gate.
- Existing example programs are under `examples/`: command injection, SQL injection, out-of-bounds indexing, function entrypoint/taint annotation, and loop unrolling.
- `.github_workflow_example.yml` documents a CI workflow example but is at the repository root rather than at `.github/workflows/...`.
- That example workflow refers to `app.py`, which is not one of the documented root files. The upgrade should use known fixtures or an explicit user-supplied target instead of assuming `app.py` exists.
- The README already explains important scope limits: bounded loop unrolling, unsupported constructs, and a restricted analysis subset.
- `requirements.txt` currently includes Flask, `z3-solver`, and Gunicorn. The analyzer's minimum runtime dependency is Z3; tests should use a clearly documented development/test dependency set.

Do not remove existing functionality or rewrite the symbolic executor wholesale as part of this upgrade. First add tests that capture the expected behaviour, then make the smallest changes needed for stable reporting and CI.

---

## 3. Goals and non-goals

### Goals

1. Add automated regression tests around current, intended analyzer behaviour.
2. Define stable machine-readable JSON output and add SARIF 2.1.0 output.
3. Ensure findings have source file paths, line numbers, and useful messages.
4. Add a working GitHub Actions workflow for tests and report artifacts.
5. Build a small, labelled benchmark corpus of vulnerable, safe, and unknown/out-of-scope examples.
6. Document setup, CLI usage, expected results, metrics, limitations, and contribution workflow.

### Non-goals for this upgrade

- Claiming SymGuard can prove arbitrary Python programs safe.
- Adding interprocedural analysis, complete Python semantics, or unbounded loop reasoning.
- Executing analyzed source code as part of the analyzer or test suite.
- Claiming production-grade security certification.
- Adding a complex hosted dashboard before the CLI, tests, and reporting formats are stable.
- Reporting fabricated performance or accuracy numbers.

---

## 4. Target repository structure

Keep existing source and example paths where practical. Add or normalize the following:

```text
SymGuard/
├── analyzer.py
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── .github/
│   └── workflows/
│       └── symguard-ci.yml
├── examples/
│   ├── command_injection.py
│   ├── function_entrypoint.py
│   ├── loop_unrolling.py
│   ├── out_of_bounds.py
│   └── sql_injection.py
├── tests/
│   ├── conftest.py
│   ├── test_sources_and_sinks.py
│   ├── test_path_constraints.py
│   ├── test_loop_bounds.py
│   ├── test_findings_schema.py
│   ├── test_cli.py
│   ├── test_json_output.py
│   └── test_sarif_output.py
├── benchmark/
│   ├── README.md
│   ├── cases/
│   │   ├── vulnerable/
│   │   ├── safe/
│   │   └── out_of_scope/
│   ├── manifest.json
│   └── run_benchmark.py
└── docs/
    ├── ARCHITECTURE.md
    ├── SUPPORTED_SUBSET.md
    └── BENCHMARK_METHODOLOGY.md
```

The exact test filenames can change if the existing code benefits from a smaller structure. Do not move or rename examples unless there is a concrete reason; links in the README should remain valid.

---

## 5. Phase 0 — Protect the existing baseline

### Tasks

- Create a feature branch, for example `upgrade/regression-sarif-ci`.
- Record the current commit SHA before modifications.
- Run the existing documented examples manually and save expected outcomes for reference.
- Confirm the CLI's actual arguments, exit codes, and JSON schema before changing them.
- Do not run vulnerable examples as applications. The analyzer should parse and analyze their source without executing them.

### Acceptance criteria

- The baseline commit is recorded.
- Existing CLI behaviour is understood and documented.
- No source code is executed by benchmark or unit tests.

---

## 6. Phase 1 — Add a regression test suite

Use `pytest`. Add `pytest` and any test-only dependencies to `requirements-dev.txt`; keep runtime requirements minimal and intentional.

### Required test categories

#### A. Sources and sinks

Cover the documented taint sources:

- `input()`
- `sys.argv` values where supported by the implementation
- `os.environ.get(...)`
- supported Flask request query/form/value patterns
- function parameters marked with `Tainted`

Cover the documented sinks:

- `eval` and `exec`
- `os.system` and `os.popen`
- `subprocess` calls with `shell=True`
- SQL `execute` with a concatenated query
- tainted list indexing

Each test should have an input snippet, expected finding category, expected verdict class, and relevant source line.

#### B. Safe versus vulnerable paths

Test both positive and negative cases:

- User-controlled data reaches a dangerous sink on a satisfiable path.
- A guard genuinely constrains the dangerous value and makes the analyzed path infeasible.
- A guard that looks restrictive but does not actually prevent the sink.
- Parameterized SQL is distinguished from string-built SQL according to the analyzer's supported rules.
- Safe `subprocess` list-form invocation without `shell=True` is not reported as shell injection if that is the implementation's declared behaviour.

Avoid assertions that depend on Z3-generated variable names or exact formatting of model strings.

#### C. Bounded loops and unsupported constructs

- Verify a vulnerability inside the configured unroll depth is found when expected.
- Verify a clean bounded result is accompanied by the documented bounded-analysis note.
- Verify unsupported constructs result in a note/unknown state rather than a false claim of proof.
- Verify branch/path handling matches the current documented subset.

#### D. Findings and CLI contracts

- Every actionable finding contains a stable rule ID, relative source path, line number when available, verdict, and message.
- JSON output parses successfully and follows a versioned schema.
- `--output` writes to the requested file and does not silently truncate or corrupt output.
- `--fail-on-vulnerable` returns a non-zero code only under its documented condition.
- Invalid source syntax, unreadable files, and invalid CLI arguments produce a helpful error and a predictable non-zero exit code.
- SARIF conforms to the supported SARIF 2.1.0 shape and preserves source locations.

### Test quality rules

- Tests must be deterministic and self-contained.
- Never require network access or live AI/API keys.
- Do not compare full outputs where a focused assertion is sufficient.
- Reset or isolate module-level state where needed so test order does not affect results.
- Keep each fixture small enough that the expected result can be reviewed by a human.

### Acceptance criteria

- All regression tests pass locally and in CI.
- Tests cover vulnerable, safe, unknown/out-of-scope, line-location, JSON, SARIF, and CLI exit-code behaviour.
- The test suite never executes the intentionally vulnerable fixture code.

---

## 7. Phase 2 — Stabilize findings and reporting contracts

Before adding SARIF, define an internal finding contract so JSON and SARIF are both generated from the same data.

### Recommended finding fields

- `rule_id`: stable identifier such as `SYM001`, `SYM002`, etc.
- `rule_name`: human-readable category.
- `vuln_type`
- `verdict`: `VULNERABLE`, `SAFE`, `UNKNOWN`, or `NOTE` as appropriate.
- `severity`: a documented value, not inferred inconsistently from free-form prose.
- `message`: concise explanation.
- `uri`: source path relative to the scan root where possible.
- `line` and optional `column`
- `sink`
- `tainted_source`
- `path_constraints_desc`
- optional `counterexample`
- `analysis_scope_note` for bounded or unsupported analysis when applicable.

Preserve backwards compatibility with the current JSON fields where feasible. If a breaking change is necessary, increment `schema_version` and document the migration.

### Stable rule catalog

Use stable IDs and a single rule catalog shared by JSON and SARIF output. Initial categories can include:

| Rule ID | Category |
|---|---|
| `SYM001` | OS command injection |
| `SYM002` | Code injection |
| `SYM003` | SQL injection |
| `SYM004` | Tainted out-of-bounds indexing |

The IDs are proposed identifiers; lock them once published and do not reuse them for a different meaning.

### Acceptance criteria

- JSON field semantics are documented.
- Every finding has consistent rule identity and verdict/severity mapping.
- Existing CLI workflows remain supported or the migration is documented.
- Output does not include machine-specific absolute paths or secrets by default.

---

## 8. Phase 3 — Implement SARIF 2.1.0 output

Add a CLI option such as:

```bash
python analyzer.py examples/command_injection.py --format sarif
python analyzer.py examples/command_injection.py --format sarif --output findings.sarif
```

Retain the current human-readable and JSON modes.

### SARIF requirements

- Set `version` to `2.1.0` and use the official SARIF schema URI.
- Populate `runs[0].tool.driver.name` as `SymGuard`.
- Declare `rules` once in the tool driver and reference them by stable `ruleId`.
- Use a relative artifact URI where possible.
- Include `region.startLine` when a line number is available; include `startColumn` only if it is accurate.
- Provide a concise `message.text`.
- Preserve useful metadata in `result.properties`, including verdict, sink, tainted source, path constraints, and bounded-analysis notes where relevant.
- Use severity levels consistently. Do not map `SAFE` findings to security errors.
- Unknown and informational notes must not be misrepresented as proven vulnerabilities.
- If no finding exists, produce a valid SARIF run with an empty results list.
- Escape all text correctly and ensure valid JSON encoding.

### Reporting policy

The command-line report can show vulnerable, safe, unknown, and informational outcomes. SARIF should be actionable: proven vulnerable paths are security findings; unknown/out-of-scope analysis is a note or explicitly documented result; safe paths should not create security alerts by default. If safe results are useful for debugging, offer an opt-in flag rather than treating safe paths as vulnerabilities.

### Validation

- Unit-test the structure and key fields.
- Validate generated reports against the official SARIF 2.1.0 schema in CI if a reliable validator dependency is added.
- Include a known fixture with a finding and one fixture with no findings.
- Confirm file paths and line numbers resolve to the expected lines.

### Acceptance criteria

- Both JSON and SARIF reports can be generated using the CLI.
- SARIF is valid JSON and conforms to SARIF 2.1.0.
- A finding's rule ID, message, and source line survive JSON-to-SARIF mapping correctly.

---

## 9. Phase 4 — GitHub Actions CI

Create `.github/workflows/symguard-ci.yml`. The existing root-level workflow example should either be moved/adapted or clearly marked as a template; avoid maintaining two contradictory workflows.

### CI stages

1. Checkout the repository.
2. Set up the supported Python version (start with Python 3.11 if that is the declared baseline; add more versions only after local compatibility is verified).
3. Install the analyzer and development dependencies.
4. Run `pytest`.
5. Exercise CLI output against known examples or dedicated benchmark fixtures.
6. Generate JSON and SARIF artifacts for a predictable, dedicated fixture.
7. Upload reports as workflow artifacts even when an analysis step fails, where practical.
8. Clearly separate test-fixture validation from scanning production code.

### Important fixture policy

Some files under `examples/` are intentionally vulnerable. Do not upload their findings as if they were vulnerabilities in SymGuard itself. For ordinary CI, assert their expected findings through tests and retain reports as artifacts. Only upload SARIF to GitHub Code Scanning when scanning a deliberately selected target and the resulting alerts are meaningful for that target.

If GitHub Code Scanning upload is implemented:

- Request only the required `security-events: write` permission.
- Document repository and plan/feature requirements.
- Make upload a distinct, optional integration if it prevents basic CI from running in forks or environments without Code Scanning access.
- Use `github/codeql-action/upload-sarif` only after verifying the generated SARIF is valid and the target/path configuration is correct.

### CI exit behaviour

- Test failures must fail CI.
- The known-vulnerable fixtures should pass their tests when the analyzer correctly identifies the expected vulnerable paths; do not make a test job fail simply because an intentionally vulnerable example is detected.
- A separate explicit scan/gate may use `--fail-on-vulnerable` against a selected target.
- Unknown or unsupported constructs should be reported as such; don't silently treat them as safe.

### Acceptance criteria

- Workflow runs on pushes and pull requests to the main branch.
- A clean clone can install dependencies and run tests without secrets or network calls.
- JSON and SARIF artifacts are produced on successful test runs.
- The workflow does not reference an assumed `app.py` target that is absent from the repository.

---

## 10. Phase 5 — Build a reproducible benchmark

The benchmark must be a small transparent corpus, not a claim that SymGuard has been evaluated against every Python vulnerability.

### Corpus design

Create a manifest for each case with:

- case ID
- relative file path
- vulnerability category (if applicable)
- expected outcome: vulnerable, safe, unknown/out-of-scope, or note
- expected rule ID where relevant
- short rationale
- whether the case is synthetic or derived from a public dataset, with attribution/licence if applicable

Use three initial groups:

1. **Vulnerable cases:** simple, clearly reachable flows for each supported category.
2. **Safe cases:** parameterized queries, safe subprocess argument lists, valid bounds checks, and guards that truly constrain the dangerous value.
3. **Out-of-scope cases:** constructs that the analyzer deliberately does not model precisely. These should evaluate whether SymGuard communicates uncertainty instead of claiming safety.

Do not execute benchmark source files. The analyzer should parse and reason about them.

### Metrics

Report these separately:

- True positives (TP), false positives (FP), true negatives (TN), false negatives (FN) for cases with a clear binary expected outcome.
- Precision, recall, and F1 where the labels and outcome mapping justify those calculations.
- Unknown/out-of-scope count and proportion.
- Analysis coverage: cases for which the analyzer returned a determinate, in-scope result.
- Per-category results.
- Runtime per case and total runtime, with hardware/runtime environment stated.

Do not silently count `UNKNOWN` as `SAFE`. Show how unknown outcomes are handled. Avoid combining unsupported cases into a binary metric without explaining the policy.

### Benchmark integrity

- Keep expected labels separate from analyzer output.
- Version the corpus and describe how each case was created.
- Include regression cases for previously fixed issues.
- If external datasets are added, verify their licence, preserve citations, and document any transformations.
- Publish measured results only after running the benchmark; never fill the README with invented accuracy claims.

### Acceptance criteria

- One documented command runs the benchmark from a clean setup.
- Results are reproducible and written to a machine-readable summary such as `benchmark/results.json`.
- A human-readable Markdown summary includes dataset size, categories, metrics, unknowns, environment, and limitations.

---

## 11. Phase 6 — Documentation and developer experience

Update `README.md` and add supporting docs.

### README changes

- State clearly that SymGuard is a research-style prototype and not a production security guarantee.
- Show installation for runtime and development dependencies.
- Document text, JSON, and SARIF CLI modes.
- Document rule IDs, verdicts, exit codes, line-location behaviour, and report artifacts.
- Link to supported-language subset, architecture, benchmark methodology, and known limitations.
- Explain the meaning of SAT, UNSAT, and UNKNOWN in the context of the modeled path constraints.
- Explicitly state that a clean result only applies to the supported subset and configured loop-unroll depth.
- Add CI status after the workflow is actually passing.
- Add screenshots only if the current UI/report output is real and up to date.

### Security and maintenance

- Confirm that no real credentials, session cookies, local database files, or private data are tracked.
- Keep intentionally vulnerable examples labelled as test fixtures.
- Keep dependencies pinned or bounded appropriately and document supported Python versions.
- Avoid sending source code to external services; analysis should remain local unless a future feature explicitly documents otherwise.

---

## 12. Suggested implementation order

Implement in reviewable steps:

1. **PR 1 — Test baseline:** test dependencies, pytest configuration, source/sink fixtures, branch/loop cases, CLI behaviour.
2. **PR 2 — Findings contract:** stable rule identifiers, consistent verdict mapping, relative paths, JSON compatibility.
3. **PR 3 — SARIF:** encoder, CLI flag, schema tests, examples.
4. **PR 4 — CI:** active GitHub Actions workflow, report artifacts, correct handling of intentionally vulnerable fixtures.
5. **PR 5 — Benchmark:** manifest, safe/vulnerable/unknown corpora, metrics script, result documentation.
6. **PR 6 — Docs and cleanup:** update README, supported subset, architecture and benchmark docs; remove or clearly label stale workflow templates.

Do not combine all phases into one large unreviewed refactor. Each PR should leave the repository in a usable state.

---

## 13. Final release acceptance checklist

- [ ] A clean checkout can install dependencies and run all tests.
- [ ] Regression tests cover each currently supported vulnerability category.
- [ ] Both vulnerable and safe cases are tested.
- [ ] Unsupported or bounded cases remain explicitly limited or unknown.
- [ ] JSON output is versioned and backward compatibility is preserved or documented.
- [ ] SARIF 2.1.0 output is valid and includes relative source paths and line regions.
- [ ] CLI exit codes are documented and tested.
- [ ] GitHub Actions runs on push and pull request.
- [ ] CI artifacts are available for debugging.
- [ ] Intentional vulnerable examples are not incorrectly reported as vulnerabilities in the SymGuard tool itself.
- [ ] Benchmark labels are documented and results are measured, not invented.
- [ ] README explains installation, usage, output modes, test commands, limitations, and benchmark methodology.
- [ ] No secrets, cookies, or private data are committed.

## 14. Final principle

SymGuard's value is its attempt to reason about reachability using symbolic path constraints and an SMT solver. The upgrade should make that reasoning easier to verify: **test what it claims, show where each result came from, distinguish unknown from safe, and publish only measured results.**
