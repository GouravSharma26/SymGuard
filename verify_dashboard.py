#!/usr/bin/env python3
"""
verify_dashboard.py
Cross-checks the running Flask dashboard's /api/analyze endpoint against the
known-correct summary counts already validated via the CLI in this project
(see conversation history / README examples). Run this against your local
`python web/app.py` server -- it is the actual "Definition of Done" check
from the original project brief, not just a smoke test.

Usage:
    python3 verify_dashboard.py [http://localhost:5000]
"""
import json
import sys
import urllib.request
import urllib.error

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
EXAMPLES_DIR = "examples"

# Known-correct summary counts, established earlier via:
#   python3 analyzer.py examples/<file> --format json
EXPECTED = {
    "command_injection.py":  {"vulnerable": 2, "safe": 0, "unknown": 0, "notes": 0},
    "function_entrypoint.py": {"vulnerable": 1, "safe": 0, "unknown": 0, "notes": 0},
    "loop_unrolling.py":     {"vulnerable": 3, "safe": 3, "unknown": 0, "notes": 2},
    "out_of_bounds.py":      {"vulnerable": 1, "safe": 1, "unknown": 0, "notes": 0},
    "sql_injection.py":      {"vulnerable": 1, "safe": 0, "unknown": 0, "notes": 0},
}


def post_analyze(code: str, filename: str):
    payload = json.dumps({"code": code, "filename": filename}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body}


def main():
    print(f"Verifying dashboard at {BASE_URL}\n{'=' * 70}")
    all_pass = True

    for fname, expected in EXPECTED.items():
        path = f"{EXAMPLES_DIR}/{fname}"
        try:
            with open(path) as f:
                code = f.read()
        except FileNotFoundError:
            print(f"[SKIP] {fname} -- not found at {path} (run from project root)")
            all_pass = False
            continue

        status, body = post_analyze(code, fname)
        if status != 200:
            print(f"[FAIL] {fname} -- HTTP {status}: {body}")
            all_pass = False
            continue

        actual = body.get("summary", {})
        mismatches = {
            k: (expected[k], actual.get(k))
            for k in expected
            if actual.get(k) != expected[k]
        }
        if mismatches:
            print(f"[FAIL] {fname} -- summary mismatch (expected, actual): {mismatches}")
            all_pass = False
        else:
            print(f"[PASS] {fname} -- {actual}")

    # Invalid syntax should come back as a clean 400, not a 500 / crash.
    print()
    status, body = post_analyze("def broken(", "broken.py")
    if status == 400:
        print(f"[PASS] invalid syntax -- correctly returned 400: {body.get('error', body)}")
    else:
        print(f"[FAIL] invalid syntax -- expected 400, got {status}: {body}")
        all_pass = False

    print(f"\n{'=' * 70}")
    print("ALL CHECKS PASSED" if all_pass else "SOME CHECKS FAILED -- see above")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
