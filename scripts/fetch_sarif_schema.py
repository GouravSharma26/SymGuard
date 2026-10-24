#!/usr/bin/env python3
"""
scripts/fetch_sarif_schema.py
=============================
Provisions the official OASIS SARIF 2.1.0 JSON Schema for local validation.
Saves to `schemas/sarif-schema-2.1.0.json`.
"""

import os
import sys
import json
import urllib.request
import urllib.error

SCHEMA_URLS = [
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
    "https://json.schemastore.org/sarif-2.1.0.json",
]

TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schemas"))
TARGET_PATH = os.path.join(TARGET_DIR, "sarif-schema-2.1.0.json")


def fetch_schema():
    os.makedirs(TARGET_DIR, exist_ok=True)
    if os.path.exists(TARGET_PATH) and os.path.getsize(TARGET_PATH) > 1000:
        print(f"SARIF schema already present at: {TARGET_PATH}")
        return True

    for url in SCHEMA_URLS:
        try:
            print(f"Fetching SARIF 2.1.0 schema from {url}...")
            req = urllib.request.Request(url, headers={"User-Agent": "SymGuard-Schema-Fetcher/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
                # Verify valid JSON
                data = json.loads(content)
                with open(TARGET_PATH, "wb") as f:
                    f.write(content)
                print(f"Successfully saved SARIF schema to {TARGET_PATH} ({len(content)} bytes)")
                return True
        except Exception as e:
            print(f"Failed to fetch from {url}: {e}", file=sys.stderr)

    print("Error: Could not download SARIF schema from any source.", file=sys.stderr)
    return False


if __name__ == "__main__":
    success = fetch_schema()
    sys.exit(0 if success else 1)
