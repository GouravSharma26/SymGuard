import os
import sys
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import Analyzer, Finding


@pytest.fixture
def analyze_snippet():
    """Helper fixture to analyze an in-memory python code snippet."""
    def _analyze(code: str, filename: str = "snippet.py") -> list[Finding]:
        analyzer = Analyzer(filename)
        return analyzer.analyze_source(code)
    return _analyze
