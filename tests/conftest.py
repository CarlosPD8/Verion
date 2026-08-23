from collections.abc import Callable
from pathlib import Path

import pytest

_SCANNER_FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


@pytest.fixture
def scanner_fixture() -> Callable[[str], str]:
    """Reads a captured scanner-output fixture by file name.

    Root-level rather than in `tests/unit/`, because both trees need it: M4.1's
    mapper unit tests read these, and M4.4's `test_normalize_scan_pipeline.py`
    feeds the same files to in-process fake scanners as their `raw_output` (which
    is what keeps that test off the container-bound budget CLAUDE.md tracks).
    `tests/` is not a package, so a shared path constant has to arrive as a
    fixture — otherwise the second consumer duplicates it or the files get moved
    into its tree, and one issue's work lands in another issue's diff.

    Returns the file's text exactly as committed, since that is what a scanner
    adapter would have handed to `ScanResult.raw_output`.
    """

    def _read(name: str) -> str:
        path = _SCANNER_FIXTURES / name
        if not path.is_file():
            available = sorted(p.name for p in _SCANNER_FIXTURES.glob("*.json"))
            raise FileNotFoundError(f"No scanner fixture '{name}'. Available: {available}")
        return path.read_text(encoding="utf-8")

    return _read
