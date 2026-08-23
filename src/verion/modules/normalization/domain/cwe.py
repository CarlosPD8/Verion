import re

# ZAP uses these as "no CWE known" sentinels rather than omitting the field.
_ZAP_ABSENT_SENTINELS = {"-1", "0"}
_CWE_NUMBER = re.compile(r"(\d+)")


def canonical_cwe(raw: str | int | None) -> str | None:
    """Normalizes the three tools' CWE spellings to one `CWE-<n>` form.

    They do not agree: Trivy emits `"CWE-20"`, ZAP emits the bare number `"693"`,
    and a Semgrep rule that declares one usually writes the full
    `"CWE-95: Improper Neutralization of Directives..."`. Correlation compares
    these across tools, so they have to be the same string or the comparison
    silently never matches — a false negative that looks exactly like "these
    findings are unrelated".

    Returns None for anything with no number in it, and for ZAP's `-1`/`0`
    sentinels. None means "the tool said nothing", which is the same contract
    every other unsourced field on Finding has.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text in _ZAP_ABSENT_SENTINELS:
        return None
    match = _CWE_NUMBER.search(text)
    if match is None:
        return None
    return f"CWE-{match.group(1)}"
