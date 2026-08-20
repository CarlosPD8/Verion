import json
from pathlib import Path

from verion.modules.scanning.adapters.outbound.scanners.semgrep_adapter import SemgrepAdapter
from verion.modules.scanning.adapters.outbound.vcs.git_repo_checkout import GitRepoCheckout

# Proves M3.2's "walking skeleton" claim — checkout and scanner adapters
# genuinely chain together against a real repo — without any use case, queue,
# or persistence, which are explicitly M3.3's scope, not this issue's.
_PUBLIC_REPO = "https://github.com/octocat/Hello-World"
_RULESET = Path(__file__).parent / "fixtures" / "semgrep_rules" / "basic.yml"


async def test_checkout_then_scan_produces_raw_results():
    checkout = GitRepoCheckout()
    scanner = SemgrepAdapter(config=str(_RULESET))

    local_path = await checkout.checkout(_PUBLIC_REPO, access_token=None)
    try:
        result = await scanner.run(local_path)
    finally:
        await checkout.cleanup(local_path)

    assert result.tool == "semgrep"
    # Hello-World has no scannable source of its own — this asserts the
    # chain produced valid output, not a specific finding (SemgrepAdapter's
    # own test already proves finding-detection against the fixture target).
    assert isinstance(json.loads(result.raw_output), dict)
