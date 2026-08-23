import hashlib
import json

from verion.shared_kernel.scanner_tools import ScannerTool

# Bumped only when the algorithm or the input set below changes. It is part of
# the stored value, so a v1 hash can never silently compare equal to a v2 one —
# the comparison fails loudly instead of matching the wrong finding.
#
# What a bump costs, recorded here because it is the whole reason the prefix
# exists: every stored dedup_hash is invalidated. The migration is
# RE-NORMALIZATION from ScanResult.raw_output, which works only because those
# rows are keyed (scan_id, tool) and are never deleted — every past scan's tool
# output is still on disk, so findings and sightings can be re-derived with no
# lossy back-fill. A future retention policy on ScanResult would quietly remove
# that property, which is why it is written down rather than assumed.
DEDUP_HASH_VERSION = "v1"


def compute_dedup_hash(
    *,
    source: ScannerTool,
    rule_id: str,
    file_path: str | None,
    package: str | None,
    url: str | None,
    http_method: str | None,
    parameter: str | None,
) -> str:
    """The identity of a finding, as one function over the common schema.

    **One function, not three.** Per-tool hash functions would break rule 4 and,
    worse, leave M5 correlating over keys with no shared definition. The three
    tools' identity candidates are different shapes — Semgrep's `check_id` plus a
    path, Trivy's `VulnerabilityID` plus a package, ZAP's `alertRef` plus a URL —
    but that difference is a *mapping* concern, and mapping is already the
    mappers' job. Each one normalizes its tool's identifier into `rule_id` and
    its locator into the `Location` fields below; this function never learns a
    tool name, it takes `source` as data. Adding a scanner means writing a
    mapper, not editing identity logic.

    **The parameters are the input set, deliberately.** Taking a `Location` would
    hide which of its eight fields participate, and three of them explicitly do
    not — see below. Naming them one by one makes the contract the signature.

    What is IN, and what each tool contributes:

    | input         | Semgrep            | Trivy              | ZAP                    |
    |---------------|--------------------|--------------------|------------------------|
    | source        | semgrep            | trivy              | zap                    |
    | rule_id       | check_id           | VulnerabilityID    | alertRef, else pluginid|
    | file_path     | repo-relative path | Results[].Target   | None                   |
    | package       | None               | PkgName            | None                   |
    | url           | None               | None               | instance uri, else site|
    | http_method   | None               | None               | instance method        |
    | parameter     | None               | None               | instance param         |

    What is OUT, and why — each of these is a real judgement, recorded in
    ADR-0019 with the measurement behind it:

    - `start_line`/`end_line`: an edit *above* a finding shifts it, so including
      them would make an untouched vulnerability look new after any refactor —
      failing M4.2's own criterion in the most ordinary case there is, and making
      M9.1 report a resolve-plus-reopen that never happened. The cost is that two
      matches of one rule in one file collapse into one Finding; that
      under-counts, where including would *fabricate* events. The discriminator
      that would fix it — a hash of the matched source line — is unavailable:
      Semgrep's `extra.lines` is the literal "requires login" (G7).
    - `installed_version`: bumping a package from one vulnerable version to
      another vulnerable one is not a new finding. When a bump actually
      remediates, the tool stops reporting the CVE and the finding stops being
      sighted, which is the correct signal.
    - `severity`, `native_severity`, `cvss`, `cwe`, `owasp_category`, `title`:
      all advisory- or ruleset-mutable. Trivy carries `LastModifiedDate` on every
      vulnerability for exactly this reason. Including any of them would re-key a
      finding on an NVD rescore.
    - `project_id`: the scope, not the identity. Two projects with the same
      vulnerable dependency produce the same hash; uniqueness is
      `(project_id, dedup_hash)` at the persistence layer (M4.3). Conflating the
      two would make the hash unusable for the cross-project question and gain
      only an index column.

    SHA-256 over a canonical JSON array. Not a security boundary — the
    requirement is collision resistance over short structured strings and
    reproducibility across processes and releases. JSON rather than a
    separator-joined string because the values are paths, URLs and parameter
    names, so no separator is safe by inspection; JSON is unambiguous by
    construction, and `None` encodes as `null`, which stays distinct from `""` —
    the same "a field with no source is not an empty value" rule the rest of the
    schema keeps. Emphatically not Python's `hash()`, which is randomized per
    process and would produce a table whose keys stop matching after a restart.
    """
    payload = json.dumps(
        [str(source), rule_id, file_path, package, url, http_method, parameter],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{DEDUP_HASH_VERSION}:{digest}"
