from enum import StrEnum


class ScannerTool(StrEnum):
    """The canonical scanner-identity vocabulary, shared between the module
    that *configures* scanners (`projects`, via `ScannerConfig.enabled_tools`)
    and the module that *runs* them (`scanning`, via `ScannerPort.tool` and the
    worker's scanner registry).

    It lives in `shared_kernel/` rather than in either module because both need
    to agree on it and neither may import the other's `domain/` (rule 3). The
    alternative — each module keeping its own literal set of tool names — puts
    the same three strings in two places, where adding a scanner means
    remembering to edit both and nothing catches it if you don't.

    Deliberately not a registry of adapters: this is the name, nothing else.
    Which adapter implements a name is `platform/worker.py`'s wiring concern,
    and what a name is capable of is `ScannerPort.target_kind`'s.
    """

    SEMGREP = "semgrep"
    TRIVY = "trivy"
    ZAP = "zap"
