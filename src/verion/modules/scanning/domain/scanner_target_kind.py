from enum import StrEnum


class ScannerTargetKind(StrEnum):
    """What a scanner's `run(target)` argument actually is.

    `ScannerPort.run`'s docstring already recorded this asymmetry — a local
    checked-out path for repo-based scanners, a live URL for one that attacks a
    running application — but left every caller to know which is which. That
    was workable while `RunScanUseCase` held one hard-coded scanner; it is not
    once dispatch is generic.

    Carrying it as data on the port, rather than as a `tool == "zap"` branch
    inside the use case, is what keeps rule 4 satisfied: a new scanner declares
    its kind and dispatch needs no edit. See ADR-016 decision 4.
    """

    REPO_PATH = "repo_path"
    URL = "url"
