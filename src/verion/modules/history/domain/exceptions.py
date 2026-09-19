class HistoryError(Exception):
    """Base for this module's own errors, on `brief`'s `BriefError` precedent."""


class RiskDismissalAccessDenied(HistoryError):
    """The caller may not read this project's dismissals.

    Like the verdict beneath it (`ProjectAccessPort`), it does not distinguish "no such project"
    from "not a member", so a route answers 404 for both (ADR-0022 decision 2).
    """


class RiskDismissalNotFound(HistoryError):
    """No dismissal record with this id in this project. A record of another project is one.

    The caller is already known to be a member here, so this reveals nothing about the project
    (ADR-0035 decision 4's shape).
    """


class RiskAlreadyDismissed(HistoryError):
    """An active snapshot already covers this surface (ADR-0036 decision 11).

    Carries the covering record's id, so the route can name the record a client would undo.
    """

    def __init__(self, covering_dismissal_id: str) -> None:
        super().__init__(f"Already dismissed by '{covering_dismissal_id}'")
        self.covering_dismissal_id = covering_dismissal_id


class RiskNotDismissed(HistoryError):
    """The record's latest event is already `undismissed`, so there is nothing to undo."""


class RiskEventConflict(HistoryError):
    """Another request appended this record's next event first (`UNIQUE(risk_id, ordinal)`).

    Nothing was written. Re-reading the record gives its current state.
    """
