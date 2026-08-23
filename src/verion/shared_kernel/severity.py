from enum import StrEnum

# Sort position, lowest to highest. Deliberately NOT a risk score and never an
# input to one: it is an ordinal index into the scale below, so that ordering a
# list of findings is well defined. `risk_engine` scores by reading the member
# (rule 5 — scoring stays traceable to explicit inputs); a bare integer that
# looked like a severity weight is exactly what that rule exists to prevent.
#
# UNKNOWN sits at the bottom because a total order needs it somewhere, and that
# placement is a display convention, not a judgment that an unknown severity is
# the least dangerous one. M6 must decide what UNKNOWN means to a score
# explicitly — treating it as "lowest" by letting it sort to the bottom would be
# deciding it by accident.
_RANK: dict[str, int] = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


class Severity(StrEnum):
    """The normalized severity scale, shared across every module downstream of
    `normalization`.

    Semgrep, Trivy and ZAP each use a different, incompatible scale; the
    per-scanner mappers in `normalization/domain/mappers/` collapse all three
    into this one. `Finding.native_severity` carries the tool's literal value
    alongside it, so the collapse is lossy for ordering but not for provenance.
    See ADR-0018 for the mapping table and what it discards.

    It lives in `shared_kernel/` under the criterion ADR-0018 states and
    `ARCHITECTURE.md` §7 records: this package takes closed vocabularies two or
    more modules must **compare or order**, not merely transport. `normalization`
    constructs a Severity, `risk_engine` orders by it for
    `RiskReasoning.severity_signal`, M5 ranks correlated findings and M8 filters
    on it — and none of those may import `normalization`'s domain (rule 3).

    **Ordering is by severity, not by the string value, and that is the whole
    reason the comparison operators are overridden below.** A plain StrEnum
    inherits str's ordering, under which `Severity.HIGH >= Severity.CRITICAL` is
    True — "high" sorts after "critical" alphabetically. That comparison is the
    exact expression ADR-0018 argues this type exists to make possible, and
    inheriting it silently wrong would put a lie in `risk_engine`, the module
    CLAUDE.md singles out for disproportionate test rigor.

    Equality is untouched: `Severity.HIGH == "high"` is still True, which is what
    keeps persistence and JSON serialization working like every other StrEnum in
    this project (`ScanStatus`, `ScanResultStatus`, `ScannerTool`).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Ordinal position in the scale. See `_RANK` for why this is not a score."""
        return _RANK[self.value]

    # Ordering is defined only against another Severity. A non-Severity operand
    # raises rather than returning NotImplemented, which is a deliberate
    # deviation from the usual convention: Severity subclasses str, so
    # NotImplemented would let Python fall back to the reflected str comparison
    # and silently reintroduce alphabetical ordering — the precise bug these
    # four methods exist to prevent, arriving through the back door.
    #
    # `other: object` rather than `Severity` because narrowing a parameter below
    # what str declares violates the Liskov substitution principle and mypy
    # --strict rejects it. Widening is the correct direction, and the isinstance
    # check is what actually enforces the contract.
    #
    # Both operand orders are covered by these four, verified rather than
    # assumed: Python gives a subclass's reflected method priority, so
    # `"high" > Severity.HIGH` routes to Severity.__lt__ and raises too.
    def __lt__(self, other: object) -> bool:
        return self.rank < _as_severity(other).rank

    def __le__(self, other: object) -> bool:
        return self.rank <= _as_severity(other).rank

    def __gt__(self, other: object) -> bool:
        return self.rank > _as_severity(other).rank

    def __ge__(self, other: object) -> bool:
        return self.rank >= _as_severity(other).rank


def _as_severity(value: object) -> Severity:
    if not isinstance(value, Severity):
        raise TypeError(f"Severity is only ordered against Severity, not {type(value).__name__}")
    return value
