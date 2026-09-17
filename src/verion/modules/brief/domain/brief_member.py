"""One member of a narrated surface, as `brief` may hold it: scalars, sanitized. ADR-0034.

**Scanned values enter `brief` only through this type.** (What a model then writes over them,
`SecurityBrief.what_happened`, is derived from them too.) `title` and the location
strings come from a scanned repository and are untrusted input to a model (`PRODUCT_SPEC.md`
§11.8). Cleaning happens here, in `domain/`, not in an adapter, so every provider receives
members that are already bounded and stripped.
"""

import unicodedata
from dataclasses import dataclass

from verion.shared_kernel.scanner_tools import ScannerTool

# ADR-0034 decision 4. Chosen so that no committed surface reaches any of them: the largest
# surface has 12 members, the longest title is 140 characters and the longest location string 51.
MAX_MEMBERS = 20
MAX_TITLE_CHARS = 200
MAX_LOCATION_CHARS = 120
TRUNCATION_MARKER = "[truncated]"

# Unicode control (Cc), format (Cf: bidi overrides, zero-width characters, BOM), line
# separator (Zl) and paragraph separator (Zp). None occurs in any committed typed field; all of
# them can reorder, hide or break up text a model reads.
_STRIPPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

# The line-breaking ones become a space rather than vanishing, so two words either side of a
# newline stay two words.
_BREAKS = frozenset({"\n", "\r", "\t", "\v", "\f", "\x85", "\u2028", "\u2029"})

_LOCATION_STRINGS = ("file_path", "package", "installed_version", "url", "http_method", "parameter")


def _is_stripped(character: str) -> bool:
    return unicodedata.category(character) in _STRIPPED_CATEGORIES


def _clean(value: str, *, cap: int) -> str:
    """M1 then M2: strip, then truncate to at most `cap` characters, marker included."""
    stripped = "".join(
        " " if character in _BREAKS else character
        for character in value.replace("\r\n", "\n")
        if character in _BREAKS or not _is_stripped(character)
    )
    if len(stripped) <= cap:
        return stripped
    return stripped[: cap - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _clean_optional(value: str | None, *, cap: int) -> str | None:
    return None if value is None else _clean(value, cap=cap)


@dataclass(frozen=True, kw_only=True)
class BriefMember:
    """`title` and `Location`'s eight fields, plus `finding_id` and `source`. Never a `Finding`.

    **`SurfaceMember`'s pattern, one module over.** `cross-module-brief` forbids
    `normalization.domain`, so `brief` holds its own type over scalars, filled at one site in
    `GenerateSecurityBriefUseCase` from `Finding` values taken by inference (ADR-0034 decision 2).
    **Every annotation copies `Finding`'s or `Location`'s without narrowing (G33)**, asserted by
    a test that derives them from both types.

    **Construct with `from_scalars`.** `__post_init__` refuses any string still carrying a
    stripped character or longer than its cap, so an unsanitized member cannot reach an adapter
    even when built directly. `finding_id` and `source` are Verion's: `finding_id` is never
    rendered, and `source` is rendered as the member's `scanner`.
    """

    finding_id: str
    source: ScannerTool
    title: str
    file_path: str | None
    start_line: int | None
    end_line: int | None
    package: str | None
    installed_version: str | None
    url: str | None
    http_method: str | None
    parameter: str | None

    @classmethod
    def from_scalars(
        cls,
        *,
        finding_id: str,
        source: ScannerTool,
        title: str,
        file_path: str | None,
        start_line: int | None,
        end_line: int | None,
        package: str | None,
        installed_version: str | None,
        url: str | None,
        http_method: str | None,
        parameter: str | None,
    ) -> "BriefMember":
        """The one sanctioned constructor: strips (M1) and truncates (M2) every scanned string."""
        return cls(
            finding_id=finding_id,
            source=source,
            title=_clean(title, cap=MAX_TITLE_CHARS),
            file_path=_clean_optional(file_path, cap=MAX_LOCATION_CHARS),
            start_line=start_line,
            end_line=end_line,
            package=_clean_optional(package, cap=MAX_LOCATION_CHARS),
            installed_version=_clean_optional(installed_version, cap=MAX_LOCATION_CHARS),
            url=_clean_optional(url, cap=MAX_LOCATION_CHARS),
            http_method=_clean_optional(http_method, cap=MAX_LOCATION_CHARS),
            parameter=_clean_optional(parameter, cap=MAX_LOCATION_CHARS),
        )

    def __post_init__(self) -> None:
        checked = [("title", self.title, MAX_TITLE_CHARS)] + [
            (name, getattr(self, name), MAX_LOCATION_CHARS) for name in _LOCATION_STRINGS
        ]
        for name, value, cap in checked:
            if value is None:
                continue
            # The messages name the field and never quote the value: it is scanned content.
            if any(_is_stripped(character) for character in value):
                raise ValueError(f"BriefMember.{name} carries a character sanitization strips")
            if len(value) > cap:
                raise ValueError(f"BriefMember.{name} is longer than its {cap}-character cap")

    def rendered_values(self) -> tuple[str, ...]:
        """Every scanned string a prompt shows for this member, as sent.

        Output validation compares against these, so it never rejects what a member supplied
        (ADR-0034 decision 5, M6).
        """
        names = ("title", *_LOCATION_STRINGS)
        return tuple(value for name in names if isinstance(value := getattr(self, name), str))
