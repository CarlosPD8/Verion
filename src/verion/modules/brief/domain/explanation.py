from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Explanation:
    """A narrative of an already-decided priority, and what produced it.

    **Text only; no priority, no score, no confidence.** The Explanation Layer narrates a
    decision the Risk Engine already made and has no field through which to restate or
    alter it (rule 6, ADR-0004).

    `model` is the id the provider REPORTS having run, which may differ from the one
    requested (an alias resolving to a snapshot). `prompt_version` names the prompt that
    produced `text`. Both exist so a narrative M7.2 persists stays traceable to its
    producer — `ARCHITECTURE.md` §4.1's "generated but inspectable" (ADR-0032).
    """

    text: str
    model: str
    prompt_version: str
