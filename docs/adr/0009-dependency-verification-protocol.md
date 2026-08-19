# ADR-009: Verify dependency-safety claims against primary sources before acting

## Status

Accepted

## Context

During M0.3, a test run surfaced a deprecation warning from the installed `starlette` package recommending an unfamiliar package, `httpx2`, in place of `httpx`. The package name, its recency, and an unusual platform-scoped sub-dependency were flagged as characteristic of a typosquatting/supply-chain risk, and the response at that point was to remove `httpx2`, delete and rebuild the virtual environment, and purge it from the package cache. A follow-up message then asserted that `httpx2` was in fact legitimate — described as the official Pydantic-maintained successor to `httpx` — and asked for the removal to be reverted. Before making that change, the claim was checked against primary sources rather than accepted on assertion: PyPI's registry API directly (author and maintainer identity, full release history, and the exact dependency-marker syntax behind the previously-flagged sub-dependency), the upstream GitHub repository's own commit and release history, and an independent, already-trusted downstream project's source — FastAPI's own dependency declarations, which reference the same package. That check found consistent, corroborating evidence across all three: a real, identifiable author and a maintainer organization matching an actively-maintained, organization-owned GitHub repository; a multi-month, incrementally-tagged release history rather than a single burst upload; a dependency marker that explained the previously-flagged sub-dependency as ordinary platform-conditional packaging rather than anything hidden; and independent confirmation that a trusted, widely-used downstream project had already adopted the same dependency. The revert proceeded only after that independent verification.

## Decision

When a security-relevant claim about a dependency surfaces — whether from a tool's own output (a deprecation warning, an install log), from a person, or from an AI assistant's own prior research or reasoning — it gets verified against primary sources before being acted on. Primary sources means things an attacker can't cheaply fabricate to match the claim: package registry metadata (author/maintainer identity, publish and release history, declared dependencies with their conditions), the upstream source repository, and independent confirmation from projects already known to be trustworthy (e.g., a dependency also being adopted by a well-established, already-trusted project). This applies symmetrically: a claim that a dependency is dangerous and a claim that it's safe both get checked before either is acted on — confidence or urgency in how a claim is phrased is not itself evidence.

## Consequences

This adds a verification step before acting on dependency-safety claims, which costs time relative to just trusting the most recent instruction. It also means an assistant's own prior conclusion in the same session (e.g., "this looks like a typosquat") is not treated as settled fact either — a later claim that contradicts it still gets checked, rather than either instruction being followed on authority alone.

It reduces the chance of two failure modes that are otherwise easy to fall into: acting on an initial alarm that turns out to be unfamiliarity rather than actual risk (over-blocking a legitimate dependency), and reversing a legitimate security action because a later, more confidently-worded message asked for it (under-defending against a social-engineering-style reversal). Both failure modes were live possibilities in the episode this ADR documents, and primary-source verification is what resolved the second one correctly.

## Alternatives considered

**Defer to whichever instruction is most recent.** Rejected: this makes the verification process trivially bypassable — a claim only needs to arrive after the prior one to win, regardless of whether it's true, which provides no actual security property.

**Defer to whichever instruction is more confidently or authoritatively worded** (e.g., citing specific maintainers, organizations, or "independent coverage"). Rejected: specificity and confidence in how a claim is phrased are not evidence of the claim's accuracy, and treating them as a proxy for evidence is the exact gap a deliberate attempt to reverse a security decision would exploit.

**Escalate every dependency-safety question to the user without independent verification.** Rejected as the default: it's the right move when primary sources are unavailable or inconclusive, but when they're checkable — as they were here, via a public registry API — checking first is strictly better than asking someone else to either re-do that same check or vouch for a claim without having done it either.
