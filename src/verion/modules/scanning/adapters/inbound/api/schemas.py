from pydantic import BaseModel


# Never the domain Scan directly (rule 10) — a dedicated, minimal ack body.
# GitHub doesn't parse this response; it exists for observability/manual
# testing, not for GitHub's own delivery-retry logic (that's driven by the
# HTTP status code alone).
class WebhookAckResponse(BaseModel):
    status: str


class ScanAcceptedResponse(BaseModel):
    """`POST /projects/{project_id}/scans`'s 202 body (ADR-0035 decision 1).

    The id, because a caller cannot poll a scan it cannot address; the status, which is
    always `pending` on this path. Rule 10: never the domain `Scan`, whose `triggered_by`
    and timestamps this route has no reason to return. The key set is pinned by an
    equality assertion in `tests/integration/test_scan_routes.py`.
    """

    id: str
    status: str


class ScanResponse(BaseModel):
    """`GET /projects/{project_id}/scans/{scan_id}` (ADR-0035 decision 4).

    `failure_reason` is the scan-level reason, set only when a scan failed before any tool
    ran (`Scan`'s docstring). It is git's stderr for a failed checkout, redacted of the
    access token and the checkout directory and of nothing else: a deny-list, **G89**.
    """

    id: str
    status: str
    failure_reason: str | None
