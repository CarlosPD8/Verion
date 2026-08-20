from pydantic import BaseModel


# Never the domain Scan directly (rule 10) — a dedicated, minimal ack body.
# GitHub doesn't parse this response; it exists for observability/manual
# testing, not for GitHub's own delivery-retry logic (that's driven by the
# HTTP status code alone).
class WebhookAckResponse(BaseModel):
    status: str
