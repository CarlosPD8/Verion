// Every call goes to /api/* on this origin; next.config.mjs rewrites it to the API
// (ADR-0031 decision 2). The types mirror the API's response schemas as read from
// `identity`'s LoginResponse and `risk_engine`'s ScoredProjectRisksResponse.

// The API's MAX_PAGE_LIMIT for this route.
export const PAGE_LIMIT = 200;

export type Signal = {
  name: string;
  value: number;
  produced_by: string[];
  note: string | null;
};

export type ScoredRisk = {
  match: { package: string | null; url: string | null };
  finding_ids: string[];
  finding_count: number;
  priority_score: number;
  priority: string;
  reasoning: { severity: Signal; exposure: Signal; corroboration: Signal };
};

export type NormalizationRun = {
  scan_id: string;
  status: string;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  failure_reason: string | null;
};

export type ScoredRisks = {
  items: ScoredRisk[];
  total: number;
  limit: number;
  offset: number;
  thresholds: { fix_now_at: number; plan_at: number };
  normalization: { latest_run: NormalizationRun | null; unfinished_runs: number };
};

export type LoginResult = { kind: "ok"; token: string } | { kind: "invalid" } | { kind: "error" };

export type ScoredRisksResult =
  | { kind: "ok"; data: ScoredRisks }
  | { kind: "unauthorized" }
  | { kind: "not_found" }
  | { kind: "error" };

export async function login(email: string, password: string): Promise<LoginResult> {
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (response.status === 401) {
      return { kind: "invalid" };
    }
    if (!response.ok) {
      return { kind: "error" };
    }
    const body = (await response.json()) as { access_token: string };
    return { kind: "ok", token: body.access_token };
  } catch {
    return { kind: "error" };
  }
}

export async function fetchScoredRisks(
  token: string,
  projectId: string,
  offset: number,
): Promise<ScoredRisksResult> {
  const query = new URLSearchParams({ limit: String(PAGE_LIMIT), offset: String(offset) });
  try {
    const response = await fetch(
      `/api/projects/${encodeURIComponent(projectId)}/scored-risks?${query}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (response.status === 401) {
      return { kind: "unauthorized" };
    }
    // The API answers 404 both for a project that does not exist and for one the user
    // may not read (ADR-0022 decision 2), so this result deliberately cannot say which.
    if (response.status === 404) {
      return { kind: "not_found" };
    }
    if (!response.ok) {
      return { kind: "error" };
    }
    return { kind: "ok", data: (await response.json()) as ScoredRisks };
  } catch {
    return { kind: "error" };
  }
}
