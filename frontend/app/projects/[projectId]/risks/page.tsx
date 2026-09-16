"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  fetchScoredRisks,
  PAGE_LIMIT,
  type ScoredRisk,
  type ScoredRisks,
  type Signal,
} from "../../../../lib/api";
import { getAccessToken, setAccessToken, setLastProjectId } from "../../../../lib/session";

type Thresholds = ScoredRisks["thresholds"];

// Tier order is the page's order. The mark carries the tier by shape and count, so a reader
// who cannot tell the colours apart still reads three tiers.
const BUCKETS = [
  { key: "fix_now", label: "Fix now", mark: "●●●" },
  { key: "plan", label: "Plan", mark: "●●○" },
  { key: "monitor", label: "Monitor", mark: "●○○" },
] as const;

const SIGNAL_LABELS = ["Severity", "Exposure", "Corroboration"] as const;

type ViewState =
  | { kind: "loading" }
  | { kind: "ok"; data: ScoredRisks }
  | { kind: "not_found" }
  | { kind: "error" };

export default function ProjectRisksPage() {
  const router = useRouter();
  const params = useParams<{ projectId: string }>();
  const projectId = params.projectId;
  const [offset, setOffset] = useState(0);
  const [view, setView] = useState<ViewState>({ kind: "loading" });

  useEffect(() => {
    setLastProjectId(projectId);
    const token = getAccessToken();
    if (token === null) {
      router.replace("/");
      return;
    }
    let cancelled = false;
    setView({ kind: "loading" });
    fetchScoredRisks(token, projectId, offset).then((result) => {
      if (cancelled) {
        return;
      }
      if (result.kind === "unauthorized") {
        setAccessToken(null);
        router.replace("/");
        return;
      }
      setView(result.kind === "ok" ? { kind: "ok", data: result.data } : { kind: result.kind });
    });
    return () => {
      cancelled = true;
    };
  }, [projectId, offset, router]);

  return (
    <main className="page">
      <header className="page-header">
        <p className="eyebrow">
          Project <span className="data">{projectId}</span>
        </p>
        <h1 className="page-title">Ranked Risks</h1>
      </header>
      {view.kind === "loading" && <p className="page-count">Loading Risks…</p>}
      {view.kind === "not_found" && (
        <p className="form-error" role="alert">
          No project with this id is visible to you. It may not exist, or you may not be a member.
        </p>
      )}
      {view.kind === "error" && (
        <p className="form-error" role="alert">
          The Risks couldn&apos;t be loaded. Reload the page to try again.
        </p>
      )}
      {view.kind === "ok" && <RiskList data={view.data} onPage={setOffset} />}
    </main>
  );
}

function RiskList({ data, onPage }: { data: ScoredRisks; onPage: (offset: number) => void }) {
  const first = data.items.length === 0 ? 0 : data.offset + 1;
  const last = data.offset + data.items.length;
  const { fix_now_at: fixNowAt, plan_at: planAt } = data.thresholds;
  const conditions = {
    fix_now: `score ≥ ${fixNowAt}`,
    plan: `${planAt} ≤ score < ${fixNowAt}`,
    monitor: `score < ${planAt}`,
  };
  return (
    <>
      <IncompletenessBanner normalization={data.normalization} />
      <div className="legend">
        {BUCKETS.map((bucket) => (
          <span key={bucket.key}>
            <span className="bucket-badge" data-bucket={bucket.key}>
              <span className="tier-mark" aria-hidden="true">
                {bucket.mark}
              </span>
              {bucket.label}
            </span>{" "}
            {conditions[bucket.key]}
          </span>
        ))}
      </div>
      {data.total > 0 && (
        <p className="page-count">
          Items {first}–{last} of {data.total}, ranked by priority score
        </p>
      )}
      {data.items.length === 0 ? (
        <p className="empty-state">
          {data.normalization.latest_run === null
            ? "Nothing to rank until a scan has been normalized."
            : "No scored Risks in the findings normalized so far."}
        </p>
      ) : (
        BUCKETS.map((bucket) => {
          const ranked = data.items
            .map((item, index) => ({ item, rank: data.offset + index + 1 }))
            .filter(({ item }) => item.priority === bucket.key);
          if (ranked.length === 0) {
            return null;
          }
          return (
            <section className="bucket-section" key={bucket.key}>
              <h2 className="bucket-heading">
                <span className="bucket-badge" data-bucket={bucket.key}>
                  <span className="tier-mark" aria-hidden="true">
                    {bucket.mark}
                  </span>
                  {bucket.label}
                </span>
                <span className="bucket-count">
                  {ranked.length} on this page
                </span>
              </h2>
              {ranked.map(({ item, rank }) => (
                <RiskCard
                  key={item.finding_ids.join(",")}
                  item={item}
                  rank={rank}
                  thresholds={data.thresholds}
                />
              ))}
            </section>
          );
        })
      )}
      {(data.offset > 0 || last < data.total) && (
        <nav className="pager" aria-label="Pages">
          <button
            className="button"
            type="button"
            disabled={data.offset === 0}
            onClick={() => onPage(Math.max(0, data.offset - PAGE_LIMIT))}
          >
            Previous
          </button>
          <button
            className="button"
            type="button"
            disabled={last >= data.total}
            onClick={() => onPage(data.offset + PAGE_LIMIT)}
          >
            Next
          </button>
        </nav>
      )}
    </>
  );
}

// A ranked list that looks clean while normalizations failed is the failure the envelope
// exists to prevent (ADR-0022 decision 3), so this is not dismissible and sits above the list.
// It is a WARNING — the list may be short — and is styled as one, not as an error.
function IncompletenessBanner({ normalization }: { normalization: ScoredRisks["normalization"] }) {
  const { latest_run: latestRun, unfinished_runs: unfinishedRuns } = normalization;
  if (latestRun === null) {
    return (
      <div className="banner" role="alert">
        <p className="banner-title">No scan has been normalized for this project</p>
        <p>An empty list here means nothing has been scanned, not that nothing is wrong.</p>
      </div>
    );
  }
  if (unfinishedRuns === 0 && latestRun.status === "completed") {
    return null;
  }
  return (
    <div className="banner" role="alert">
      <p className="banner-title">This list may be incomplete</p>
      <p>
        {unfinishedRuns} scan{unfinishedRuns === 1 ? " has" : "s have"} not finished normalizing
        or failed to, so their findings may be missing. Latest normalization status:{" "}
        <span className="data">{latestRun.status}</span>.
      </p>
    </div>
  );
}

function bucketTest(score: number, priority: string, thresholds: Thresholds): string {
  if (priority === "fix_now") {
    return `${score} ≥ ${thresholds.fix_now_at}, so Fix now`;
  }
  if (priority === "plan") {
    return `${thresholds.plan_at} ≤ ${score} < ${thresholds.fix_now_at}, so Plan`;
  }
  return `${score} < ${thresholds.plan_at}, so Monitor`;
}

function RiskCard({ item, rank, thresholds }: { item: ScoredRisk; rank: number; thresholds: Thresholds }) {
  const bucket = BUCKETS.find((candidate) => candidate.key === item.priority);
  const kind =
    item.match.package !== null ? "Package" : item.match.url !== null ? "Route path" : "Location";
  const surface = item.match.package ?? item.match.url ?? "no shared package or route path";
  const signals: Signal[] = [
    item.reasoning.severity,
    item.reasoning.exposure,
    item.reasoning.corroboration,
  ];
  return (
    <article className="risk-card" data-bucket={item.priority}>
      <div className="risk-surface">
        <p className="eyebrow">
          #{rank} · {kind}
        </p>
        <p className="surface-name data">{surface}</p>
        <p className="surface-meta">
          {item.finding_count} finding{item.finding_count === 1 ? "" : "s"}
        </p>
        <p>
          <span className="bucket-badge" data-bucket={item.priority}>
            <span className="tier-mark" aria-hidden="true">
              {bucket?.mark ?? "○○○"}
            </span>
            {bucket?.label ?? item.priority}
          </span>
        </p>
      </div>
      <div className="ledger" aria-label={`Priority score ${item.priority_score}, worked`}>
        {signals.map((signal, index) => (
          <div className="signal-row" key={signal.name}>
            <span className="operator" aria-hidden="true">
              {index === 0 ? "" : "+"}
            </span>
            <span className="term">{signal.value}</span>
            <span className="signal-detail">
              <span className="signal-name">{SIGNAL_LABELS[index]}</span>
              {signal.produced_by.length > 0 && (
                <span className="finding-id">
                  from {signal.produced_by.join(", ")}
                </span>
              )}
              {signal.note !== null && <span className="signal-note">{signal.note}</span>}
            </span>
          </div>
        ))}
        <div className="ledger-total">
          <span className="operator" aria-hidden="true">
            =
          </span>
          <span className="term">{item.priority_score}</span>
          <span className="threshold">{bucketTest(item.priority_score, item.priority, thresholds)}</span>
        </div>
      </div>
    </article>
  );
}
