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

const BUCKET_LABELS: Record<string, string> = {
  fix_now: "Fix now",
  plan: "Plan",
  monitor: "Monitor",
};

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
    <main>
      <h1>Risks for project {projectId}</h1>
      {view.kind === "loading" && <p>Loading…</p>}
      {view.kind === "not_found" && (
        <p role="alert">This project was not found, or you are not a member of it.</p>
      )}
      {view.kind === "error" && <p role="alert">The Risks could not be loaded. Try again.</p>}
      {view.kind === "ok" && <RiskList data={view.data} onPage={setOffset} />}
    </main>
  );
}

function RiskList({ data, onPage }: { data: ScoredRisks; onPage: (offset: number) => void }) {
  const first = data.items.length === 0 ? 0 : data.offset + 1;
  const last = data.offset + data.items.length;
  return (
    <>
      <IncompletenessBanner normalization={data.normalization} />
      <p>
        Buckets: Fix now at a score of {data.thresholds.fix_now_at} or more; Plan at{" "}
        {data.thresholds.plan_at} or more; Monitor below {data.thresholds.plan_at}.
      </p>
      <p>
        Items {first}–{last} of {data.total}
      </p>
      {data.items.length === 0 ? (
        <p>
          {data.normalization.latest_run === null
            ? "No scan has been normalized yet."
            : "No scored Risks in the findings normalized so far."}
        </p>
      ) : (
        <ol start={first}>
          {data.items.map((item) => (
            <RiskItem key={item.finding_ids.join(",")} item={item} />
          ))}
        </ol>
      )}
      <nav>
        <button
          type="button"
          disabled={data.offset === 0}
          onClick={() => onPage(Math.max(0, data.offset - PAGE_LIMIT))}
        >
          Previous
        </button>
        <button
          type="button"
          disabled={last >= data.total}
          onClick={() => onPage(data.offset + PAGE_LIMIT)}
        >
          Next
        </button>
      </nav>
    </>
  );
}

// A ranked list that looks clean while normalizations failed is the failure the envelope
// exists to prevent (ADR-0022 decision 3), so this is not dismissible and sits above the list.
function IncompletenessBanner({ normalization }: { normalization: ScoredRisks["normalization"] }) {
  const { latest_run: latestRun, unfinished_runs: unfinishedRuns } = normalization;
  if (latestRun === null) {
    return (
      <p role="alert">
        No scan has been normalized for this project. An empty list here means nothing has been
        scanned, not that nothing is wrong.
      </p>
    );
  }
  if (unfinishedRuns === 0 && latestRun.status === "completed") {
    return null;
  }
  return (
    <p role="alert">
      This list may be incomplete: {unfinishedRuns} scan
      {unfinishedRuns === 1 ? " has" : "s have"} not finished normalizing or failed to, and their
      findings may be missing. Latest normalization status: {latestRun.status}.
    </p>
  );
}

function RiskItem({ item }: { item: ScoredRisk }) {
  const surface = item.match.package ?? item.match.url ?? "(no package or route path)";
  return (
    <li>
      <p>
        <strong>{BUCKET_LABELS[item.priority] ?? item.priority}</strong> — priority score{" "}
        {item.priority_score} — {surface} ({item.finding_count} finding
        {item.finding_count === 1 ? "" : "s"})
      </p>
      <table>
        <thead>
          <tr>
            <th scope="col">Signal</th>
            <th scope="col">Value</th>
            <th scope="col">Produced by (finding ids)</th>
            <th scope="col">Note</th>
          </tr>
        </thead>
        <tbody>
          <SignalRow signal={item.reasoning.severity} />
          <SignalRow signal={item.reasoning.exposure} />
          <SignalRow signal={item.reasoning.corroboration} />
        </tbody>
      </table>
    </li>
  );
}

function SignalRow({ signal }: { signal: Signal }) {
  return (
    <tr>
      <th scope="row">{signal.name}</th>
      <td>{signal.value}</td>
      <td>{signal.produced_by.length === 0 ? "—" : signal.produced_by.join(", ")}</td>
      <td>{signal.note ?? ""}</td>
    </tr>
  );
}
