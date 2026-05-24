import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type { ScanDetail } from "../types";
import ComponentTable from "../components/ComponentTable";
import RiskBadge from "../components/RiskBadge";
import SeverityChart from "../components/SeverityChart";
import StatCard from "../components/StatCard";
import VulnerabilityTable from "../components/VulnerabilityTable";

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let active = true;
    const load = () =>
      api
        .getScan(id)
        .then((d) => active && setDetail(d))
        .catch((e: Error) => active && setErr(e.message));
    load();
    const t = setInterval(() => {
      if (detail && (detail.status === "completed" || detail.status === "failed")) {
        return;
      }
      load();
    }, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [id, detail?.status]);

  if (err) return <div className="text-red-400 text-sm">Error: {err}</div>;
  if (!detail) return <div className="text-muted text-sm">loading…</div>;

  const sc = detail.severity_counts;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <Link to="/" className="text-xs text-accent hover:underline">
            ← back to dashboard
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight mt-1">
            {detail.project_name}
          </h1>
          <p className="text-sm text-muted font-mono">{detail.target_value}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusPill status={detail.status} />
          <RiskBadge score={detail.risk_score} />
        </div>
      </div>

      {detail.error_message && (
        <div className="rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-4 py-3 text-xs text-yellow-200">
          <span className="font-semibold">Scanner warnings:</span>{" "}
          {detail.error_message}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <StatCard label="Components" value={detail.component_count} />
        <StatCard label="Vulnerabilities" value={detail.vulnerability_count} />
        <StatCard
          label="Critical"
          value={sc.critical}
          tone={sc.critical ? "critical" : "default"}
        />
        <StatCard label="High" value={sc.high} tone={sc.high ? "high" : "default"} />
        <StatCard
          label="Fixable"
          value={detail.fixable_count}
          tone={detail.fixable_count ? "ok" : "default"}
        />
        <div className="rounded-xl border border-border bg-panel/60 p-4 flex flex-col gap-2">
          <div className="text-xs uppercase tracking-wider text-muted">Reports</div>
          <div className="flex gap-2 flex-wrap text-xs">
            <ReportLink
              available={detail.sbom_available}
              href={api.reportUrl(detail.id, "sbom")}
              label="SBOM"
            />
            <ReportLink
              available={detail.grype_available}
              href={api.reportUrl(detail.id, "grype")}
              label="Grype"
            />
            <ReportLink
              available={detail.trivy_available}
              href={api.reportUrl(detail.id, "trivy")}
              label="Trivy"
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <VulnerabilityTable scanId={detail.id} />
        </div>
        <div className="space-y-6">
          <SeverityChart counts={sc} />
          <TopPackages
            items={detail.top_packages}
          />
        </div>
      </div>

      <ComponentTable scanId={detail.id} />
    </div>
  );
}

function StatusPill({ status }: { status: ScanDetail["status"] }) {
  const cls: Record<ScanDetail["status"], string> = {
    queued: "bg-slate-500/15 text-slate-300 border-slate-500/40",
    running: "bg-sky-500/15 text-sky-300 border-sky-500/40",
    completed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    failed: "bg-red-500/15 text-red-300 border-red-500/40",
  };
  return (
    <span className={`px-3 py-1 rounded-full text-xs border ${cls[status]}`}>
      {status}
    </span>
  );
}

function ReportLink({
  available,
  href,
  label,
}: {
  available: boolean;
  href: string;
  label: string;
}) {
  if (!available) {
    return (
      <span className="px-2 py-1 rounded-md border border-border text-muted">
        {label}: n/a
      </span>
    );
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="px-2 py-1 rounded-md border border-accent/40 text-accent hover:bg-accent/10"
    >
      {label} JSON
    </a>
  );
}

function TopPackages({ items }: { items: { package: string; count: number }[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-panel/60 p-4 text-sm text-muted">
        No top packages.
      </div>
    );
  }
  return (
    <div className="rounded-xl border border-border bg-panel/60 p-4">
      <div className="text-sm font-medium mb-3">Top vulnerable packages</div>
      <ul className="space-y-2">
        {items.map((it) => (
          <li
            key={it.package}
            className="flex items-center justify-between text-sm"
          >
            <span className="truncate mr-2">{it.package}</span>
            <span className="font-mono text-xs text-muted">{it.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
