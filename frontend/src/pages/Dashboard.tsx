import { useEffect, useState } from "react";
import { api } from "../api";
import type { ScanSummary, SeverityCounts } from "../types";
import ScanForm from "../components/ScanForm";
import ScanHistory from "../components/ScanHistory";
import SeverityChart from "../components/SeverityChart";
import StatCard from "../components/StatCard";
import RiskBadge from "../components/RiskBadge";

const EMPTY_SEV: SeverityCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  unknown: 0,
};

export default function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const load = () =>
      api.listScans().then((s) => {
        if (active) {
          setScans(s);
          setLoading(false);
        }
      });
    load();
    const id = setInterval(load, 5000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const latest = scans[0];
  const severity = latest?.severity_counts ?? EMPTY_SEV;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted">
            Scan Docker images for SBOMs, CVEs, and risk.
          </p>
        </div>
      </div>

      <ScanForm />

      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <StatCard label="Total scans" value={scans.length} />
        <StatCard
          label="Components"
          value={latest?.component_count ?? 0}
          hint={latest ? `latest: ${latest.project_name}` : undefined}
        />
        <StatCard
          label="Critical"
          value={severity.critical}
          tone={severity.critical ? "critical" : "default"}
        />
        <StatCard
          label="High"
          value={severity.high}
          tone={severity.high ? "high" : "default"}
        />
        <StatCard
          label="Fixable"
          value={latest?.fixable_count ?? 0}
          tone={latest?.fixable_count ? "ok" : "default"}
        />
        <div className="rounded-xl border border-border bg-panel/60 p-4 flex flex-col justify-between">
          <div className="text-xs uppercase tracking-wider text-muted">
            Latest risk
          </div>
          <div className="mt-2">
            <RiskBadge score={latest?.risk_score ?? null} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          {loading ? (
            <div className="rounded-xl border border-border bg-panel/60 p-6 text-sm text-muted">
              loading…
            </div>
          ) : (
            <ScanHistory scans={scans} />
          )}
        </div>
        <SeverityChart counts={severity} />
      </div>
    </div>
  );
}
