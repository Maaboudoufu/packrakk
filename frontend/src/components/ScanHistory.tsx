import { Link } from "react-router-dom";
import type { ScanSummary } from "../types";
import RiskBadge from "./RiskBadge";

function StatusPill({ status }: { status: ScanSummary["status"] }) {
  const cls: Record<ScanSummary["status"], string> = {
    queued: "bg-slate-500/15 text-slate-300 border-slate-500/40",
    running: "bg-sky-500/15 text-sky-300 border-sky-500/40",
    completed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    failed: "bg-red-500/15 text-red-300 border-red-500/40",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs border ${cls[status]}`}>
      {status}
    </span>
  );
}

function formatTime(t: string | null) {
  if (!t) return "—";
  try {
    return new Date(t).toLocaleString();
  } catch {
    return t;
  }
}

export default function ScanHistory({ scans }: { scans: ScanSummary[] }) {
  if (scans.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-panel/60 p-6 text-center text-sm text-muted">
        No scans yet. Run your first scan above.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-panel/60 overflow-hidden">
      <div className="px-4 py-3 border-b border-border text-sm font-medium">
        Recent scans
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-panel2 text-xs uppercase tracking-wider text-muted">
            <tr>
              <th className="text-left px-4 py-2">Name</th>
              <th className="text-left px-4 py-2">Target</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Started</th>
              <th className="text-left px-4 py-2">Finished</th>
              <th className="text-left px-4 py-2">Risk</th>
              <th className="text-left px-4 py-2">Crit / High</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr
                key={s.id}
                className="border-t border-border hover:bg-panel2/60"
              >
                <td className="px-4 py-2">
                  <Link
                    className="text-accent hover:underline"
                    to={`/scans/${s.id}`}
                  >
                    {s.project_name}
                  </Link>
                </td>
                <td className="px-4 py-2 font-mono text-xs">{s.target_value}</td>
                <td className="px-4 py-2">
                  <StatusPill status={s.status} />
                </td>
                <td className="px-4 py-2 text-xs text-muted">
                  {formatTime(s.started_at)}
                </td>
                <td className="px-4 py-2 text-xs text-muted">
                  {formatTime(s.finished_at)}
                </td>
                <td className="px-4 py-2">
                  <RiskBadge score={s.risk_score} />
                </td>
                <td className="px-4 py-2">
                  <span className="text-red-300">{s.severity_counts.critical}</span>{" "}
                  /{" "}
                  <span className="text-orange-300">{s.severity_counts.high}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
