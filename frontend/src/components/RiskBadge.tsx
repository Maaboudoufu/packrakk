export default function RiskBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) {
    return <span className="text-muted text-xs">n/a</span>;
  }
  const { label, cls } = riskMeta(score);
  return (
    <span className={`inline-flex items-center gap-1 text-xs rounded-md px-2 py-0.5 border ${cls}`}>
      <span className="font-mono font-semibold">{score.toFixed(0)}</span>
      <span className="hidden sm:inline">{label}</span>
    </span>
  );
}

function riskMeta(score: number): { label: string; cls: string } {
  if (score >= 90)
    return { label: "Urgent", cls: "bg-red-500/15 text-red-300 border-red-500/40" };
  if (score >= 70)
    return { label: "High priority", cls: "bg-orange-500/15 text-orange-300 border-orange-500/40" };
  if (score >= 45)
    return { label: "Medium priority", cls: "bg-yellow-500/15 text-yellow-200 border-yellow-500/40" };
  if (score >= 20)
    return { label: "Low priority", cls: "bg-sky-500/15 text-sky-300 border-sky-500/40" };
  return { label: "Informational", cls: "bg-slate-500/15 text-slate-300 border-slate-500/40" };
}
