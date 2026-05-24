type Tone = "default" | "critical" | "high" | "ok" | "warn";

const toneClasses: Record<Tone, string> = {
  default: "border-border",
  critical: "border-red-500/40 bg-red-500/5",
  high: "border-orange-500/40 bg-orange-500/5",
  warn: "border-yellow-500/40 bg-yellow-500/5",
  ok: "border-emerald-500/40 bg-emerald-500/5",
};

export default function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: Tone;
}) {
  return (
    <div
      className={`rounded-xl border bg-panel/60 p-4 ${toneClasses[tone]} transition`}
    >
      <div className="text-xs uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {hint && <div className="text-xs text-muted mt-1">{hint}</div>}
    </div>
  );
}
