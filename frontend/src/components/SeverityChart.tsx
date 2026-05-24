import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { SeverityCounts } from "../types";

const COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#0ea5e9",
  Unknown: "#64748b",
};

export default function SeverityChart({ counts }: { counts: SeverityCounts }) {
  const data = [
    { name: "Critical", value: counts.critical, fill: COLORS.Critical },
    { name: "High", value: counts.high, fill: COLORS.High },
    { name: "Medium", value: counts.medium, fill: COLORS.Medium },
    { name: "Low", value: counts.low, fill: COLORS.Low },
    { name: "Unknown", value: counts.unknown, fill: COLORS.Unknown },
  ];

  return (
    <div className="rounded-xl border border-border bg-panel/60 p-4">
      <div className="text-sm font-medium mb-2">Severity breakdown</div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2a4a" />
            <XAxis dataKey="name" stroke="#8b95b2" tick={{ fontSize: 12 }} />
            <YAxis stroke="#8b95b2" tick={{ fontSize: 12 }} allowDecimals={false} />
            <Tooltip
              contentStyle={{
                background: "#11172b",
                border: "1px solid #1f2a4a",
                borderRadius: 8,
              }}
              labelStyle={{ color: "#cbd5e1" }}
            />
            <Bar dataKey="value" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
