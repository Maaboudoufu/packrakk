export default function SeverityBadge({ value }: { value: string | null }) {
  const label = value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : "Unknown";
  const cls = severityClass(label);
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded-full text-xs border ${cls}`}
    >
      {label}
    </span>
  );
}

function severityClass(label: string): string {
  switch (label.toLowerCase()) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-unknown";
  }
}
