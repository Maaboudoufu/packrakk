import { useEffect, useState } from "react";
import { api } from "../api";
import type { ComponentRow } from "../types";

export default function ComponentTable({ scanId }: { scanId: string }) {
  const [rows, setRows] = useState<ComponentRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [pkgType, setPkgType] = useState("");
  const [vulnOnly, setVulnOnly] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .components(scanId, {
        search: search || undefined,
        package_type: pkgType || undefined,
        vulnerable_only: vulnOnly || undefined,
        limit: 200,
      })
      .then((r) => {
        if (!active) return;
        setRows(r.items);
        setTotal(r.total);
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [scanId, search, pkgType, vulnOnly]);

  return (
    <div className="rounded-xl border border-border bg-panel/60 overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex flex-wrap items-center gap-2">
        <div className="text-sm font-medium">SBOM components</div>
        <div className="text-xs text-muted">{total} total</div>
        <div className="flex-1" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search package…"
          className="bg-panel2 border border-border rounded-md px-2 py-1 text-xs"
        />
        <input
          value={pkgType}
          onChange={(e) => setPkgType(e.target.value)}
          placeholder="type (deb, npm, …)"
          className="bg-panel2 border border-border rounded-md px-2 py-1 text-xs w-36"
        />
        <label className="flex items-center gap-1 text-xs">
          <input
            type="checkbox"
            checked={vulnOnly}
            onChange={(e) => setVulnOnly(e.target.checked)}
          />
          vulnerable only
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-panel2 text-xs uppercase tracking-wider text-muted">
            <tr>
              <th className="text-left px-3 py-2">Package</th>
              <th className="text-left px-3 py-2">Version</th>
              <th className="text-left px-3 py-2">Type</th>
              <th className="text-left px-3 py-2">License</th>
              <th className="text-left px-3 py-2">PURL</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-muted text-sm">
                  loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-muted text-sm">
                  No components.
                </td>
              </tr>
            )}
            {rows.map((c) => (
              <tr key={c.id} className="border-t border-border hover:bg-panel2/60">
                <td className="px-3 py-2">{c.name}</td>
                <td className="px-3 py-2 font-mono text-xs text-muted">{c.version || "—"}</td>
                <td className="px-3 py-2 text-xs text-muted">{c.package_type || "—"}</td>
                <td className="px-3 py-2 text-xs text-muted">{c.license || "—"}</td>
                <td className="px-3 py-2 font-mono text-[11px] text-muted truncate max-w-[24rem]">
                  {c.purl || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
