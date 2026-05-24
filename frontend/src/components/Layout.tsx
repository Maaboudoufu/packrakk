import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { Health } from "../types";

export default function Layout({ children }: { children: React.ReactNode }) {
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch((e: Error) => setErr(e.message));
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-border bg-panel/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="size-7 rounded-md bg-accent/20 grid place-items-center text-accent font-bold">
              P
            </div>
            <div>
              <div className="font-semibold tracking-tight">PackRakk</div>
              <div className="text-xs text-muted -mt-0.5">
                supply chain security
              </div>
            </div>
          </Link>
          <div className="flex items-center gap-3 text-xs">
            {err && <span className="text-red-400">api: {err}</span>}
            {health && (
              <>
                <Pill ok={health.database === "ok"} label="db" />
                <Pill ok={health.tools.syft} label="syft" />
                <Pill ok={health.tools.grype} label="grype" />
                <Pill ok={health.tools.trivy} label="trivy" />
              </>
            )}
          </div>
        </div>
      </header>
      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-6">{children}</main>
      <footer className="border-t border-border py-4 text-center text-xs text-muted">
        PackRakk MVP
      </footer>
    </div>
  );
}

function Pill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`px-2 py-0.5 rounded-full border ${
        ok
          ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
          : "bg-red-500/10 text-red-300 border-red-500/30"
      }`}
    >
      {label}: {ok ? "ok" : "missing"}
    </span>
  );
}
