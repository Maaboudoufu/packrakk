import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function ScanForm() {
  const navigate = useNavigate();
  const [name, setName] = useState("nginx demo");
  const [image, setImage] = useState("nginx:latest");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const res = await api.createScan({ name, target_value: image });
      navigate(`/scans/${res.scan_id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-xl border border-border bg-panel/60 p-4"
    >
      <div className="text-sm font-medium mb-3">Start a scan</div>
      <div className="grid grid-cols-1 md:grid-cols-[1fr_2fr_auto] gap-3">
        <input
          className="bg-panel2 border border-border rounded-lg px-3 py-2 text-sm placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent/60"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Scan name"
          required
        />
        <input
          className="bg-panel2 border border-border rounded-lg px-3 py-2 text-sm placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent/60 font-mono"
          value={image}
          onChange={(e) => setImage(e.target.value)}
          placeholder="docker image ref e.g. nginx:latest"
          required
        />
        <button
          type="submit"
          disabled={busy}
          className="rounded-lg bg-accent/20 border border-accent/40 text-accent px-4 py-2 text-sm font-medium hover:bg-accent/30 disabled:opacity-50"
        >
          {busy ? "Starting…" : "Start Scan"}
        </button>
      </div>
      {err && <div className="text-xs text-red-400 mt-2">{err}</div>}
    </form>
  );
}
