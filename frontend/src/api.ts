import type {
  ComponentRow,
  CreateScanResponse,
  Health,
  Paginated,
  ScanDetail,
  ScanSummary,
  VulnerabilityRow,
} from "./types";

const BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail: string;
    try {
      const body = await res.json();
      detail = body?.detail ?? res.statusText;
    } catch {
      detail = res.statusText;
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () => request<Health>("/health"),

  listScans: () => request<ScanSummary[]>("/scans"),

  getScan: (id: string) => request<ScanDetail>(`/scans/${id}`),

  createScan: (payload: { name: string; target_value: string }) =>
    request<CreateScanResponse>("/scans", {
      method: "POST",
      body: JSON.stringify({
        name: payload.name,
        target_type: "docker_image",
        target_value: payload.target_value,
      }),
    }),

  components: (
    id: string,
    q: { search?: string; package_type?: string; vulnerable_only?: boolean; limit?: number; offset?: number } = {}
  ) => {
    const params = new URLSearchParams();
    if (q.search) params.set("search", q.search);
    if (q.package_type) params.set("package_type", q.package_type);
    if (q.vulnerable_only) params.set("vulnerable_only", "true");
    if (q.limit) params.set("limit", String(q.limit));
    if (q.offset) params.set("offset", String(q.offset));
    const qs = params.toString();
    return request<Paginated<ComponentRow>>(
      `/scans/${id}/components${qs ? `?${qs}` : ""}`
    );
  },

  vulnerabilities: (
    id: string,
    q: {
      severity?: string;
      fix_available?: boolean;
      scanner?: string;
      search?: string;
      limit?: number;
      offset?: number;
    } = {}
  ) => {
    const params = new URLSearchParams();
    if (q.severity) params.set("severity", q.severity);
    if (q.fix_available !== undefined)
      params.set("fix_available", String(q.fix_available));
    if (q.scanner) params.set("scanner", q.scanner);
    if (q.search) params.set("search", q.search);
    if (q.limit) params.set("limit", String(q.limit));
    if (q.offset) params.set("offset", String(q.offset));
    const qs = params.toString();
    return request<Paginated<VulnerabilityRow>>(
      `/scans/${id}/vulnerabilities${qs ? `?${qs}` : ""}`
    );
  },

  reportUrl: (id: string, kind: "sbom" | "grype" | "trivy") =>
    `${BASE_URL}/scans/${id}/reports/${kind}`,
};
