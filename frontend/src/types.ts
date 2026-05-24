export type SeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
};

export type TopPackage = {
  package: string;
  count: number;
};

export type ScanSummary = {
  id: string;
  project_id: string;
  project_name: string;
  target_type: string;
  target_value: string;
  status: "queued" | "running" | "completed" | "failed";
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  risk_score: number | null;
  created_at: string;
  component_count: number;
  vulnerability_count: number;
  severity_counts: SeverityCounts;
  fixable_count: number;
};

export type ScanDetail = ScanSummary & {
  top_packages: TopPackage[];
  sbom_available: boolean;
  grype_available: boolean;
  trivy_available: boolean;
};

export type ComponentRow = {
  id: string;
  name: string;
  version: string | null;
  package_type: string | null;
  purl: string | null;
  license: string | null;
  source_path: string | null;
};

export type VulnerabilityRow = {
  id: string;
  scanner: string;
  cve_id: string | null;
  vulnerability_id: string | null;
  severity: string | null;
  cvss_score: number | null;
  package_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  fix_available: boolean;
  advisory_url: string | null;
  description: string | null;
  risk_score: number | null;
};

export type Paginated<T> = {
  total: number;
  items: T[];
};

export type Health = {
  status: string;
  database: string;
  tools: { syft: boolean; grype: boolean; trivy: boolean };
};

export type CreateScanResponse = {
  scan_id: string;
  project_id: string;
  status: string;
};
