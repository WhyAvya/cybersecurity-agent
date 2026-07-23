export type HealthStatus = 'ok' | 'unavailable' | 'degraded' | 'error' | string;

export interface HealthCheck {
  name: string;
  status: HealthStatus;
  response_time_ms: number;
  version?: string | null;
  message?: string;
  error?: string;
}

export interface HealthResponse {
  api_version: string;
  scanner_version: string;
  supported_language: string;
  active_model: string;
  active_scan_count: number;
  temporary_workspace_policy: string;
  checks: HealthCheck[];
}

export interface ApiConfig {
  supported_language: string;
  scan_modes: Array<'semgrep' | 'llm' | 'semgrep_gated' | 'hybrid'>;
  default_mode: 'semgrep' | 'llm' | 'semgrep_gated' | 'hybrid';
  active_model: string;
  limits: {
    max_source_files: number;
    max_source_file_bytes: number;
    max_zip_bytes: number;
    ignored_paths: string[];
  };
}

export interface FrozenEvaluationResponse {
  available: boolean;
  run_id: string;
  label?: string;
  error?: string;
  path?: string;
  conclusion?: string;
  summary_markdown?: string;
  mode_comparison?: Array<Record<string, string>>;
  hybrid_agreement?: Array<Record<string, string>>;
  runtime_errors?: Array<Record<string, string>>;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  stage?: string | null;
  recoverable: boolean;
  details: Record<string, unknown>;
}

export interface SourceFile {
  path: string;
  size: number;
  selected: boolean;
  content?: string | null;
}

export interface SourceRecord {
  source_id: string;
  source_type: 'paste' | 'files' | 'zip' | 'github';
  name: string;
  created_at: string;
  files: SourceFile[];
  metadata: Record<string, unknown>;
  warnings: string[];
}

export type ScanModeValue = 'semgrep' | 'llm' | 'semgrep_gated' | 'hybrid';
export type ScanState = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string;

export interface ScanProgress {
  stage: string;
  current_file?: string | null;
  files_completed: number;
  files_total: number;
  started_at?: string | null;
  ended_at?: string | null;
  elapsed_seconds: number;
}

export interface Artifact {
  name: string;
  category: string;
  path: string;
  size: number;
}

export interface ScanJob {
  scan_id: string;
  source_id: string;
  name: string;
  mode: ScanModeValue;
  state: ScanState;
  progress: ScanProgress;
  warnings: string[];
  error?: ApiErrorPayload | null;
  result?: ScanResult | null;
  artifacts: Artifact[];
}

export interface CreateScanPayload {
  source_id: string;
  mode: ScanModeValue;
  scan_name: string;
  selected_files: string[];
  save_raw: boolean;
}

export interface ScanFinding {
  finding_id: string;
  group_id?: string | null;
  normalized_cwe?: string;
  severity?: string;
  confidence?: number;
  relative_file?: string;
  line_start?: number;
  line_end?: number;
  location_is_approximate?: boolean;
  location_note?: string | null;
  original_start_line?: number | null;
  original_end_line?: number | null;
  detector?: string;
  detectors?: string[];
  agreement_status?: string;
  reasoning_summary?: string;
  remediation?: string;
  status?: string;
  user_classification?: string;
  needs_human_review?: boolean;
  review_reason?: string;
  rule_id?: string;
  underlying_rule_ids?: string[];
  analyzer_verdict?: string;
  source_evidence?: string;
  sink_evidence?: string;
  data_flow_evidence?: string;
  sanitization_evidence?: string;
  detector_errors?: string[];
}

export interface ScanResult {
  available?: boolean;
  state?: string;
  status_label?: string;
  summary?: Record<string, number>;
  findings?: ScanFinding[];
  source_files?: Record<string, string>;
  manifest?: Record<string, unknown>;
}
