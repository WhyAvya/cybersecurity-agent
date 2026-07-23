import type { ApiConfig, Artifact, CreateScanPayload, FrozenEvaluationResponse, HealthResponse, ScanJob, ScanResult, SourceRecord } from '../types/api';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let message = `API request failed with status ${response.status}`;
    try {
      const body = await response.json();
      message = body?.detail?.message ?? body?.message ?? message;
    } catch {
      // Keep the status-based message when the backend returns no JSON body.
    }
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export const apiClient = {
  getHealth: () => request<HealthResponse>('/api/health'),
  getConfig: () => request<ApiConfig>('/api/config'),
  getFrozenEvaluation: () => request<FrozenEvaluationResponse>('/api/evaluation/frozen'),
  createPasteSource: (filename: string, code: string) =>
    request<SourceRecord>('/api/sources/paste', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, code }),
    }),
  createFileSource: (files: File[]) => {
    const form = new FormData();
    files.forEach((file) => form.append('files', file, file.name));
    return request<SourceRecord>('/api/sources/files', { method: 'POST', body: form });
  },
  createZipSource: (file: File) => {
    const form = new FormData();
    form.append('file', file, file.name);
    return request<SourceRecord>('/api/sources/zip', { method: 'POST', body: form });
  },
  inspectGitHubSource: (payload: {
    repository_url: string;
    revision: { type: 'default' | 'branch' | 'tag' | 'commit'; value: string };
    subdirectory: string;
    include_tests: boolean;
  }) =>
    request<SourceRecord>('/api/sources/github/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  getSource: (sourceId: string) => request<SourceRecord>(`/api/sources/${sourceId}`),
  deleteSource: async (sourceId: string) => {
    await request<{ deleted: boolean }>(`/api/sources/${sourceId}`, { method: 'DELETE' });
  },
  createScan: (payload: CreateScanPayload) =>
    request<ScanJob>('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  getScan: (scanId: string) => request<ScanJob>(`/api/scans/${scanId}`),
  getScanResult: (scanId: string) => request<ScanResult>(`/api/scans/${scanId}/result`),
  cancelScan: (scanId: string) => request<ScanJob>(`/api/scans/${scanId}/cancel`, { method: 'POST' }),
  getArtifacts: (scanId: string) => request<Artifact[]>(`/api/scans/${scanId}/artifacts`),
  artifactUrl: (scanId: string, artifactPath: string) =>
    `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/artifacts/${artifactPath.split('/').map(encodeURIComponent).join('/')}`,
};

export { API_BASE_URL, ApiError };
