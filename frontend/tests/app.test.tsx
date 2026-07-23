import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { routes } from '../src/router';

const routerMocks = vi.hoisted(() => ({
  navigate: vi.fn(),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => routerMocks.navigate,
  };
});

const healthPayload = {
  api_version: '0.1.0',
  scanner_version: '0.1.0',
  supported_language: 'Python',
  active_model: 'qwen2.5-coder:7b',
  active_scan_count: 0,
  temporary_workspace_policy: 'Temporary workspaces under .scan_runtime, TTL 3600s',
  checks: [
    { name: 'Backend API', status: 'ok', response_time_ms: 4, version: '0.1.0' },
    { name: 'Semgrep', status: 'unavailable', response_time_ms: 15, error: 'missing' },
    { name: 'Ollama', status: 'ok', response_time_ms: 8, message: 'reachable' },
  ],
};

const configPayload = {
  supported_language: 'Python',
  scan_modes: ['semgrep', 'llm', 'semgrep_gated', 'hybrid'],
  default_mode: 'hybrid',
  active_model: 'qwen2.5-coder:7b',
  limits: {
    max_source_files: 200,
    max_source_file_bytes: 1000000,
    max_zip_bytes: 20000000,
    ignored_paths: ['.git'],
  },
};

function mockFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/health')) return Response.json(healthPayload);
    if (url.endsWith('/api/config')) return Response.json(configPayload);
    if (url.endsWith('/api/evaluation/frozen')) {
      return Response.json({ available: false, run_id: '20260722T152729Z-ed7e47fb', error: 'Missing frozen artifact files: summary' });
    }
    return new Response('{}', { status: 404 });
  });
}

function renderApp(initialPath = '/') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  routerMocks.navigate.mockReset();
  window.localStorage.clear();
});

describe('React phase 1 shell', () => {
  it('renders dashboard with real health and config data', async () => {
    mockFetch();
    renderApp();
    expect(screen.getByRole('heading', { name: /source-code security analysis console/i })).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText('qwen2.5-coder:7b').length).toBeGreaterThan(0));
    expect(screen.getByText('Python validated')).toBeInTheDocument();
    expect(screen.getByText(/Missing frozen artifact files/i)).toBeInTheDocument();
  });

  it('navigates to the health route and shows live status cards', async () => {
    mockFetch();
    renderApp('/health');
    await waitFor(() => expect(screen.getAllByRole('heading', { name: 'System Health' }).length).toBeGreaterThan(0));
    expect(screen.getByRole('link', { name: /system health/i })).toBeInTheDocument();
    expect(await screen.findByText('Temporary workspaces under .scan_runtime, TTL 3600s')).toBeInTheDocument();
    expect(screen.getAllByText('Semgrep').length).toBeGreaterThan(0);
  });

  it('renders all four source tabs and keeps true hybrid selected by default', async () => {
    mockFetch();
    renderApp('/scan');
    expect(screen.getByRole('tab', { name: 'Paste Code' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Upload Files' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Upload Project / ZIP' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'GitHub Repository' })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /True Hybrid/i })).toBeChecked();
    expect(screen.getByRole('button', { name: /continue to scan/i })).toBeDisabled();
  });

  it('renders backend unavailable state honestly', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network down'));
    renderApp('/health');
    expect(await screen.findByText('Health check failed')).toBeInTheDocument();
  });
});

describe('New Scan ingestion', () => {
  it('supports keyboard tab switching and paste validation/examples/clear/copy', async () => {
    mockFetch();
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
    renderApp('/scan');
    const githubTab = screen.getByRole('tab', { name: 'GitHub Repository' });
    githubTab.focus();
    await userEvent.keyboard('{Enter}');
    await userEvent.click(githubTab);
    expect(screen.getByLabelText('Repository URL')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Paste Code' }));
    await userEvent.click(screen.getByRole('button', { name: /Create Source/i }));
    expect(await screen.findByText('Paste Python code before creating a source.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Load safe example/i }));
    expect((screen.getByLabelText('Python code') as HTMLTextAreaElement).value).toContain('def greet');
    await userEvent.click(screen.getByRole('button', { name: /Copy/i }));
    expect(navigator.clipboard.writeText).toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: /Clear/i }));
    await userEvent.click(screen.getByRole('button', { name: /Load vulnerable example/i }));
    expect((screen.getByLabelText('Python code') as HTMLTextAreaElement).value).toContain('os.system');
  });

  it('creates a scan with mode and selected files then navigates to progress', async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/sources/paste')) {
        expect(init?.method).toBe('POST');
        return Response.json({ source_id: 'src_paste', source_type: 'paste', name: 'Pasted code', created_at: 'now', warnings: [], metadata: {}, files: [{ path: 'example.py', size: 12, selected: true }] });
      }
      if (url.endsWith('/api/scans')) {
        expect(JSON.parse(String(init?.body))).toMatchObject({ source_id: 'src_paste', mode: 'hybrid', selected_files: ['example.py'], save_raw: true });
        return Response.json({ scan_id: 'scan_1', source_id: 'src_paste', name: 'Security scan', mode: 'hybrid', state: 'queued', progress: { stage: 'queued', files_completed: 0, files_total: 1, elapsed_seconds: 0 }, warnings: [], artifacts: [] });
      }
      if (url.endsWith('/api/scans/scan_1')) return Response.json({ scan_id: 'scan_1', source_id: 'src_paste', name: 'Security scan', mode: 'hybrid', state: 'running', progress: { stage: 'running scanner', current_file: 'example.py', files_completed: 0, files_total: 1, elapsed_seconds: 1.2 }, warnings: [], artifacts: [] });
      return Response.json({ available: false, run_id: 'x' });
    });
    renderApp('/scan');
    await userEvent.click(screen.getByRole('button', { name: /Load safe example/i }));
    await userEvent.click(screen.getByRole('button', { name: /Create Source/i }));
    expect(await screen.findByText(/source ID: src_paste/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Continue to Scan/i })).toBeEnabled();
    await userEvent.click(screen.getByRole('button', { name: /Continue to Scan/i }));
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith('/scan/scan_1'));
  });

  it('validates file uploads and submits multiple Python files', async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/sources/files')) return Response.json({ source_id: 'src_files', source_type: 'files', name: 'Uploaded files', created_at: 'now', warnings: [], metadata: {}, files: [{ path: 'a.py', size: 5, selected: true }, { path: 'b.py', size: 5, selected: true }] });
      return Response.json({ available: false, run_id: 'x' });
    });
    renderApp('/scan');
    await userEvent.click(screen.getByRole('tab', { name: 'Upload Files' }));
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.drop(input.closest('label') as HTMLElement, { dataTransfer: { files: [new File(['x'], 'bad.txt', { type: 'text/plain' })] } });
    expect(screen.getByText('bad.txt is not a .py file.')).toBeInTheDocument();
    await userEvent.upload(input, new File([''], 'empty.py', { type: 'text/x-python' }));
    expect(screen.getByText('empty.py is empty.')).toBeInTheDocument();
    await userEvent.upload(input, [new File(['x=1'], 'a.py'), new File(['y=2'], 'b.py')]);
    await userEvent.click(screen.getByRole('button', { name: /Create Source/i }));
    expect(await screen.findByText(/source ID: src_files/i)).toBeInTheDocument();
  });

  it('submits ZIP ingestion and GitHub inspection with validation', async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/sources/zip')) return Response.json({ source_id: 'src_zip', source_type: 'zip', name: 'project.zip', created_at: 'now', warnings: [], metadata: { ignored_paths: '.git' }, files: [{ path: 'app.py', size: 5, selected: true }] });
      if (url.endsWith('/api/sources/github/inspect')) return Response.json({ source_id: 'src_gh', source_type: 'github', name: 'owner/repo', created_at: 'now', warnings: [], metadata: { owner: 'owner', repository: 'repo', requested_revision: 'branch:main', resolved_commit: 'abcdef', commit_date: '2026-07-23', repository_size: 100 }, files: [{ path: 'src/app.py', size: 5, selected: true }] });
      return Response.json({ available: false, run_id: 'x' });
    });
    renderApp('/scan');
    await userEvent.click(screen.getByRole('tab', { name: 'Upload Project / ZIP' }));
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(['zip'], 'project.zip', { type: 'application/zip' }));
    await userEvent.click(screen.getByRole('button', { name: /Create Source/i }));
    expect(await screen.findByText(/source ID: src_zip/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'GitHub Repository' }));
    await userEvent.type(screen.getByLabelText('Repository URL'), 'https://example.com/nope');
    await userEvent.click(screen.getByRole('button', { name: /Import and Inspect/i }));
    expect(screen.getByText('Use https://github.com/owner/repository for public repositories.')).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('Repository URL'));
    await userEvent.type(screen.getByLabelText('Repository URL'), 'https://github.com/owner/repo');
    await userEvent.selectOptions(screen.getByLabelText('Revision type'), 'branch');
    expect(screen.getByLabelText('Revision value')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Revision value'), 'main');
    await userEvent.click(screen.getByRole('button', { name: /Import and Inspect/i }));
    expect(await screen.findByText(/source ID: src_gh/i)).toBeInTheDocument();
    expect(screen.getByText('abcdef')).toBeInTheDocument();
  });

  it('displays backend ingestion errors', async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/sources/paste')) return Response.json({ detail: { message: 'Backend rejected source.' } }, { status: 400 });
      return Response.json({ available: false, run_id: 'x' });
    });
    renderApp('/scan');
    await userEvent.click(screen.getByRole('button', { name: /Load safe example/i }));
    await userEvent.click(screen.getByRole('button', { name: /Create Source/i }));
    expect(await screen.findByText('Backend rejected source.')).toBeInTheDocument();
  });
});

describe('Scan progress and results', () => {
  const runningJob = {
    scan_id: 'scan_run',
    source_id: 'src_1',
    name: 'Security scan',
    mode: 'hybrid',
    state: 'running',
    progress: { stage: 'Running Semgrep', current_file: 'src/app.py', files_completed: 1, files_total: 3, elapsed_seconds: 4.2 },
    warnings: ['Slow model response'],
    artifacts: [],
  };
  const completedJob = { ...runningJob, state: 'completed', progress: { ...runningJob.progress, stage: 'completed', files_completed: 3, elapsed_seconds: 8.5 } };
  const resultPayload = {
    status_label: 'Manual review recommended',
    summary: { files_scanned: 1, files_with_findings: 1, total_grouped_findings: 1, potentially_vulnerable_findings: 1, review_required_findings: 1, semgrep_matches: 1, llm_matches: 1, detector_agreements: 1, errors: 0 },
    findings: [{
      finding_id: 'group-1',
      normalized_cwe: 'CWE-078',
      severity: 'HIGH',
      confidence: 0.82,
      relative_file: 'src/app.py',
      line_start: 2,
      line_end: 2,
      detector: 'semgrep+llm',
      detectors: ['semgrep', 'llm'],
      agreement_status: 'detectors_agree',
      reasoning_summary: 'Command execution may use untrusted input.',
      remediation: 'Avoid shell command construction.',
      needs_human_review: true,
      rule_id: 'python.lang.security.audit',
      analyzer_verdict: 'TP',
      sink_evidence: 'os.system(user_input)',
    }],
    source_files: { 'src/app.py': 'import os\nos.system(user_input)\n' },
    manifest: {},
  };

  it('renders running state, real counters, and cancellation request', async () => {
    const fetchMock = mockFetch();
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/scans/scan_run/cancel')) return Response.json({ ...runningJob, state: 'cancelled', progress: { ...runningJob.progress, stage: 'cancelled' } });
      if (url.endsWith('/api/scans/scan_run')) return Response.json(runningJob);
      return Response.json({ available: false });
    });
    renderApp('/scan/scan_run');
    expect((await screen.findAllByText('Running Semgrep')).length).toBeGreaterThan(0);
    expect(screen.getByText('1 / 3')).toBeInTheDocument();
    expect(screen.getAllByText('src/app.py').length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole('button', { name: /Cancel Scan/i }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/api/scans/scan_run/cancel'), expect.objectContaining({ method: 'POST', headers: expect.any(Object) })));
  });

  it('fetches completed results, filters findings, opens drawer, and shows artifacts/source safely', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/scans/scan_done')) return Response.json(completedJob);
      if (url.endsWith('/api/scans/scan_done/result')) return Response.json(resultPayload);
      if (url.endsWith('/api/scans/scan_done/artifacts')) return Response.json([{ name: 'scan_report.md', category: 'Human-readable report', path: 'scan_report.md', size: 42 }]);
      return Response.json({});
    });
    renderApp('/scan/scan_done');
    expect(await screen.findByText('Manual review recommended')).toBeInTheDocument();
    expect(screen.getByText('Grouped findings')).toBeInTheDocument();
    expect(screen.getByText('CWE-078')).toBeInTheDocument();
    expect(screen.queryByText(/C:\\Users/i)).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Search findings'), 'command');
    await userEvent.click(screen.getAllByRole('button', { name: /CWE-078/i })[0]);
    expect(screen.getByRole('dialog', { name: 'Finding details' })).toBeInTheDocument();
    expect(screen.getByText('Suggested remediation - review before applying.')).toBeInTheDocument();
    expect(screen.getAllByText('src/app.py').length).toBeGreaterThan(0);
    expect(await screen.findByRole('link', { name: 'Download' })).toHaveAttribute('href', expect.stringContaining('/api/scans/scan_done/artifacts/scan_report.md'));
  });

  it('shows uncertainty context for uncertain low-confidence LLM-only findings', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/scans/uncertain')) return Response.json({ ...completedJob, scan_id: 'uncertain' });
      if (url.endsWith('/api/scans/uncertain/result')) return Response.json({
        status_label: 'Manual review recommended',
        summary: { files_scanned: 1, total_grouped_findings: 1, review_required_findings: 1 },
        findings: [{
          finding_id: 'uncertain-1',
          normalized_cwe: 'CWE-078',
          severity: 'MEDIUM',
          confidence: 0.5,
          relative_file: 'app.py',
          line_start: 11,
          line_end: 11,
          detector: 'llm',
          detectors: ['llm'],
          agreement_status: 'llm_only',
          reasoning_summary: 'Allowlist handling needs human review.',
          analyzer_verdict: 'UNCERTAIN',
          user_classification: 'UNCERTAIN',
          needs_human_review: true,
          sink_evidence: 'subprocess.run(',
        }],
        source_files: { 'app.py': 'subprocess.run(\n' },
      });
      if (url.endsWith('/api/scans/uncertain/artifacts')) return Response.json([]);
      return Response.json({});
    });
    renderApp('/scan/uncertain');

    expect(await screen.findByText('Needs human review')).toBeInTheDocument();
    expect(screen.getByText('Possible false positive')).toBeInTheDocument();
    expect(screen.getByText('LLM-only finding')).toBeInTheDocument();
    expect(screen.getByText(/Review the control flow, validation, allowlists, and input restrictions/i)).toBeInTheDocument();
  });

  it('shows exact locations normally and approximate locations with warnings', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/scans/locations')) return Response.json({ ...completedJob, scan_id: 'locations' });
      if (url.endsWith('/api/scans/locations/result')) return Response.json({
        status_label: 'Manual review recommended',
        summary: { files_scanned: 1, total_grouped_findings: 2 },
        findings: [
          {
            finding_id: 'exact-1',
            normalized_cwe: 'CWE-078',
            severity: 'HIGH',
            confidence: 0.95,
            relative_file: 'app.py',
            line_start: 2,
            line_end: 2,
            detector: 'llm',
            detectors: ['llm'],
            agreement_status: 'llm_only',
            reasoning_summary: 'Exact sink.',
            analyzer_verdict: 'TP',
          },
          {
            finding_id: 'approx-1',
            normalized_cwe: 'CWE-078',
            severity: 'MEDIUM',
            confidence: 0.4,
            relative_file: 'app.py',
            line_start: 3,
            line_end: 3,
            location_is_approximate: true,
            location_note: 'Location could not be verified from returned evidence.',
            original_start_line: 99,
            original_end_line: 99,
            detector: 'llm',
            detectors: ['llm'],
            agreement_status: 'llm_only',
            reasoning_summary: 'Approximate sink.',
            analyzer_verdict: 'UNCERTAIN',
          },
        ],
        source_files: { 'app.py': 'import os\nos.system(user_input)\nprint("done")\n' },
      });
      if (url.endsWith('/api/scans/locations/artifacts')) return Response.json([]);
      return Response.json({});
    });
    renderApp('/scan/locations');

    expect(await screen.findByText('app.py:2')).toBeInTheDocument();
    expect(screen.queryByText('app.py:2 approximate')).not.toBeInTheDocument();
    expect(screen.getByText('app.py:3 approximate')).toBeInTheDocument();
    expect(screen.getByText(/Approximate location: one or more findings/i)).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole('button', { name: /CWE-078/i })[0]);
    expect(screen.queryByText(/Approximate location: returned evidence/i)).not.toBeInTheDocument();
  });

  it('handles failed, cancelled, no-findings, result-not-ready, and backend error states', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/scans/missing')) return Response.json({ detail: { message: 'Scan was not found.' } }, { status: 404 });
      if (url.endsWith('/api/scans/failed')) return Response.json({ ...runningJob, scan_id: 'failed', state: 'failed', error: { message: 'LLM timeout', stage: 'Running LLM', recoverable: true, details: {} } });
      if (url.endsWith('/api/scans/cancelled')) return Response.json({ ...runningJob, scan_id: 'cancelled', state: 'cancelled' });
      if (url.endsWith('/api/scans/empty')) return Response.json({ ...completedJob, scan_id: 'empty' });
      if (url.endsWith('/api/scans/empty/result')) return Response.json({ status_label: 'No findings detected', summary: { files_scanned: 1, total_grouped_findings: 0 }, findings: [], source_files: {} });
      if (url.endsWith('/api/scans/empty/artifacts')) return Response.json([]);
      return Response.json({ available: false });
    });
    renderApp('/scan/failed');
    expect((await screen.findAllByText('Scan failed')).length).toBeGreaterThan(0);
    cleanup();
    renderApp('/scan/cancelled');
    expect(await screen.findByText('Scan cancelled.')).toBeInTheDocument();
    cleanup();
    renderApp('/scan/empty');
    expect((await screen.findAllByText('No findings detected')).length).toBeGreaterThan(0);
    cleanup();
    renderApp('/scan/missing');
    expect(await screen.findByText('Scan status unavailable')).toBeInTheDocument();
  });
});

describe('Phase 4 pages', () => {
  const sourcePayload = {
    source_id: 'src_compare',
    source_type: 'paste',
    name: 'Pasted source',
    created_at: 'now',
    warnings: [],
    metadata: {},
    files: [{ path: 'app.py', size: 44, selected: true }],
  };
  const completedScan = (scan_id: string, mode: string) => ({
    scan_id,
    source_id: 'src_compare',
    name: `Compare ${mode}`,
    mode,
    state: 'completed',
    progress: { stage: 'completed', files_completed: 1, files_total: 1, elapsed_seconds: mode === 'semgrep' ? 1.2 : 7.8 },
    warnings: [],
    artifacts: [],
  });
  const resultFor = (mode: string) => ({
    status_label: 'Potential vulnerabilities detected',
    summary: {
      files_scanned: 1,
      total_grouped_findings: mode === 'semgrep' ? 1 : 2,
      potentially_vulnerable_findings: 1,
      review_required_findings: mode === 'semgrep' ? 0 : 1,
      semgrep_matches: mode === 'llm' ? 0 : 1,
      llm_matches: mode === 'semgrep' ? 0 : 1,
      detector_agreements: mode === 'hybrid' ? 1 : 0,
      errors: 0,
    },
    findings: [{
      finding_id: `${mode}-finding`,
      normalized_cwe: 'CWE-078',
      severity: 'HIGH',
      confidence: 0.9,
      relative_file: 'app.py',
      line_start: 4,
      line_end: 4,
      user_classification: 'VULNERABLE',
      detectors: mode === 'hybrid' ? ['semgrep', 'llm'] : [mode],
      agreement_status: mode === 'hybrid' ? 'detectors_agree' : `${mode}_only`,
    }],
    source_files: { 'app.py': 'import os\n\ncmd=input()\nos.system(cmd)\n' },
  });

  it('runs Compare Modes sequentially and renders completed results without live accuracy metrics', async () => {
    const fetchMock = mockFetch();
    const created: string[] = [];
    fetchMock.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/sources/src_compare')) return Response.json(sourcePayload);
      if (url.endsWith('/api/scans') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        created.push(body.mode);
        return Response.json(completedScan(`scan_${body.mode}`, body.mode));
      }
      const scanMatch = url.match(/\/api\/scans\/scan_([^/]+)$/);
      if (scanMatch) return Response.json(completedScan(`scan_${scanMatch[1]}`, scanMatch[1]));
      const resultMatch = url.match(/\/api\/scans\/scan_([^/]+)\/result$/);
      if (resultMatch) return Response.json(resultFor(resultMatch[1]));
      return Response.json({ available: false, run_id: 'x' });
    });

    renderApp('/compare');
    await userEvent.type(screen.getByLabelText('Existing source ID'), 'src_compare');
    await userEvent.click(screen.getByRole('button', { name: /Load source/i }));
    expect(await screen.findByText(/Loaded Pasted source/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Run comparison/i }));

    await waitFor(() => expect(created).toEqual(['semgrep', 'hybrid']));
    expect((await screen.findAllByText('True Hybrid')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('CWE-078').length).toBeGreaterThan(0);
    expect(screen.queryByText(/^F1$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Precision$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Recall$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Accuracy$/i)).not.toBeInTheDocument();
  });

  it('preserves successful Compare Modes results when another mode fails and allows retry', async () => {
    const fetchMock = mockFetch();
    let hybridAttempts = 0;
    fetchMock.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/sources/src_compare')) return Response.json(sourcePayload);
      if (url.endsWith('/api/scans') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        if (body.mode === 'hybrid' && hybridAttempts++ === 0) return Response.json({ detail: { message: 'Model unavailable' } }, { status: 500 });
        return Response.json(completedScan(`scan_${body.mode}`, body.mode));
      }
      const scanMatch = url.match(/\/api\/scans\/scan_([^/]+)$/);
      if (scanMatch) return Response.json(completedScan(`scan_${scanMatch[1]}`, scanMatch[1]));
      const resultMatch = url.match(/\/api\/scans\/scan_([^/]+)\/result$/);
      if (resultMatch) return Response.json(resultFor(resultMatch[1]));
      return Response.json({ available: false, run_id: 'x' });
    });

    renderApp('/compare');
    await userEvent.type(screen.getByLabelText('Existing source ID'), 'src_compare');
    await userEvent.click(screen.getByRole('button', { name: /Load source/i }));
    await screen.findByText(/Loaded Pasted source/i);
    await userEvent.click(screen.getByRole('button', { name: /Run comparison/i }));

    expect(await screen.findByText('Model unavailable')).toBeInTheDocument();
    expect(screen.getAllByText('CWE-078').length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole('button', { name: /Retry True Hybrid/i }));
    await waitFor(() => expect(screen.queryByText('Model unavailable')).not.toBeInTheDocument());
  });

  it('renders evaluation unavailable and available states from backend payload fields', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/evaluation/frozen')) return Response.json({ available: false, run_id: 'run-x', error: 'Missing frozen artifact files: summary', path: 'artifacts/evaluation/run-x' });
      return Response.json({});
    });
    renderApp('/evaluation');
    expect(await screen.findByText('Verified artifacts are missing')).toBeInTheDocument();
    expect(screen.getByText('run-x')).toBeInTheDocument();
    expect(screen.getByText('artifacts/evaluation/run-x')).toBeInTheDocument();

    cleanup();
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/evaluation/frozen')) return Response.json({
        available: true,
        run_id: 'run-y',
        label: 'Frozen benchmark evaluation',
        conclusion: 'Small sample.',
        mode_comparison: [{ mode: 'semgrep', precision: '1.0' }],
        hybrid_agreement: [{ agreement_status: 'detectors_agree', count: '2' }],
        runtime_errors: [{ mode: 'llm', errors: '0' }],
      });
      return Response.json({});
    });
    renderApp('/evaluation');
    expect(await screen.findByText('Frozen benchmark evaluation')).toBeInTheDocument();
    expect(screen.getByText('Mode metrics')).toBeInTheDocument();
    expect(screen.getByText('Hybrid agreement')).toBeInTheDocument();
    expect(screen.getByText('Runtime errors')).toBeInTheDocument();
  });

  it('recovers from stale source IDs after backend restart or expiry', async () => {
    window.localStorage.setItem('vuln-agent:last-source-id', 'expired_source');
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/sources/expired_source')) return Response.json({ detail: { message: 'Source not found' } }, { status: 404 });
      return Response.json({ available: false, run_id: 'x' });
    });

    renderApp('/scan');
    expect(await screen.findByText('Previous source expired')).toBeInTheDocument();
    expect(screen.getByText(/backend may have restarted or the temporary workspace may have expired/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Return to source input/i }));
    expect(screen.queryByText('Previous source expired')).not.toBeInTheDocument();
    expect(window.localStorage.getItem('vuln-agent:last-source-id')).toBeNull();
  });

  it('cleans completed timeline labels and inactive file text', async () => {
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/scans/timeline')) return Response.json({
        scan_id: 'timeline',
        source_id: 'src',
        name: 'Timeline scan',
        mode: 'semgrep',
        state: 'completed',
        progress: { stage: 'completed', current_file: null, files_completed: 1, files_total: 1, elapsed_seconds: 2 },
        warnings: [],
        artifacts: [],
      });
      if (url.endsWith('/api/scans/timeline/result')) return Response.json({ status_label: 'No findings detected', summary: { files_scanned: 1, total_grouped_findings: 0 }, findings: [], source_files: {} });
      if (url.endsWith('/api/scans/timeline/artifacts')) return Response.json([]);
      return Response.json({});
    });

    renderApp('/scan/timeline');
    expect(await screen.findByText('No active file')).toBeInTheDocument();
    expect(screen.getByText('Finished')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Scan stage timeline')).getAllByText('completed')).toHaveLength(1);
  });

  it('renders About page limitations and supports drawer close from keyboard-accessible button', async () => {
    mockFetch();
    renderApp('/about');
    expect(await screen.findByText(/Python source code/i)).toBeInTheDocument();
    expect(screen.getByText(/Qwen2.5-Coder 7B through Ollama/i)).toBeInTheDocument();
    expect(screen.getByText(/CWE-078 command injection/i)).toBeInTheDocument();
    expect(screen.getByText(/not a guarantee that code is completely secure/i)).toBeInTheDocument();

    cleanup();
    mockFetch().mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/api/health')) return Response.json(healthPayload);
      if (url.endsWith('/api/config')) return Response.json(configPayload);
      if (url.endsWith('/api/scans/drawer')) return Response.json({
        scan_id: 'drawer',
        source_id: 'src',
        name: 'Drawer scan',
        mode: 'semgrep',
        state: 'completed',
        progress: { stage: 'completed', files_completed: 1, files_total: 1, elapsed_seconds: 2 },
        warnings: [],
        artifacts: [],
      });
      if (url.endsWith('/api/scans/drawer/result')) return Response.json(resultFor('semgrep'));
      if (url.endsWith('/api/scans/drawer/artifacts')) return Response.json([]);
      return Response.json({});
    });
    renderApp('/scan/drawer');
    await userEvent.click((await screen.findAllByRole('button', { name: /CWE-078/i }))[0]);
    expect(screen.getByRole('dialog', { name: 'Finding details' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('dialog', { name: 'Finding details' })).not.toBeInTheDocument();
  });
});
