import { RotateCcw } from 'lucide-react';
import { useMemo, useState } from 'react';
import { apiClient } from '../api/client';
import { terminalScanStates, useConfig } from '../api/queries';
import { GlassPanel } from '../components/GlassPanel';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { ValidationMessage } from '../components/ValidationMessage';
import type { ScanFinding, ScanJob, ScanModeValue, ScanResult, SourceRecord } from '../types/api';
import './pages.css';

const modeLabels: Record<ScanModeValue, string> = {
  semgrep: 'Semgrep',
  llm: 'LLM',
  semgrep_gated: 'Semgrep-gated',
  hybrid: 'True Hybrid',
};

const summaryKeys = [
  ['files_scanned', 'Files scanned'],
  ['total_grouped_findings', 'Grouped findings'],
  ['potentially_vulnerable_findings', 'Potential vulnerabilities'],
  ['review_required_findings', 'Review required'],
  ['semgrep_matches', 'Semgrep matches'],
  ['llm_matches', 'LLM matches'],
  ['detector_agreements', 'Detector agreements'],
  ['errors', 'Errors'],
] as const;

interface ModeRun {
  mode: ScanModeValue;
  status: 'idle' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  elapsed: number;
  job?: ScanJob;
  result?: ScanResult;
  error?: string;
}

async function waitForScan(scanId: string, onUpdate: (job: ScanJob) => void): Promise<ScanJob> {
  for (;;) {
    const job = await apiClient.getScan(scanId);
    onUpdate(job);
    if (terminalScanStates.has(job.state)) return job;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

function location(finding: ScanFinding) {
  const file = finding.relative_file ?? 'Unknown file';
  const start = finding.line_start ?? '?';
  const end = finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : '';
  return `${file}:${start}${end}${finding.location_is_approximate ? ' approximate' : ''}`;
}

export function CompareModes() {
  const config = useConfig();
  const supportedModes = config.data?.scan_modes ?? ['semgrep', 'llm', 'semgrep_gated', 'hybrid'];
  const [sourceId, setSourceId] = useState(() => window.localStorage.getItem('vuln-agent:last-source-id') ?? '');
  const [source, setSource] = useState<SourceRecord | null>(null);
  const [selectedModes, setSelectedModes] = useState<ScanModeValue[]>(['semgrep', 'hybrid']);
  const [runs, setRuns] = useState<Record<string, ModeRun>>({});
  const [loadingSource, setLoadingSource] = useState(false);
  const [message, setMessage] = useState('');
  const [running, setRunning] = useState(false);

  const selectedFiles = useMemo(() => source?.files.filter((file) => file.selected).map((file) => file.path) ?? [], [source]);
  const rows = selectedModes.map((mode) => runs[mode] ?? { mode, status: 'idle' as const, elapsed: 0 });

  async function loadSource() {
    setMessage('');
    setLoadingSource(true);
    try {
      const next = await apiClient.getSource(sourceId.trim());
      setSource(next);
      window.localStorage.setItem('vuln-agent:last-source-id', next.source_id);
    } catch {
      window.localStorage.removeItem('vuln-agent:last-source-id');
      setSource(null);
      setMessage('This source is no longer available. The backend may have restarted or the temporary workspace may have expired. Return to source input to create it again.');
    } finally {
      setLoadingSource(false);
    }
  }

  function patchRun(mode: ScanModeValue, patch: Partial<ModeRun>) {
    setRuns((current) => ({ ...current, [mode]: { ...(current[mode] ?? { mode, status: 'idle', elapsed: 0 }), ...patch } }));
  }

  async function runMode(mode: ScanModeValue) {
    if (!source) return;
    const started = performance.now();
    patchRun(mode, { status: 'queued', error: undefined });
    try {
      const job = await apiClient.createScan({
        source_id: source.source_id,
        mode,
        scan_name: `Compare ${modeLabels[mode]}`,
        selected_files: selectedFiles,
        save_raw: true,
      });
      patchRun(mode, { job, status: job.state === 'queued' ? 'queued' : 'running' });
      const terminal = await waitForScan(job.scan_id, (next) => {
        patchRun(mode, { job: next, status: next.state === 'queued' ? 'queued' : next.state === 'running' ? 'running' : next.state as ModeRun['status'], elapsed: next.progress.elapsed_seconds });
      });
      if (terminal.state === 'completed') {
        const result = await apiClient.getScanResult(terminal.scan_id);
        patchRun(mode, { job: terminal, result, status: 'completed', elapsed: terminal.progress.elapsed_seconds || (performance.now() - started) / 1000 });
      } else {
        patchRun(mode, { job: terminal, status: terminal.state as ModeRun['status'], elapsed: terminal.progress.elapsed_seconds, error: terminal.error?.message ?? `Scan ${terminal.state}` });
      }
    } catch (exc) {
      patchRun(mode, { status: 'failed', elapsed: (performance.now() - started) / 1000, error: exc instanceof Error ? exc.message : 'Mode scan failed.' });
    }
  }

  async function runSelected() {
    setMessage('');
    if (!source) {
      setMessage('Load an existing source before comparing modes.');
      return;
    }
    if (selectedModes.length < 2) {
      setMessage('Select at least two modes.');
      return;
    }
    setRunning(true);
    try {
      for (const mode of selectedModes) {
        await runMode(mode);
      }
    } finally {
      setRunning(false);
    }
  }

  const allFindings = rows.flatMap((run) => (run.result?.findings ?? []).map((finding) => ({ mode: run.mode, finding })));

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Live scan comparison" title="Compare Modes">
        Run selected modes sequentially against one existing source. Live scans do not include ground truth, so this view does not calculate precision, recall, F1, or accuracy.
      </PageHeader>
      <GlassPanel className="compare-controls">
        <label>
          <span>Existing source ID</span>
          <input value={sourceId} onChange={(event) => setSourceId(event.target.value)} placeholder="source_..." />
        </label>
        <button type="button" className="secondary-action" disabled={loadingSource || !sourceId.trim()} onClick={() => void loadSource()}>
          {loadingSource ? 'Loading source' : 'Load source'}
        </button>
        {source ? <p className="muted-line">Loaded {source.name} with {source.files.length} Python file(s).</p> : null}
        <fieldset className="compare-mode-list">
          <legend>Modes</legend>
          {supportedModes.map((mode) => (
            <label key={mode}>
              <input
                type="checkbox"
                checked={selectedModes.includes(mode)}
                onChange={(event) => setSelectedModes((current) => event.target.checked ? [...current, mode] : current.filter((item) => item !== mode))}
              />
              {modeLabels[mode]}
            </label>
          ))}
        </fieldset>
        <button type="button" className="primary-action" disabled={running} onClick={() => void runSelected()}>
          {running ? 'Running selected modes' : 'Run comparison'}
        </button>
      </GlassPanel>
      {message ? <ValidationMessage tone="warning">{message}</ValidationMessage> : null}
      <section className="comparison-grid" aria-label="Mode comparison status">
        {rows.map((run) => (
          <GlassPanel key={run.mode} as="article" className="comparison-card">
            <div className="summary-head">
              <h2>{modeLabels[run.mode]}</h2>
              <StatusBadge status={run.status} />
            </div>
            <dl className="technical-list technical-list--compact">
              <div><dt>Elapsed</dt><dd>{run.elapsed.toFixed(1)}s</dd></div>
              {summaryKeys.map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{run.result?.summary?.[key] ?? 'Unavailable'}</dd></div>)}
            </dl>
            {run.error ? <ValidationMessage tone="danger">{run.error}</ValidationMessage> : null}
            {run.status === 'failed' ? <button type="button" className="secondary-action" onClick={() => void runMode(run.mode)}><RotateCcw size={16} aria-hidden="true" /> Retry {modeLabels[run.mode]}</button> : null}
          </GlassPanel>
        ))}
      </section>
      <section className="table-panel" aria-label="Finding-level comparison">
        <h2>Finding-level comparison</h2>
        <p className="muted-line">This table compares detector outputs only. It does not infer live-scan accuracy.</p>
        <div className="responsive-table">
          <table>
            <thead><tr><th>Mode</th><th>File</th><th>CWE</th><th>Verdict</th><th>Severity</th><th>Provenance</th><th>Location</th><th>Confidence</th></tr></thead>
            <tbody>
              {allFindings.map(({ mode, finding }) => (
                <tr key={`${mode}-${finding.finding_id}`}>
                  <td>{modeLabels[mode]}</td>
                  <td>{finding.relative_file ?? 'Unavailable'}</td>
                  <td>{finding.normalized_cwe ?? 'Unavailable'}</td>
                  <td>{finding.user_classification ?? finding.status ?? finding.analyzer_verdict ?? 'Unavailable'}</td>
                  <td>{finding.severity ?? 'Unavailable'}</td>
                  <td>{finding.detectors?.join(' + ') ?? finding.detector ?? 'Unavailable'}</td>
                  <td>{location(finding)}</td>
                  <td>{typeof finding.confidence === 'number' ? finding.confidence.toFixed(2) : 'Unavailable'}</td>
                </tr>
              ))}
              {!allFindings.length ? <tr><td colSpan={8}>No completed finding results yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
