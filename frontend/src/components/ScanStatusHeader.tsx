import type { ScanJob } from '../types/api';
import { GlassPanel } from './GlassPanel';
import { StatusBadge } from './StatusBadge';
import './results.css';

export function ScanStatusHeader({ scan }: { scan: ScanJob }) {
  return (
    <GlassPanel className="scan-header">
      <div>
        <p className="eyebrow">Scan {scan.scan_id}</p>
        <h1>{scan.name}</h1>
        <p>{scan.mode} · source {scan.source_id}</p>
      </div>
      <StatusBadge status={scan.state} />
      <dl className="scan-meta">
        <div><dt>Stage</dt><dd>{scan.progress.stage}</dd></div>
        <div><dt>Files</dt><dd>{scan.progress.files_completed} / {scan.progress.files_total}</dd></div>
        <div><dt>Elapsed</dt><dd>{scan.progress.elapsed_seconds.toFixed(1)}s</dd></div>
        <div><dt>Current file</dt><dd>{scan.progress.current_file ?? 'No active file'}</dd></div>
      </dl>
    </GlassPanel>
  );
}
