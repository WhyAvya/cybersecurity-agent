import type { ScanJob } from '../types/api';
import './results.css';

export function StageTimeline({ scan }: { scan: ScanJob }) {
  const terminal = ['completed', 'failed', 'cancelled'].includes(scan.state);
  const stage = terminal && scan.progress.stage === scan.state ? 'Finished' : scan.progress.stage;
  return (
    <ol className="stage-timeline" aria-label="Scan stage timeline">
      <li className="stage stage--done">Queued</li>
      <li className={`stage ${scan.state === 'running' ? 'stage--running' : terminal ? 'stage--done' : ''}`}>{stage}</li>
      {terminal ? <li className={`stage stage--${scan.state === 'failed' ? 'failed' : 'done'}`}>{scan.state}</li> : null}
    </ol>
  );
}
