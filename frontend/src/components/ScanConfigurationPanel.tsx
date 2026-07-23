import type { ApiConfig } from '../types/api';
import type { ScanMode } from './ModeSelector';
import { ModeSelector } from './ModeSelector';
import './scan.css';

export function ScanConfigurationPanel({
  config,
  mode,
  onModeChange,
  scanName,
  onScanNameChange,
  selectedFileCount,
  canContinue,
  starting,
  onContinue,
}: {
  config?: ApiConfig;
  mode: ScanMode;
  onModeChange: (mode: ScanMode) => void;
  scanName: string;
  onScanNameChange: (name: string) => void;
  selectedFileCount: number;
  canContinue: boolean;
  starting?: boolean;
  onContinue: () => void;
}) {
  return (
    <aside className="scan-config" aria-label="Scan configuration">
      <label>
        <span>Scan name</span>
        <input value={scanName} onChange={(event) => onScanNameChange(event.target.value)} />
      </label>
      <label>
        <span>Language</span>
        <input value="Python" readOnly />
      </label>
      <label>
        <span>Backend model</span>
        <input value={config?.active_model ?? 'Unavailable'} readOnly />
      </label>
      <ModeSelector value={mode} onChange={onModeChange} />
      <dl className="config-limits">
        <div><dt>Selected files</dt><dd>{selectedFileCount}</dd></div>
        <div><dt>Maximum files</dt><dd>{config?.limits.max_source_files ?? 'Unavailable'}</dd></div>
        <div><dt>Ignored paths</dt><dd>{config?.limits.ignored_paths.join(', ') ?? 'Unavailable'}</dd></div>
        <div><dt>Raw evidence</dt><dd>Saved when the scan request enables raw artifact collection.</dd></div>
      </dl>
      <button className="primary-action" type="button" disabled={!canContinue || starting} onClick={onContinue}>
        {starting ? 'Starting scan' : 'Continue to Scan'}
      </button>
      <p className="muted-line">Starts a backend scan using the selected source and mode.</p>
    </aside>
  );
}
