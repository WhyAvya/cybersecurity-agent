import { Trash2 } from 'lucide-react';
import type { SourceRecord } from '../types/api';
import { GlassPanel } from './GlassPanel';
import { FileList } from './FileList';
import './scan.css';

export function SourceSummary({
  source,
  selectedFiles,
  onToggleFile,
  onRemove,
}: {
  source: SourceRecord;
  selectedFiles: string[];
  onToggleFile: (path: string) => void;
  onRemove: () => void;
}) {
  const metadata = source.metadata ?? {};
  const sourceTypeFallback = 'Not reported for this source type';
  return (
    <GlassPanel className="source-summary">
      <div className="summary-head">
        <div>
          <p className="eyebrow">Ingested source</p>
          <h2>{source.name}</h2>
          <p>{source.source_type} source ID: {source.source_id}</p>
        </div>
        <button className="icon-text-button" type="button" onClick={onRemove}>
          <Trash2 size={16} aria-hidden="true" /> Remove
        </button>
      </div>
      {source.warnings.length ? <p className="validation validation--warning">{source.warnings.join(' ')}</p> : null}
      <div className="summary-grid">
        <div>
          <strong>Discovered files</strong>
          <span>{source.files.length}</span>
        </div>
        <div>
          <strong>Included files</strong>
          <span>{selectedFiles.length}</span>
        </div>
        <div>
          <strong>Ignored paths</strong>
          <span>{String(metadata.ignored_paths ?? metadata.ignored_directory_count ?? sourceTypeFallback)}</span>
        </div>
        <div>
          <strong>Excluded files</strong>
          <span>{String(metadata.excluded_files ?? metadata.unsupported_file_count ?? sourceTypeFallback)}</span>
        </div>
      </div>
      {source.source_type === 'github' ? (
        <dl className="repo-meta">
          {['owner', 'repository', 'requested_revision', 'resolved_commit', 'commit_date', 'repository_size'].map((key) => (
            <div key={key}>
              <dt>{key.replace(/_/g, ' ')}</dt>
              <dd>{String(metadata[key] ?? 'Unavailable')}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      <FileList files={source.files} selectable selected={selectedFiles} onToggle={onToggleFile} />
    </GlassPanel>
  );
}
