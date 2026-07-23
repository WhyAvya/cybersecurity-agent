import { useState } from 'react';
import { apiClient } from '../api/client';
import type { ApiConfig, SourceRecord } from '../types/api';
import { DropZone } from './DropZone';
import { formatBytes } from './FileList';
import { ValidationMessage } from './ValidationMessage';

export function ZipUploadPanel({ config, onSource }: { config?: ApiConfig; onSource: (source: SourceRecord) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  function select(files: File[]) {
    const selected = files[0];
    setError('');
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith('.zip')) {
      setError('Select a ZIP archive.');
      return;
    }
    setFile(selected);
  }

  async function submit() {
    if (!file) {
      setError('Select a ZIP archive first.');
      return;
    }
    setLoading(true);
    try {
      onSource(await apiClient.createZipSource(file));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'ZIP upload failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="source-panel">
      <DropZone label="Drop a ZIP project here" accept=".zip" onFiles={select}>
        <span>The browser uploads the archive; extraction and safety checks happen in the backend.</span>
      </DropZone>
      <p className="muted-line">Ignored paths: {config?.limits.ignored_paths.join(', ') ?? 'Unavailable'}</p>
      {file ? <ValidationMessage tone="success">{`${file.name} selected, ${formatBytes(file.size)}`}</ValidationMessage> : null}
      <div className="button-row">
        <button type="button" onClick={() => setFile(null)}>Clear</button>
        <button className="primary-action" type="button" disabled={loading} onClick={() => void submit()}>{loading ? 'Uploading' : 'Create Source'}</button>
      </div>
      {error ? <ValidationMessage tone="danger">{error}</ValidationMessage> : null}
    </section>
  );
}
