import { useState } from 'react';
import { apiClient } from '../api/client';
import type { ApiConfig, SourceRecord } from '../types/api';
import { DropZone } from './DropZone';
import { FileList } from './FileList';
import { ValidationMessage } from './ValidationMessage';

export function FileUploadPanel({ config, onSource }: { config?: ApiConfig; onSource: (source: SourceRecord) => void }) {
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  function addFiles(next: File[]) {
    setError('');
    const rejected = next.find((file) => !file.name.endsWith('.py') || file.size === 0);
    if (rejected) {
      setError(rejected.size === 0 ? `${rejected.name} is empty.` : `${rejected.name} is not a .py file.`);
      return;
    }
    if (config && files.length + next.length > config.limits.max_source_files) {
      setError(`File count exceeds backend limit of ${config.limits.max_source_files}.`);
      return;
    }
    setFiles((current) => [...current, ...next]);
  }

  async function submit() {
    if (!files.length) {
      setError('Select one or more Python files.');
      return;
    }
    setLoading(true);
    try {
      onSource(await apiClient.createFileSource(files));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'File upload failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="source-panel">
      <DropZone label="Drop Python files here" accept=".py" multiple onFiles={addFiles}>
        <span>Backend limit: {config?.limits.max_source_files ?? 'unavailable'} files, {config?.limits.max_source_file_bytes ?? 'unavailable'} bytes per file.</span>
      </DropZone>
      <FileList files={files} onRemove={(name) => setFiles((current) => current.filter((file) => file.name !== name))} />
      <div className="button-row">
        <button type="button" onClick={() => setFiles([])}>Clear all</button>
        <button className="primary-action" type="button" disabled={loading} onClick={() => void submit()}>{loading ? 'Uploading' : 'Create Source'}</button>
      </div>
      {error ? <ValidationMessage tone="danger">{error}</ValidationMessage> : null}
    </section>
  );
}
