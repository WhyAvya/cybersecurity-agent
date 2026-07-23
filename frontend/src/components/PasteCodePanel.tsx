import { useState } from 'react';
import { apiClient } from '../api/client';
import type { SourceRecord } from '../types/api';
import { CopyButton } from './CopyButton';
import { ValidationMessage } from './ValidationMessage';
import './scan.css';

const safeExample = "def greet(name: str) -> str:\n    return f\"Hello, {name}\"\n";
const vulnerableExample = "import os\n\n\ndef run_command(user_input: str) -> None:\n    os.system(\"ls \" + user_input)\n";

export function PasteCodePanel({ onSource }: { onSource: (source: SourceRecord) => void }) {
  const [filename, setFilename] = useState('example.py');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const lineCount = Math.max(1, code.split('\n').length);

  async function submit() {
    setError('');
    if (!filename.endsWith('.py') || filename.includes('..') || filename.startsWith('/')) {
      setError('Use a repository-relative Python filename ending in .py.');
      return;
    }
    if (!code.trim()) {
      setError('Paste Python code before creating a source.');
      return;
    }
    setLoading(true);
    try {
      onSource(await apiClient.createPasteSource(filename, code));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'Paste source creation failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="source-panel">
      <ValidationMessage tone="success">Python scanning is currently validated. Other languages are not yet fully implemented or benchmarked.</ValidationMessage>
      <label>
        <span>Filename</span>
        <input value={filename} onChange={(event) => setFilename(event.target.value)} />
      </label>
      <div className="editor-shell">
        <pre aria-hidden="true">{Array.from({ length: lineCount }, (_, index) => index + 1).join('\n')}</pre>
        <textarea aria-label="Python code" value={code} onChange={(event) => setCode(event.target.value)} spellCheck={false} />
      </div>
      <div className="button-row">
        <button type="button" onClick={() => setCode(safeExample)}>Load safe example</button>
        <button type="button" onClick={() => setCode(vulnerableExample)}>Load vulnerable example</button>
        <CopyButton text={code} />
        <button type="button" onClick={() => setCode('')}>Clear</button>
        <button type="button" className="primary-action" disabled={loading} onClick={() => void submit()}>{loading ? 'Creating source' : 'Create Source'}</button>
      </div>
      {error ? <ValidationMessage tone="danger">{error}</ValidationMessage> : null}
    </section>
  );
}
