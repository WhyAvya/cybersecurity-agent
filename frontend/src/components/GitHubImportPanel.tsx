import { useMemo, useState } from 'react';
import { apiClient } from '../api/client';
import type { SourceRecord } from '../types/api';
import { ValidationMessage } from './ValidationMessage';

type RevisionType = 'default' | 'branch' | 'tag' | 'commit';

function isCanonicalGithub(url: string) {
  return /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}(?:\.git)?\/?$/.test(url);
}

export function GitHubImportPanel({ onSource }: { onSource: (source: SourceRecord) => void }) {
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [revisionType, setRevisionType] = useState<RevisionType>('default');
  const [revisionValue, setRevisionValue] = useState('');
  const [subdirectory, setSubdirectory] = useState('');
  const [includeTests, setIncludeTests] = useState(true);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const urlValid = useMemo(() => !repositoryUrl || isCanonicalGithub(repositoryUrl), [repositoryUrl]);

  async function submit() {
    setError('');
    if (!isCanonicalGithub(repositoryUrl)) {
      setError('Use https://github.com/owner/repository for public repositories.');
      return;
    }
    if (revisionType !== 'default' && !revisionValue.trim()) {
      setError('Enter a revision value.');
      return;
    }
    setLoading(true);
    try {
      onSource(await apiClient.inspectGitHubSource({
        repository_url: repositoryUrl,
        revision: { type: revisionType, value: revisionType === 'default' ? '' : revisionValue },
        subdirectory,
        include_tests: includeTests,
      }));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'Repository inspection failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="source-panel">
      <ValidationMessage tone="warning">Public repositories only. Private repository access and pull-request scanning are planned future extensions.</ValidationMessage>
      <label>
        <span>Repository URL</span>
        <input value={repositoryUrl} onChange={(event) => setRepositoryUrl(event.target.value)} placeholder="https://github.com/owner/repository" />
      </label>
      {urlValid ? null : <ValidationMessage tone="danger">Only canonical HTTPS GitHub repository URLs are accepted in the UI.</ValidationMessage>}
      <label>
        <span>Revision type</span>
        <select value={revisionType} onChange={(event) => setRevisionType(event.target.value as RevisionType)}>
          <option value="default">Default branch</option>
          <option value="branch">Branch</option>
          <option value="tag">Tag</option>
          <option value="commit">Commit</option>
        </select>
      </label>
      {revisionType !== 'default' ? (
        <label>
          <span>Revision value</span>
          <input value={revisionValue} onChange={(event) => setRevisionValue(event.target.value)} />
        </label>
      ) : null}
      <label>
        <span>Optional subdirectory</span>
        <input value={subdirectory} onChange={(event) => setSubdirectory(event.target.value)} />
      </label>
      <label className="checkbox-row">
        <input type="checkbox" checked={includeTests} onChange={(event) => setIncludeTests(event.target.checked)} />
        <span>Include tests</span>
      </label>
      <button className="primary-action" type="button" disabled={loading} onClick={() => void submit()}>{loading ? 'Inspecting' : 'Import and Inspect Repository'}</button>
      {error ? <ValidationMessage tone="danger">{error}</ValidationMessage> : null}
    </section>
  );
}
