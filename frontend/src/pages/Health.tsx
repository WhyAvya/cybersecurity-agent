import { RefreshCw } from 'lucide-react';
import { useHealth } from '../api/queries';
import { ErrorState } from '../components/ErrorState';
import { HealthCard } from '../components/HealthCard';
import { PageHeader } from '../components/PageHeader';
import './pages.css';

export function Health() {
  const health = useHealth();

  return (
    <div className="page-stack">
      <div className="page-title-row">
        <PageHeader eyebrow="Real service checks" title="System Health">
          Live status from the backend API, scanner adapter, Semgrep, Ollama, report generation, temporary workspace, and evaluation artifacts.
        </PageHeader>
        <button className="secondary-action" onClick={() => void health.refetch()}>
          <RefreshCw size={18} aria-hidden="true" /> Retry
        </button>
      </div>
      {health.isError ? (
        <ErrorState title="Health check failed" message="The backend API did not return health data." onRetry={() => void health.refetch()} />
      ) : null}
      <section className="status-grid">
        {(health.data?.checks ?? Array.from({ length: 7 })).map((check, index) => (
          <HealthCard key={check ? check.name : index} title={check ? check.name : 'Loading'} check={check} loading={health.isLoading} />
        ))}
      </section>
      {health.data ? (
        <dl className="technical-list">
          <div>
            <dt>API version</dt>
            <dd>{health.data.api_version}</dd>
          </div>
          <div>
            <dt>Scanner version</dt>
            <dd>{health.data.scanner_version}</dd>
          </div>
          <div>
            <dt>Supported language</dt>
            <dd>{health.data.supported_language}</dd>
          </div>
          <div>
            <dt>Active scans</dt>
            <dd>{health.data.active_scan_count}</dd>
          </div>
          <div>
            <dt>Workspace policy</dt>
            <dd>{health.data.temporary_workspace_policy}</dd>
          </div>
        </dl>
      ) : null}
    </div>
  );
}
