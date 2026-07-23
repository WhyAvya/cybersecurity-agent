import { RefreshCw } from 'lucide-react';
import { useFrozenEvaluation } from '../api/queries';
import { ErrorState } from '../components/ErrorState';
import { GlassPanel } from '../components/GlassPanel';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { PageHeader } from '../components/PageHeader';
import './pages.css';

function DataTable({ title, rows }: { title: string; rows?: Array<Record<string, string>> }) {
  if (!rows?.length) return null;
  const columns = Array.from(new Set(rows.flatMap((row) => Object.keys(row))));
  return (
    <section className="table-panel">
      <h2>{title}</h2>
      <div className="responsive-table">
        <table>
          <thead><tr>{columns.map((column) => <th key={column}>{column.replace(/_/g, ' ')}</th>)}</tr></thead>
          <tbody>{rows.map((row, index) => <tr key={index}>{columns.map((column) => <td key={column}>{row[column] || 'Unavailable'}</td>)}</tr>)}</tbody>
        </table>
      </div>
    </section>
  );
}

export function Evaluation() {
  const evaluation = useFrozenEvaluation();
  const data = evaluation.data;

  return (
    <div className="page-stack">
      <div className="page-title-row">
        <PageHeader eyebrow="Frozen artifacts" title="Evaluation">
          This page renders saved benchmark artifacts only. It does not calculate metrics from live scans.
        </PageHeader>
        <button className="secondary-action" type="button" onClick={() => void evaluation.refetch()}>
          <RefreshCw size={18} aria-hidden="true" /> Retry
        </button>
      </div>
      {evaluation.isLoading ? <LoadingSkeleton lines={4} /> : null}
      {evaluation.isError ? <ErrorState title="Evaluation unavailable" message="The backend did not return evaluation metadata." onRetry={() => void evaluation.refetch()} /> : null}
      {data && !data.available ? (
        <GlassPanel className="info-card">
          <h2>Verified artifacts are missing</h2>
          <p>{data.error ?? 'The frozen evaluation files were not found.'}</p>
          <dl className="technical-list">
            <div><dt>Run ID</dt><dd>{data.run_id || 'Unavailable'}</dd></div>
            <div><dt>Expected artifact path</dt><dd>{data.path ?? 'Unavailable'}</dd></div>
          </dl>
        </GlassPanel>
      ) : null}
      {data?.available ? (
        <>
          <GlassPanel className="info-card">
            <h2>{data.label ?? 'Frozen evaluation'}</h2>
            <dl className="technical-list">
              <div><dt>Run ID</dt><dd>{data.run_id}</dd></div>
              {data.path ? <div><dt>Artifact path</dt><dd>{data.path}</dd></div> : null}
            </dl>
            {data.conclusion ? <p>{data.conclusion}</p> : null}
          </GlassPanel>
          {data.summary_markdown ? <pre className="markdown-summary">{data.summary_markdown}</pre> : null}
          <DataTable title="Mode metrics" rows={data.mode_comparison} />
          <DataTable title="Hybrid agreement" rows={data.hybrid_agreement} />
          <DataTable title="Runtime errors" rows={data.runtime_errors} />
        </>
      ) : null}
    </div>
  );
}
