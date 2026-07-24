import type { HealthCheck } from '../types/api';
import { StatusBadge } from './StatusBadge';
import { LoadingSkeleton } from './LoadingSkeleton';
import './components.css';

interface HealthCardProps {
  title: string;
  check?: HealthCheck;
  detail?: string;
  status?: string;
  loading?: boolean;
}

export function HealthCard({ title, check, detail, status, loading }: HealthCardProps) {
  if (loading) {
    return (
      <article className="health-card">
        <h3>{title}</h3>
        <LoadingSkeleton lines={2} />
      </article>
    );
  }

  return (
    <article className="health-card">
      <div className="health-card__top">
        <h3>{title}</h3>
        {check ? <StatusBadge status={check.status} /> : <StatusBadge status={status ?? 'unavailable'} label={status ? undefined : 'Unavailable'} />}
      </div>
      <p>{detail ?? check?.message ?? check?.error ?? 'No detail reported.'}</p>
      {check ? (
        <dl>
          <div>
            <dt>Response</dt>
            <dd>{check.response_time_ms} ms</dd>
          </div>
          {check.version ? (
            <div>
              <dt>Version</dt>
              <dd>{check.version}</dd>
            </div>
          ) : null}
        </dl>
      ) : null}
    </article>
  );
}
