import './components.css';

interface StatusBadgeProps {
  status: string;
  label?: string;
}

export function StatusBadge({ status, label }: StatusBadgeProps) {
  const normalized = status.toLowerCase();
  const tone = normalized === 'ok' ? 'success' : normalized === 'unavailable' || normalized === 'error' ? 'danger' : 'warning';
  return (
    <span className={`status-badge status-badge--${tone}`}>
      <span className="status-badge__dot" aria-hidden="true" />
      {label ?? status}
    </span>
  );
}
