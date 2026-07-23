import './results.css';

export function SeverityBadge({ severity }: { severity?: string }) {
  const value = severity ?? 'UNKNOWN';
  return <span className={`severity severity--${value.toLowerCase()}`}>{value}</span>;
}
