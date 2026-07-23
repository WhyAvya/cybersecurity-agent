import './results.css';

export function ProvenanceBadge({ detectors, agreement }: { detectors?: string[]; agreement?: string }) {
  const label = detectors?.length ? detectors.join(' + ') : 'Unavailable';
  return <span className="provenance">{label}{agreement ? ` · ${agreement}` : ''}</span>;
}
