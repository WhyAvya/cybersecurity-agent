import type { ScanResult } from '../types/api';
import './results.css';

const labels: Record<string, string> = {
  files_scanned: 'Files scanned',
  files_with_findings: 'Files with findings',
  total_grouped_findings: 'Grouped findings',
  potentially_vulnerable_findings: 'Potential vulnerabilities',
  review_required_findings: 'Review required',
  semgrep_matches: 'Semgrep matches',
  llm_matches: 'LLM matches',
  detector_agreements: 'Detector agreements',
  errors: 'Errors',
};

export function ScanSummary({ result }: { result?: ScanResult }) {
  const entries = Object.entries(result?.summary ?? {}).filter(([key]) => key in labels);
  if (!entries.length) return null;
  return (
    <section className="summary-cards" aria-label="Scan result summary">
      {entries.map(([key, value]) => (
        <article key={key} className="summary-card">
          <span>{labels[key]}</span>
          <strong>{value}</strong>
        </article>
      ))}
    </section>
  );
}
