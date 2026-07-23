import { useMemo, useState } from 'react';
import type { ScanFinding } from '../types/api';
import { FindingReviewLabels, UncertaintyNotice } from './FindingReviewLabels';
import { ProvenanceBadge } from './ProvenanceBadge';
import { SeverityBadge } from './SeverityBadge';
import './results.css';

export function FindingsList({ findings, onSelect }: { findings: ScanFinding[]; onSelect: (finding: ScanFinding) => void }) {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [detector, setDetector] = useState('');
  const [review, setReview] = useState(false);
  const [sort, setSort] = useState('severity');
  const filtered = useMemo(() => {
    const text = search.toLowerCase();
    return findings
      .filter((item) => !text || JSON.stringify(item).toLowerCase().includes(text))
      .filter((item) => !severity || item.severity === severity)
      .filter((item) => !detector || item.detectors?.includes(detector))
      .filter((item) => !review || item.needs_human_review)
      .sort((a, b) => String(a[sort as keyof ScanFinding] ?? '').localeCompare(String(b[sort as keyof ScanFinding] ?? '')));
  }, [detector, findings, review, search, severity, sort]);
  return (
    <section className="findings-panel">
      <div className="finding-filters">
        <input aria-label="Search findings" placeholder="Search findings" value={search} onChange={(event) => setSearch(event.target.value)} />
        <select aria-label="Severity filter" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option>
          <option value="LOW">LOW</option><option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
        </select>
        <select aria-label="Detector filter" value={detector} onChange={(event) => setDetector(event.target.value)}>
          <option value="">All detectors</option><option value="semgrep">Semgrep</option><option value="llm">LLM</option>
        </select>
        <select aria-label="Sort findings" value={sort} onChange={(event) => setSort(event.target.value)}>
          <option value="severity">Severity</option><option value="confidence">Confidence</option><option value="relative_file">Filename</option><option value="normalized_cwe">CWE</option><option value="detector">Detector</option>
        </select>
        <label className="checkbox-row"><input type="checkbox" checked={review} onChange={(event) => setReview(event.target.checked)} /> Review required</label>
      </div>
      {filtered.length ? (
        <div className="findings-list">
          {filtered.map((finding) => (
            <button key={finding.finding_id} className="finding-row" type="button" onClick={() => onSelect(finding)}>
              <span><strong>{finding.normalized_cwe ?? 'CWE unavailable'}</strong>{finding.user_classification ?? finding.status ?? 'Finding'}</span>
              <SeverityBadge severity={finding.severity} />
              <span>{finding.relative_file}:{finding.line_start ?? '?'}{finding.location_is_approximate ? ' approximate' : ''}</span>
              <span>{typeof finding.confidence === 'number' ? finding.confidence.toFixed(2) : 'Confidence unavailable'}</span>
              <ProvenanceBadge detectors={finding.detectors} agreement={finding.agreement_status} />
              <FindingReviewLabels finding={finding} />
              <UncertaintyNotice finding={finding} />
              <small>{finding.reasoning_summary ?? 'No explanation provided.'}</small>
            </button>
          ))}
        </div>
      ) : <p className="muted-line">No findings match the current filters.</p>}
    </section>
  );
}
