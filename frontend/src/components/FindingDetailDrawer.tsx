import type { ScanFinding } from '../types/api';
import { FindingReviewLabels, UncertaintyNotice } from './FindingReviewLabels';
import { ProvenanceBadge } from './ProvenanceBadge';
import { SeverityBadge } from './SeverityBadge';
import './results.css';

export function FindingDetailDrawer({ finding, onClose }: { finding: ScanFinding | null; onClose: () => void }) {
  if (!finding) return null;
  return (
    <aside className="finding-drawer" role="dialog" aria-modal="false" aria-label="Finding details">
      <button className="icon-text-button" type="button" onClick={onClose}>Close</button>
      <h2>{finding.normalized_cwe ?? 'Finding'}</h2>
      <div className="drawer-badges"><SeverityBadge severity={finding.severity} /><ProvenanceBadge detectors={finding.detectors} agreement={finding.agreement_status} /></div>
      <FindingReviewLabels finding={finding} />
      <UncertaintyNotice finding={finding} />
      <dl className="repo-meta">
        <div><dt>Finding ID</dt><dd>{finding.finding_id}</dd></div>
        <div><dt>File</dt><dd>{finding.relative_file ?? 'Unavailable'}</dd></div>
        <div><dt>Line range</dt><dd>{finding.line_start ?? '?'}-{finding.line_end ?? '?'}{finding.location_is_approximate ? ' (Approximate location)' : ''}</dd></div>
        {finding.original_start_line != null ? <div><dt>Original model line</dt><dd>{finding.original_start_line}-{finding.original_end_line ?? finding.original_start_line}</dd></div> : null}
        <div><dt>Confidence</dt><dd>{typeof finding.confidence === 'number' ? finding.confidence.toFixed(2) : 'Unavailable'}</dd></div>
        <div><dt>Rule IDs</dt><dd>{finding.underlying_rule_ids?.join(', ') || finding.rule_id || 'Unavailable'}</dd></div>
        <div><dt>LLM classification</dt><dd>{finding.analyzer_verdict ?? 'Unavailable'}</dd></div>
      </dl>
      <section><h3>Explanation</h3><p>{finding.reasoning_summary ?? 'No explanation provided.'}</p></section>
      <section><h3>Detector evidence</h3><p>{finding.sink_evidence || finding.source_evidence || finding.data_flow_evidence || 'No evidence text provided.'}</p></section>
      {finding.location_is_approximate ? <p className="validation validation--warning">{finding.location_note ?? 'Approximate location: returned evidence could not verify an exact line.'}</p> : null}
      <section><h3>Suggested remediation - review before applying.</h3><p>{finding.remediation || 'No remediation provided.'}</p></section>
      {finding.review_reason ? <p className="validation validation--warning">{finding.review_reason}</p> : null}
    </aside>
  );
}
