import type { ScanFinding } from '../types/api';

const LOW_CONFIDENCE_THRESHOLD = 0.6;

export function isLlmOnlyFinding(finding: ScanFinding) {
  return finding.agreement_status === 'llm_only' || (finding.detectors?.length === 1 && finding.detectors[0] === 'llm');
}

export function isUncertainFinding(finding: ScanFinding) {
  return finding.analyzer_verdict === 'UNCERTAIN' || finding.user_classification === 'UNCERTAIN' || finding.status === 'NEEDS_REVIEW';
}

export function isLowConfidenceFinding(finding: ScanFinding) {
  return typeof finding.confidence === 'number' && finding.confidence < LOW_CONFIDENCE_THRESHOLD;
}

export function needsHumanReview(finding: ScanFinding) {
  return Boolean(finding.needs_human_review) || isUncertainFinding(finding);
}

export function shouldShowPossibleFalsePositive(finding: ScanFinding) {
  return isUncertainFinding(finding) || isLowConfidenceFinding(finding);
}

export function shouldShowUncertaintyNotice(finding: ScanFinding) {
  return isLlmOnlyFinding(finding) && shouldShowPossibleFalsePositive(finding);
}

export function FindingReviewLabels({ finding }: { finding: ScanFinding }) {
  const labels = [
    needsHumanReview(finding) ? 'Needs human review' : '',
    shouldShowPossibleFalsePositive(finding) ? 'Possible false positive' : '',
    isLlmOnlyFinding(finding) ? 'LLM-only finding' : '',
  ].filter(Boolean);
  if (!labels.length) return null;
  return (
    <div className="finding-labels" aria-label="Finding review labels">
      {labels.map((label) => <span key={label}>{label}</span>)}
    </div>
  );
}

export function UncertaintyNotice({ finding }: { finding: ScanFinding }) {
  if (!shouldShowUncertaintyNotice(finding)) return null;
  return (
    <p className="technical-notice">
      This finding was produced by the LLM only and has low confidence or uncertain evidence. Review the control flow,
      validation, allowlists, and input restrictions before treating it as a vulnerability.
    </p>
  );
}
