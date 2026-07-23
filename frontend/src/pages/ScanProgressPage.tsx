import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { terminalScanStates, useArtifacts, useScan, useScanResult } from '../api/queries';
import { ArtifactDownloads } from '../components/ArtifactDownloads';
import { CancelScanButton } from '../components/CancelScanButton';
import { ErrorState } from '../components/ErrorState';
import { FindingDetailDrawer } from '../components/FindingDetailDrawer';
import { FindingsList } from '../components/FindingsList';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ScanStatusHeader } from '../components/ScanStatusHeader';
import { ScanSummary } from '../components/ScanSummary';
import { SourceViewer } from '../components/SourceViewer';
import { StageTimeline } from '../components/StageTimeline';
import { ValidationMessage } from '../components/ValidationMessage';
import type { ScanFinding } from '../types/api';
import './scanPage.css';

export function ScanProgressPage() {
  const { scanId } = useParams();
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null);
  const scan = useScan(scanId);
  const terminal = Boolean(scan.data?.state && terminalScanStates.has(scan.data.state));
  const shouldLoadResult = Boolean(scanId && (scan.data?.state === 'completed' || scan.data?.state === 'completed_with_errors'));
  const result = useScanResult(scanId, shouldLoadResult);
  const artifacts = useArtifacts(scanId, shouldLoadResult);
  const findings = result.data?.findings ?? scan.data?.result?.findings ?? [];

  if (scan.isLoading) return <LoadingSkeleton lines={4} />;
  if (scan.isError) return <ErrorState title="Scan status unavailable" message="The backend did not return scan status." onRetry={() => void scan.refetch()} />;
  if (!scan.data) return <ErrorState title="Scan not found" message="No scan was returned for this ID." />;

  return (
    <div className="page-stack">
      <ScanStatusHeader scan={scan.data} />
      <div className="progress-actions">
        {!terminal ? <CancelScanButton scanId={scanId ?? scan.data.scan_id} /> : null}
        {scan.data.warnings.map((warning) => <ValidationMessage key={warning} tone="warning">{warning}</ValidationMessage>)}
      </div>
      <StageTimeline scan={scan.data} />
      {scan.data.state === 'failed' ? (
        <ErrorState title="Scan failed" message={`${scan.data.error?.message ?? 'The scan failed.'} Stage: ${scan.data.error?.stage ?? scan.data.progress.stage}`} />
      ) : null}
      {scan.data.state === 'cancelled' ? <ValidationMessage tone="warning">Scan cancelled.</ValidationMessage> : null}
      {shouldLoadResult && result.isLoading ? <LoadingSkeleton lines={3} /> : null}
      {result.data?.available === false ? <ValidationMessage tone="warning">Result is not ready yet.</ValidationMessage> : null}
      {result.data ? (
        <>
          <h2>{result.data.status_label ?? 'Scan completed with errors'}</h2>
          <ScanSummary result={result.data} />
          {findings.length ? <FindingsList findings={findings} onSelect={setSelectedFinding} /> : <ValidationMessage tone="success">No findings detected</ValidationMessage>}
          <div className="result-split">
            <SourceViewer files={result.data.source_files} findings={findings} onSelectFinding={setSelectedFinding} />
            <ArtifactDownloads scanId={scanId ?? scan.data.scan_id} artifacts={artifacts.data ?? scan.data.artifacts} />
          </div>
        </>
      ) : null}
      <FindingDetailDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
}
