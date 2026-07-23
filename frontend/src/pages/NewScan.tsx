import { useEffect, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';
import { useConfig } from '../api/queries';
import { FileUploadPanel } from '../components/FileUploadPanel';
import { GitHubImportPanel } from '../components/GitHubImportPanel';
import { GlassPanel } from '../components/GlassPanel';
import { PageHeader } from '../components/PageHeader';
import { PasteCodePanel } from '../components/PasteCodePanel';
import { ScanConfigurationPanel } from '../components/ScanConfigurationPanel';
import type { ScanMode } from '../components/ModeSelector';
import { SourceSummary } from '../components/SourceSummary';
import { SourceTabs, type SourceTab } from '../components/SourceTabs';
import { ValidationMessage } from '../components/ValidationMessage';
import { ZipUploadPanel } from '../components/ZipUploadPanel';
import type { SourceRecord } from '../types/api';
import './newScan.css';

const LAST_SOURCE_KEY = 'vuln-agent:last-source-id';

export function NewScan() {
  const config = useConfig();
  const navigate = useNavigate();
  const [tab, setTab] = useState<SourceTab>('paste');
  const [source, setSource] = useState<SourceRecord | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [mode, setMode] = useState<ScanMode>('hybrid');
  const [scanName, setScanName] = useState('Security scan');
  const [message, setMessage] = useState('');
  const [removeError, setRemoveError] = useState('');
  const [staleSourceNotice, setStaleSourceNotice] = useState('');

  useEffect(() => {
    const sourceId = window.localStorage.getItem(LAST_SOURCE_KEY);
    if (!sourceId) return;
    let cancelled = false;
    apiClient.getSource(sourceId)
      .then((next) => {
        if (!cancelled) acceptSource(next);
      })
      .catch(() => {
        if (!cancelled) {
          window.localStorage.removeItem(LAST_SOURCE_KEY);
          setStaleSourceNotice('The previously selected source is no longer available. The backend may have restarted or the temporary workspace may have expired.');
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function acceptSource(next: SourceRecord) {
    setSource(next);
    setSelectedFiles(next.files.map((file) => file.path));
    setMessage('');
    setRemoveError('');
    setStaleSourceNotice('');
    window.localStorage.setItem(LAST_SOURCE_KEY, next.source_id);
  }

  async function removeSource() {
    if (!source) return;
    try {
      await apiClient.deleteSource(source.source_id);
      setSource(null);
      setSelectedFiles([]);
      window.localStorage.removeItem(LAST_SOURCE_KEY);
    } catch (exc) {
      setRemoveError(exc instanceof Error ? exc.message : 'Source removal failed.');
    }
  }

  const canContinue = Boolean(source && selectedFiles.length && mode);
  const createScan = useMutation({
    mutationFn: apiClient.createScan,
    onSuccess: (job) => void navigate(`/scan/${job.scan_id}`),
    onError: (exc) => setMessage(exc instanceof Error ? exc.message : 'Scan creation failed.'),
  });

  return (
    <div className="page-stack">
      <PageHeader eyebrow="New Scan" title="Prepare a Python source">
        Ingest code or inspect a public repository, choose the scanner mode, and start a backend scan.
      </PageHeader>
      {staleSourceNotice ? (
        <div className="error-state" role="status">
          <div>
            <h3>Previous source expired</h3>
            <p>{staleSourceNotice}</p>
            <button type="button" onClick={() => setStaleSourceNotice('')}>Return to source input</button>
          </div>
        </div>
      ) : null}
      <div className="new-scan-layout">
        <GlassPanel className="source-workbench">
          <SourceTabs value={tab} onChange={setTab} />
          {tab === 'paste' ? <PasteCodePanel onSource={acceptSource} /> : null}
          {tab === 'files' ? <FileUploadPanel config={config.data} onSource={acceptSource} /> : null}
          {tab === 'zip' ? <ZipUploadPanel config={config.data} onSource={acceptSource} /> : null}
          {tab === 'github' ? <GitHubImportPanel onSource={acceptSource} /> : null}
        </GlassPanel>
        <ScanConfigurationPanel
          config={config.data}
          mode={mode}
          onModeChange={setMode}
          scanName={scanName}
          onScanNameChange={setScanName}
          selectedFileCount={selectedFiles.length}
          canContinue={canContinue}
          starting={createScan.isPending}
          onContinue={() => {
            if (!source) return;
            createScan.mutate({
              source_id: source.source_id,
              mode,
              scan_name: scanName || 'Security scan',
              selected_files: selectedFiles,
              save_raw: true,
            });
          }}
        />
      </div>
      {source ? (
        <SourceSummary
          source={source}
          selectedFiles={selectedFiles}
          onToggleFile={(path) =>
            setSelectedFiles((current) => (current.includes(path) ? current.filter((item) => item !== path) : [...current, path]))
          }
          onRemove={() => void removeSource()}
        />
      ) : null}
      {message ? <ValidationMessage tone="warning">{message}</ValidationMessage> : null}
      {removeError ? <ValidationMessage tone="danger">{removeError}</ValidationMessage> : null}
    </div>
  );
}
