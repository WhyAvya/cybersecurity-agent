import { useMemo, useState } from 'react';
import type { ScanFinding } from '../types/api';
import { CopyButton } from './CopyButton';
import './results.css';

export function SourceViewer({ files, findings, onSelectFinding }: { files?: Record<string, string>; findings: ScanFinding[]; onSelectFinding: (finding: ScanFinding) => void }) {
  const fileNames = Object.keys(files ?? {});
  const [selected, setSelected] = useState(fileNames[0] ?? '');
  const active = selected || fileNames[0];
  const code = files?.[active] ?? '';
  const lines = code.split('\n');
  const approximate = findings.filter((finding) => finding.relative_file === active && finding.location_is_approximate);
  const affected = useMemo(() => new Set(findings.filter((f) => f.relative_file === active && !f.location_is_approximate).flatMap((f) => {
    const start = f.line_start ?? 0;
    const end = f.line_end ?? start;
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, i) => start + i);
  })), [active, findings]);
  if (!fileNames.length) return <p className="muted-line">Source text is unavailable from the scan result.</p>;
  return (
    <section className="source-viewer">
      <div className="source-files">
        <h2>Source files</h2>
        {fileNames.map((name) => <button key={name} type="button" className={active === name ? 'active' : ''} onClick={() => setSelected(name)}>{name}</button>)}
      </div>
      <div className="code-panel">
        <div className="code-panel__bar"><strong>{active}</strong><CopyButton text={code} /></div>
        {approximate.length ? <p className="validation validation--warning">Approximate location: one or more findings in this file could not be verified to an exact line.</p> : null}
        <pre>{lines.map((line, index) => {
          const number = index + 1;
          const finding = findings.find((item) => item.relative_file === active && !item.location_is_approximate && number >= (item.line_start ?? 0) && number <= (item.line_end ?? 0));
          return (
            <button key={number} className={affected.has(number) ? 'code-line code-line--hit' : 'code-line'} type="button" onClick={() => finding && onSelectFinding(finding)}>
              <span>{number}</span><code>{line || ' '}</code>
            </button>
          );
        })}</pre>
      </div>
    </section>
  );
}
