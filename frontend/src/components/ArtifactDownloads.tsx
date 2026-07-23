import { apiClient } from '../api/client';
import type { Artifact } from '../types/api';
import { formatBytes } from './FileList';
import './results.css';

export function ArtifactDownloads({ scanId, artifacts }: { scanId: string; artifacts?: Artifact[] }) {
  if (!artifacts?.length) return <p className="muted-line">No artifacts are available for download.</p>;
  const groups = artifacts.reduce<Record<string, Artifact[]>>((acc, artifact) => {
    acc[artifact.category] = [...(acc[artifact.category] ?? []), artifact];
    return acc;
  }, {});
  return (
    <section className="artifact-panel">
      <h2>Downloads</h2>
      {Object.entries(groups).map(([category, items]) => (
        <div key={category}>
          <h3>{category}</h3>
          <ul className="file-list">
            {items.map((artifact) => (
              <li key={artifact.path}>
                <div><span>{artifact.name}</span></div>
                <small>{formatBytes(artifact.size)}</small>
                <a href={apiClient.artifactUrl(scanId, artifact.path)} download={artifact.name}>Download</a>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
