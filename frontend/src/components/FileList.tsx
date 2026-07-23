import type { SourceFile } from '../types/api';
import './scan.css';

export function formatBytes(size: number) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

export function FileList({
  files,
  onRemove,
  selectable,
  selected,
  onToggle,
}: {
  files: Array<File | SourceFile>;
  onRemove?: (name: string) => void;
  selectable?: boolean;
  selected?: string[];
  onToggle?: (path: string) => void;
}) {
  if (!files.length) return <p className="muted-line">No files selected.</p>;
  return (
    <ul className="file-list">
      {files.map((file) => {
        const path = 'path' in file ? file.path : file.name;
        const size = file.size;
        return (
          <li key={path}>
            <div>
              {selectable ? (
                <input
                  aria-label={`Select ${path}`}
                  type="checkbox"
                  checked={selected?.includes(path) ?? true}
                  onChange={() => onToggle?.(path)}
                />
              ) : null}
              <span>{path}</span>
            </div>
            <small>{formatBytes(size)}</small>
            {onRemove ? (
              <button type="button" onClick={() => onRemove(path)}>
                Remove
              </button>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
