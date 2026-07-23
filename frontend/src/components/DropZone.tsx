import { UploadCloud } from 'lucide-react';
import type { ReactNode } from 'react';
import './scan.css';

export function DropZone({
  label,
  accept,
  multiple,
  children,
  onFiles,
}: {
  label: string;
  accept: string;
  multiple?: boolean;
  children?: ReactNode;
  onFiles: (files: File[]) => void;
}) {
  return (
    <label
      className="drop-zone"
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        onFiles(Array.from(event.dataTransfer.files));
      }}
    >
      <UploadCloud size={24} aria-hidden="true" />
      <strong>{label}</strong>
      {children}
      <input
        type="file"
        accept={accept}
        multiple={multiple}
        onChange={(event) => onFiles(Array.from(event.currentTarget.files ?? []))}
      />
    </label>
  );
}
