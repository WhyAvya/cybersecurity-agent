import { Copy } from 'lucide-react';
import { useState } from 'react';
import './scan.css';

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="icon-text-button"
      type="button"
      onClick={async () => {
        await navigator.clipboard?.writeText(text);
        setCopied(true);
      }}
    >
      <Copy size={16} aria-hidden="true" />
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}
