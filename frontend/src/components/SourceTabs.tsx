import './scan.css';

export type SourceTab = 'paste' | 'files' | 'zip' | 'github';

const tabs: Array<{ value: SourceTab; label: string }> = [
  { value: 'paste', label: 'Paste Code' },
  { value: 'files', label: 'Upload Files' },
  { value: 'zip', label: 'Upload Project / ZIP' },
  { value: 'github', label: 'GitHub Repository' },
];

export function SourceTabs({ value, onChange }: { value: SourceTab; onChange: (tab: SourceTab) => void }) {
  return (
    <div className="source-tabs" role="tablist" aria-label="Source input modes">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          role="tab"
          aria-selected={value === tab.value}
          className={value === tab.value ? 'source-tab source-tab--active' : 'source-tab'}
          type="button"
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
