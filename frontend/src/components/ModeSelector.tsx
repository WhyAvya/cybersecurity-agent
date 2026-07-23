import './scan.css';

const modes = [
  { value: 'semgrep', title: 'Semgrep', description: 'Fast rule-based static analysis.', llm: 'LLM not called', speed: 'Fastest' },
  { value: 'llm', title: 'LLM', description: 'Independent full-file LLM analysis.', llm: 'LLM used', speed: 'Model-dependent' },
  { value: 'semgrep_gated', title: 'Semgrep-gated', description: 'Semgrep determines whether LLM analysis is invoked.', llm: 'Conditional LLM', speed: 'Usually faster than full LLM' },
  { value: 'hybrid', title: 'True Hybrid', description: 'Independent Semgrep and LLM execution with provenance-aware merge.', llm: 'LLM used', speed: 'Most complete', recommended: true },
] as const;

export type ScanMode = (typeof modes)[number]['value'];

export function ModeSelector({ value, onChange }: { value: ScanMode; onChange: (value: ScanMode) => void }) {
  return (
    <fieldset className="mode-selector">
      <legend>Scanner mode</legend>
      {modes.map((mode) => (
        <label key={mode.value} className={`mode-option ${value === mode.value ? 'mode-option--selected' : ''}`}>
          <input type="radio" name="scan-mode" value={mode.value} checked={value === mode.value} onChange={() => onChange(mode.value)} />
          <span>
            <strong>{mode.title}{'recommended' in mode ? ' · recommended' : ''}</strong>
            <small>{mode.description}</small>
            <em>{mode.llm} · {mode.speed}</em>
          </span>
        </label>
      ))}
    </fieldset>
  );
}
