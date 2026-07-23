import { GlassPanel } from '../components/GlassPanel';
import { PageHeader } from '../components/PageHeader';
import './pages.css';

export function About() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Project scope" title="About">
        A local Python security analysis workflow that combines deterministic static analysis with structured model review.
      </PageHeader>
      <section className="two-column">
        <GlassPanel className="info-card">
          <h2>Validated scope</h2>
          <p>The scanner is currently validated for Python source code. Other languages should be treated as outside the verified workflow.</p>
          <p>Model analysis uses Qwen2.5-Coder 7B through Ollama. No model training happens in this application; labelled data is used for evaluation.</p>
        </GlassPanel>
        <GlassPanel className="info-card">
          <h2>Scanner modes</h2>
          <p>Semgrep mode uses rule-based static analysis. LLM mode performs independent full-file model analysis. Semgrep-gated mode invokes the model only after Semgrep reports a finding.</p>
          <p>True Hybrid means independent Semgrep and LLM detector execution followed by provenance-aware merge and reporting.</p>
        </GlassPanel>
      </section>
      <section className="two-column">
        <GlassPanel className="info-card">
          <h2>Review model</h2>
          <p>Reports preserve detector provenance, uncertainty, human-review signals, source evidence, structured JSONL output, Markdown summaries, and raw artifacts when requested.</p>
        </GlassPanel>
        <GlassPanel className="info-card">
          <h2>Limitations</h2>
          <p>Local Semgrep coverage is currently deterministic for CWE-078 command injection. Broader CWE coverage varies by available rules, code shape, and model behavior.</p>
          <p>Findings are evidence for review, not a guarantee that code is completely secure.</p>
        </GlassPanel>
      </section>
    </div>
  );
}
