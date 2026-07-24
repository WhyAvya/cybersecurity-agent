import { ArrowRight, Cpu, GitBranch, Layers, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useConfig, useFrozenEvaluation, useHealth } from '../api/queries';
import { GlassPanel } from '../components/GlassPanel';
import { HealthCard } from '../components/HealthCard';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import './pages.css';

const modes = [
  ['Semgrep', 'Static rule-based analysis. LLM is not called.'],
  ['LLM', 'Independent full-file model analysis.'],
  ['Semgrep-gated', 'Semgrep controls whether model analysis is invoked.'],
  ['True Hybrid', 'Independent Semgrep and LLM outputs are merged with provenance.'],
];

export function Dashboard() {
  const health = useHealth();
  const config = useConfig();
  const evaluation = useFrozenEvaluation();
  const checks = health.data?.checks ?? [];
  const ollama = checks.find((check) => check.name === 'Ollama');
  const activeModel = health.data?.active_model?.trim() ?? '';
  const activeModelAvailable = Boolean(activeModel) && ollama?.status === 'ok';

  return (
    <div className="page-stack">
      <GlassPanel className="hero-panel">
        <PageHeader eyebrow="Validated Python workflow" title="Source-code security analysis console">
          Run the existing scanner through a focused web console with truthful system status and no fabricated metrics.
        </PageHeader>
        <div className="hero-panel__actions">
          <Link className="primary-action" to="/scan">
            Start New Scan <ArrowRight size={18} aria-hidden="true" />
          </Link>
          <StatusBadge status="ok" label="Python validated" />
        </div>
      </GlassPanel>

      <section className="status-grid" aria-label="System status summary">
        <HealthCard title="Backend API" check={checks.find((check) => check.name === 'Backend API')} loading={health.isLoading} />
        <HealthCard title="Semgrep" check={checks.find((check) => check.name === 'Semgrep')} loading={health.isLoading} />
        <HealthCard title="Ollama" check={ollama} loading={health.isLoading} />
        <HealthCard
          title="Active model"
          detail={activeModel || config.data?.active_model || 'Model unavailable until health check completes.'}
          status={activeModelAvailable ? 'ok' : 'unavailable'}
          loading={health.isLoading}
        />
      </section>

      <section className="mode-grid" aria-label="Scanner modes">
        {modes.map(([name, description]) => (
          <GlassPanel key={name} className="mode-card" as="article">
            <Layers size={22} aria-hidden="true" />
            <h2>{name}</h2>
            <p>{description}</p>
          </GlassPanel>
        ))}
      </section>

      <section className="two-column">
        <GlassPanel className="info-card">
          <ShieldCheck size={24} aria-hidden="true" />
          <h2>Frozen evaluation</h2>
          {evaluation.isLoading ? <LoadingSkeleton lines={2} /> : null}
          {evaluation.data ? (
            <p>
              {evaluation.data.available
                ? `${evaluation.data.label ?? 'Frozen evaluation'} is available.`
                : evaluation.data.error ?? 'Frozen evaluation artifacts are unavailable.'}
            </p>
          ) : null}
        </GlassPanel>
        <GlassPanel className="info-card">
          <Cpu size={24} aria-hidden="true" />
          <h2>Architecture</h2>
          <p>React calls the FastAPI adapter. The adapter delegates scans to the existing Python orchestrator and report writers.</p>
          <div className="architecture-line">
            <span>React</span>
            <GitBranch size={16} aria-hidden="true" />
            <span>FastAPI</span>
            <GitBranch size={16} aria-hidden="true" />
            <span>Scanner</span>
          </div>
        </GlassPanel>
      </section>
    </div>
  );
}
