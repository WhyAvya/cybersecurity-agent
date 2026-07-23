import { useMemo, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { useConfig, useHealth } from '../api/queries';
import { StatusBadge } from './StatusBadge';
import { Sidebar } from './Sidebar';
import { MobileNav } from './MobileNav';
import './shell.css';

const titles: Record<string, string> = {
  '/': 'Dashboard',
  '/scan': 'New Scan',
  '/compare': 'Compare Modes',
  '/evaluation': 'Evaluation',
  '/health': 'System Health',
  '/about': 'About',
};

export function AppShell() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const location = useLocation();
  const health = useHealth();
  const config = useConfig();
  const title = useMemo(() => {
    if (location.pathname.startsWith('/scan/')) return 'Scan';
    return titles[location.pathname] ?? 'Security Console';
  }, [location.pathname]);
  const backend = health.data?.checks.find((check) => check.name === 'Backend API');
  const semgrep = health.data?.checks.find((check) => check.name === 'Semgrep');
  const ollama = health.data?.checks.find((check) => check.name === 'Ollama');

  return (
    <div className="app-shell">
      <aside className="app-shell__sidebar">
        <Sidebar />
      </aside>
      <div className="app-shell__main">
        <header className="topbar">
          <MobileNav open={drawerOpen} onOpen={() => setDrawerOpen(true)} onClose={() => setDrawerOpen(false)} />
          <h1>{title}</h1>
          <div className="topbar__status" aria-label="System summary">
            {health.isLoading ? <span className="topbar__muted">Checking services</span> : null}
            {backend ? <StatusBadge status={backend.status} label="API" /> : null}
            {semgrep ? <StatusBadge status={semgrep.status} label="Semgrep" /> : null}
            {ollama ? <StatusBadge status={ollama.status} label="Ollama" /> : null}
            <span className="topbar__model">{config.data?.active_model ?? 'Model unavailable'}</span>
          </div>
        </header>
        <main className="content-canvas">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
