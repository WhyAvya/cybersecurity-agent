import { Activity, BarChart3, HeartPulse, Home, Info, PlayCircle, ShieldCheck } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import './shell.css';

const links = [
  { to: '/', label: 'Dashboard', icon: Home },
  { to: '/scan', label: 'New Scan', icon: PlayCircle },
  { to: '/compare', label: 'Compare Modes', icon: BarChart3 },
  { to: '/evaluation', label: 'Evaluation', icon: ShieldCheck },
  { to: '/health', label: 'System Health', icon: HeartPulse },
  { to: '/about', label: 'About', icon: Info },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <Activity size={24} aria-hidden="true" />
        <div>
          <strong>Security Console</strong>
          <span>Python analysis</span>
        </div>
      </div>
      <div className="sidebar__links">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'} onClick={onNavigate}>
            <Icon size={18} aria-hidden="true" />
            <span>{label}</span>
          </NavLink>
        ))}
      </div>
    </nav>
  );
}
