import { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { Radar, Server, Zap, Activity, History, Settings, ShieldCheck } from 'lucide-react';

interface NavProps {
  to: string;
  icon: ReactNode;
  label: string;
  badge?: string;
}

function Nav({ to, icon, label, badge }: NavProps) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}>
      {icon}
      <span>{label}</span>
      {badge && <span className="nav-badge">{badge}</span>}
    </NavLink>
  );
}

export function Sidebar({ runningTestsCount }: { runningTestsCount: number }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Radar size={24} />
        </div>
        <div className="brand-text">
          <h2>DNStrike</h2>
          <span>Resilience Lab</span>
        </div>
      </div>
      
      <nav className="nav-menu">
        <Nav to="/targets" icon={<Server size={20} />} label="Targets" />
        <Nav to="/tests/new" icon={<Zap size={20} />} label="New Test" />
        <Nav to="/tests/running" icon={<Activity size={20} />} label="Running Tests" badge={runningTestsCount > 0 ? String(runningTestsCount) : undefined} />
        <Nav to="/tests/history" icon={<History size={20} />} label="Test History" />
      </nav>
      
      <div className="sidebar-footer">
        <Nav to="/settings" icon={<Settings size={20} />} label="Settings" />
        <div className="safety-card">
          <ShieldCheck size={20} />
          <div>
            <b>Safe mode active</b>
            <span>Private networks only</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
