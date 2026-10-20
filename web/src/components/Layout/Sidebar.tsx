import { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { Radar, LayoutDashboard, Server, Zap, Activity, History, Settings, ShieldCheck } from 'lucide-react';

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
        <div className="nav-section">
          <span className="nav-section-label">Workspace</span>
          <Nav to="/dashboard" icon={<LayoutDashboard size={19} />} label="Dashboard" />
          <Nav to="/targets" icon={<Server size={19} />} label="Targets" />
        </div>
        <div className="nav-section">
          <span className="nav-section-label">Test operations</span>
          <Nav to="/tests/new" icon={<Zap size={19} />} label="New Test" />
          <Nav to="/tests/running" icon={<Activity size={19} />} label="Running Tests" badge={runningTestsCount > 0 ? String(runningTestsCount) : undefined} />
          <Nav to="/tests/history" icon={<History size={19} />} label="Test History" />
        </div>
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
