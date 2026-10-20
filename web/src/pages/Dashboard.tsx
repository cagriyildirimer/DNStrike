import { ShieldCheck, Activity, Server, Gauge, FlaskConical } from 'lucide-react';
import { PageHeader } from '../components/Layout/PageHeader';
import { StatCard } from '../components/Layout/StatCard';
import { Target, TestRun } from '../types';
import { Link } from 'react-router-dom';

interface DashboardPageProps {
  targets: Target[];
  tests: TestRun[];
}

export function DashboardPage({ targets, tests }: DashboardPageProps) {
  const completed = tests.filter(x => x.status === 'COMPLETED').length;
  const running = tests.filter(x => x.status === 'RUNNING').length;
  const failed = tests.filter(x => x.status === 'FAILED').length;

  const scoredTests = tests.filter(x => x.status === 'COMPLETED' && x.resilience_score !== null && x.resilience_score !== undefined);
  const avgScore = scoredTests.length > 0
    ? Math.round(scoredTests.reduce((acc, t) => acc + (t.resilience_score ?? 0), 0) / scoredTests.length)
    : null;

  const recentTests = tests.slice(0, 5);

  return (
    <>
      <PageHeader 
        eyebrow="OVERVIEW" 
        title="Dashboard" 
        description="Authorized DNS infrastructure resilience & security operations."
      />

      <section className="card-grid" style={{ marginBottom: '2rem' }}>
        <StatCard 
          label="Total targets" 
          value={String(targets.length)} 
          detail="Configured endpoints"
          icon={<Server size={18} />}
          tone="cyan"
        />
        <StatCard 
          label="Total Tests" 
          value={String(tests.length)} 
          detail={`${completed} finished, ${running} running, ${failed} failed`}
          icon={<FlaskConical size={18} />}
          tone="violet"
        />
        <StatCard 
          label="Avg Resilience Score" 
          value={avgScore !== null ? `${avgScore}/100` : 'N/A'} 
          detail="Across completed tests"
          icon={<Gauge size={18} />}
          tone="emerald"
        />
      </section>
      
      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-header" style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldCheck size={18} style={{ color: 'var(--accent-blue)' }} /> Target Endpoints
            </h3>
            <Link to="/targets" className="btn btn-secondary" style={{ padding: '0.25rem 0.75rem', fontSize: '0.8rem' }}>View All</Link>
          </div>
          <div className="table-responsive">
            <table style={{ margin: 0 }}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>IP / Host</th>
                  <th>Port</th>
                </tr>
              </thead>
              <tbody>
                {targets.slice(0, 5).map(t => (
                  <tr key={t.id}>
                    <td style={{ fontWeight: 600 }}>{t.name}</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.ip_address}</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.port}</td>
                  </tr>
                ))}
                {targets.length === 0 && (
                  <tr><td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>No targets configured yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header" style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={18} style={{ color: 'var(--accent-purple)' }} /> Recent Test Executions
            </h3>
            <Link to="/tests" className="btn btn-secondary" style={{ padding: '0.25rem 0.75rem', fontSize: '0.8rem' }}>View All</Link>
          </div>
          <div className="table-responsive">
            <table style={{ margin: 0 }}>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Scenario</th>
                  <th>Status</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {recentTests.map(t => (
                  <tr key={t.id}>
                    <td style={{ fontFamily: 'monospace' }}>#{t.id}</td>
                    <td style={{ fontSize: '0.85rem' }}>{t.scenario}</td>
                    <td>
                      <span className={`pill ${t.status === 'COMPLETED' ? 'pill-completed' : t.status === 'FAILED' ? 'pill-failed' : 'pill-pending'}`}>
                        {t.status}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: (t.resilience_score !== null && t.resilience_score !== undefined) ? (t.resilience_score >= 80 ? 'var(--accent-green)' : 'var(--accent-amber)') : 'var(--text-muted)' }}>
                      {(t.resilience_score !== null && t.resilience_score !== undefined) ? `${t.resilience_score}` : '-'}
                    </td>
                  </tr>
                ))}
                {recentTests.length === 0 && (
                  <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>No tests run yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
