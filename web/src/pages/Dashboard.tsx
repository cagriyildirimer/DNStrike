import { CircleGauge } from 'lucide-react';
import { PageHeader } from '../components/Layout/PageHeader';
import { StatCard } from '../components/Layout/StatCard';
import { Target, TestRun } from '../types';
import { ReactNode } from 'react';

function PlaceholderPanel({ title, text, icon }: { title: string; text: string; icon: ReactNode }) {
  return (
    <section className="panel">
      <div className="empty-state">
        <div className="empty-icon">{icon}</div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
    </section>
  );
}

interface DashboardPageProps {
  targets: Target[];
  tests: TestRun[];
}

export function DashboardPage({ targets, tests }: DashboardPageProps) {
  const completed = tests.filter(x => x.status === 'COMPLETED').length;
  
  return (
    <>
      <PageHeader 
        eyebrow="OVERVIEW" 
        title="Dashboard" 
        description="Authorized DNS infrastructure and test lifecycle status."
      />
      <section className="card-grid">
        <StatCard 
          label="Total targets" 
          value={String(targets.length)} 
          detail="Authorized endpoints" 
        />
        <StatCard 
          label="Test records" 
          value={String(tests.length)} 
          detail="Persisted lifecycle entries" 
        />
        <StatCard 
          label="Completed" 
          value={String(completed)} 
          detail="Finished assessments" 
        />
      </section>
      
      <PlaceholderPanel 
        title="Platform ready" 
        text="Target discovery is active. Benchmark execution is the next milestone." 
        icon={<CircleGauge />} 
      />
    </>
  );
}
