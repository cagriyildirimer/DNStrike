import type { ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: string;
  detail: string;
  icon?: ReactNode;
  tone?: 'cyan' | 'violet' | 'emerald';
}

export function StatCard({ label, value, detail, icon, tone = 'cyan' }: StatCardProps) {
  return (
    <div className={`stat-card stat-card-${tone}`}>
      <div className="stat-card-topline">
        <span className="label">{label}</span>
        {icon && <span className="stat-card-icon">{icon}</span>}
      </div>
      <strong className="value">{value}</strong>
      <small className="detail">{detail}</small>
    </div>
  );
}
