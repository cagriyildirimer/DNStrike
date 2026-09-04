interface StatCardProps {
  label: string;
  value: string;
  detail: string;
}

export function StatCard({ label, value, detail }: StatCardProps) {
  return (
    <div className="stat-card">
      <span className="label">{label}</span>
      <strong className="value">{value}</strong>
      <small className="detail">{detail}</small>
    </div>
  );
}
