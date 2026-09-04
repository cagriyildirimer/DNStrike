import { ReactNode } from 'react';
import { PageHeader } from '../components/Layout/PageHeader';

interface PlaceholderPageProps {
  eyebrow: string;
  title: string;
  description: string;
  icon: ReactNode;
}

export function PlaceholderPage({ eyebrow, title, description, icon }: PlaceholderPageProps) {
  return (
    <>
      <PageHeader eyebrow={eyebrow} title={title} description={description} />
      <section className="panel">
        <div className="empty-state">
          <div className="empty-icon">{icon}</div>
          <h3>Development milestone</h3>
          <p>{description}</p>
        </div>
      </section>
    </>
  );
}
