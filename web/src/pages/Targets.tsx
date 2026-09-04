import { Plus, Server, Radar, Trash2, ChevronRight } from 'lucide-react';
import { PageHeader } from '../components/Layout/PageHeader';
import { StatCard } from '../components/Layout/StatCard';
import { Target } from '../types';

interface TargetsPageProps {
  items: Target[];
  loading: boolean;
  failed: boolean;
  openForm: () => void;
  discover: (target: Target) => void;
  discovering: boolean;
  remove: (target: Target) => void;
}

export function TargetsPage({ items, loading, failed, openForm, discover, discovering, remove }: TargetsPageProps) {
  return (
    <>
      <PageHeader 
        eyebrow="INFRASTRUCTURE" 
        title="DNS Targets" 
        description="Manage authorized resolvers and inspect their protocol posture." 
        action={
          <button className="btn btn-primary" onClick={openForm}>
            <Plus size={18} /> Add target
          </button>
        }
      />
      
      <section className="card-grid">
        <StatCard label="Total targets" value={String(items.length)} detail="Authorized endpoints" />
        <StatCard label="UDP enabled" value={String(items.filter(x => x.udp_enabled).length)} detail="Datagram checks ready" />
        <StatCard label="TCP enabled" value={String(items.filter(x => x.tcp_enabled).length)} detail="Fallback checks ready" />
      </section>
      
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Configured targets</h2>
            <p>Discovery sends one bounded probe per enabled protocol.</p>
          </div>
          <span className="count-badge">{items.length} TARGETS</span>
        </div>
        
        {loading ? (
          <div className="empty-state">Loading targets...</div>
        ) : failed ? (
          <div className="empty-state">Targets could not be loaded.</div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon"><Server /></div>
            <h3>No targets yet</h3>
            <p>Add a private or local DNS server to begin discovery.</p>
            <button className="btn btn-secondary" onClick={openForm}>Add your first target</button>
          </div>
        ) : (
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Endpoint</th>
                  <th>Environment</th>
                  <th>Protocols</th>
                  <th>Tags</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {items.map(t => (
                  <tr key={t.id}>
                    <td>
                      <div className="target-info">
                        <span className="status-indicator" />
                        <div>
                          <b>{t.name}</b>
                          <small>{t.description || 'No description'}</small>
                        </div>
                      </div>
                    </td>
                    <td><span className="mono">{t.ip_address}:{t.port}</span></td>
                    <td>{t.environment || '—'}</td>
                    <td>
                      <div className="pills">
                        {t.udp_enabled && <span className="pill">UDP</span>}
                        {t.tcp_enabled && <span className="pill">TCP</span>}
                      </div>
                    </td>
                    <td>
                      <div className="tags">
                        {t.tags.length ? t.tags.map(x => <span className="tag" key={x}>{x}</span>) : '—'}
                      </div>
                    </td>
                    <td>
                      <div className="table-actions">
                        <button className="btn btn-icon btn-danger" title="Delete" onClick={() => remove(t)}>
                          <Trash2 size={16} />
                        </button>
                        <button className="btn btn-icon" onClick={() => discover(t)} disabled={discovering} title="Discover Profile">
                           <ChevronRight size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
