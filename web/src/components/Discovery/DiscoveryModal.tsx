import { X } from 'lucide-react';
import { Target, DiscoveryProfile } from '../../types';

interface DiscoveryModalProps {
  target: Target;
  data: DiscoveryProfile;
  close: () => void;
}

function Protocol({ name, item }: { name: string; item: { available: boolean; latency_ms: number; error?: string } }) {
  return (
    <div className={`protocol-status ${item.available ? 'ok' : 'fail'}`}>
      <div>
        <span style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{name}</span>
        <strong>{item.available ? 'Available' : 'Unavailable'}</strong>
      </div>
      <small style={{ color: 'var(--text-muted)' }}>
        {item.available ? `${item.latency_ms.toFixed(2)} ms` : item.error}
      </small>
    </div>
  );
}

function Feature({ label, value }: { label: string; value: boolean }) {
  return (
    <div className={`feature-item ${value ? 'yes' : 'no'}`}>
      <span>{label}</span>
      <b>{value ? 'Supported' : 'Not detected'}</b>
    </div>
  );
}

export function DiscoveryModal({ target, data, close }: DiscoveryModalProps) {
  return (
    <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) close(); }}>
      <div className="modal-content">
        <div className="modal-header">
          <div>
            <span className="eyebrow" style={{ color: 'var(--accent-blue)', fontSize: '0.8rem', letterSpacing: '0.1em' }}>SERVER PROFILE</span>
            <h2 style={{ marginTop: '0.25rem', marginBottom: '0.5rem' }}>{target.name}</h2>
            <span className="mono">{data.target}</span>
          </div>
          <button className="btn-icon" onClick={close}><X /></button>
        </div>
        
        <div className="modal-body">
          <div className="discovery-stats">
            <div className="discovery-stat-box">
              <span className="title">Average Latency</span>
              <span className="val">{data.average_latency_ms.toFixed(2)} ms</span>
            </div>
            <div className="discovery-stat-box">
              <span className="title">Response Size</span>
              <span className="val">{data.response_size} B</span>
            </div>
          </div>
          
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Protocols</h3>
          <div className="form-grid-2" style={{ marginBottom: '2rem' }}>
            <Protocol name="UDP" item={data.udp} />
            <Protocol name="TCP" item={data.tcp} />
          </div>
          
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div className="features-grid">
            <Feature label="Recursion" value={data.recursion_enabled} />
            <Feature label="Authoritative" value={data.authoritative} />
            <Feature label="EDNS" value={data.edns_supported} />
            <Feature label="DNSSEC signals" value={data.dnssec_supported} />
            <Feature label="TCP fallback" value={data.tcp_fallback} />
          </div>
          
          <div style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginRight: '1rem' }}>FLAGS</span>
            <span className="pill" style={{ marginRight: '0.5rem' }}>RA {Number(data.flags.ra)}</span>
            <span className="pill" style={{ marginRight: '0.5rem' }}>RD {Number(data.flags.rd)}</span>
            <span className="pill" style={{ marginRight: '0.5rem' }}>AA {Number(data.flags.aa)}</span>
            <span className="pill">TC {Number(data.flags.tc)}</span>
          </div>
        </div>
        
        <div className="modal-footer">
          <button className="btn btn-primary" onClick={close}>Done</button>
        </div>
      </div>
    </div>
  );
}
