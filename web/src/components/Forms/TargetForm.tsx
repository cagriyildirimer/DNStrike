import { FormEvent } from 'react';
import { X } from 'lucide-react';
import { TargetInput } from '../../types';

interface TargetFormProps {
  form: TargetInput;
  setForm: (form: TargetInput) => void;
  close: () => void;
  submit: (event: FormEvent) => void;
  pending: boolean;
  error: Error | null;
}

export function TargetForm({ form, setForm, close, submit, pending, error }: TargetFormProps) {
  return (
    <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) close(); }}>
      <form className="modal-content" onSubmit={submit}>
        <div className="modal-header">
          <div>
            <span className="eyebrow" style={{ color: 'var(--accent-blue)', fontSize: '0.8rem', letterSpacing: '0.1em' }}>AUTHORIZED ASSET</span>
            <h2 style={{ marginTop: '0.25rem' }}>Add DNS target</h2>
          </div>
          <button type="button" className="btn-icon" onClick={close}><X /></button>
        </div>
        
        <div className="modal-body">
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
            Only private, loopback, link-local and IPv6 ULA addresses are accepted.
          </p>
          
          <div className="form-grid-2">
            <div className="form-group">
              <label>Target name</label>
              <input 
                className="form-control"
                required 
                maxLength={100} 
                placeholder="Internal AD DNS" 
                value={form.name} 
                onChange={e => setForm({ ...form, name: e.target.value })} 
              />
            </div>
            <div className="form-group">
              <label>Environment</label>
              <input 
                className="form-control"
                placeholder="Production Lab" 
                value={form.environment} 
                onChange={e => setForm({ ...form, environment: e.target.value })} 
              />
            </div>
            <div className="form-group">
              <label>DNS server IP</label>
              <input 
                className="form-control"
                required 
                placeholder="192.168.1.53" 
                value={form.ip_address} 
                onChange={e => setForm({ ...form, ip_address: e.target.value })} 
              />
            </div>
            <div className="form-group">
              <label>Port</label>
              <input 
                className="form-control"
                required 
                type="number" 
                min={1} 
                max={65535} 
                value={form.port} 
                onChange={e => setForm({ ...form, port: Number(e.target.value) })} 
              />
            </div>
          </div>
          
          <div className="form-group">
            <label>Description</label>
            <textarea 
              className="form-control"
              rows={3} 
              placeholder="Resolver role and ownership notes" 
              value={form.description} 
              onChange={e => setForm({ ...form, description: e.target.value })} 
            />
          </div>
          
          <div className="form-group">
            <label>Tags (comma separated)</label>
            <input 
              className="form-control"
              placeholder="ad, branch-01" 
              onChange={e => setForm({ ...form, tags: e.target.value.split(',').map(x => x.trim()).filter(Boolean) })} 
            />
          </div>
          
          <div className="form-grid-2" style={{ marginTop: '1rem' }}>
            <label className="checkbox-label">
              <input 
                type="checkbox" 
                checked={form.udp_enabled} 
                onChange={e => setForm({ ...form, udp_enabled: e.target.checked })} 
              />
              UDP enabled
            </label>
            <label className="checkbox-label">
              <input 
                type="checkbox" 
                checked={form.tcp_enabled} 
                onChange={e => setForm({ ...form, tcp_enabled: e.target.checked })} 
              />
              TCP enabled
            </label>
          </div>
          
          {error && <div style={{ color: 'var(--accent-red)', marginTop: '1rem', padding: '1rem', background: 'rgba(239,68,68,0.1)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.3)' }}>{error.message}</div>}
        </div>
        
        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={close}>Cancel</button>
          <button className="btn btn-primary" disabled={pending}>{pending ? 'Saving...' : 'Save target'}</button>
        </div>
      </form>
    </div>
  );
}
