import { useState, useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Play, Zap, ShieldAlert } from 'lucide-react';
import { PageHeader } from '../components/Layout/PageHeader';
import { api } from '../api';

export function NewTestPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const targets = useQuery({ queryKey: ['targets'], queryFn: api.listTargets });
  const scenarios = useQuery({ queryKey: ['scenarios'], queryFn: api.listScenarios });
  
  const [targetId, setTargetId] = useState(0);
  const [selectedScenarioId, setSelectedScenarioId] = useState('');
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [notice, setNotice] = useState('');

  // Update default config when scenario changes
  useEffect(() => {
    if (scenarios.data && selectedScenarioId) {
      const scenario = scenarios.data.find(s => s.id === selectedScenarioId);
      if (scenario && scenario.default_config) {
        setConfig({ ...scenario.default_config });
      }
    }
  }, [selectedScenarioId, scenarios.data]);

  // Set initial scenario once loaded
  useEffect(() => {
    if (scenarios.data && scenarios.data.length > 0 && !selectedScenarioId) {
      setSelectedScenarioId(scenarios.data[0].id);
    }
  }, [scenarios.data, selectedScenarioId]);

  const submit = useMutation({
    mutationFn: api.createTest,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tests'] });
      navigate('/tests/running');
    },
    onError: (e: Error) => setNotice(e.message)
  });

  const selectedScenario = scenarios.data?.find(s => s.id === selectedScenarioId);

  const [activeCategory, setActiveCategory] = useState<string>('all');

  const categories = [
    { id: 'all', label: 'All Scenarios', icon: '🌐' },
    { id: 'audit', label: 'Security Audits', icon: '🛡️' },
    { id: 'performance', label: 'Performance', icon: '⚡' },
    { id: 'resolver-cache', label: 'Resolver Cache', icon: '🧠' },
    { id: 'volume', label: 'Volume & Exhaustion', icon: '💣' },
  ];

  const filteredScenarios = scenarios.data?.filter(s => 
    activeCategory === 'all' ? true : s.category === activeCategory
  ) ?? [];

  // Auto select first scenario when category changes if current scenario doesn't belong
  const handleCategoryChange = (catId: string) => {
    setActiveCategory(catId);
    if (scenarios.data) {
      const match = scenarios.data.find(s => catId === 'all' || s.category === catId);
      if (match) {
        setSelectedScenarioId(match.id);
      }
    }
  };

  return (
    <>
      <PageHeader 
        eyebrow="TEST ORCHESTRATOR" 
        title="New Execution" 
        description="Launch an automated security audit or benchmark against an authorized target." 
        action={
          <button 
            className="btn btn-primary" 
            onClick={() => submit.mutate({ target_id: targetId, scenario: selectedScenarioId, config })} 
            disabled={submit.isPending || targetId === 0 || !selectedScenarioId}
          >
            <Play size={18} /> {submit.isPending ? 'Queuing...' : 'Launch Test'}
          </button>
        }
      />
      
      {notice && <div className="notice" style={{ marginBottom: '1.5rem' }} onClick={() => setNotice('')}>{notice}</div>}
      
      <div className="card-grid" style={{ gridTemplateColumns: '2fr 1fr' }}>
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Configuration</h2>
              <p>Select category, attack scenario, and define execution parameters.</p>
            </div>
            <Zap size={24} style={{ color: 'var(--accent-blue)' }} />
          </div>
          
          <div className="modal-body" style={{ padding: '0 1.5rem 1.5rem 1.5rem' }}>
            <div className="form-group">
              <label>Target Server</label>
              <select className="form-control" value={targetId} onChange={e => setTargetId(Number(e.target.value))}>
                <option value={0}>-- Select an authorized target --</option>
                {targets.data?.map(t => <option key={t.id} value={t.id}>{t.name} ({t.ip_address}:{t.port})</option>)}
              </select>
            </div>
            
            <div className="form-group" style={{ marginTop: '1.5rem' }}>
              <label>1. Attack Category</label>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                {categories.map(cat => (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => handleCategoryChange(cat.id)}
                    className="btn"
                    style={{
                      padding: '0.4rem 0.8rem',
                      fontSize: '0.8rem',
                      background: activeCategory === cat.id ? 'var(--accent-blue)' : 'rgba(255,255,255,0.05)',
                      color: activeCategory === cat.id ? '#fff' : 'var(--text-secondary)',
                      border: `1px solid ${activeCategory === cat.id ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      borderRadius: '6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem'
                    }}
                  >
                    <span>{cat.icon}</span>
                    <span>{cat.label}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="form-group" style={{ marginTop: '1.25rem' }}>
              <label>2. Attack Simulation Routine ({filteredScenarios.length} Available)</label>
              <select 
                className="form-control" 
                value={selectedScenarioId} 
                onChange={e => setSelectedScenarioId(e.target.value)}
                style={{ fontSize: '0.9rem', fontWeight: 500 }}
              >
                {activeCategory === 'all' ? (
                  <>
                    <optgroup label="🛡️ Security Audits & Recon">
                      {scenarios.data?.filter(s => s.category === 'audit').map(s => (
                        <option key={s.id} value={s.id}>{s.name}</option>
                      ))}
                    </optgroup>
                    <optgroup label="⚡ Performance & Benchmarking">
                      {scenarios.data?.filter(s => s.category === 'performance').map(s => (
                        <option key={s.id} value={s.id}>{s.name}</option>
                      ))}
                    </optgroup>
                    <optgroup label="🧠 Resolver Cache Stress">
                      {scenarios.data?.filter(s => s.category === 'resolver-cache').map(s => (
                        <option key={s.id} value={s.id}>{s.name}</option>
                      ))}
                    </optgroup>
                    <optgroup label="💣 Volume & Exhaustion">
                      {scenarios.data?.filter(s => s.category === 'volume').map(s => (
                        <option key={s.id} value={s.id}>{s.name}</option>
                      ))}
                    </optgroup>
                  </>
                ) : (
                  filteredScenarios.map(s => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))
                )}
              </select>
            </div>
            
            {selectedScenario && Object.keys(config).length > 0 && (
              <div style={{ marginTop: '2rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
                <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}>SCENARIO PARAMETERS</h3>
                <div className="form-grid-2">
                  {Object.entries(config).map(([key, value]) => {
                    if (key === 'domain_list') {
                      return (
                        <div className="form-group" key={key} style={{ gridColumn: '1 / -1' }}>
                          <label>Domain List (.txt)</label>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                            <input 
                              type="file" 
                              accept=".txt"
                              className="form-control" 
                              onChange={e => {
                                const file = e.target.files?.[0];
                                if (!file) return;
                                const reader = new FileReader();
                                reader.onload = (event) => {
                                  const text = event.target?.result as string;
                                  const domains = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
                                  setConfig({...config, domain_list: domains});
                                };
                                reader.readAsText(file);
                              }} 
                            />
                            {Array.isArray(value) && value.length > 0 && (
                              <span style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>
                                ✓ Loaded {value.length} domains
                              </span>
                            )}
                          </div>
                          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Upload a text file with one domain per line.</p>
                        </div>
                      );
                    }
                    if (key === 'subdomains' || key === 'subdomains_list') {
                      return (
                        <div className="form-group" key={key} style={{ gridColumn: '1 / -1' }}>
                          <label style={{ textTransform: 'capitalize' }}>Subdomains (one per line)</label>
                          <textarea 
                            className="form-control" 
                            rows={3}
                            placeholder="api.example.com&#10;staging.example.com"
                            value={Array.isArray(value) ? value.join('\n') : (typeof value === 'string' ? value : '')} 
                            onChange={e => {
                              const lines = e.target.value.split('\n').map(s => s.trim()).filter(Boolean);
                              setConfig({...config, [key]: lines});
                            }} 
                          />
                          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Enter subdomains to scan/audit, one per line.</p>
                        </div>
                      );
                    }
                    if (Array.isArray(value)) {
                      return (
                        <div className="form-group" key={key} style={{ gridColumn: '1 / -1' }}>
                          <label style={{ textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')} (comma-separated)</label>
                          <input 
                            type="text" 
                            className="form-control" 
                            value={value.join(', ')} 
                            onChange={e => setConfig({...config, [key]: e.target.value.split(',').map(s => s.trim()).filter(Boolean)})} 
                          />
                        </div>
                      );
                    }
                    if (typeof value === 'object' && value !== null) {
                      return (
                        <div className="form-group" key={key} style={{ gridColumn: '1 / -1' }}>
                          <label style={{ textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')} (JSON)</label>
                          <input 
                            type="text" 
                            className="form-control" 
                            value={JSON.stringify(value)} 
                            onChange={e => {
                              try {
                                setConfig({...config, [key]: JSON.parse(e.target.value)});
                              } catch {
                                // ignore invalid JSON while typing
                              }
                            }} 
                          />
                        </div>
                      );
                    }
                    return (
                      <div className="form-group" key={key}>
                        <label style={{ textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')}</label>
                        <input 
                          type={typeof value === 'number' ? 'number' : 'text'} 
                          className="form-control" 
                          value={value as string | number} 
                          onChange={e => setConfig({...config, [key]: typeof value === 'number' ? Number(e.target.value) : e.target.value})} 
                        />
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </section>

        {selectedScenario && (
          <section className="panel">
            <div className="panel-header" style={{ padding: '1.5rem' }}>
              <div>
                <h2 style={{ fontSize: '1rem' }}>Scenario Profile</h2>
              </div>
            </div>
            <div style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>{selectedScenario.name}</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
                {selectedScenario.description}
              </p>

              <div style={{ marginBottom: '1.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '0.5rem' }}>RISK LEVEL</span>
                <span className={`pill status-${selectedScenario.risk_level.toLowerCase()}`} style={{
                  background: selectedScenario.risk_level === 'HIGH' ? 'rgba(239, 68, 68, 0.1)' : selectedScenario.risk_level === 'MEDIUM' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                  color: selectedScenario.risk_level === 'HIGH' ? 'var(--accent-red)' : selectedScenario.risk_level === 'MEDIUM' ? 'var(--accent-amber)' : 'var(--accent-green)',
                  border: `1px solid ${selectedScenario.risk_level === 'HIGH' ? 'rgba(239, 68, 68, 0.2)' : selectedScenario.risk_level === 'MEDIUM' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'}`
                }}>
                  {selectedScenario.risk_level} IMPACT
                </span>
                {selectedScenario.risk_level === 'HIGH' && (
                  <p style={{ fontSize: '0.75rem', color: 'var(--accent-red)', marginTop: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <ShieldAlert size={12} /> May cause denial of service. Ensure authorization.
                  </p>
                )}
              </div>

              {selectedScenario.recommended_limits && (
                <div>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '0.5rem' }}>ENGINE LIMITS</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', background: 'rgba(0,0,0,0.2)', padding: '0.5rem', borderRadius: '4px' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Max QPS</span>
                      <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{selectedScenario.recommended_limits.max_qps}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', background: 'rgba(0,0,0,0.2)', padding: '0.5rem', borderRadius: '4px' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Max Duration</span>
                      <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{selectedScenario.recommended_limits.max_duration_seconds}s</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </>
  );
}
