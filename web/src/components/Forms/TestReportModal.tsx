import { useState } from 'react';
import { X, ShieldAlert, CheckCircle2, XCircle, Clock, Zap, Download } from 'lucide-react';
import type { TestRun } from '../../types';
import { generatePdfReport } from '../../utils/pdfGenerator';

interface TestReportModalProps {
  test: TestRun;
  close: () => void;
}

export function TestReportModal({ test, close }: TestReportModalProps) {
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const isFailed = test.status === 'FAILED';
  const score = test.resilience_score ?? 0;
  
  let scoreColor = 'var(--text-muted)';
  let ScoreIcon = ShieldAlert;
  if (test.status === 'COMPLETED') {
    if (score >= 90) {
      scoreColor = 'var(--accent-green)';
      ScoreIcon = CheckCircle2;
    } else if (score >= 50) {
      scoreColor = 'var(--accent-amber)';
      ScoreIcon = ShieldAlert;
    } else {
      scoreColor = 'var(--accent-red)';
      ScoreIcon = XCircle;
    }
  }

  const downloadPdf = () => {
    setGeneratingPdf(true);
    try {
      generatePdfReport(test);
    } catch (e) {
      console.error('Failed to generate PDF:', e);
    } finally {
      setTimeout(() => setGeneratingPdf(false), 500);
    }
  };

  return (
    <div className="modal-overlay" onClick={close}>
      <div 
        className="modal-content" 
        onClick={e => e.stopPropagation()} 
        style={{ maxWidth: '700px' }}
      >
        <div className="modal-header">
          <div>
            <h2 style={{ fontSize: '1.25rem', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
              Execution Report: #{test.id}
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Scenario: {test.scenario}
            </p>
          </div>
          <button className="btn-icon" onClick={close}><X size={20} /></button>
        </div>
        
        <div className="modal-body" style={{ padding: '2rem' }}>
          
          <div className="discovery-stats" style={{ gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2.5rem' }}>
            <div className="discovery-stat-box" style={{ 
              borderColor: isFailed ? 'rgba(239, 68, 68, 0.3)' : (test.status === 'COMPLETED' ? 'rgba(16, 185, 129, 0.3)' : 'var(--border-color)'),
              background: isFailed ? 'rgba(239, 68, 68, 0.05)' : (test.status === 'COMPLETED' ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255,255,255,0.03)')
            }}>
              <span className="title">Final Status</span>
              <span className="val" style={{ color: isFailed ? 'var(--accent-red)' : (test.status === 'COMPLETED' ? 'var(--accent-green)' : 'var(--text-primary)') }}>
                {test.status}
              </span>
            </div>
            
            <div className="discovery-stat-box">
              <span className="title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Resilience Score <ScoreIcon size={14} style={{ color: scoreColor }}/>
              </span>
              <span className="val" style={{ color: scoreColor, fontSize: '2rem' }}>
                {test.status === 'COMPLETED' ? `${score}/100` : 'N/A'}
              </span>
            </div>
          </div>

          <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={16} style={{ color: 'var(--accent-blue)' }} /> Configuration Profile
          </h3>
          <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
            <table style={{ margin: 0 }}>
              <tbody>
                {Object.entries(test.config || {}).map(([key, value]) => (
                  <tr key={key}>
                    <td style={{ width: '40%', padding: '0.75rem 1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                      {key.replace(/_/g, ' ')}
                    </td>
                    <td style={{ padding: '0.75rem 1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                      {String(value)}
                    </td>
                  </tr>
                ))}
                {Object.keys(test.config || {}).length === 0 && (
                  <tr><td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No configuration parameters provided.</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {test.result && Boolean(test.result.amplification_results) && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Zap size={16} style={{ color: 'var(--accent-amber)' }} /> Amplification & RRL Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>MAX AMPLIFICATION</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: (test.result.max_amplification_factor as number) > 20 ? 'var(--accent-red)' : (test.result.max_amplification_factor as number) > 10 ? 'var(--accent-amber)' : 'var(--accent-green)' }}>
                    {String(test.result.max_amplification_factor)}x
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>RRL POSTURE</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 700, color: test.result.rrl_active ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    {String(test.result.rrl_status)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>MAX RESPONSE SIZE</span>
                  <span style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {String(test.result.max_response_bytes)} B
                  </span>
                </div>
              </div>
              <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                <table style={{ margin: 0 }}>
                  <thead>
                    <tr>
                      <th style={{ padding: '0.75rem 1rem' }}>Query Type</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Req Size</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Resp Size</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Multiplier</th>
                      <th style={{ padding: '0.75rem 1rem' }}>RCode</th>
                      <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(test.result.amplification_results as Array<Record<string, unknown>>).map((item, idx) => (
                      <tr key={idx}>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>{String(item.query_type)} {item.edns0 ? '(EDNS0 4K)' : ''}</td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(item.request_bytes)} B</td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(item.response_bytes)} B</td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontWeight: 700 }}>{String(item.amplification)}x</td>
                        <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem' }}>{String(item.rcode)}</td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span className={`pill ${item.status === 'CRITICAL' ? 'pill-failed' : item.status === 'HIGH' || item.status === 'MODERATE' ? 'pill-pending' : 'pill-completed'}`}>
                            {String(item.status)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {test.result && test.scenario === 'tcp-slowloris' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Zap size={16} style={{ color: 'var(--accent-red)' }} /> TCP Slowloris & Connection Exhaustion Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>ESTABLISHED SOCKETS</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {String(test.result.connections_established)} / {String(test.result.connections_requested)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>LEGITIMATE PROBE</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 700, color: test.result.legitimate_tcp_served ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    {test.result.legitimate_tcp_served ? 'PASSED (SERVED)' : 'FAILED (BLOCKED)'}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>RESILIENCE SUMMARY</span>
                  <span style={{ fontSize: '1rem', fontWeight: 700, color: test.result.legitimate_tcp_served ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    {String(test.result.status_summary)}
                  </span>
                </div>
              </div>
            </>
          )}

          {test.result && test.scenario === 'zone-transfer-audit' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={16} style={{ color: (test.result.total_leaked_records as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }} /> AXFR Zone Transfer Leak Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>LEAKED RECORDS</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: (test.result.total_leaked_records as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {String(test.result.total_leaked_records)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>TARGET DOMAIN</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {String(test.result.domain)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>SECURITY POSTURE</span>
                  <span style={{ fontSize: '0.9rem', fontWeight: 700, color: (test.result.total_leaked_records as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {String(test.result.status_summary)}
                  </span>
                </div>
              </div>

              {Boolean(test.result.sample_records) && (test.result.sample_records as Array<unknown>).length > 0 && (
                <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                  <table style={{ margin: 0 }}>
                    <thead>
                      <tr>
                        <th style={{ padding: '0.75rem 1rem' }}>Record Name</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Siphoned Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(test.result.sample_records as Array<Record<string, unknown>>).map((rec, idx) => (
                        <tr key={idx}>
                          <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>{String(rec.name)}</td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <span className="pill pill-pending">{String(rec.type)}</span>
                          </td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>{String(rec.value)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {test.result && test.scenario === 'dns-fuzzing' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={16} style={{ color: test.result.target_crashed ? 'var(--accent-red)' : 'var(--accent-green)' }} /> DNS Fuzzing & Malformed Packet Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>VECTORS TESTED</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {String(test.result.vectors_tested)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>PROCESS RESILIENCE</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 700, color: test.result.target_crashed ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {test.result.target_crashed ? 'CRITICAL (UNRESPONSIVE)' : 'STABLE (RESILIENT)'}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>STATUS SUMMARY</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: test.result.target_crashed ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {String(test.result.status_summary)}
                  </span>
                </div>
              </div>

              {Boolean(test.result.fuzzing_results) && (
                <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                  <table style={{ margin: 0 }}>
                    <thead>
                      <tr>
                        <th style={{ padding: '0.75rem 1rem' }}>Category</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Fuzz Vector Name</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Server Response</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Post-Fuzz Health Check</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(test.result.fuzzing_results as Array<Record<string, unknown>>).map((vec, idx) => (
                        <tr key={idx}>
                          <td style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{String(vec.category)}</td>
                          <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>{String(vec.name)}</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>{String(vec.response_status)}</td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <span className={`pill ${String(vec.health_check).includes('PASSED') ? 'pill-completed' : 'pill-failed'}`}>
                              {String(vec.health_check)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {test.result && test.scenario === 'subdomain-takeover' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={16} style={{ color: (test.result.vulnerable_count as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }} /> Subdomain Takeover & Dangling CNAME Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>SUBDOMAINS SCANNED</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {String(test.result.subdomains_scanned)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>DANGLING CNAMEs</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: (test.result.vulnerable_count as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {String(test.result.vulnerable_count)}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>SECURITY SUMMARY</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: (test.result.vulnerable_count as number) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                    {String(test.result.status_summary)}
                  </span>
                </div>
              </div>

              {Boolean(test.result.scan_results) && (test.result.scan_results as Array<unknown>).length > 0 && (
                <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                  <table style={{ margin: 0 }}>
                    <thead>
                      <tr>
                        <th style={{ padding: '0.75rem 1rem' }}>Subdomain</th>
                        <th style={{ padding: '0.75rem 1rem' }}>CNAME Target</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Cloud Provider</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Vulnerability Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(test.result.scan_results as Array<Record<string, unknown>>).map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>{String(item.subdomain)}</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>{String(item.cname_target)}</td>
                          <td style={{ padding: '0.75rem 1rem', fontSize: '0.85rem' }}>{String(item.cloud_provider)}</td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <span className={`pill ${String(item.status).includes('VULNERABLE') ? 'pill-failed' : 'pill-completed'}`}>
                              {String(item.status)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {test.result && test.scenario === 'rrl-threshold' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Zap size={16} style={{ color: 'var(--accent-amber)' }} /> Response Rate Limiting (RRL) & SLIP Threshold Analysis
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>DETECTED THRESHOLD</span>
                  <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {(test.result.detected_threshold_qps as number) > 0 ? `${String(test.result.detected_threshold_qps)} QPS` : 'N/A (>500)'}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>SLIP TCP FALLBACK</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 700, color: test.result.slip_fallback_active ? 'var(--accent-green)' : 'var(--accent-amber)' }}>
                    {test.result.slip_fallback_active ? 'ACTIVE (TC=1 SLIP)' : 'INACTIVE (STRICT DROP)'}
                  </span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>RRL POSTURE</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: test.result.rate_limit_active ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    {String(test.result.status_summary)}
                  </span>
                </div>
              </div>

              {Boolean(test.result.stage_results) && (
                <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                  <table style={{ margin: 0 }}>
                    <thead>
                      <tr>
                        <th style={{ padding: '0.75rem 1rem' }}>Test Stage</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Target QPS</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Responded</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Dropped</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Truncated (TC=1)</th>
                        <th style={{ padding: '0.75rem 1rem' }}>Stage Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(test.result.stage_results as Array<Record<string, unknown>>).map((stg, idx) => (
                        <tr key={idx}>
                          <td style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>{String(stg.stage_name)}</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(stg.target_qps)} QPS</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(stg.responded_pct)}%</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(stg.dropped_pct)}%</td>
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace' }}>{String(stg.truncated_pct)}%</td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <span className={`pill ${String(stg.stage_result_text).includes('ACTIVE') ? 'pill-completed' : 'pill-pending'}`}>
                              {String(stg.stage_result_text)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {test.result && Object.keys(test.result).length > 0 && !test.result.amplification_results && test.scenario !== 'tcp-slowloris' && test.scenario !== 'zone-transfer-audit' && test.scenario !== 'dns-fuzzing' && test.scenario !== 'subdomain-takeover' && test.scenario !== 'rrl-threshold' && (
            <>
              <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle2 size={16} style={{ color: 'var(--accent-green)' }} /> Execution Results
              </h3>
              <div className="table-responsive" style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '2.5rem' }}>
                <table style={{ margin: 0 }}>
                  <tbody>
                    {Object.entries(test.result).map(([key, value]) => (
                      <tr key={key}>
                        <td style={{ width: '40%', padding: '0.75rem 1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                          {key.replace(/_/g, ' ')}
                        </td>
                        <td style={{ padding: '0.75rem 1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-primary)', fontFamily: 'monospace', fontWeight: 600 }}>
                          {typeof value === 'number' && key.includes('latency') ? value.toFixed(2) + ' ms' : String(value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={16} style={{ color: 'var(--accent-blue)' }} /> Timeline
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
            <div>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>CREATED</span>
              <span style={{ fontSize: '0.85rem' }}>{new Date(test.created_at).toLocaleString()}</span>
            </div>
            <div>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>STARTED</span>
              <span style={{ fontSize: '0.85rem' }}>{test.started_at ? new Date(test.started_at).toLocaleString() : '-'}</span>
            </div>
            <div>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>FINISHED</span>
              <span style={{ fontSize: '0.85rem' }}>{test.finished_at ? new Date(test.finished_at).toLocaleString() : '-'}</span>
            </div>
          </div>
          
        </div>
        
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
          <button type="button" className="btn btn-primary" onClick={downloadPdf} disabled={generatingPdf} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Download size={18} /> {generatingPdf ? 'Generating...' : 'Download PDF Report'}
          </button>
          <button className="btn btn-secondary" onClick={close}>Close Report</button>
        </div>
      </div>
    </div>
  );
}
