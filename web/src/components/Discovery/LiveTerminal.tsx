import { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal } from 'lucide-react';
import { api } from '../../api';
import { Sparkline } from './Sparkline';

interface LiveTerminalProps {
  testId: number;
  scenario: string;
}

interface MetricPoint {
  qps: number;
  avg: number;
  p50: number;
  p99: number;
  errors: number;
  loss: number;
  total: number;
}

const MAX_POINTS = 90;

const toNumber = (value: unknown): number => {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
};

export function LiveTerminal({ testId, scenario }: LiveTerminalProps) {
  const [logs, setLogs] = useState<string[]>([]);
  const [series, setSeries] = useState<MetricPoint[]>([]);
  const [status, setStatus] = useState<'CONNECTING' | 'RUNNING' | 'COMPLETED' | 'FAILED'>('CONNECTING');
  const [score, setScore] = useState<number | null>(null);
  
  const bottomRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef(status);

  // Keep statusRef in sync with status state
  const updateStatus = useCallback((newStatus: typeof status) => {
    statusRef.current = newStatus;
    setStatus(newStatus);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    let disposed = false;
    const syncPersistedStatus = async () => {
      try {
        const test = await api.getTest(testId);
        if (disposed) return;
        if (test.status === 'COMPLETED') {
          updateStatus('COMPLETED');
          setScore(test.resilience_score ?? null);
        } else if (test.status === 'FAILED' || test.status === 'CANCELLED') {
          updateStatus('FAILED');
        } else if (test.status === 'RUNNING') {
          updateStatus('RUNNING');
        } else {
          updateStatus('CONNECTING');
        }
      } catch {
        // The WebSocket remains the primary live channel; retry on the next poll.
      }
    };
    void syncPersistedStatus();
    const statusPoll = window.setInterval(() => void syncPersistedStatus(), 1500);

    // Determine websocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/tests/${testId}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      void syncPersistedStatus();
      setLogs(prev => [...prev, `[SYSTEM] Connected to Orchestrator stream for Test #${testId}`]);
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'log':
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${data.message}`]);
            break;
          case 'metric': {
            const point: MetricPoint = {
              qps: toNumber(data.qps),
              avg: toNumber(data.avg_latency_ms),
              p50: toNumber(data.p50_latency_ms),
              p99: toNumber(data.p99_latency_ms),
              errors: toNumber(data.errors),
              loss: toNumber(data.loss),
              total: toNumber(data.total_queries),
            };
            setSeries(prev => {
              const next = [...prev, point];
              return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next;
            });
            break;
          }
          case 'status_change':
            if (data.status === 'RUNNING') updateStatus('RUNNING');
            break;
          case 'completed':
            updateStatus('COMPLETED');
            if (data.score !== undefined) setScore(data.score);
            setLogs(prev => [...prev, `[SYSTEM] Test execution completed. Resilience Score: ${data.score}`]);
            break;
          case 'failed':
            updateStatus('FAILED');
            setLogs(prev => [...prev, `[SYSTEM ERROR] Test execution failed: ${data.reason}`]);
            break;
        }
      } catch (e) {
        console.error("Failed to parse WS message", e);
      }
    };
    
    ws.onerror = () => {
      setLogs(prev => [...prev, `[SYSTEM ERROR] WebSocket connection failed.`]);
      updateStatus('FAILED');
    };
    
    ws.onclose = () => {
      if (statusRef.current === 'RUNNING') {
        setLogs(prev => [...prev, `[SYSTEM] Connection closed by server.`]);
      }
    };
    
    return () => {
      disposed = true;
      window.clearInterval(statusPoll);
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  }, [testId, updateStatus]);

  // Charts appear whenever the scenario actually streams metric frames, rather
  // than relying on a hardcoded scenario allowlist.
  const last = series.length > 0 ? series[series.length - 1] : null;

  return (
    <div className="live-terminal-container">
      <div className="terminal-header">
        <div className="terminal-title">
          <Terminal size={16} />
          <span>Live Execution: Test #{testId} ({scenario})</span>
        </div>
        <div className={`terminal-status status-${status.toLowerCase()}`}>
          {status} {score !== null && `- Score: ${score}`}
        </div>
      </div>
      
      {last && (
        <>
          <div className="live-metrics-bar">
            <div className="live-metric">
              <span className="label">Total Queries</span>
              <span className="value">{last.total.toLocaleString()}</span>
            </div>
            <div className="live-metric">
              <span className="label">QPS</span>
              <span className="value">{last.qps.toFixed(0)}</span>
            </div>
            <div className="live-metric">
              <span className="label">Avg Latency</span>
              <span className="value">{last.avg.toFixed(2)} ms</span>
            </div>
            <div className="live-metric">
              <span className="label">P99 Latency</span>
              <span className="value">{last.p99.toFixed(2)} ms</span>
            </div>
          </div>

          <div className="live-charts">
            <div className="spark-card">
              <div className="spark-head">
                <span className="spark-label">Queries / sec</span>
                <span className="spark-val" style={{ color: '#00f0ff' }}>{last.qps.toFixed(0)}</span>
              </div>
              <Sparkline series={[{ label: 'QPS', color: '#00f0ff', values: series.map(p => p.qps) }]} />
            </div>

            <div className="spark-card">
              <div className="spark-head">
                <span className="spark-label">Latency (ms)</span>
                <span className="spark-legend">
                  <span><i style={{ background: '#00f0ff' }} />avg {last.avg.toFixed(1)}</span>
                  <span><i style={{ background: 'var(--accent-amber)' }} />p99 {last.p99.toFixed(1)}</span>
                </span>
              </div>
              <Sparkline
                series={[
                  { label: 'avg latency', color: '#00f0ff', values: series.map(p => p.avg) },
                  { label: 'p99 latency', color: '#f59e0b', values: series.map(p => p.p99) },
                ]}
              />
            </div>

            <div className="spark-card">
              <div className="spark-head">
                <span className="spark-label">Errors / Loss</span>
                <span className="spark-legend">
                  <span><i style={{ background: 'var(--accent-red)' }} />err {last.errors}</span>
                  <span><i style={{ background: 'var(--accent-amber)' }} />loss {last.loss}</span>
                </span>
              </div>
              <Sparkline
                series={[
                  { label: 'errors', color: '#ef4444', values: series.map(p => p.errors) },
                  { label: 'loss', color: '#f59e0b', values: series.map(p => p.loss) },
                ]}
              />
            </div>
          </div>
        </>
      )}

      <div className="terminal-window">
        {logs.map((log, i) => (
          <div key={i} className={`terminal-line ${log.includes('ERROR') || log.includes('CRITICAL') ? 'text-red' : log.includes('WARNING') ? 'text-yellow' : log.includes('OK') ? 'text-green' : ''}`}>
            {log}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
