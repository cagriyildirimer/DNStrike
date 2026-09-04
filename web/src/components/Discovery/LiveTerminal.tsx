import { useEffect, useRef, useState } from 'react';
import { Terminal, Activity, AlertTriangle, ArrowRight } from 'lucide-react';

interface LiveTerminalProps {
  testId: number;
  scenario: string;
}

export function LiveTerminal({ testId, scenario }: LiveTerminalProps) {
  const [logs, setLogs] = useState<string[]>([]);
  const [metrics, setMetrics] = useState({ qps: 0, errors: 0, loss: 0, latency: 0 });
  const [status, setStatus] = useState<'CONNECTING' | 'RUNNING' | 'COMPLETED' | 'FAILED'>('CONNECTING');
  const [score, setScore] = useState<number | null>(null);
  
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    // Determine websocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    // For local dev, Vite runs on 5173 but API is on 8080. If port is 5173, force 8080.
    const port = window.location.port === '5173' ? '8080' : window.location.port;
    const wsUrl = `${protocol}//${host}${port ? ':'+port : ''}/ws/tests/${testId}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      setStatus('RUNNING');
      setLogs(prev => [...prev, `[SYSTEM] Connected to Orchestrator stream for Test #${testId}`]);
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'log':
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${data.message}`]);
            break;
          case 'metric':
            setMetrics({
              qps: data.qps,
              errors: data.errors,
              loss: data.loss || 0,
              latency: data.avg_latency_ms
            });
            break;
          case 'status_change':
            if (data.status === 'RUNNING') setStatus('RUNNING');
            break;
          case 'completed':
            setStatus('COMPLETED');
            if (data.score !== undefined) setScore(data.score);
            setLogs(prev => [...prev, `[SYSTEM] Test execution completed. Resilience Score: ${data.score}`]);
            break;
          case 'failed':
            setStatus('FAILED');
            setLogs(prev => [...prev, `[SYSTEM ERROR] Test execution failed: ${data.reason}`]);
            break;
        }
      } catch (e) {
        console.error("Failed to parse WS message", e);
      }
    };
    
    ws.onerror = () => {
      setLogs(prev => [...prev, `[SYSTEM ERROR] WebSocket connection failed.`]);
      setStatus('FAILED');
    };
    
    ws.onclose = () => {
      if (status === 'RUNNING') {
        setLogs(prev => [...prev, `[SYSTEM] Connection closed by server.`]);
      }
    };
    
    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [testId]);

  const isBenchmark = scenario === 'benchmark' || scenario === 'nxdomain';

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
      
      {isBenchmark && status !== 'CONNECTING' && (
        <div className="live-metrics-bar">
          <div className="live-metric">
            <span className="label">QPS Sent</span>
            <span className="value">
              <Activity size={14} /> {metrics.qps}
            </span>
          </div>
          <div className="live-metric">
            <span className="label">Avg Latency</span>
            <span className="value">
              <ArrowRight size={14} /> {metrics.latency.toFixed(2)} ms
            </span>
          </div>
          <div className="live-metric">
            <span className="label">Errors</span>
            <span className={`value ${metrics.errors > 0 ? 'has-errors' : ''}`}>
              <AlertTriangle size={14} /> {metrics.errors}
            </span>
          </div>
          <div className="live-metric">
            <span className="label">Loss</span>
            <span className={`value ${metrics.loss > 0 ? 'has-errors' : ''}`}>
              <AlertTriangle size={14} /> {metrics.loss}
            </span>
          </div>
        </div>
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
