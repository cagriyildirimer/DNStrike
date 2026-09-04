import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { History, Activity, FileText, Trash2 } from 'lucide-react';
import { PageHeader } from '../components/Layout/PageHeader';
import { LiveTerminal } from '../components/Discovery/LiveTerminal';
import { TestReportModal } from '../components/Forms/TestReportModal';
import { TestRun, Target } from '../types';
import { api } from '../api';

interface TestListPageProps {
  title: string;
  description: string;
  items: TestRun[];
  targets?: Target[];
  loading: boolean;
}

export function TestListPage({ title, description, items, targets = [], loading }: TestListPageProps) {
  const queryClient = useQueryClient();
  const [activeTest, setActiveTest] = useState<TestRun | null>(null);
  const [reportTest, setReportTest] = useState<TestRun | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);

  const deleteMutation = useMutation({
    mutationFn: api.deleteTest,
    onMutate: async (id: number) => {
      await queryClient.cancelQueries({ queryKey: ['tests'] });
      const previousTests = queryClient.getQueryData<TestRun[]>(['tests']);
      if (previousTests) {
        queryClient.setQueryData<TestRun[]>(['tests'], previousTests.filter(t => t.id !== id));
      }
      return { previousTests };
    },
    onError: (_err, _id, context) => {
      if (context?.previousTests) {
        queryClient.setQueryData(['tests'], context.previousTests);
      }
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['tests'] });
    }
  });

  if (activeTest) {
    return (
      <>
        <PageHeader 
          eyebrow="LIVE MONITORING" 
          title={`Test #${activeTest.id}`} 
          description="Real-time WebSocket stream from the DNS Orchestrator." 
          action={
            <button className="btn btn-secondary" onClick={() => setActiveTest(null)}>
              Back to List
            </button>
          }
        />
        <LiveTerminal testId={activeTest.id} scenario={activeTest.scenario} />
      </>
    );
  }

  return (
    <>
      <PageHeader 
        eyebrow="TEST OPERATIONS" 
        title={title} 
        description={description} 
      />
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>{title}</h2>
            <p>Statuses are read directly from SQLite.</p>
          </div>
          <span className="count-badge">{items.length} TESTS</span>
        </div>
        
        {loading ? (
          <div className="empty-state">Loading tests...</div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon"><History /></div>
            <h3>No matching tests</h3>
            <p>Test execution will appear here when the orchestrator is enabled.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Scenario</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {items.map(item => {
                  const isTerminal = item.status === 'COMPLETED' || item.status === 'FAILED' || item.status === 'CANCELLED';
                  const isLive = item.status === 'RUNNING' || item.status === 'PENDING';
                  const target = targets.find(t => t.id === item.target_id);
                  return (
                    <tr key={item.id} className={item.status === 'RUNNING' ? 'row-active' : ''}>
                      <td><span className="mono">#{item.id}</span></td>
                      <td>{item.scenario}</td>
                      <td>{target ? `${target.name} (${target.ip_address})` : `Target #${item.target_id}`}</td>
                      <td>
                        <span className={`pill status-${item.status.toLowerCase()}`}>
                          {item.status}
                        </span>
                      </td>
                      <td>{new Date(item.created_at).toLocaleString()}</td>
                      <td>
                        <div className="table-actions">
                          {isLive && (
                            <button 
                              className="btn btn-icon" 
                              onClick={() => setActiveTest(item)} 
                              title="View Live Data"
                            >
                              <Activity size={16} style={{ color: 'var(--accent-green)' }} />
                            </button>
                          )}
                          {isTerminal && (
                            <button 
                              className="btn btn-icon" 
                              onClick={() => setReportTest(item)} 
                              title="View Final Report"
                            >
                              <FileText size={16} style={{ color: 'var(--accent-blue)' }} />
                            </button>
                          )}
                          {confirmDeleteId === item.id ? (
                            <button 
                              className="btn btn-danger" 
                              style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem', backgroundColor: 'var(--accent-red)', color: '#ffffff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                              disabled={deleteMutation.isPending}
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteMutation.mutate(item.id);
                                setConfirmDeleteId(null);
                              }}
                            >
                              Confirm?
                            </button>
                          ) : (
                            <button 
                              className="btn btn-icon" 
                              style={{ color: 'var(--accent-red)' }}
                              disabled={deleteMutation.isPending}
                              onClick={(e) => {
                                e.stopPropagation();
                                setConfirmDeleteId(item.id);
                              }}
                              title="Delete Test"
                            >
                              <Trash2 size={16} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {reportTest && (
        <TestReportModal test={reportTest} close={() => setReportTest(null)} />
      )}
    </>
  );
}
