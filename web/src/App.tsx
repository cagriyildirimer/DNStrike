import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Settings, X } from 'lucide-react';
import { api } from './api';
import type { DiscoveryProfile, Target, TargetInput } from './types';

import { Sidebar } from './components/Layout/Sidebar';
import { TargetsPage } from './pages/Targets';
import { TestListPage } from './pages/Tests';
import { PlaceholderPage } from './pages/Placeholder';
import { TargetForm } from './components/Forms/TargetForm';
import { DiscoveryModal } from './components/Discovery/DiscoveryModal';
import { NewTestPage } from './pages/NewTest';

const emptyForm: TargetInput = { 
  name: '', ip_address: '', port: 53, description: '', environment: 'Lab', 
  udp_enabled: true, tcp_enabled: true, tags: [] 
};

export default function App() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<TargetInput>(emptyForm);
  const [notice, setNotice] = useState('');
  const [profile, setProfile] = useState<{ target: Target; data: DiscoveryProfile } | null>(null);

  const targets = useQuery({ queryKey: ['targets'], queryFn: api.listTargets, refetchInterval: 5000 });
  const tests = useQuery({ queryKey: ['tests'], queryFn: api.listTests, refetchInterval: 3000 });

  const create = useMutation({
    mutationFn: api.createTarget,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      setForm(emptyForm);
      setShowForm(false);
      setNotice('Target safely registered.');
    },
    onError: (e: Error) => setNotice(e.message)
  });

  const remove = useMutation({
    mutationFn: api.deleteTarget,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['targets'] }),
    onError: (e: Error) => setNotice(e.message)
  });

  const discover = useMutation({
    mutationFn: async (t: Target) => ({ target: t, data: await api.discoverTarget(t.id) }),
    onSuccess: setProfile,
    onError: (e: Error) => setNotice(e.message)
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setNotice('');
    create.mutate(form);
  };

  const targetItems = targets.data ?? [];
  const testItems = tests.data ?? [];
  const runningCount = testItems.filter(item => item.status === 'RUNNING').length;

  return (
    <div className="app-container">
      <Sidebar runningTestsCount={runningCount} />
      
      <main className="main-content">
        {notice && (
          <div className="notice" onClick={() => setNotice('')}>
            {notice}
            <X size={16} />
          </div>
        )}
        
        <Routes>
          <Route 
            path="/targets" 
            element={
              <TargetsPage 
                items={targetItems} 
                loading={targets.isLoading} 
                failed={targets.isError} 
                openForm={() => setShowForm(true)} 
                discover={target => discover.mutate(target)} 
                discovering={discover.isPending} 
                remove={target => remove.mutate(target.id)} 
              />
            } 
          />
          <Route 
            path="/tests/new" 
            element={<NewTestPage />} 
          />
          <Route 
            path="/tests/running" 
            element={
              <TestListPage 
                title="Running Tests" 
                description="Tests currently executing through the orchestrator." 
                items={testItems.filter(item => item.status === 'RUNNING')} 
                targets={targetItems}
                loading={tests.isLoading} 
              />
            } 
          />
          <Route 
            path="/tests/history" 
            element={
              <TestListPage 
                title="Test History" 
                description="Persisted lifecycle records and scenario configurations." 
                items={testItems} 
                targets={targetItems}
                loading={tests.isLoading} 
              />
            } 
          />
          <Route 
            path="/settings" 
            element={
              <PlaceholderPage 
                eyebrow="PLATFORM" 
                title="Settings" 
                description="Public target testing remains disabled. Runtime safety settings will be exposed here later." 
                icon={<Settings />} 
              />
            } 
          />
          <Route path="*" element={<Navigate to="/targets" replace />} />
        </Routes>
      </main>

      {showForm && (
        <TargetForm 
          form={form} 
          setForm={setForm} 
          close={() => setShowForm(false)} 
          submit={submit} 
          pending={create.isPending} 
          error={create.error as Error | null} 
        />
      )}
      
      {profile && (
        <DiscoveryModal 
          target={profile.target} 
          data={profile.data} 
          close={() => setProfile(null)} 
        />
      )}
    </div>
  );
}
