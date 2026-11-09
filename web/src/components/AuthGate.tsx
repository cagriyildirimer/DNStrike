import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { KeyRound, LoaderCircle, Radar, ShieldCheck } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { api, unauthorizedEvent } from '../api';

interface AuthGateProps {
  children: (logout: () => Promise<void>) => ReactNode;
}

export function AuthGate({ children }: AuthGateProps) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<'checking' | 'authenticated' | 'anonymous'>('checking');
  const [apiKey, setAPIKey] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    void api.session()
      .then(() => { if (active) setStatus('authenticated'); })
      .catch(() => { if (active) setStatus('anonymous'); });
    const handleUnauthorized = () => {
      queryClient.clear();
      setStatus('anonymous');
    };
    window.addEventListener(unauthorizedEvent, handleUnauthorized);
    return () => {
      active = false;
      window.removeEventListener(unauthorizedEvent, handleUnauthorized);
    };
  }, [queryClient]);

  const login = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await api.login(apiKey);
      setAPIKey('');
      setStatus('authenticated');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Giriş yapılamadı.');
    } finally {
      setSubmitting(false);
    }
  };

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      queryClient.clear();
      setStatus('anonymous');
    }
  };

  if (status === 'checking') {
    return (
      <div className="auth-screen auth-loading" role="status">
        <LoaderCircle className="auth-spinner" size={30} />
        <span>Secure session is being checked...</span>
      </div>
    );
  }

  if (status === 'anonymous') {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={login}>
          <div className="auth-brand">
            <span className="auth-brand-icon"><Radar size={28} /></span>
            <div><h1>DNStrike</h1><span>Resilience Lab</span></div>
          </div>
          <div className="auth-heading">
            <ShieldCheck size={22} />
            <div>
              <h2>Protected workspace</h2>
              <p>Enter the API key configured on the DNStrike server.</p>
            </div>
          </div>
          <label className="form-group">
            <span>API key</span>
            <span className="auth-input-wrap">
              <KeyRound size={18} />
              <input
                className="form-control"
                type="password"
                value={apiKey}
                onChange={event => setAPIKey(event.target.value)}
                minLength={32}
                autoComplete="current-password"
                autoFocus
                required
              />
            </span>
          </label>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <button className="btn btn-primary auth-submit" disabled={submitting || apiKey.length < 32}>
            {submitting ? <LoaderCircle className="auth-spinner" size={18} /> : <ShieldCheck size={18} />}
            {submitting ? 'Authenticating...' : 'Open workspace'}
          </button>
          <p className="auth-footnote">The key is exchanged for an HttpOnly session and is not stored in browser storage.</p>
        </form>
      </main>
    );
  }

  return children(logout);
}
