import React, { useState } from 'react';
import { ShieldAlert, Lock, User, KeyRound, ArrowRight, ShieldCheck, Sparkles } from 'lucide-react';
import { loginUser } from '../api';

interface LoginViewProps {
  onLoginSuccess: (token: string, role: string, username: string) => void;
  oidcEnabled?: boolean;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess, oidcEnabled = false }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMsg('Username and password are required');
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const data = await loginUser(username, password);
      onLoginSuccess(data.access_token, data.role || 'SuperAdmin', username);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const fillQuickDemo = (demoUser: string, demoPass: string, _demoRole?: string) => {
    setUsername(demoUser);
    setPassword(demoPass);
    setErrorMsg(null);
  };

  const handleOidcRedirect = () => {
    // In production, redirects to IdP auth endpoint
    window.location.href = '/v1/auth/oidc/login';
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-2xl backdrop-blur">
        {/* Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="bg-brand-500/20 p-3 rounded-2xl border border-brand-500/30 mb-3 shadow-lg shadow-brand-500/10">
            <ShieldAlert className="w-10 h-10 text-brand-500" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AegisGate Portal</h1>
          <p className="text-xs text-slate-400 mt-1">
            Sub-15ms AI Guardrails & Governance Control Plane
          </p>
        </div>

        {/* Error message */}
        {errorMsg && (
          <div className="mb-4 p-3 bg-red-950/60 border border-red-500/50 rounded-xl text-xs text-red-300 flex items-center space-x-2">
            <Lock className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Username</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white focus:outline-none focus:border-brand-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white focus:outline-none focus:border-brand-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl shadow-lg shadow-brand-600/30 flex items-center justify-center space-x-2 transition-all mt-2"
          >
            <span>{loading ? 'Authenticating...' : 'Sign In to AegisGate'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Conditional OIDC Button */}
        {oidcEnabled && (
          <div className="mt-4 pt-4 border-t border-slate-800/80">
            <button
              type="button"
              onClick={handleOidcRedirect}
              className="w-full py-2.5 px-4 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm rounded-xl border border-slate-700 flex items-center justify-center space-x-2 transition-all"
            >
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              <span>Sign in with Enterprise OIDC SSO</span>
            </button>
          </div>
        )}

        {/* Quick Demo Credentials */}
        <div className="mt-6 pt-5 border-t border-slate-800/60">
          <div className="flex items-center space-x-1.5 text-xs text-slate-400 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-semibold text-slate-300">Quick Demo Presets:</span>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => fillQuickDemo('admin', 'adminpass123', 'SuperAdmin')}
              className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-mono text-center border border-slate-700/60 hover:border-brand-500/50 transition-all"
            >
              SuperAdmin
            </button>
            <button
              type="button"
              onClick={() => fillQuickDemo('author', 'authorpass123', 'PolicyAuthor')}
              className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-mono text-center border border-slate-700/60 hover:border-brand-500/50 transition-all"
            >
              PolicyAuthor
            </button>
            <button
              type="button"
              onClick={() => fillQuickDemo('auditor', 'auditpass123', 'Auditor')}
              className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-mono text-center border border-slate-700/60 hover:border-brand-500/50 transition-all"
            >
              Auditor
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
