import React, { useState } from 'react';
import {
  Key,
  Shield,
  PlusCircle,
  DollarSign,
  AlertTriangle,
  Building2,
} from 'lucide-react';

interface TenantsVirtualKeysViewProps {
  tenantId: string;
}

interface VirtualKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  workspace_id: string;
  default_policy_pack_id: string;
  budget_cap_usd: number;
  rate_limit_rpm: number;
  allowed_models: string[];
  status: 'active' | 'revoked';
  created_at: string;
}

export const TenantsVirtualKeysView: React.FC<TenantsVirtualKeysViewProps> = ({
  tenantId,
}) => {
  const [keys, setKeys] = useState<VirtualKeyItem[]>([
    {
      id: 'vk-001',
      name: 'Production LLM Gateway Key',
      key_prefix: 'ag_live_prod_99f2',
      workspace_id: 'default',
      default_policy_pack_id: 'base-enterprise',
      budget_cap_usd: 50.0,
      rate_limit_rpm: 600,
      allowed_models: ['gpt-4o', 'claude-3-5-sonnet', 'ollama/*'],
      status: 'active',
      created_at: '2026-11-20 14:00 UTC',
    },
    {
      id: 'vk-002',
      name: 'Autonomous SOC Research Key',
      key_prefix: 'ag_live_soc_a12b',
      workspace_id: 'default',
      default_policy_pack_id: 'soc-investigation-pack',
      budget_cap_usd: 25.0,
      rate_limit_rpm: 300,
      allowed_models: ['gpt-4o', 'local-sovereign'],
      status: 'active',
      created_at: '2026-11-21 09:30 UTC',
    },
  ]);

  const [newKeyName, setNewKeyName] = useState('');
  const [budgetCap, setBudgetCap] = useState(20);
  const [rpmLimit, setRpmLimit] = useState(300);
  const [modalOpen, setModalOpen] = useState(false);
  const [createdKeyPlaintext, setCreatedKeyPlaintext] = useState<string | null>(null);

  const handleRevoke = (id: string) => {
    setKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, status: 'revoked' } : k))
    );
  };

  const handleCreateKey = (e: React.FormEvent) => {
    e.preventDefault();
    const mockPlaintext = `ag_live_${Math.random().toString(36).substring(2, 10)}_${Date.now()}`;
    const newRecord: VirtualKeyItem = {
      id: `vk-${Date.now()}`,
      name: newKeyName || 'Custom Virtual Key',
      key_prefix: mockPlaintext.substring(0, 16) + '...',
      workspace_id: 'default',
      default_policy_pack_id: 'base-enterprise',
      budget_cap_usd: budgetCap,
      rate_limit_rpm: rpmLimit,
      allowed_models: ['*'],
      status: 'active',
      created_at: 'Just now',
    };
    setKeys((prev) => [newRecord, ...prev]);
    setCreatedKeyPlaintext(mockPlaintext);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Building2 className="w-6 h-6 text-brand-400" /> Multi-Tenancy & Virtual API Keys
          </h1>
          <p className="text-sm text-slate-400">
            Secure client authentication, tenant isolation, model allowlists, and live budget enforcement.
          </p>
        </div>

        <button
          onClick={() => {
            setCreatedKeyPlaintext(null);
            setModalOpen(true);
          }}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold shadow transition-colors"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Issue Virtual API Key</span>
        </button>
      </div>

      {/* Tenancy Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Active Tenant Scope</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">{tenantId}</div>
          <div className="text-[11px] text-emerald-400 mt-2 flex items-center gap-1">
            <Shield className="w-3.5 h-3.5" /> Workspace Isolation Enforced
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Virtual Keys Issued</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">{keys.length}</div>
          <div className="text-[11px] text-brand-400 mt-2 flex items-center gap-1">
            <Key className="w-3.5 h-3.5" /> {keys.filter((k) => k.status === 'active').length} Active
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Live Budget Ceiling</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">
            ${keys.reduce((acc, k) => acc + (k.status === 'active' ? k.budget_cap_usd : 0), 0).toFixed(2)}
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
            <DollarSign className="w-3.5 h-3.5 text-amber-400" /> Atomic Lua Quota Sync
          </div>
        </div>
      </div>

      {/* Keys Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-brand-400" /> Issued Virtual API Keys
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 font-medium">
              <tr>
                <th className="p-3.5">Name / Prefix</th>
                <th className="p-3.5">Policy Pack</th>
                <th className="p-3.5">Allowed Models</th>
                <th className="p-3.5">Budget Cap</th>
                <th className="p-3.5">Rate Limit</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {keys.map((k) => (
                <tr key={k.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3.5">
                    <div className="font-semibold text-white">{k.name}</div>
                    <div className="font-mono text-slate-500 text-[11px]">{k.key_prefix}</div>
                  </td>
                  <td className="p-3.5 font-mono text-brand-400">{k.default_policy_pack_id}</td>
                  <td className="p-3.5">
                    <div className="flex flex-wrap gap-1">
                      {k.allowed_models.map((m) => (
                        <span key={m} className="px-1.5 py-0.5 text-[10px] bg-slate-800 text-slate-300 rounded font-mono">
                          {m}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-3.5 font-mono">${k.budget_cap_usd.toFixed(2)}</td>
                  <td className="p-3.5 font-mono">{k.rate_limit_rpm} rpm</td>
                  <td className="p-3.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                        k.status === 'active'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      {k.status}
                    </span>
                  </td>
                  <td className="p-3.5 text-right space-x-2">
                    {k.status === 'active' && (
                      <button
                        onClick={() => handleRevoke(k.id)}
                        className="px-2.5 py-1 text-[11px] bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded font-medium transition"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-md rounded-xl p-6 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2 mb-4">
              <Key className="w-5 h-5 text-brand-400" /> Issue New Virtual API Key
            </h3>

            {createdKeyPlaintext ? (
              <div className="space-y-4 text-xs">
                <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>
                    Copy this Virtual API Key now. For security, it will never be displayed again.
                  </span>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg font-mono text-white text-xs border border-slate-800 break-all select-all">
                  {createdKeyPlaintext}
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={() => {
                      setModalOpen(false);
                      setCreatedKeyPlaintext(null);
                    }}
                    className="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white rounded-lg font-semibold"
                  >
                    Done
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleCreateKey} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Key Name / Description</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Agent Fleet Production Worker"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Budget Cap (USD)</label>
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    value={budgetCap}
                    onChange={(e) => setBudgetCap(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Rate Limit (RPM)</label>
                  <input
                    type="number"
                    min="10"
                    max="5000"
                    value={rpmLimit}
                    onChange={(e) => setRpmLimit(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setModalOpen(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white rounded-lg font-semibold shadow transition"
                  >
                    Generate Key
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
