import React, { useState } from 'react';
import {
  Compass,
  Cpu,
  Wrench,
  ShieldCheck,
  AlertOctagon,
  Eye,
  Server,
  Lock,
} from 'lucide-react';

interface McpDiscoveryViewProps {
  tenantId?: string;
}

interface McpToolPin {
  tool_name: string;
  server_name: string;
  schema_hash: string;
  is_quarantined: boolean;
  quarantine_reason?: string;
  status: 'pinned' | 'quarantined';
  last_verified: string;
}

interface DiscoveredAsset {
  id: string;
  name: string;
  asset_type: 'model' | 'tool' | 'agent';
  request_count: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  governance_status: 'governed' | 'shadow_unapproved' | 'blocked';
  last_seen: string;
}

export const McpDiscoveryView: React.FC<McpDiscoveryViewProps> = ({ tenantId: _tenantId = 'default' }) => {
  const [activeTab, setActiveTab] = useState<'mcp' | 'shadow'>('mcp');

  const [mcpPins, setMcpPins] = useState<McpToolPin[]>([
    {
      tool_name: 'query_customer_database',
      server_name: 'internal-db-mcp',
      schema_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      is_quarantined: false,
      status: 'pinned',
      last_verified: '2 mins ago',
    },
    {
      tool_name: 'execute_remote_sql',
      server_name: 'analytics-mcp',
      schema_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      is_quarantined: true,
      quarantine_reason: 'Anti-Rug-Pull: Upstream schema mutated unexpectedly without policy approval',
      status: 'quarantined',
      last_verified: '10 mins ago',
    },
  ]);

  const [discoveredAssets, setDiscoveredAssets] = useState<DiscoveredAsset[]>([
    {
      id: 'ast-001',
      name: 'claude-3-5-sonnet-shadow',
      asset_type: 'model',
      request_count: 142,
      risk_level: 'high',
      governance_status: 'shadow_unapproved',
      last_seen: '1 min ago',
    },
    {
      id: 'ast-002',
      name: 'web_scraper_custom',
      asset_type: 'tool',
      request_count: 58,
      risk_level: 'medium',
      governance_status: 'shadow_unapproved',
      last_seen: '5 mins ago',
    },
    {
      id: 'ast-003',
      name: 'gpt-4o',
      asset_type: 'model',
      request_count: 1240,
      risk_level: 'low',
      governance_status: 'governed',
      last_seen: 'Just now',
    },
  ]);

  const handleApproveAsset = (id: string) => {
    setDiscoveredAssets((prev) =>
      prev.map((a) => (a.id === id ? { ...a, governance_status: 'governed', risk_level: 'low' } : a))
    );
  };

  const handleBlockAsset = (id: string) => {
    setDiscoveredAssets((prev) =>
      prev.map((a) => (a.id === id ? { ...a, governance_status: 'blocked', risk_level: 'critical' } : a))
    );
  };

  const handleUnquarantineTool = (name: string) => {
    setMcpPins((prev) =>
      prev.map((t) => (t.tool_name === name ? { ...t, is_quarantined: false, status: 'pinned' } : t))
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Compass className="w-6 h-6 text-brand-400" /> MCP Security & Shadow AI Discovery
          </h1>
          <p className="text-sm text-slate-400">
            Anti-Rug-Pull tool schema pinning, dynamic tool quarantine, and automated Shadow AI asset discovery.
          </p>
        </div>

        <div className="flex bg-slate-900 border border-slate-800 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('mcp')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'mcp' ? 'bg-brand-500 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            MCP Anti-Rug-Pull ({mcpPins.length})
          </button>
          <button
            onClick={() => setActiveTab('shadow')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'shadow' ? 'bg-brand-500 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Shadow AI Assets ({discoveredAssets.filter((a) => a.governance_status === 'shadow_unapproved').length})
          </button>
        </div>
      </div>

      {activeTab === 'mcp' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">Upstream MCP Tools Pinned</div>
              <div className="text-xl font-bold text-white mt-1 font-mono">{mcpPins.length}</div>
              <div className="text-[11px] text-emerald-400 mt-2 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> SHA-256 Hashes Verified
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">Quarantined MCP Tools</div>
              <div className="text-xl font-bold text-rose-400 mt-1 font-mono">
                {mcpPins.filter((p) => p.is_quarantined).length}
              </div>
              <div className="text-[11px] text-rose-400 mt-2 flex items-center gap-1">
                <AlertOctagon className="w-3.5 h-3.5" /> Stripped from tools/list
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">Anti-Rug-Pull Protection</div>
              <div className="text-xl font-bold text-brand-400 mt-1">ENFORCED</div>
              <div className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
                <Lock className="w-3.5 h-3.5 text-brand-400" /> Monotonic Attenuation Active
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-brand-400" /> Pinned MCP Tool Catalog
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 font-medium">
                  <tr>
                    <th className="p-3.5">Tool Name / Server</th>
                    <th className="p-3.5">Schema SHA-256 Hash</th>
                    <th className="p-3.5">Status</th>
                    <th className="p-3.5">Last Verified</th>
                    <th className="p-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {mcpPins.map((t) => (
                    <tr key={t.tool_name} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3.5">
                        <div className="font-semibold text-white flex items-center gap-2">
                          <Wrench className="w-3.5 h-3.5 text-brand-400" />
                          {t.tool_name}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">{t.server_name}</div>
                        {t.quarantine_reason && (
                          <div className="text-[10px] text-rose-400 mt-1">{t.quarantine_reason}</div>
                        )}
                      </td>
                      <td className="p-3.5 font-mono text-slate-400 text-[11px]">
                        {t.schema_hash.substring(0, 20)}...
                      </td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                            t.is_quarantined
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {t.status}
                        </span>
                      </td>
                      <td className="p-3.5 text-slate-400">{t.last_verified}</td>
                      <td className="p-3.5 text-right">
                        {t.is_quarantined ? (
                          <button
                            onClick={() => handleUnquarantineTool(t.tool_name)}
                            className="px-2.5 py-1 text-[11px] bg-brand-500/10 hover:bg-brand-500/20 text-brand-400 border border-brand-500/30 rounded font-medium transition"
                          >
                            Re-Pin & Release
                          </button>
                        ) : (
                          <span className="text-slate-500 text-[11px]">Protected</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'shadow' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Eye className="w-4 h-4 text-amber-400" /> Auto-Discovered Shadow AI Inventory
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 font-medium">
                  <tr>
                    <th className="p-3.5">Asset Name</th>
                    <th className="p-3.5">Type</th>
                    <th className="p-3.5">Traffic</th>
                    <th className="p-3.5">Risk Level</th>
                    <th className="p-3.5">Governance Status</th>
                    <th className="p-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {discoveredAssets.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3.5 font-semibold text-white">
                        <div className="flex items-center gap-2">
                          {a.asset_type === 'model' ? (
                            <Cpu className="w-3.5 h-3.5 text-blue-400" />
                          ) : (
                            <Wrench className="w-3.5 h-3.5 text-amber-400" />
                          )}
                          <span>{a.name}</span>
                        </div>
                      </td>
                      <td className="p-3.5 uppercase font-mono text-[10px] text-slate-400">{a.asset_type}</td>
                      <td className="p-3.5 font-mono">{a.request_count} calls</td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            a.risk_level === 'low'
                              ? 'bg-emerald-500/10 text-emerald-400'
                              : a.risk_level === 'medium'
                              ? 'bg-amber-500/10 text-amber-400'
                              : 'bg-rose-500/10 text-rose-400'
                          }`}
                        >
                          {a.risk_level}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            a.governance_status === 'governed'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : a.governance_status === 'blocked'
                              ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}
                        >
                          {a.governance_status}
                        </span>
                      </td>
                      <td className="p-3.5 text-right space-x-2">
                        {a.governance_status === 'shadow_unapproved' && (
                          <>
                            <button
                              onClick={() => handleApproveAsset(a.id)}
                              className="px-2.5 py-1 text-[11px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 rounded font-medium transition"
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => handleBlockAsset(a.id)}
                              className="px-2.5 py-1 text-[11px] bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded font-medium transition"
                            >
                              Block
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
