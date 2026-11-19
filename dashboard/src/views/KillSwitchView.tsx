import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Clock,
  Layers,
  Terminal,
  Cpu,
} from 'lucide-react';
import { KillSwitchItem } from '../types';
import { fetchKillSwitches, activateKillSwitch, deactivateKillSwitch } from '../api';

interface KillSwitchViewProps {
  tenantId: string;
}

export const KillSwitchView: React.FC<KillSwitchViewProps> = ({ tenantId }) => {
  const [activeSwitches, setActiveSwitches] = useState<KillSwitchItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [selectedScope, setSelectedScope] = useState<string>('agent');
  const [targetId, setTargetId] = useState<string>('');
  const [reason, setReason] = useState<string>('');
  const [ttlSeconds, setTtlSeconds] = useState<number | undefined>(undefined);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadSwitches = async () => {
    try {
      setLoading(true);
      const data = await fetchKillSwitches();
      setActiveSwitches(data);
    } catch {
      setActiveSwitches([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSwitches();
  }, [tenantId]);

  const handleOpenModal = (scope: string, defaultTarget: string = '') => {
    setSelectedScope(scope);
    setTargetId(defaultTarget);
    setReason('');
    setTtlSeconds(undefined);
    setErrorMsg(null);
    setModalOpen(true);
  };

  const handleTripSwitch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) {
      setErrorMsg('Audit reason is strictly mandatory to engage kill switch.');
      return;
    }

    try {
      await activateKillSwitch(selectedScope, targetId, tenantId, reason, ttlSeconds);
      setModalOpen(false);
      await loadSwitches();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to engage kill switch');
    }
  };

  const handleDisengage = async (item: KillSwitchItem) => {
    try {
      await deactivateKillSwitch(item.scope, item.target || '', item.tenant_id || tenantId);
      await loadSwitches();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to disengage kill switch');
    }
  };

  const isGlobalTripped = activeSwitches.some((s) => s.scope.toLowerCase() === 'global');

  return (
    <div className="space-y-6">
      {/* Top Banner Alert */}
      {isGlobalTripped ? (
        <div className="p-4 bg-red-950/60 border border-red-500/50 rounded-xl flex items-center justify-between shadow-lg shadow-red-950/50 animate-pulse">
          <div className="flex items-center space-x-3">
            <Flame className="w-8 h-8 text-red-500" />
            <div>
              <h2 className="text-lg font-bold text-red-400">GLOBAL KILL SWITCH ENGAGED</h2>
              <p className="text-xs text-red-300/80">
                All incoming tool executions and LLM pipeline evaluations are unconditionally hard-blocked.
              </p>
            </div>
          </div>
          <button
            onClick={() => handleDisengage({ scope: 'global', target: '', tenant_id: tenantId })}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-lg shadow"
          >
            DISENGAGE GLOBAL BREAKER
          </button>
        </div>
      ) : activeSwitches.length > 0 ? (
        <div className="p-4 bg-amber-950/40 border border-amber-500/40 rounded-xl flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-6 h-6 text-amber-400" />
            <div>
              <h2 className="text-sm font-semibold text-amber-300">
                {activeSwitches.length} Active Circuit Breaker(s) Tripped
              </h2>
              <p className="text-xs text-amber-200/70">
                Scoped boundaries are actively suppressing targeted agents, tools, or workspaces.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 bg-emerald-950/30 border border-emerald-500/30 rounded-xl flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            <div>
              <h2 className="text-sm font-semibold text-emerald-300">Emergency Circuit Breakers Normal</h2>
              <p className="text-xs text-slate-400">
                Sub-millisecond Redis MGET checks active on all evaluation paths. No active tripwires.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-emerald-400/80 bg-emerald-950/80 px-2.5 py-1 rounded border border-emerald-500/30">
            P95 LATENCY &lt; 0.5ms
          </span>
        </div>
      )}

      {/* Control Room Scopes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {/* Global Breaker Card */}
        <div className="bg-slate-900 border border-red-900/40 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Level 0: Global</span>
              <ShieldAlert className="w-5 h-5 text-red-500" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Global Engine Halt</h3>
            <p className="text-xs text-slate-400 mb-4">
              Instantly terminates all traffic across all tenants, agents, and gateways.
            </p>
          </div>
          <button
            onClick={() => handleOpenModal('global', '')}
            className="w-full py-2 bg-red-950 hover:bg-red-900/80 border border-red-700/60 text-red-300 hover:text-white rounded-lg text-xs font-bold transition-colors"
          >
            ENGAGE GLOBAL HALT
          </button>
        </div>

        {/* Tenant Scope */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Level 1: Tenant</span>
              <Layers className="w-5 h-5 text-amber-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Tenant Quarantine</h3>
            <p className="text-xs text-slate-400 mb-4">
              Isolate this entire tenant ({tenantId}) from executing tools or proxying LLM requests.
            </p>
          </div>
          <button
            onClick={() => handleOpenModal('tenant', tenantId)}
            className="w-full py-2 bg-slate-800 hover:bg-amber-950/60 border border-slate-700 hover:border-amber-600/50 text-slate-200 hover:text-amber-300 rounded-lg text-xs font-semibold transition-colors"
          >
            TRIP TENANT
          </button>
        </div>

        {/* Workspace Scope */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Level 2: Workspace</span>
              <Cpu className="w-5 h-5 text-blue-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Workspace Halt</h3>
            <p className="text-xs text-slate-400 mb-4">
              Quarantine a specific project workspace environment (e.g. staging, prod-eu).
            </p>
          </div>
          <button
            onClick={() => handleOpenModal('workspace', 'prod')}
            className="w-full py-2 bg-slate-800 hover:bg-blue-950/60 border border-slate-700 hover:border-blue-600/50 text-slate-200 hover:text-blue-300 rounded-lg text-xs font-semibold transition-colors"
          >
            TRIP WORKSPACE
          </button>
        </div>

        {/* Agent Scope */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Level 3: Agent</span>
              <Terminal className="w-5 h-5 text-purple-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Agent Containment</h3>
            <p className="text-xs text-slate-400 mb-4">
              Immediately revoke permissions from a runaway, compromised, or looping agent ID.
            </p>
          </div>
          <button
            onClick={() => handleOpenModal('agent', 'autonomous-agent-01')}
            className="w-full py-2 bg-slate-800 hover:bg-purple-950/60 border border-slate-700 hover:border-purple-600/50 text-slate-200 hover:text-purple-300 rounded-lg text-xs font-semibold transition-colors"
          >
            CONTAIN AGENT
          </button>
        </div>

        {/* Tool Scope */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Level 4: Tool</span>
              <Terminal className="w-5 h-5 text-cyan-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Tool Blacklist</h3>
            <p className="text-xs text-slate-400 mb-4">
              Halt execution of high-risk tools like bash_executor or aws_iam across all agents.
            </p>
          </div>
          <button
            onClick={() => handleOpenModal('tool', 'bash_executor')}
            className="w-full py-2 bg-slate-800 hover:bg-cyan-950/60 border border-slate-700 hover:border-cyan-600/50 text-slate-200 hover:text-cyan-300 rounded-lg text-xs font-semibold transition-colors"
          >
            HALT TOOL
          </button>
        </div>
      </div>

      {/* Active Kill Switches Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Active Emergency Breakers</h2>
            <p className="text-xs text-slate-400">Live tripwires recorded in distributed Redis cache</p>
          </div>
          <button
            onClick={loadSwitches}
            className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 text-sm">Querying breaker states...</div>
        ) : activeSwitches.length === 0 ? (
          <div className="p-10 text-center">
            <CheckCircle2 className="w-10 h-10 text-emerald-500/40 mx-auto mb-2" />
            <p className="text-sm font-medium text-slate-300">All Systems Nominal</p>
            <p className="text-xs text-slate-500">No emergency breakers are currently active.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {activeSwitches.map((item, idx) => (
              <div key={idx} className="p-4 flex items-center justify-between hover:bg-slate-800/40 transition">
                <div className="flex items-center space-x-4">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-bold uppercase px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/50">
                        {item.scope}
                      </span>
                      {item.target && (
                        <span className="text-sm font-mono text-white font-semibold">{item.target}</span>
                      )}
                      <span className="text-xs text-slate-500">tenant: {item.tenant_id || tenantId}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      <span className="font-semibold text-slate-300">Reason:</span> {item.reason || 'No audit reason recorded'}
                    </p>
                    {item.activated_at && (
                      <p className="text-[11px] text-slate-500 flex items-center space-x-1 mt-0.5">
                        <Clock className="w-3 h-3" />
                        <span>Activated: {item.activated_at}</span>
                      </p>
                    )}
                  </div>
                </div>

                <button
                  onClick={() => handleDisengage(item)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-emerald-950/80 border border-slate-700 hover:border-emerald-600/50 text-slate-300 hover:text-emerald-300 rounded-lg text-xs font-semibold transition"
                >
                  Disengage Breaker
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Confirmation Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-red-500/40 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center space-x-3 text-red-400">
              <ShieldAlert className="w-7 h-7" />
              <div>
                <h3 className="text-lg font-bold text-white">Trip Circuit Breaker</h3>
                <p className="text-xs text-slate-400">Scope: <span className="font-mono uppercase text-red-400">{selectedScope}</span></p>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3 bg-red-950/60 border border-red-700/50 rounded-lg text-xs text-red-300">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleTripSwitch} className="space-y-4">
              {selectedScope !== 'global' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Target Identifier ({selectedScope === 'agent' ? 'Agent ID' : selectedScope === 'tool' ? 'Tool Name' : 'Target'})
                  </label>
                  <input
                    type="text"
                    required
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    placeholder={selectedScope === 'agent' ? 'agent-fleet-04' : selectedScope === 'tool' ? 'bash_executor' : 'target-id'}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-red-500"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Audit & Compliance Reason <span className="text-red-400">*</span>
                </label>
                <textarea
                  required
                  rows={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Explain why this emergency breaker is being tripped (logged immutably to audit ledger)..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Optional Auto-Expiring TTL (Seconds)
                </label>
                <input
                  type="number"
                  min={1}
                  value={ttlSeconds || ''}
                  onChange={(e) => setTtlSeconds(e.target.value ? parseInt(e.target.value, 10) : undefined)}
                  placeholder="e.g. 300 (5 minutes)"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-red-950/60"
                >
                  CONFIRM & TRIP BREAKER
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
