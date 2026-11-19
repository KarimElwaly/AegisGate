import React from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react';
import { TelemetryKPIs } from '../types';

interface OverviewViewProps {
  kpis: TelemetryKPIs;
  tenantId: string;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ kpis, tenantId }) => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Overview & Telemetry</h1>
        <p className="text-sm text-slate-400">
          Real-time metrics, sub-15ms fast path evaluation, and guardrail performance for <span className="text-brand-400 font-medium">{tenantId}</span>.
        </p>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {/* Total Requests */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Total Evaluated</span>
            <Activity className="w-4 h-4 text-brand-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {kpis.totalRequests.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-emerald-400 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" /> +14.2% today
          </div>
        </div>

        {/* P95 Latency */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>P95 Latency</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">
            {kpis.p95LatencyMs} ms
          </div>
          <div className="mt-1 text-xs text-slate-400">
            DoD Target &lt; 15.0 ms
          </div>
        </div>

        {/* Block Rate */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Block Rate</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">
            {(kpis.blockRate * 100).toFixed(1)}%
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Threats neutralized
          </div>
        </div>

        {/* Modify Rate */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Redaction Rate</span>
            <ShieldCheck className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">
            {(kpis.modifyRate * 100).toFixed(1)}%
          </div>
          <div className="mt-1 text-xs text-slate-400">
            PII masked / tokenized
          </div>
        </div>

        {/* HITL Queue */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active HITL Queue</span>
            <CheckCircle2 className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-indigo-400">
            {kpis.activeHitlQueue}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Pending analyst review
          </div>
        </div>

        {/* Shadow Deltas */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Shadow Deltas</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-cyan-400">
            {kpis.shadowDeltasCount}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Candidate diff logged
          </div>
        </div>
      </div>

      {/* Main Grid: Telemetry & Live Trace Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Latency Tier Distribution & Budgets */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
            <h3 className="text-sm font-semibold text-white mb-4">Pipeline Latency Tiers</h3>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">Tier 1: Deterministic (<span className="text-emerald-400">0.23 ms</span>)</span>
                  <span className="text-slate-400">Sync Blocking</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-emerald-500 h-full w-[95%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">Tier 2: ONNX Classifier (<span className="text-cyan-400">22.4 ms</span>)</span>
                  <span className="text-slate-400">Local Semantic ML</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[45%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">Tier 3: LLM Judge (<span className="text-indigo-400">180 ms</span>)</span>
                  <span className="text-slate-400">Async Audit</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-indigo-500 h-full w-[15%]"></div>
                </div>
              </div>
            </div>
          </div>

          {/* Budget Utilization Meter */}
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
            <h3 className="text-sm font-semibold text-white mb-3">Session Token & Cost Burn</h3>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-xs mb-1 text-slate-400">
                  <span>Tokens (Current Session)</span>
                  <span className="text-white font-medium">12,450 / 50,000</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-brand-500 h-full w-[24.9%]"></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-xs mb-1 text-slate-400">
                  <span>Estimated Cost USD</span>
                  <span className="text-white font-medium">$0.25 / $5.00</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-amber-500 h-full w-[5%]"></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Simulated Live Activity Stream */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                Live Evaluation Feed
              </h3>
              <span className="text-xs text-slate-400">Auto-refresh active</span>
            </div>

            <div className="space-y-2.5">
              {[
                {
                  id: 'tr-094',
                  stage: 'tool_pre_call',
                  actor: 'soc-agent-01',
                  action: 'isolate_host',
                  decision: 'SUSPEND_FOR_APPROVAL',
                  reason: 'Tier-0 Asset Containment requires Dual Approval',
                  time: 'Just now',
                },
                {
                  id: 'tr-093',
                  stage: 'llm_input',
                  actor: 'log-parser-agent',
                  action: 'parse_log_chunk',
                  decision: 'DENY',
                  reason: 'Indirect prompt injection detected in untrusted data',
                  time: '12s ago',
                },
                {
                  id: 'tr-092',
                  stage: 'tool_pre_call',
                  actor: 'analyst-bot',
                  action: 'query_siem',
                  decision: 'ALLOW',
                  reason: 'Read-only SOC investigation tool authorized',
                  time: '34s ago',
                },
                {
                  id: 'tr-091',
                  stage: 'llm_output',
                  actor: 'fleet-coordinator',
                  action: 'handoff_summary',
                  decision: 'MODIFY',
                  reason: 'PII IPv4 address replaced with ephemeral token',
                  time: '1m ago',
                },
                {
                  id: 'tr-090',
                  stage: 'tool_pre_call',
                  actor: 'worker-agent',
                  action: 'deploy_code',
                  decision: 'DENY',
                  reason: 'Worker role forbidden from privileged deployment tool',
                  time: '2m ago',
                },
              ].map((ev) => (
                <div
                  key={ev.id}
                  className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded font-semibold text-[10px] ${
                        ev.decision === 'ALLOW'
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20'
                          : ev.decision === 'DENY'
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/20'
                          : ev.decision === 'SUSPEND_FOR_APPROVAL'
                          ? 'bg-amber-500/15 text-amber-400 border border-amber-500/20'
                          : 'bg-brand-500/15 text-brand-400 border border-brand-500/20'
                      }`}
                    >
                      {ev.decision}
                    </span>
                    <div>
                      <span className="font-mono text-slate-300">{ev.action}</span>
                      <span className="text-slate-500 ml-2">by {ev.actor}</span>
                      <p className="text-[11px] text-slate-400">{ev.reason}</p>
                    </div>
                  </div>
                  <span className="text-slate-500 text-[11px]">{ev.time}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-500 flex justify-between items-center">
            <span>Cryptographic provenance enabled (SHA256 chained)</span>
            <span className="text-brand-400 font-mono">P95: 7.86ms</span>
          </div>
        </div>
      </div>
    </div>
  );
};

