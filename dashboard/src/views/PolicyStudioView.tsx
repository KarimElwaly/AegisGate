import React, { useState } from 'react';
import { FileCode, ArrowUpRight, History, Check, Save } from 'lucide-react';
import { PolicyPackSummary } from '../types';
import { savePolicyPack } from '../api';

interface PolicyStudioViewProps {
  packs: PolicyPackSummary[];
  tenantId?: string;
  onRefresh?: () => void;
}

export const PolicyStudioView: React.FC<PolicyStudioViewProps> = ({ packs, tenantId = 'default', onRefresh }) => {
  const [selectedPackId, setSelectedPackId] = useState<string>(packs[0]?.pack_id || 'soc-investigation-pack');
  const [activeTab, setActiveTab] = useState<'editor' | 'diff' | 'history'>('editor');
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  const selectedPack = packs.find((p) => p.pack_id === selectedPackId) || packs[0];

  const sampleYamls: Record<string, string> = {
    'soc-investigation-pack': `id: soc-investigation-pack
name: Autonomous SOC Investigation & Containment Policy Pack
version: 1.0.0
extends: base-enterprise
execution_mode: enforce
description: Real-time SOC guardrails with dynamic CMDB asset enrichment, DC protection, and tiered HITL single/dual containment approval.

resolvers:
  - name: http_context_resolver
    enabled: true
    timeout_ms: 300
    cache_ttl_seconds: 60
    config:
      url: "http://asset-inventory.internal/v1/assets/{action.parameters.asset_id}"

rules:
  - id: soc-deny-domain-controller-containment
    name: Block Containment on Domain Controllers
    priority: 8
    stages: ["tool_pre_call"]
    condition:
      all:
        - field: action.name
          operator: in
          value: ["isolate_host", "block_ip", "disable_user"]
        - field: resolved_context.is_domain_controller
          operator: eq
          value: true
    action:
      decision: DENY
      severity: critical
      reason: "Target asset is an essential Domain Controller"

  - id: soc-suspend-tier0-dual-approval
    name: Require Dual Approval for Tier-0 Asset Containment
    priority: 15
    stages: ["tool_pre_call"]
    condition:
      all:
        - field: action.name
          operator: in
          value: ["isolate_host", "block_ip"]
        - field: resolved_context.asset_tier
          operator: eq
          value: "tier0"
    action:
      decision: SUSPEND_FOR_APPROVAL
      severity: critical
      reason: "Tier-0 Asset Containment requires Dual Approval (4-eyes principle)"
      approval_config:
        required_approvals: 2
        required_approver_roles: ["security_lead", "soc_manager"]
        ttl_seconds: 600`,
    'agent-fleet-pack': `id: agent-fleet-pack
name: Multi-Agent Fleet Orchestration Policy Pack
version: 1.0.0
extends: base-enterprise
execution_mode: enforce

budgets:
  max_tokens: 50000
  max_cost_usd: 5.00
  max_tool_calls: 30

rules:
  - id: fleet-block-excessive-delegation-depth
    priority: 5
    condition:
      field: actor.delegation_depth
      operator: gt
      value: 3
    action:
      decision: DENY
      severity: critical
      reason: "Maximum delegation depth exceeded (limit: 3)"

  - id: fleet-loop-circuit-breaker
    priority: 15
    stages: ["tool_pre_call"]
    condition:
      field: metadata.loop_count
      operator: gt
      value: 3
    action:
      decision: DENY
      severity: critical
      reason: "Runaway loop circuit breaker tripped (3 identical calls)"`,
    'log-analysis-pack': `id: log-analysis-pack
name: High-Volume Log Anomaly Analysis Policy Pack
version: 1.0.0
extends: base-enterprise
execution_mode: enforce

scanners:
  - name: tier2_onnx_injection_classifier
    enabled: true
    tier: 2
    timeout_ms: 80
    config:
      action_on_match: block
      threshold: 0.75
      inspect_untrusted_data_only: true

rules:
  - id: log-block-indirect-prompt-injection
    priority: 8
    condition:
      field: scanner_findings.tier2_onnx_injection_classifier.status
      operator: eq
      value: block
    action:
      decision: DENY
      severity: critical
      reason: "Indirect prompt injection detected inside untrusted log payload"`,
  };

  const [editableYamls, setEditableYamls] = useState<Record<string, string>>(sampleYamls);
  const currentYaml = editableYamls[selectedPackId] || sampleYamls[selectedPackId] || sampleYamls['soc-investigation-pack'];

  const handleYamlChange = (val: string) => {
    setEditableYamls((prev) => ({ ...prev, [selectedPackId]: val }));
  };

  const handleSave = async (status = 'active') => {
    try {
      setSavedNotice('Saving...');
      await savePolicyPack(currentYaml, tenantId, status);
      setSavedNotice(status === 'active' ? 'Published & Hot-Reloaded' : 'Promoted to Shadow');
      if (onRefresh) onRefresh();
      setTimeout(() => setSavedNotice(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Save failed');
      setSavedNotice(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileCode className="w-6 h-6 text-brand-400" /> Policy Pack Studio
          </h1>
          <p className="text-sm text-slate-400">
            Declarative YAML DSL with inheritance, atomic hot-reload, version diffs, and safe shadow rollout.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleSave('active')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold shadow transition-colors"
          >
            {savedNotice ? <Check className="w-4 h-4 text-emerald-200" /> : <Save className="w-4 h-4" />}
            <span>{savedNotice || 'Save & Publish'}</span>
          </button>
          <button
            onClick={() => handleSave('shadow')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
          >
            <ArrowUpRight className="w-4 h-4 text-amber-400" />
            <span>Promote to Shadow</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left: Pack Selection */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1">
            Registered Packs
          </div>
          <div className="space-y-2">
            {packs.map((pack) => (
              <button
                key={pack.pack_id}
                onClick={() => setSelectedPackId(pack.pack_id)}
                className={`w-full text-left p-3 rounded-lg border transition-all ${
                  selectedPackId === pack.pack_id
                    ? 'bg-slate-800 border-brand-500/50 shadow-sm'
                    : 'bg-slate-950/40 border-slate-800/80 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-xs text-white truncate">{pack.name}</span>
                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                    {pack.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono truncate">v{pack.version} · {pack.pack_id}</div>
              </button>
            ))}
          </div>

          <div className="pt-3 border-t border-slate-800">
            <button className="w-full py-2 px-3 text-xs text-brand-400 hover:text-brand-300 bg-brand-500/10 hover:bg-brand-500/15 border border-brand-500/20 rounded-lg text-center font-medium transition-colors">
              + New Draft Policy Pack
            </button>
          </div>
        </div>

        {/* Right: YAML Editor and Controls */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl flex flex-col overflow-hidden">
          {/* Editor Tabs & Status Bar */}
          <div className="bg-slate-950/80 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between">
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setActiveTab('editor')}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  activeTab === 'editor' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                YAML DSL Editor
              </button>
              <button
                onClick={() => setActiveTab('diff')}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  activeTab === 'diff' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Version Diff (v1.0.0 vs v0.9.8)
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  activeTab === 'history' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Release History
              </button>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-emerald-400 flex items-center gap-1 font-mono">
                <Check className="w-3.5 h-3.5" /> Schema Validated
              </span>
              <button className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1">
                <History className="w-3.5 h-3.5" /> 1-Click Rollback
              </button>
            </div>
          </div>

          {/* Editor Body */}
          <div className="p-4 flex-1">
            {activeTab === 'editor' && (
              <textarea
                value={currentYaml}
                onChange={(e) => handleYamlChange(e.target.value)}
                className="w-full h-[460px] bg-slate-950 p-4 rounded-lg font-mono text-xs text-brand-300 leading-relaxed border border-slate-800 focus:outline-none resize-none selection:bg-brand-500 selection:text-white"
                spellCheck={false}
              />
            )}
            {activeTab === 'diff' && (
              <div className="h-[460px] bg-slate-950 p-4 rounded-lg font-mono text-xs overflow-y-auto space-y-1">
                <div className="text-slate-500">--- a/policy_packs/{selectedPack.pack_id}/policy.yaml (v0.9.8)</div>
                <div className="text-slate-500">+++ b/policy_packs/{selectedPack.pack_id}/policy.yaml (v1.0.0)</div>
                <div className="text-indigo-400">@@ -15,7 +15,9 @@</div>
                <div className="text-slate-300">   - id: soc-suspend-tier0-dual-approval</div>
                <div className="text-rose-400">-    required_approvals: 1</div>
                <div className="text-emerald-400">+    required_approvals: 2 # 4-eyes principle enforced</div>
                <div className="text-emerald-400">+    required_approver_roles: ["security_lead", "soc_manager"]</div>
              </div>
            )}
            {activeTab === 'history' && (
              <div className="h-[460px] bg-slate-950 p-4 rounded-lg text-xs space-y-3">
                <div className="p-3 bg-slate-900 border border-slate-800 rounded flex justify-between items-center">
                  <div>
                    <span className="font-semibold text-white">v1.0.0 (Active)</span>
                    <p className="text-slate-400">Added dual-approval 4-eyes enforcement and Domain Controller block.</p>
                  </div>
                  <span className="text-slate-500">2026-11-20 00:00 UTC</span>
                </div>
                <div className="p-3 bg-slate-900 border border-slate-800 rounded flex justify-between items-center">
                  <div>
                    <span className="font-semibold text-slate-400">v0.9.8 (Archived)</span>
                    <p className="text-slate-400">Baseline rules for SOC investigation tools.</p>
                  </div>
                  <span className="text-slate-500">2026-11-19 18:30 UTC</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

