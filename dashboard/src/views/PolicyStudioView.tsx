import React, { useState, useEffect } from 'react';
import {
  FileCode,
  ArrowUpRight,
  History,
  Check,
  Save,
  PlusCircle,
  X,
  AlertCircle,
  RotateCcw,
} from 'lucide-react';
import { PolicyPackSummary } from '../types';
import { savePolicyPack, rollbackPolicyPack } from '../api';

interface PolicyStudioViewProps {
  packs: PolicyPackSummary[];
  tenantId?: string;
  onRefresh?: () => void;
}

export const PolicyStudioView: React.FC<PolicyStudioViewProps> = ({
  packs,
  tenantId = 'default',
  onRefresh,
}) => {
  const [localPacks, setLocalPacks] = useState<PolicyPackSummary[]>(packs);
  const [selectedPackId, setSelectedPackId] = useState<string>(
    packs[0]?.pack_id || 'soc-investigation-pack'
  );
  const [activeTab, setActiveTab] = useState<'editor' | 'diff' | 'history'>('editor');
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  // New Pack Modal State
  const [createModalOpen, setCreateModalOpen] = useState<boolean>(false);
  const [newPackId, setNewPackId] = useState<string>('');
  const [newPackName, setNewPackName] = useState<string>('');
  const [newPackTemplate, setNewPackTemplate] = useState<string>('blank');
  const [newPackDesc, setNewPackDesc] = useState<string>('');

  useEffect(() => {
    if (packs.length > 0) {
      setLocalPacks((prev) => {
        // Merge without losing locally created drafts
        const existingIds = new Set(packs.map((p) => p.pack_id));
        const customLocal = prev.filter((p) => !existingIds.has(p.pack_id));
        return [...packs, ...customLocal];
      });
    }
  }, [packs]);

  const selectedPack =
    localPacks.find((p) => p.pack_id === selectedPackId) || localPacks[0] || packs[0];

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
  const currentYaml =
    editableYamls[selectedPackId] ||
    sampleYamls[selectedPackId] ||
    sampleYamls['soc-investigation-pack'] ||
    '';

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

  const handleRollback = async (targetVersion: string = '0.9.8') => {
    if (!selectedPack) return;
    try {
      setSavedNotice(`Rolling back to ${targetVersion}...`);
      await rollbackPolicyPack(selectedPack.pack_id, targetVersion, tenantId);
      setSavedNotice(`Rolled back to v${targetVersion}`);
      if (onRefresh) onRefresh();
      setTimeout(() => setSavedNotice(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Rollback failed');
      setSavedNotice(null);
    }
  };

  const handleCreateDraftPack = (e: React.FormEvent) => {
    e.preventDefault();
    const slugId = newPackId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    if (!slugId) {
      alert('Pack ID is required.');
      return;
    }

    let starterYaml = '';
    if (newPackTemplate === 'agent-fleet') {
      starterYaml = `id: ${slugId}
name: ${newPackName || 'Custom Multi-Agent Guardrails'}
version: 0.1.0-draft
extends: base-enterprise
execution_mode: enforce
description: ${newPackDesc || 'Custom agent fleet guardrail policies'}

budgets:
  max_tokens: 30000
  max_cost_usd: 2.50
  max_tool_calls: 20

rules:
  - id: ${slugId}-depth-guard
    priority: 5
    condition:
      field: actor.delegation_depth
      operator: gt
      value: 2
    action:
      decision: DENY
      severity: high
      reason: "Delegation depth limit reached for ${slugId}"`;
    } else if (newPackTemplate === 'soc-investigation') {
      starterYaml = `id: ${slugId}
name: ${newPackName || 'Custom SOC Security Pack'}
version: 0.1.0-draft
extends: base-enterprise
execution_mode: enforce
description: ${newPackDesc || 'Custom SOC security and containment guardrails'}

rules:
  - id: ${slugId}-critical-action-guard
    priority: 10
    stages: ["tool_pre_call"]
    condition:
      field: action.name
      operator: in
      value: ["wipe_disk", "format_volume", "drop_firewall"]
    action:
      decision: DENY
      severity: critical
      reason: "Dangerous action blocked by ${slugId}"`;
    } else {
      starterYaml = `id: ${slugId}
name: ${newPackName || 'Custom Enterprise Guardrail'}
version: 0.1.0-draft
extends: base-enterprise
execution_mode: enforce
description: ${newPackDesc || 'Custom policy pack'}

rules:
  - id: ${slugId}-sample-rule
    name: "Sample Guardrail Rule"
    priority: 10
    stages: ["tool_pre_call"]
    condition:
      field: action.name
      operator: eq
      value: "restricted_operation"
    action:
      decision: DENY
      severity: high
      reason: "Blocked by custom rule in ${slugId}"`;
    }

    const newSummary: PolicyPackSummary = {
      pack_id: slugId,
      name: newPackName || slugId,
      version: '0.1.0-draft',
      status: 'draft',
      description: newPackDesc || 'Custom draft policy pack',
    };

    setLocalPacks((prev) => [newSummary, ...prev]);
    setEditableYamls((prev) => ({ ...prev, [slugId]: starterYaml }));
    setSelectedPackId(slugId);
    setActiveTab('editor');
    setCreateModalOpen(false);
    setNewPackId('');
    setNewPackName('');
    setNewPackDesc('');
    setSavedNotice('Draft created! Edit and click Save & Publish.');
    setTimeout(() => setSavedNotice(null), 4000);
  };

  // Simple validation check
  const isYamlValid =
    currentYaml.includes('id:') &&
    currentYaml.includes('name:') &&
    currentYaml.includes('rules:');

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
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1 flex justify-between items-center">
            <span>Registered Packs</span>
            <span className="font-mono text-brand-400">{localPacks.length}</span>
          </div>
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {localPacks.map((pack) => (
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
                  <span
                    className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded border ${
                      pack.status === 'active'
                        ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20'
                        : pack.status === 'shadow'
                        ? 'bg-amber-500/15 text-amber-400 border-amber-500/20'
                        : 'bg-indigo-500/15 text-indigo-400 border-indigo-500/20'
                    }`}
                  >
                    {pack.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono truncate">
                  v{pack.version} · {pack.pack_id}
                </div>
              </button>
            ))}
          </div>

          <div className="pt-3 border-t border-slate-800">
            <button
              onClick={() => setCreateModalOpen(true)}
              className="w-full py-2 px-3 text-xs text-brand-400 hover:text-brand-300 bg-brand-500/10 hover:bg-brand-500/15 border border-brand-500/20 rounded-lg text-center font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>+ New Draft Policy Pack</span>
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

            <div className="flex items-center gap-3 text-xs">
              {isYamlValid ? (
                <span className="text-emerald-400 flex items-center gap-1 font-mono">
                  <Check className="w-3.5 h-3.5" /> Schema Validated
                </span>
              ) : (
                <span className="text-amber-400 flex items-center gap-1 font-mono">
                  <AlertCircle className="w-3.5 h-3.5" /> Checking Syntax
                </span>
              )}
              <button
                onClick={() => handleRollback('0.9.8')}
                className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1 px-2 py-1 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition"
              >
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
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">v1.0.0</span>
                      <span className="px-1.5 py-0.5 text-[9px] bg-emerald-500/20 text-emerald-300 font-mono rounded">
                        Active
                      </span>
                    </div>
                    <p className="text-slate-400 mt-1">Added dual-approval 4-eyes enforcement and Domain Controller block.</p>
                  </div>
                  <span className="text-slate-500">2026-11-20 00:00 UTC</span>
                </div>
                <div className="p-3 bg-slate-900 border border-slate-800 rounded flex justify-between items-center">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-300">v0.9.8</span>
                      <span className="px-1.5 py-0.5 text-[9px] bg-slate-700 text-slate-300 font-mono rounded">
                        Archived
                      </span>
                    </div>
                    <p className="text-slate-400 mt-1">Baseline rules for SOC investigation tools.</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-slate-500">2026-11-19 18:30 UTC</span>
                    <button
                      onClick={() => handleRollback('0.9.8')}
                      className="px-2.5 py-1 text-[11px] bg-brand-500/10 hover:bg-brand-500/20 text-brand-400 border border-brand-500/30 rounded font-medium transition flex items-center gap-1"
                    >
                      <RotateCcw className="w-3 h-3" /> Restore
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Create Draft Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-md rounded-xl p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <PlusCircle className="w-5 h-5 text-brand-400" /> Create Draft Policy Pack
              </h3>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateDraftPack} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Pack ID (Slug)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. data-governance-pack"
                  value={newPackId}
                  onChange={(e) => setNewPackId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-brand-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Display Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Enterprise Data Governance Pack"
                  value={newPackName}
                  onChange={(e) => setNewPackName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Starter Template</label>
                <select
                  value={newPackTemplate}
                  onChange={(e) => setNewPackTemplate(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                >
                  <option value="blank">Blank Custom Pack (extends base-enterprise)</option>
                  <option value="agent-fleet">Multi-Agent Fleet Guardrails (budgets + loop breaker)</option>
                  <option value="soc-investigation">Autonomous SOC Security (containment guards)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Policy scope, target agents, and compliance objectives..."
                  value={newPackDesc}
                  onChange={(e) => setNewPackDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:border-brand-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white rounded-lg font-semibold shadow transition"
                >
                  Create Draft
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
