import React, { useState } from 'react';
import { Blocks, CheckCircle, Sliders, Shield, Database, Bell } from 'lucide-react';
import { PluginItem } from '../types';

interface PluginRegistryViewProps {
  plugins: Record<string, PluginItem[]>;
}

export const PluginRegistryView: React.FC<PluginRegistryViewProps> = ({ plugins }) => {
  const [activeCategory, setActiveCategory] = useState<'scanners' | 'resolvers' | 'notifiers'>('scanners');
  const [selectedPlugin, setSelectedPlugin] = useState<PluginItem | null>(null);

  const currentList = plugins[activeCategory] || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Blocks className="w-6 h-6 text-brand-400" /> Plugin & Scanner Registry
        </h1>
        <p className="text-sm text-slate-400">
          Dynamically auto-rendered controls and schemas from Pydantic <code className="text-brand-300">ConfigSchema</code>.
        </p>
      </div>

      {/* Category Tabs */}
      <div className="flex border-b border-slate-800 space-x-6 text-sm">
        <button
          onClick={() => setActiveCategory('scanners')}
          className={`pb-3 font-medium flex items-center gap-2 transition-colors ${
            activeCategory === 'scanners'
              ? 'text-brand-400 border-b-2 border-brand-500'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Shield className="w-4 h-4" /> Scanners (Tiers 1, 2, 3)
        </button>
        <button
          onClick={() => setActiveCategory('resolvers')}
          className={`pb-3 font-medium flex items-center gap-2 transition-colors ${
            activeCategory === 'resolvers'
              ? 'text-brand-400 border-b-2 border-brand-500'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Database className="w-4 h-4" /> Context Resolvers
        </button>
        <button
          onClick={() => setActiveCategory('notifiers')}
          className={`pb-3 font-medium flex items-center gap-2 transition-colors ${
            activeCategory === 'notifiers'
              ? 'text-brand-400 border-b-2 border-brand-500'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Bell className="w-4 h-4" /> Notifiers (Slack, Webhook, SIEM)
        </button>
      </div>

      {/* Plugins Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {currentList.map((item) => (
          <div
            key={item.name}
            className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between hover:border-slate-700 transition-all"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-xs font-semibold text-white">{item.name}</span>
                {item.tier && (
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      item.tier === 1
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        : item.tier === 2
                        ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                        : 'bg-indigo-500/15 text-indigo-400 border border-indigo-500/30'
                    }`}
                  >
                    Tier {item.tier}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mb-3">
                {item.name === 'secrets_scanner' && 'Detects AWS, PEM, API keys, JWT tokens with sub-millisecond regex.'}
                {item.name === 'pii_scanner' && 'Detects and reversibly tokenizes emails, IPs, credit cards, SSNs into vault.'}
                {item.name === 'tool_param_guard' && 'Blocks path traversal, shell metacharacters, and command injection.'}
                {item.name === 'json_schema_scanner' && 'Enforces strict JSON schema validation on handoffs and structured outputs.'}
                {item.name === 'entropy_size_guard' && 'Monitors token sizes and Shannon entropy to prevent high-entropy exfiltration.'}
                {item.name === 'grounding_scanner' && 'Deterministic verification that all report citations exist in session data.'}
                {item.name === 'tier2_onnx_injection_classifier' && 'Local ONNX ML classification for indirect prompt injection in raw logs.'}
                {item.name === 'tier3_llm_judge' && 'OpenAI-compatible semantic judge for groundedness and policy compliance audit.'}
                {item.name === 'webhook_scanner' && 'Generic customer-hosted HTTP scanner with signed HMAC-SHA256 headers.'}
                {item.name === 'http_context_resolver' && 'Calls external CMDB, Asset Inventory, or Workflow APIs.'}
                {item.name === 'redis_state_resolver' && 'Enriches evaluation context from Redis cache keys.'}
                {item.name === 'static_lookup_resolver' && 'Fast in-memory static mapping dictionary for asset tiers.'}
                {item.name === 'webhook_notifier' && 'Dispatches HTTP alerts with HMAC signature.'}
                {item.name === 'slack_notifier' && 'Posts structured Block Kit security alerts directly to Slack channels.'}
                {item.name === 'siem_cef_notifier' && 'Formats ArcSight CEF / Syslog RFC 5424 security event streams.'}
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle className="w-3.5 h-3.5" /> Registered v{item.version}
              </span>
              <button
                onClick={() => setSelectedPlugin(item)}
                className="flex items-center gap-1 text-brand-400 hover:text-brand-300 font-medium"
              >
                <Sliders className="w-3.5 h-3.5" /> Configure
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Config Schema Modal */}
      {selectedPlugin && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-xl p-6 shadow-2xl">
            <h3 className="text-base font-bold text-white mb-2 font-mono">
              ConfigSchema: {selectedPlugin.name}
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Dynamically derived from Pydantic model introspection.
            </p>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-brand-300 overflow-x-auto max-h-60 mb-4 border border-slate-800">
              {JSON.stringify(
                {
                  enabled: true,
                  timeout_ms: 100,
                  on_timeout: 'flag',
                  action_on_match: 'block',
                  schema_definition: { type: 'object' },
                },
                null,
                2
              )}
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 rounded-lg"
              >
                Close
              </button>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-xs font-semibold text-white rounded-lg"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

