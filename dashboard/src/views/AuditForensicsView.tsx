import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Download,
  Play,
  RotateCcw,
  CheckCircle,
  AlertTriangle,
  FileCode,
  Layers,
  Search,
} from 'lucide-react';
import {
  AuditRecordItem,
  HashVerificationResponse,
  PolicyPackSummary,
  ReplayReport,
} from '../types';
import {
  fetchAuditLogs,
  verifyAuditChain,
  runSimulationReplay,
  fetchPolicyPacks,
} from '../api';

interface AuditForensicsViewProps {
  tenantId: string;
}

export const AuditForensicsView: React.FC<AuditForensicsViewProps> = ({ tenantId }) => {
  const [logs, setLogs] = useState<AuditRecordItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRecord, setSelectedRecord] = useState<AuditRecordItem | null>(null);

  // Verification State
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<HashVerificationResponse | null>(null);

  // Replay State
  const [policyPacks, setPolicyPacks] = useState<PolicyPackSummary[]>([]);
  const [selectedCandidatePack, setSelectedCandidatePack] = useState<string>('');
  const [replaying, setReplaying] = useState<boolean>(false);
  const [replayReport, setReplayReport] = useState<ReplayReport | null>(null);
  const [replayModalOpen, setReplayModalOpen] = useState<boolean>(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [logData, packs] = await Promise.all([
        fetchAuditLogs(tenantId, 100),
        fetchPolicyPacks(tenantId),
      ]);
      setLogs(logData);
      setPolicyPacks(packs);
      if (packs.length > 0 && !selectedCandidatePack) {
        setSelectedCandidatePack(packs[0].pack_id);
      }
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [tenantId]);

  const handleVerifyChain = async () => {
    try {
      setVerifying(true);
      const res = await verifyAuditChain(tenantId);
      setVerificationResult(res);
    } catch (err: unknown) {
      setVerificationResult({
        is_valid: false,
        total_records: 0,
        tampered_records: [],
        message: err instanceof Error ? err.message : 'Verification request failed',
      });
    } finally {
      setVerifying(false);
    }
  };

  const handleRunReplay = async () => {
    if (!selectedCandidatePack) return;
    try {
      setReplaying(true);
      const res = await runSimulationReplay(tenantId, selectedCandidatePack);
      setReplayReport(res);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Replay simulation failed');
    } finally {
      setReplaying(false);
    }
  };

  const handleExport = (format: 'jsonl' | 'csv') => {
    const url = `/v1/audit/export?tenant_id=${encodeURIComponent(tenantId)}&format=${format}`;
    window.open(url, '_blank');
  };

  const handleComplianceReport = (framework: string, format: 'json' | 'markdown' = 'markdown') => {
    const url = `/v1/audit/compliance-report?tenant_id=${encodeURIComponent(tenantId)}&framework=${framework}&format=${format}`;
    window.open(url, '_blank');
  };

  const filteredLogs = logs.filter((log) => {
    if (decisionFilter !== 'ALL' && log.decision !== decisionFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTrace = log.trace_id?.toLowerCase().includes(q);
      const matchAction = JSON.stringify(log.action || {}).toLowerCase().includes(q);
      const matchActor = JSON.stringify(log.actor || {}).toLowerCase().includes(q);
      const matchTags = (log.compliance_tags || []).some((t) => t.toLowerCase().includes(q));
      if (!matchTrace && !matchAction && !matchActor && !matchTags) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Action Bar: Integrity, Export, Replay */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Verification Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                Cryptographic Integrity
              </span>
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Hash-Chained Ledger</h3>
            <p className="text-xs text-slate-400 mb-4">
              Topological verification: <code className="text-emerald-300 font-mono text-[11px]">SHA256(prev_hash || payload)</code>
            </p>
          </div>
          <div>
            <button
              onClick={handleVerifyChain}
              disabled={verifying}
              className="w-full py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-600/50 text-emerald-300 rounded-lg text-xs font-bold transition flex items-center justify-center space-x-2"
            >
              {verifying ? (
                <span>Verifying Merkle-Chain...</span>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Verify Ledger Continuity</span>
                </>
              )}
            </button>
            {verificationResult && (
              <div
                className={`mt-2 p-2 rounded text-xs flex items-center space-x-2 ${
                  verificationResult.is_valid
                    ? 'bg-emerald-950/70 border border-emerald-500/40 text-emerald-300'
                    : 'bg-red-950/70 border border-red-500/40 text-red-300'
                }`}
              >
                {verificationResult.is_valid ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Intact ({verificationResult.total_records} records verified)</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>Tamper Detected ({verificationResult.tampered_records.length} corrupted)</span>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Regulatory Export Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
                Compliance & Legal
              </span>
              <Download className="w-5 h-5 text-blue-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Audit Ledger Export</h3>
            <p className="text-xs text-slate-400 mb-4">
              Cryptographically signed exports mapped to OWASP LLM Top 10, SOC 2, and EU AI Act.
            </p>
          </div>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleExport('jsonl')}
                className="flex-1 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition flex items-center justify-center space-x-1.5"
              >
                <FileCode className="w-3.5 h-3.5 text-blue-400" />
                <span>Export JSONL</span>
              </button>
              <button
                onClick={() => handleExport('csv')}
                className="flex-1 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition flex items-center justify-center space-x-1.5"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Export CSV</span>
              </button>
            </div>
            <div className="flex items-center space-x-1 pt-1 border-t border-slate-800">
              <span className="text-[10px] text-slate-400 font-medium shrink-0">Report:</span>
              <button
                onClick={() => handleComplianceReport('eu-ai-act')}
                className="px-1.5 py-1 text-[10px] bg-blue-950/60 hover:bg-blue-900/60 border border-blue-500/30 text-blue-300 rounded font-mono"
              >
                EU AI Act
              </button>
              <button
                onClick={() => handleComplianceReport('hipaa')}
                className="px-1.5 py-1 text-[10px] bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-500/30 text-emerald-300 rounded font-mono"
              >
                HIPAA
              </button>
              <button
                onClick={() => handleComplianceReport('pci-dss')}
                className="px-1.5 py-1 text-[10px] bg-purple-950/60 hover:bg-purple-900/60 border border-purple-500/30 text-purple-300 rounded font-mono"
              >
                PCI-DSS
              </button>
              <button
                onClick={() => handleComplianceReport('nist-ai-rmf')}
                className="px-1.5 py-1 text-[10px] bg-amber-950/60 hover:bg-amber-900/60 border border-amber-500/30 text-amber-300 rounded font-mono"
              >
                NIST RMF
              </button>
            </div>
          </div>
        </div>

        {/* Simulation Replay Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">
                Simulation & Shadow
              </span>
              <Layers className="w-5 h-5 text-purple-400" />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Replay Simulation Lab</h3>
            <p className="text-xs text-slate-400 mb-4">
              Replay historical audit events against candidate policy packs to compute concordance.
            </p>
          </div>
          <button
            onClick={() => setReplayModalOpen(true)}
            className="w-full py-2 bg-purple-950 hover:bg-purple-900 border border-purple-600/50 text-purple-300 rounded-lg text-xs font-bold transition flex items-center justify-center space-x-2"
          >
            <Play className="w-4 h-4" />
            <span>Open Replay Simulator</span>
          </button>
        </div>
      </div>

      {/* Audit Log Table Header Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-2 flex-1">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search trace ID, action, actor, or compliance tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            {['ALL', 'ALLOW', 'DENY', 'MODIFY', 'REQUIRE_APPROVAL'].map((dec) => (
              <button
                key={dec}
                onClick={() => setDecisionFilter(dec)}
                className={`px-2.5 py-1 text-[11px] font-semibold rounded ${
                  decisionFilter === dec
                    ? 'bg-slate-800 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={loadData}
          className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Audit Records Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-500 text-sm">Loading forensic records...</div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-sm">No matching audit records found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Timestamp / Trace</th>
                  <th className="px-4 py-3">Decision</th>
                  <th className="px-4 py-3">Stage</th>
                  <th className="px-4 py-3">Action Details</th>
                  <th className="px-4 py-3">Latency</th>
                  <th className="px-4 py-3">Hash Linkage</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {filteredLogs.map((log) => {
                  const decisionColor =
                    log.decision === 'ALLOW'
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : log.decision === 'DENY'
                      ? 'bg-red-950 text-red-400 border-red-800'
                      : log.decision === 'MODIFY'
                      ? 'bg-amber-950 text-amber-400 border-amber-800'
                      : 'bg-purple-950 text-purple-400 border-purple-800';

                  const actionName = (log.action as any)?.name || (log.action as any)?.tool_name || log.stage;

                  return (
                    <tr key={log.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3">
                        <div className="font-mono text-white text-[11px]">{log.trace_id}</div>
                        <div className="text-[10px] text-slate-500">{log.created_at}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${decisionColor}`}>
                          {log.decision}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">{log.stage}</td>
                      <td className="px-4 py-3">
                        <div className="font-mono text-white text-[11px]">{actionName}</div>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {(log.compliance_tags || []).slice(0, 3).map((tag, tIdx) => (
                            <span
                              key={tIdx}
                              className="text-[9px] bg-slate-950 text-cyan-400 px-1.5 py-0.2 rounded border border-cyan-800/40"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">{log.latency_ms?.toFixed(2)} ms</td>
                      <td className="px-4 py-3">
                        <div className="text-[10px] font-mono text-slate-500 truncate max-w-[140px]" title={log.record_hash}>
                          hash: {log.record_hash?.slice(0, 10)}...
                        </div>
                        <div className="text-[9px] font-mono text-slate-600 truncate max-w-[140px]" title={log.prev_hash}>
                          prev: {log.prev_hash?.slice(0, 10)}...
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedRecord(log)}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] rounded transition"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Audit Forensics Record</h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="text-slate-400 hover:text-white text-xs font-bold px-2 py-1 bg-slate-800 rounded"
              >
                Close
              </button>
            </div>

            <div className="overflow-y-auto space-y-3 pr-2 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800">
                <div>
                  <span className="text-slate-500 text-[10px]">Trace ID:</span>
                  <p className="font-mono text-white text-[11px]">{selectedRecord.trace_id}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Decision:</span>
                  <p className="font-bold text-emerald-400">{selectedRecord.decision}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Record Hash:</span>
                  <p className="font-mono text-cyan-300 text-[10px] break-all">{selectedRecord.record_hash}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Prev Record Hash:</span>
                  <p className="font-mono text-slate-400 text-[10px] break-all">{selectedRecord.prev_hash}</p>
                </div>
              </div>

              <div>
                <h4 className="text-[11px] font-semibold text-slate-300 mb-1">Actor & Subject</h4>
                <pre className="p-3 bg-slate-950 rounded-lg text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                  {JSON.stringify(selectedRecord.actor, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="text-[11px] font-semibold text-slate-300 mb-1">Action & Parameters</h4>
                <pre className="p-3 bg-slate-950 rounded-lg text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                  {JSON.stringify(selectedRecord.action, null, 2)}
                </pre>
              </div>

              {selectedRecord.resolved_context && (
                <div>
                  <h4 className="text-[11px] font-semibold text-slate-300 mb-1">Resolved Context</h4>
                  <pre className="p-3 bg-slate-950 rounded-lg text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                    {JSON.stringify(selectedRecord.resolved_context, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Replay Simulation Lab Modal */}
      {replayModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-purple-500/40 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center space-x-3 text-purple-400">
              <Layers className="w-6 h-6" />
              <div>
                <h3 className="text-lg font-bold text-white">Replay Simulation Lab</h3>
                <p className="text-xs text-slate-400">
                  Execute historical audit events against candidate policy pack to quantify impact
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Candidate Policy Pack
                </label>
                <select
                  value={selectedCandidatePack}
                  onChange={(e) => setSelectedCandidatePack(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-purple-500"
                >
                  {policyPacks.map((pack) => (
                    <option key={pack.pack_id} value={pack.pack_id}>
                      {pack.name} ({pack.pack_id} v{pack.version})
                    </option>
                  ))}
                </select>
              </div>

              <button
                onClick={handleRunReplay}
                disabled={replaying}
                className="w-full py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-lg shadow-lg transition flex items-center justify-center space-x-2"
              >
                {replaying ? (
                  <span>Executing Historical Replay...</span>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Run Simulation Replay</span>
                  </>
                )}
              </button>

              {replayReport && (
                <div className="mt-4 p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">Concordance Rate:</span>
                    <span className="text-sm font-bold text-emerald-400 font-mono">
                      {(replayReport.concordance_rate * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">Total Replayed Events</span>
                      <p className="font-mono text-white text-sm font-bold">{replayReport.total_events}</p>
                    </div>
                    <div className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">Concordant Decisions</span>
                      <p className="font-mono text-emerald-400 text-sm font-bold">{replayReport.concordant_count}</p>
                    </div>
                    <div className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">Newly Blocked Actions</span>
                      <p className="font-mono text-red-400 text-sm font-bold">{replayReport.new_blocks_count}</p>
                    </div>
                    <div className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">Newly Allowed Actions</span>
                      <p className="font-mono text-cyan-400 text-sm font-bold">{replayReport.new_allows_count}</p>
                    </div>
                  </div>

                  <div className="text-[11px] text-slate-400 text-center font-mono">
                    Avg Replay Latency: {replayReport.avg_replayed_latency_ms?.toFixed(2)} ms
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setReplayModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg"
              >
                Close Simulator
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
