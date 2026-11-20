import React, { useState, useEffect } from 'react';
import {
  UserCheck2,
  Check,
  X,
  AlertCircle,
  Clock,
  ShieldCheck,
  Edit3,
  RotateCcw,
} from 'lucide-react';
import { ApprovalTicket } from '../types';
import { decideApproval } from '../api';

interface HitlRoomViewProps {
  tickets: ApprovalTicket[];
  tenantId: string;
  operatorRole: string;
  onRefresh: () => void;
}

export const HitlRoomView: React.FC<HitlRoomViewProps> = ({
  tickets,
  tenantId,
  operatorRole,
  onRefresh,
}) => {
  const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
  const [modifiedParamsText, setModifiedParamsText] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedTicketId || !tickets.some((t) => t.ticket_id === selectedTicketId)) {
      const firstPending = tickets.find((t) => t.status === 'pending');
      const target = firstPending || tickets[0];
      if (target) {
        setSelectedTicketId(target.ticket_id);
        setModifiedParamsText(JSON.stringify(target.modified_parameters || target.original_parameters, null, 2));
        setNotes(target.decision_notes || '');
      }
    }
  }, [tickets, selectedTicketId]);

  const selectedTicket = tickets.find((t) => t.ticket_id === selectedTicketId) || tickets[0];

  const handleSelectTicket = (t: ApprovalTicket) => {
    setSelectedTicketId(t.ticket_id);
    setModifiedParamsText(JSON.stringify(t.modified_parameters || t.original_parameters, null, 2));
    setNotes(t.decision_notes || '');
  };

  const handleDecision = async (decision: 'approve' | 'reject') => {
    if (!selectedTicket) return;
    try {
      let overrideObj: Record<string, unknown> | undefined;
      if (modifiedParamsText.trim()) {
        overrideObj = JSON.parse(modifiedParamsText);
      }
      await decideApproval(
        selectedTicket.ticket_id,
        'operator_admin',
        operatorRole,
        decision,
        overrideObj,
        notes
      );
      setActionMessage(`Ticket successfully ${decision}d.`);
      setTimeout(() => {
        setActionMessage(null);
        onRefresh();
      }, 1500);
    } catch (err) {
      alert(String(err));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <UserCheck2 className="w-6 h-6 text-brand-400" /> HITL Decision Room
          </h1>
          <p className="text-sm text-slate-400">
            Actionable inbox with parameter overrides and single/dual-approval (4-eyes) for{' '}
            <span className="text-brand-400 font-medium">{tenantId}</span>. Active role:{' '}
            <span className="text-indigo-400 font-medium">{operatorRole}</span>.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          {actionMessage && (
            <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold flex items-center gap-1.5">
              <Check className="w-4 h-4" /> {actionMessage}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Ticket List */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1 flex justify-between">
            <span>Review Queue</span>
            <span className="font-mono text-brand-400">
              {tickets.filter((t) => t.status === 'pending').length} pending / {tickets.length} total
            </span>
          </div>

          {tickets.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs">
              <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              HITL Queue is empty. No actions currently suspended.
            </div>
          ) : (
            <div className="space-y-2.5">
              {tickets.map((t) => {
                const isSelected = selectedTicket?.ticket_id === t.ticket_id;
                return (
                  <button
                    key={t.ticket_id}
                    data-ticket-id={t.ticket_id}
                    onClick={() => handleSelectTicket(t)}
                    className={`w-full text-left p-3.5 rounded-lg border transition-all ${
                      isSelected
                        ? 'bg-slate-800 border-brand-500/60 shadow-md'
                        : 'bg-slate-950/40 border-slate-800 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-xs font-bold text-white">
                        {t.action_name}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono uppercase ${
                            t.status === 'approved'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : t.status === 'rejected'
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {t.status}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
                          {t.required_approvals > 1 ? '4-EYES' : 'SINGLE'}
                        </span>
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 mb-1">
                      ID: {t.ticket_id.slice(0, 8)}...
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Risk: {(t.risk_score * 100).toFixed(0)}%</span>
                      <span className="flex items-center gap-1 text-slate-500">
                        <Clock className="w-3 h-3" />
                        {new Date(t.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Ticket Review & Parameter Override */}
        {selectedTicket ? (
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              {/* Ticket Meta Header */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between pb-4 border-b border-slate-800 gap-2">
                <div>
                  <h3 className="text-lg font-bold text-white font-mono flex items-center gap-2">
                    Action: {selectedTicket.action_name}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Ticket ID: {selectedTicket.ticket_id} · Trace: {selectedTicket.trace_id}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold uppercase ${
                      selectedTicket.status === 'approved'
                        ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400'
                        : selectedTicket.status === 'rejected'
                        ? 'bg-rose-500/15 border border-rose-500/30 text-rose-400'
                        : 'bg-amber-500/15 border border-amber-500/30 text-amber-400'
                    }`}
                  >
                    Status: {selectedTicket.status}
                  </span>
                  <span className="px-2.5 py-1 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-xs font-semibold">
                    Approved: {selectedTicket.approved_by.length} / {selectedTicket.required_approvals}
                  </span>
                </div>
              </div>

              {/* Triggered Rules & Risk Reason */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Suspension Reason & Rules
                </h4>
                <div className="space-y-2">
                  {selectedTicket.triggered_rules.map((r, i) => (
                    <div
                      key={i}
                      className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg text-xs text-amber-300 flex items-start gap-2"
                    >
                      <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="font-semibold">{r.rule_id}:</span> {r.reason}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Editable Parameters (Approve with Parameter Override) */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Edit3 className="w-3.5 h-3.5 text-brand-400" />
                    Action Parameters (Sanitize / Override)
                  </h4>
                  <span className="text-[11px] text-slate-500">
                    {selectedTicket.status === 'pending'
                      ? 'Edit values directly before approving'
                      : 'Parameters locked (ticket already decided)'}
                  </span>
                </div>
                <textarea
                  value={modifiedParamsText || JSON.stringify(selectedTicket.original_parameters, null, 2)}
                  onChange={(e) => setModifiedParamsText(e.target.value)}
                  disabled={selectedTicket.status !== 'pending'}
                  className={`w-full h-32 bg-slate-950 p-3 rounded-lg font-mono text-xs border focus:outline-none ${
                    selectedTicket.status !== 'pending'
                      ? 'text-slate-500 border-slate-800/60 cursor-not-allowed'
                      : 'text-brand-300 border-slate-800 focus:border-brand-500'
                  }`}
                />
              </div>

              {/* Approver Justification Notes */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  Decision Notes / Justification
                </h4>
                <input
                  type="text"
                  placeholder="e.g. Approved with reduced isolation window to 4 hours."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  disabled={selectedTicket.status !== 'pending'}
                  className={`w-full bg-slate-950 px-3 py-2 rounded-lg text-xs border focus:outline-none ${
                    selectedTicket.status !== 'pending'
                      ? 'text-slate-500 border-slate-800/60 cursor-not-allowed'
                      : 'text-white border-slate-800 focus:border-brand-500'
                  }`}
                />
              </div>
            </div>

            {/* Decision Action Buttons */}
            {selectedTicket.status === 'pending' ? (
              <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
                <button
                  onClick={() => handleDecision('reject')}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 border border-rose-500/30 text-xs font-bold transition-colors"
                >
                  <X className="w-4 h-4" /> Reject Action
                </button>
                <button
                  onClick={() => handleDecision('approve')}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white text-xs font-bold shadow-lg transition-colors"
                >
                  <Check className="w-4 h-4" />
                  {selectedTicket.required_approvals > 1
                    ? `Authorize (${selectedTicket.approved_by.length + 1}/${selectedTicket.required_approvals} Approvals)`
                    : 'Authorize & Resume Tool'}
                </button>
              </div>
            ) : selectedTicket.status === 'approved' ? (
              <div className="pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 p-3 rounded-lg">
                <span className="flex items-center gap-2 font-medium">
                  <Check className="w-4 h-4" /> Action Approved & Authorized. Execution resumed for tool caller.
                </span>
                <span className="text-slate-400 font-mono text-[11px]">
                  Approver(s): {selectedTicket.approved_by.join(', ') || 'operator_admin'}
                </span>
              </div>
            ) : (
              <div className="pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg">
                <span className="flex items-center gap-2 font-medium">
                  <X className="w-4 h-4" /> Action Rejected. Execution blocked permanently for this ticket.
                </span>
              </div>
            )}
          </div>
        ) : (
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-8 flex items-center justify-center text-slate-500 text-xs">
            Select a ticket from the left queue to review and authorize.
          </div>
        )}
      </div>
    </div>
  );
};
