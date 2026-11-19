import React from 'react';
import {
  LayoutDashboard,
  FileCode,
  Blocks,
  UserCheck2,
  PowerOff,
  History,
  Layers,
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  pendingApprovalsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  setCurrentTab,
  pendingApprovalsCount,
}) => {
  const navItems = [
    { id: 'overview', label: 'Overview & Telemetry', icon: LayoutDashboard },
    { id: 'policies', label: 'Policy Pack Studio', icon: FileCode },
    { id: 'plugins', label: 'Plugin & Scanner Registry', icon: Blocks },
    {
      id: 'hitl',
      label: 'HITL Decision Room',
      icon: UserCheck2,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
    },
    { id: 'killswitch', label: 'Kill Switch & Breakers', icon: PowerOff, danger: true },
    { id: 'audit', label: 'Forensic Audit & Simulator', icon: History },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/40 p-4 flex flex-col justify-between">
      <div className="space-y-1">
        <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
          Governance Control
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-brand-500/15 text-brand-400 border border-brand-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-brand-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="bg-amber-500/20 text-amber-400 text-xs px-2 py-0.5 rounded-full border border-amber-500/30">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-1.5">
        <div className="flex items-center gap-2 text-slate-300 font-medium">
          <Layers className="w-4 h-4 text-brand-400" />
          <span>Multi-Tenant Mesh</span>
        </div>
        <p className="text-[11px] leading-relaxed text-slate-500">
          Encrypted PII vault with HMAC ledger chain & atomic Lua quota enforcement.
        </p>
      </div>
    </aside>
  );
};
