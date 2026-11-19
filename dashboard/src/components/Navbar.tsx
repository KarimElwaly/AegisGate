import React from 'react';
import { ShieldAlert, Server, UserCheck, Activity } from 'lucide-react';

interface NavbarProps {
  tenantId: string;
  setTenantId: (tenant: string) => void;
  operatorRole: string;
}

export const Navbar: React.FC<NavbarProps> = ({ tenantId, setTenantId, operatorRole }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3">
        <div className="bg-brand-500/20 p-2 rounded-lg border border-brand-500/30">
          <ShieldAlert className="w-6 h-6 text-brand-500" />
        </div>
        <div>
          <span className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            AegisGate <span className="text-xs px-2 py-0.5 rounded bg-brand-500/10 text-brand-400 border border-brand-500/20">v0.1.0</span>
          </span>
          <p className="text-xs text-slate-400">Sub-15ms AI Guardrails & Governance PDP</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Real-time PDP status */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <Activity className="w-3.5 h-3.5" />
          PDP Engine Online (7.86ms P95)
        </div>

        {/* Tenant Switcher */}
        <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
          <Server className="w-3.5 h-3.5 text-slate-400" />
          <span>Tenant:</span>
          <select
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
          >
            <option value="default" className="bg-slate-900">default</option>
            <option value="tenant-fleet" className="bg-slate-900">tenant-fleet (Multi-Agent)</option>
            <option value="tenant-soc" className="bg-slate-900">tenant-soc (SOC & CMDB)</option>
            <option value="tenant-logs" className="bg-slate-900">tenant-logs (Log Security)</option>
          </select>
        </div>

        {/* Operator Role Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs font-semibold">
          <UserCheck className="w-4 h-4 text-indigo-400" />
          <span>{operatorRole}</span>
        </div>
      </div>
    </header>
  );
};

