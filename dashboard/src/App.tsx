import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { PolicyStudioView } from './views/PolicyStudioView';
import { PluginRegistryView } from './views/PluginRegistryView';
import { HitlRoomView } from './views/HitlRoomView';
import { KillSwitchView } from './views/KillSwitchView';
import { AuditForensicsView } from './views/AuditForensicsView';
import {
  fetchKPIs,
  fetchPolicyPacks,
  fetchPluginCatalog,
  fetchApprovals,
} from './api';
import {
  ApprovalTicket,
  PluginItem,
  PolicyPackSummary,
  TelemetryKPIs,
} from './types';

export const App: React.FC = () => {
  const [tenantId, setTenantId] = useState<string>('default');
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [operatorRole] = useState<string>('SuperAdmin');

  const [kpis, setKpis] = useState<TelemetryKPIs>({
    totalRequests: 24800,
    blockRate: 0.024,
    modifyRate: 0.062,
    p95LatencyMs: 7.86,
    activeHitlQueue: 3,
    shadowDeltasCount: 4,
  });
  const [packs, setPacks] = useState<PolicyPackSummary[]>([]);
  const [plugins, setPlugins] = useState<Record<string, PluginItem[]>>({
    scanners: [],
    resolvers: [],
    notifiers: [],
  });
  const [tickets, setTickets] = useState<ApprovalTicket[]>([]);

  const loadData = useCallback(async () => {
    try {
      const [kpiData, packData, pluginData, ticketData] = await Promise.all([
        fetchKPIs(tenantId),
        fetchPolicyPacks(tenantId),
        fetchPluginCatalog(),
        fetchApprovals(tenantId),
      ]);
      setKpis(kpiData);
      setPacks(packData);
      setPlugins(pluginData);
      setTickets(ticketData);
    } catch {
      // Keep existing state
    }
  }, [tenantId]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const pendingApprovalsCount = tickets.filter((t) => t.status === 'pending').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar
        tenantId={tenantId}
        setTenantId={setTenantId}
        operatorRole={operatorRole}
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentTab={currentTab}
          setCurrentTab={setCurrentTab}
          pendingApprovalsCount={pendingApprovalsCount}
        />

        <main className="flex-1 overflow-y-auto p-6 bg-slate-950/60">
          <div className="max-w-7xl mx-auto">
            {currentTab === 'overview' && <OverviewView kpis={kpis} tenantId={tenantId} />}
            {currentTab === 'policies' && <PolicyStudioView packs={packs} tenantId={tenantId} onRefresh={loadData} />}
            {currentTab === 'plugins' && <PluginRegistryView plugins={plugins} />}
            {currentTab === 'hitl' && (
              <HitlRoomView
                tickets={tickets}
                tenantId={tenantId}
                operatorRole={operatorRole}
                onRefresh={loadData}
              />
            )}
            {currentTab === 'killswitch' && <KillSwitchView tenantId={tenantId} />}
            {currentTab === 'audit' && <AuditForensicsView tenantId={tenantId} />}
          </div>
        </main>
      </div>
    </div>
  );
};

export default App;
