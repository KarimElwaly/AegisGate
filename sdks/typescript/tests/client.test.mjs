import { test, describe } from 'node:test';
import assert from 'node:assert';

// Import from built dist or test client logic
describe('AegisClient TypeScript SDK v2 Parity Tests', () => {
  test('header generation includes Virtual API Key header', async () => {
    // Dynamic import to test client class
    const { AegisClient } = await import('../dist/client.js');
    const client = new AegisClient({
      virtualApiKey: 'ag_live_test_virtual_key_123',
      tenantId: 'tenant-acme',
      workspaceId: 'ws-finance',
      policyPackId: 'pci-dss-pack',
    });

    const headers = client.getHeaders();
    assert.strictEqual(headers['X-Aegis-Tenant-Id'], 'tenant-acme');
    assert.strictEqual(headers['X-Aegis-Workspace-Id'], 'ws-finance');
    assert.strictEqual(headers['X-Aegis-Policy-Pack'], 'pci-dss-pack');
    assert.strictEqual(headers['X-Aegis-Api-Key'], 'ag_live_test_virtual_key_123');
    assert.strictEqual(headers['Authorization'], 'Bearer ag_live_test_virtual_key_123');
  });

  test('wrapTool enforces pre-call and post-call policy evaluation', async () => {
    const { AegisClient } = await import('../dist/client.js');
    const client = new AegisClient({
      virtualApiKey: 'ag_live_test_virtual_key_123',
    });

    let preCallEvaluated = false;
    let postCallEvaluated = false;

    // Mock evaluate method
    client.evaluate = async (req) => {
      if (req.stage === 'tool_pre_call') {
        preCallEvaluated = true;
        assert.strictEqual(req.action?.name, 'calc_total');
        return {
          verdict_id: 'v-1',
          decision: 'ALLOW',
          effective_mode: 'enforce',
          would_have_decided: 'ALLOW',
          risk_score: 0.1,
          triggered_rules: [],
          scanner_findings: [],
          resolved_context: {},
          latency_ms: 1,
        };
      }
      if (req.stage === 'tool_post_call') {
        postCallEvaluated = true;
        return {
          verdict_id: 'v-2',
          decision: 'ALLOW',
          effective_mode: 'enforce',
          would_have_decided: 'ALLOW',
          risk_score: 0.1,
          triggered_rules: [],
          scanner_findings: [],
          resolved_context: {},
          latency_ms: 1,
        };
      }
      throw new Error(`Unexpected stage: ${req.stage}`);
    };

    const myTool = async (params) => {
      return { total: params.a + params.b };
    };

    const governedTool = client.wrapTool('calc_total', myTool);
    const result = await governedTool({ a: 10, b: 20 });

    assert.strictEqual(result.total, 30);
    assert.strictEqual(preCallEvaluated, true);
    assert.strictEqual(postCallEvaluated, true);
  });

  test('wrapTool rejects execution when pre-call policy denies', async () => {
    const { AegisClient } = await import('../dist/client.js');
    const client = new AegisClient();

    client.evaluate = async () => {
      return {
        verdict_id: 'v-deny',
        decision: 'DENY',
        effective_mode: 'enforce',
        would_have_decided: 'DENY',
        risk_score: 0.95,
        triggered_rules: [
          {
            rule_id: 'block_shell',
            policy_pack: 'base-enterprise',
            policy_version: '1.0.0',
            severity: 'CRITICAL',
            reason: 'Shell execution blocked',
            compliance_tags: ['TOOL-SAFETY'],
          },
        ],
        scanner_findings: [],
        resolved_context: {},
        latency_ms: 1,
      };
    };

    const shellTool = async () => 'executed';
    const governed = client.wrapTool('bash_run', shellTool);

    await assert.rejects(async () => {
      await governed({});
    }, /AegisGate Policy Denied/);
  });
});

