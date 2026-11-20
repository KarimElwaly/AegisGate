import { chromium } from 'playwright';
import path from 'path';
import fs from 'fs';

const ARTIFACTS_DIR = 'C:/Users/Karim ElWaly/.gemini/antigravity/brain/ba8027a3-2882-4da4-bbe0-30dc425f911f';

async function main() {
  console.log('--- Starting Playwright UI Verification Audit ---');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  const consoleErrors = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  page.on('pageerror', (err) => {
    consoleErrors.push(err.message);
  });

  // 1. Overview
  console.log('[1/6] Inspecting Overview View...');
  await page.goto('http://localhost:3088/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '01_overview.png') });
  console.log('   [+] Captured 01_overview.png');

  // 2. Policy Studio
  console.log('[2/6] Inspecting Policy Studio View...');
  await page.click('button:has-text("Policy Pack Studio")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '02_policy_studio.png') });
  console.log('   [+] Captured 02_policy_studio.png');

  // Test Diff view toggle
  const diffBtn = await page.$('button:has-text("Diff")');
  if (diffBtn) {
    await diffBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, '02_policy_studio_diff.png') });
    console.log('   [+] Captured 02_policy_studio_diff.png');
  }

  // 3. Plugin Registry
  console.log('[3/6] Inspecting Plugin Registry View...');
  await page.click('button:has-text("Plugin & Scanner Registry")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '03_plugin_registry.png') });
  console.log('   [+] Captured 03_plugin_registry.png');

  // Test Configure button modal
  const configBtns = await page.$$('button:has-text("Configure")');
  if (configBtns.length > 0) {
    await configBtns[0].click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, '03_plugin_configure_modal.png') });
    console.log('   [+] Captured 03_plugin_configure_modal.png');
    // Close modal
    const closeBtn = await page.$('button:has-text("Cancel")') || await page.$('button:has-text("Close")');
    if (closeBtn) await closeBtn.click();
  }

  // 4. HITL Approval Room
  console.log('[4/6] Inspecting HITL Approvals View...');
  await page.click('button:has-text("HITL Decision Room")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '04_hitl_approvals.png') });
  console.log('   [+] Captured 04_hitl_approvals.png');

  // 5. Emergency Kill Switch
  console.log('[5/6] Inspecting Kill Switch View...');
  await page.click('button:has-text("Kill Switch & Breakers")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '05_kill_switch.png') });
  console.log('   [+] Captured 05_kill_switch.png');

  // 6. Audit Forensics
  console.log('[6/6] Inspecting Audit Forensics View...');
  await page.click('button:has-text("Forensic Audit & Simulator")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, '06_audit_forensics.png') });
  console.log('   [+] Captured 06_audit_forensics.png');

  // Test Verify Ledger Continuity
  const verifyBtn = await page.$('button:has-text("Verify Ledger Continuity")');
  if (verifyBtn) {
    await verifyBtn.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, '06_audit_verified.png') });
    console.log('   [+] Captured 06_audit_verified.png');
  }

  // Test Inspect Record Modal
  const inspectBtns = await page.$$('button:has-text("Inspect")');
  if (inspectBtns.length > 0) {
    await inspectBtns[0].click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, '06_audit_record_inspect_modal.png') });
    console.log('   [+] Captured 06_audit_record_inspect_modal.png');
    const closeBtn = await page.$('button:has-text("Close")');
    if (closeBtn) await closeBtn.click();
  }

  // Test Policy Replay Simulation modal
  const replayBtn = await page.$('button:has-text("Open Replay Simulator")');
  if (replayBtn) {
    await replayBtn.click();
    await page.waitForTimeout(500);
    // Click Run Simulation Replay
    const runReplayBtn = await page.$('button:has-text("Run Simulation Replay")');
    if (runReplayBtn) {
      await runReplayBtn.click();
      await page.waitForTimeout(1500);
    }
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, '06_replay_simulation_modal.png') });
    console.log('   [+] Captured 06_replay_simulation_modal.png');
    const cancelBtn = await page.$('button:has-text("Close Simulator")');
    if (cancelBtn) await cancelBtn.click();
  }

  await browser.close();

  console.log('\n--- UI AUDIT RESULTS ---');
  if (consoleErrors.length === 0) {
    console.log('[+] Zero Console Errors Detected!');
  } else {
    console.log(`[!] ${consoleErrors.length} Console Errors Detected:`);
    consoleErrors.forEach((err, idx) => console.log(`   ${idx + 1}. ${err}`));
  }
}

main().catch((err) => {
  console.error('Fatal audit error:', err);
  process.exit(1);
});
