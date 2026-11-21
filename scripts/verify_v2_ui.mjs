import { chromium } from 'playwright';
import path from 'path';

async function runV2UITest() {
  console.log('======================================================================');
  console.log('   AEGISGATE V2 UI EXTENDED VERIFICATION SCRIPT');
  console.log('======================================================================\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const consoleErrors = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  page.on('dialog', async (dialog) => {
    console.log(`   [Browser Dialog] ${dialog.message()}`);
    await dialog.accept();
  });

  // 1. Navigate to Dashboard
  console.log('[Test 1] Navigating to http://localhost:3088...');
  await page.goto('http://localhost:3088/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  console.log('   [+] Dashboard loaded successfully.');

  // 2. Policy Pack Studio & Draft Modal
  console.log('\n[Test 2] Testing Policy Studio & "+ New Draft Policy Pack" Modal...');
  await page.click('button:has-text("Policy Pack Studio")');
  await page.waitForTimeout(1000);

  // Click "+ New Draft Policy Pack"
  const newDraftBtn = await page.$('button:has-text("+ New Draft Policy Pack")');
  if (!newDraftBtn) {
    throw new Error('Button "+ New Draft Policy Pack" not found!');
  }
  await newDraftBtn.click();
  await page.waitForTimeout(500);

  // Verify modal is open
  const modalHeader = await page.textContent('h3');
  console.log('   [+] Draft creation modal opened:', modalHeader?.includes('Create Draft Policy Pack'));
  if (!modalHeader?.includes('Create Draft Policy Pack')) {
    throw new Error('Modal failed to open upon clicking "+ New Draft Policy Pack"');
  }

  // Fill in form
  await page.fill('input[placeholder*="data-governance-pack"]', 'eu-compliance-guard');
  await page.fill('input[placeholder*="Enterprise Data Governance Pack"]', 'EU AI Act Compliance Guard');
  await page.locator('form select').selectOption('agent-fleet');
  await page.fill('textarea[placeholder*="Policy scope"]', 'Automated EU compliance rules');

  // Submit
  await page.click('button:has-text("Create Draft")');
  await page.waitForTimeout(1000);

  // Verify new draft in sidebar list
  const sidebarContent = await page.textContent('body');
  const draftCreated = sidebarContent.includes('eu-compliance-guard') && sidebarContent.includes('EU AI Act Compliance Guard');
  console.log('   [+] Draft pack created and selected in studio:', draftCreated);
  if (!draftCreated) {
    throw new Error('Draft pack was not added to registered packs list!');
  }

  // Verify editor contains the generated starter YAML
  const editorYaml = await page.inputValue('textarea');
  const yamlMatches = editorYaml.includes('id: eu-compliance-guard') && editorYaml.includes('max_tokens: 30000');
  console.log('   [+] Starter YAML DSL populated in editor:', yamlMatches);
  if (!yamlMatches) {
    throw new Error('Editor did not display the generated starter YAML!');
  }

  // Take screenshot of Policy Studio
  const studioScreenshot = 'C:/Users/Karim ElWaly/.gemini/antigravity/brain/ba8027a3-2882-4da4-bbe0-30dc425f911f/v2_01_policy_studio_draft.png';
  await page.screenshot({ path: studioScreenshot });
  console.log(`   [+] Screenshot saved to ${studioScreenshot}`);

  // 3. Multi-Tenancy & Virtual Keys View
  console.log('\n[Test 3] Testing Multi-Tenancy & Virtual Keys View...');
  await page.click('button:has-text("Tenants & Virtual Keys")');
  await page.waitForTimeout(1000);

  const tenantsPageText = await page.textContent('body');
  const tenantCardsOk = tenantsPageText.includes('Active Tenant Scope') && tenantsPageText.includes('Virtual Keys Issued');
  console.log('   [+] Tenancy metrics cards rendered:', tenantCardsOk);

  // Click Issue Virtual API Key
  await page.click('button:has-text("Issue Virtual API Key")');
  await page.waitForTimeout(500);

  await page.fill('input[placeholder*="Agent Fleet Production Worker"]', 'Test Virtual Agent Key');
  await page.click('button:has-text("Generate Key")');
  await page.waitForTimeout(500);

  const keyModalText = await page.textContent('body');
  const keyGeneratedOk = keyModalText.includes('ag_live_') && keyModalText.includes('Copy this Virtual API Key');
  console.log('   [+] Virtual API key minted and displayed:', keyGeneratedOk);
  if (!keyGeneratedOk) {
    throw new Error('Virtual API Key was not generated or displayed!');
  }

  await page.click('button:has-text("Done")');
  await page.waitForTimeout(500);

  const keysScreenshot = 'C:/Users/Karim ElWaly/.gemini/antigravity/brain/ba8027a3-2882-4da4-bbe0-30dc425f911f/v2_02_virtual_keys.png';
  await page.screenshot({ path: keysScreenshot });
  console.log(`   [+] Screenshot saved to ${keysScreenshot}`);

  // 4. MCP Security & Shadow AI Discovery View
  console.log('\n[Test 4] Testing MCP Security & Shadow AI Discovery View...');
  await page.click('button:has-text("MCP & Shadow Discovery")');
  await page.waitForTimeout(1000);

  const mcpViewText = await page.textContent('body');
  const mcpPinnedOk = mcpViewText.includes('query_customer_database') && mcpViewText.includes('Anti-Rug-Pull Protection');
  console.log('   [+] Pinned MCP catalog & Anti-Rug-Pull status displayed:', mcpPinnedOk);

  // Switch to Shadow AI Assets tab
  await page.click('button:has-text("Shadow AI Assets")');
  await page.waitForTimeout(500);

  const shadowViewText = await page.textContent('body');
  const shadowAssetsOk = shadowViewText.includes('claude-3-5-sonnet-shadow') && shadowViewText.includes('web_scraper_custom');
  console.log('   [+] Auto-discovered Shadow AI assets displayed:', shadowAssetsOk);
  if (!shadowAssetsOk) {
    throw new Error('Discovered shadow assets not rendered!');
  }

  // Click Approve on the unapproved tool
  const approveButtons = await page.$$('button:has-text("Approve")');
  if (approveButtons.length > 0) {
    await approveButtons[0].click();
    await page.waitForTimeout(500);
    const updatedViewText = await page.textContent('body');
    const assetApproved = updatedViewText.includes('governed');
    console.log('   [+] Shadow asset approved to governed state in UI:', assetApproved);
  }

  const discoveryScreenshot = 'C:/Users/Karim ElWaly/.gemini/antigravity/brain/ba8027a3-2882-4da4-bbe0-30dc425f911f/v2_03_mcp_shadow_discovery.png';
  await page.screenshot({ path: discoveryScreenshot });
  console.log(`   [+] Screenshot saved to ${discoveryScreenshot}`);

  console.log('\n======================================================================');
  console.log(`   V2 UI EXTENDED VERIFICATION SUCCESSFUL`);
  console.log(`   Total Console Errors: ${consoleErrors.length}`);
  console.log('======================================================================');

  await browser.close();
}

runV2UITest().catch((err) => {
  console.error('\n[!] UI VERIFICATION ERROR:', err);
  process.exit(1);
});

