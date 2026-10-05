/**
 * Regenerates the README screenshots: `npm run screenshots`. Starts the app on a
 * throwaway data directory filled with the demo dataset (demo-seed.js, synthetic
 * data only), drives it with Chromium and writes PNGs to docs/screenshots.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { chromium } = require("@playwright/test");
const { seedDemo } = require("./demo-seed");

const PROJECT = path.join(__dirname, "..", "..");
const OUT = path.join(PROJECT, "docs", "screenshots");
const PORT = Number(process.env.SCREENSHOT_PORT) || 3992;
const BASE = `http://127.0.0.1:${PORT}`;

async function waitForServer() {
  for (let i = 0; i < 100; i += 1) {
    try {
      const r = await fetch(`${BASE}/api/auth/me`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("the server did not start");
}

(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-shots-"));
  const seeded = seedDemo(dataDir);
  console.log(`seeded ${seeded.reports} reports (${seeded.messages} messages), ${seeded.alerts} alerts`);
  fs.mkdirSync(OUT, { recursive: true });

  const server = spawn(process.execPath, ["server.js"], {
    cwd: PROJECT,
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dataDir, SYNC_INTERVAL_MINUTES: "0", UPDATE_CHECK: "false", GEOIP_ONLINE: "false", GRAPH_TENANT_ID: "", GRAPH_CLIENT_ID: "", GRAPH_CLIENT_SECRET: "", DMARC_MAILBOX: "" },
    stdio: ["ignore", "ignore", "inherit"]
  });
  let browser;
  try {
    await waitForServer();
    browser = await chromium.launch();
    const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
    const shot = async (name, locator) => {
      const file = path.join(OUT, `${name}.png`);
      if (locator) await locator.screenshot({ path: file });
      else await page.screenshot({ path: file });
      console.log(`wrote docs/screenshots/${name}.png`);
    };
    // The site header is sticky; for a shot of one panel it must not sit on top of it.
    const panel = async (name, id) => {
      const el = page.locator(`#${id}`);
      const style = await page.addStyleTag({ content: "header { position: static !important; }" });
      await el.scrollIntoViewIfNeeded();
      await page.waitForTimeout(250);
      await shot(name, el);
      await style.evaluate((node) => node.remove());
    };

    // First administrator, then past the two first-run prompts.
    await page.goto(BASE);
    await page.fill("#setup-username", "admin");
    await page.fill("#setup-password", "correct-horse-battery");
    await page.fill("#setup-password2", "correct-horse-battery");
    await page.locator("#auth-setup-form button[type=submit]").click();
    await page.locator("#enrol-skip").click();
    await page.locator("#sw-skip").click({ timeout: 20000 });
    await page.locator("#ips-results tbody tr").first().waitFor();
    await page.selectOption("#domain-select", "example.com");
    await page.locator("#policy-body .tab").first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(800);

    await page.evaluate("window.scrollTo(0, 0)");
    await shot("dashboard");
    await panel("domains", "scorecard-panel");
    await panel("weekly", "weekly-panel");
    await page.locator("#policy-body .tab").filter({ hasText: "If p=reject" }).click();
    await panel("policy", "policy-panel");
    await panel("sources", "sources-panel");
    await panel("tls-reports", "tls-panel");

    // Header analysis with the sample message.
    await page.locator("#nav-headers").click();
    await page.fill("#hdr-input", fs.readFileSync(path.join(PROJECT, "examples", "sample-headers.txt"), "utf8"));
    await page.locator("#hdr-analyze").click();
    await page.locator("#headers-results-panel").waitFor({ timeout: 30000 });
    await page.waitForTimeout(400);
    await panel("header-analysis", "headers-results-panel");
    await page.locator("#hdr-body .tab").filter({ hasText: "Path" }).click();
    await panel("header-path", "headers-results-panel");

    // Settings: mailbox sync with the retry options.
    await page.locator("#nav-settings").click();
    await page.locator("#sync-retry").waitFor();
    await panel("settings-sync", "sync-panel");

    // Dark theme, top of the dashboard.
    await page.locator("#nav-dashboard").click();
    await page.locator("#theme-toggle").click();
    await page.evaluate("window.scrollTo(0, 0)");
    await page.waitForTimeout(500);
    await shot("dashboard-dark");
  } finally {
    if (browser) await browser.close();
    server.kill();
    await new Promise((r) => setTimeout(r, 300));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
