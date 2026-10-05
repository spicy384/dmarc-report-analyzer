// The browser tour: first-run setup, the dashboard with seeded reports, the Policy
// tabs, a report drawer, a one-time analysis by file upload, and the Settings page.
const path = require("path");
const { test, expect } = require("@playwright/test");

const EXAMPLES = path.join(__dirname, "..", "..", "examples");

test("first run, dashboard, policy, analysis and settings", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (msg) => { if (msg.type() === "error") errors.push(msg.text()); });

  await page.goto("/");

  // --- first administrator ---
  await expect(page.locator("#auth-setup-form")).toBeVisible();
  await page.fill("#setup-username", "admin");
  await page.fill("#setup-password", "correct-horse-battery");
  await page.fill("#setup-password2", "correct-horse-battery");
  await page.locator("#auth-setup-form button[type=submit]").click();
  // Two prompts follow in order: enrol two-factor (skipped), then, once the dashboard has
  // loaded, the mailbox walkthrough because no mailbox exists (skipped too).
  const enrolSkip = page.locator("#enrol-skip");
  await expect(enrolSkip).toBeVisible();
  await enrolSkip.click();
  const wizardSkip = page.locator("#sw-skip");
  await expect(wizardSkip).toBeVisible({ timeout: 20_000 });
  await wizardSkip.click();
  await expect(page.locator("#setup-wizard")).toBeHidden();

  // --- dashboard with the seeded reports ---
  await expect(page.locator("#view-nav")).toBeVisible();
  await expect(page.locator("#reports-count")).toContainText("10 reports");
  await expect(page.locator("#stat-grid")).toContainText("Messages");
  await expect(page.locator("#ips-results tbody tr").first()).toBeVisible();
  await expect(page.locator("#ips-results")).toContainText("mail.spammer.test");

  // Filtering by domain narrows every panel and lands in the page link.
  await page.selectOption("#domain-select", "example.com");
  await expect(page).toHaveURL(/domain=example\.com/);

  // --- policy tabs (DNS for example.com resolves to a real DMARC record) ---
  const policyTabs = page.locator("#policy-body .tab");
  await expect(policyTabs.first()).toBeVisible();
  for (const label of ["SPF record", "DKIM selectors", "MTA-STS / TLS-RPT", "History", "If p=reject"]) {
    await policyTabs.filter({ hasText: label }).click();
    await expect(page.locator("#policy-body .tab-panel:not([hidden])")).toBeVisible();
  }

  // --- a report drawer with its records and the Exchange Online block ---
  await page.locator("#reports-results tbody tr").first().click();
  await expect(page.locator("#report-detail")).toBeVisible();
  await expect(page.locator("#report-detail-body tbody tr").first()).toBeVisible();
  await page.locator("#report-detail-close").click();

  // --- one-time analysis: upload a file, dashboard switches, then back ---
  await page.locator("#nav-analyze").click();
  await expect(page.locator("#view-analyze")).toBeVisible();
  await page.setInputFiles("#analyze-input", path.join(EXAMPLES, "microsoft-aggregate.xml"));
  await expect(page.locator("#scratch-banner")).toBeVisible();
  await expect(page.locator("#scratch-summary")).toContainText("1 aggregate report");
  await expect(page.locator("#reports-count")).toContainText("1 report");
  await expect(page).toHaveURL(/scratch=/);
  await expect(page.locator("#upload-panel")).toBeHidden();
  await page.locator("#scratch-exit").click();
  await expect(page.locator("#scratch-banner")).toBeHidden();
  await expect(page.locator("#reports-count")).toContainText("10 reports");

  // --- lookup panel against a real domain ---
  await page.fill("#lookup-input", "example.com");
  await page.locator("#lookup-input").press("Enter");
  await expect(page.locator("#lookup-body .tab").first()).toBeVisible({ timeout: 20_000 });

  // --- settings page: admin panels present ---
  await page.locator("#nav-settings").click();
  await expect(page.locator("#view-settings")).toBeVisible();
  await expect(page.locator("#monitor-panel")).toBeVisible();
  await expect(page.locator("#notify-panel")).toBeVisible();
  await expect(page.locator("#users-panel")).toBeVisible();
  await expect(page.locator("#app-version")).toContainText(/\d+\.\d+\.\d+/);
  // The test server runs with UPDATE_CHECK=false, so the switch is shown off and locked.
  await expect(page.locator("#version-panel")).toBeVisible();
  await expect(page.locator("#version-check-enabled")).not.toBeChecked();
  await expect(page.locator("#version-check-enabled")).toBeDisabled();
  await expect(page.locator("#version-locked")).toBeVisible();

  expect(errors, `console errors: ${errors.join(" | ")}`).toEqual([]);
});
