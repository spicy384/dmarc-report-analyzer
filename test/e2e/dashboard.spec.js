// The browser tour: first-run setup, the dashboard with seeded reports, the Policy
// tabs, a report drawer, a one-time analysis by file upload, and the Settings page.
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const EXAMPLES = path.join(__dirname, "..", "..", "examples");

test("first run, dashboard, policy, analysis and settings", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  // The junk-headers step below provokes one 400 on purpose; the browser logs that as an error.
  page.on("console", (msg) => { if (msg.type() === "error" && !/status of 400/.test(msg.text())) errors.push(msg.text()); });

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

  // --- header analysis: paste, analyze, read the verdicts, walk the tabs ---
  await page.locator("#nav-headers").click();
  await expect(page.locator("#view-headers")).toBeVisible();
  await page.fill("#hdr-input", fs.readFileSync(path.join(EXAMPLES, "sample-headers.txt"), "utf8"));
  await page.locator("#hdr-analyze").click();
  await expect(page.locator("#headers-results-panel")).toBeVisible({ timeout: 30_000 });
  await expect(page.locator("#hdr-verdicts")).toContainText("DMARC pass");
  await expect(page.locator("#hdr-verdicts")).toContainText("SPF pass");
  await expect(page.locator("#hdr-findings")).toContainText("DMARC passes for example.com");
  await expect(page.locator("#hdr-summary")).toContainText("billing@example.com");
  const hdrTabs = page.locator("#hdr-body .tab");
  for (const label of ["Path (5)", "DKIM signatures (1)", "Sending address", "Spam filter", "All headers", "Authentication"]) {
    await hdrTabs.filter({ hasText: label }).click();
    await expect(page.locator("#hdr-body .tab-panel:not([hidden])")).toBeVisible();
  }
  await hdrTabs.filter({ hasText: "Sending address" }).click();
  await expect(page.locator("#hdr-body .tab-panel:not([hidden])")).toContainText("167.89.12.34");
  await expect(page).not.toHaveURL(/Received|billing/); // the headers never reach the page link

  // Exports: a self-contained HTML report, the JSON, and the plain-text form.
  const [htmlDownload] = await Promise.all([page.waitForEvent("download"), page.locator("#hdr-export-html").click()]);
  expect(htmlDownload.suggestedFilename()).toMatch(/^email-header-report-your-september-invoice-2026-09-28\.html$/);
  const html = fs.readFileSync(await htmlDownload.path(), "utf8");
  expect(html).toContain("<title>Email header report: Your September invoice</title>");
  expect(html).toContain("DMARC passes for example.com");
  expect(html).toContain("167.89.12.34");
  expect(html).toContain("X-Forefront-Antispam-Report");
  expect(html).not.toContain("<script");
  const [jsonDownload] = await Promise.all([page.waitForEvent("download"), page.locator("#hdr-export-json").click()]);
  const exported = JSON.parse(fs.readFileSync(await jsonDownload.path(), "utf8"));
  expect(exported.verdicts.dmarc.computed).toBe("pass");
  expect(exported.hops).toHaveLength(5);
  const text = await page.evaluate("headerReportText(lastHeaderAnalysis)");
  expect(text).toContain("Email header report: Your September invoice");
  expect(text).toContain("[ok]  DMARC passes for example.com");
  expect(text).toContain("Message-ID                     <AbCdEfGhQ_abc123@geopod-ismtpd-1>");
  expect(text).toContain("Received: from o1.ptr1234.sendgrid.net");
  await page.fill("#hdr-input", "this is not a set of headers");
  await page.locator("#hdr-analyze").click();
  await expect(page.locator("#hdr-status")).toContainText("does not look like email headers");

  // --- settings page: admin panels present ---
  await page.locator("#nav-settings").click();
  await expect(page.locator("#view-settings")).toBeVisible();
  await expect(page.locator("#monitor-panel")).toBeVisible();
  await expect(page.locator("#notify-panel")).toBeVisible();
  await expect(page.locator("#users-panel")).toBeVisible();
  await expect(page.locator("#app-version")).toContainText(/\d+\.\d+\.\d+/);
  // Retry and retention settings load their saved values and explain themselves.
  await expect(page.locator("#sync-retry")).toBeVisible();
  await expect(page.locator("#retry-attempts")).toHaveValue("2");
  await expect(page.locator("#retry-preview")).toContainText("10 s, then 20 s");
  await page.selectOption("#retry-attempts", "3");
  await page.selectOption("#retry-backoff", "fixed");
  await expect(page.locator("#retry-preview")).toContainText("10 s, then 10 s, then 10 s");
  await page.locator("#retry-save").click();
  await expect(page.locator("#status")).toContainText("3 retries");
  await expect(page.locator("#retention-months")).toHaveValue("0");
  await expect(page.locator("#retention-status")).toContainText("Keeping everything");
  await expect(page.locator("#retention-apply")).toBeDisabled();
  // The test server runs with UPDATE_CHECK=false, so the switch is shown off and locked.
  await expect(page.locator("#version-panel")).toBeVisible();
  await expect(page.locator("#version-check-enabled")).not.toBeChecked();
  await expect(page.locator("#version-check-enabled")).toBeDisabled();
  await expect(page.locator("#version-locked")).toBeVisible();

  expect(errors, `console errors: ${errors.join(" | ")}`).toEqual([]);
});

// Runs after the tour above, which created the administrator. Uses the localhost name
// (a secure context, and a host name rather than an IP, which passkeys require) and a
// virtual authenticator, so a real WebAuthn registration and sign-in happen in the browser.
test("first sign-in offers a passkey, and the passkey then signs in", async ({ page, baseURL }) => {
  const origin = baseURL.replace("127.0.0.1", "localhost");
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }
  });

  await page.goto(origin);
  await page.fill("#auth-username", "admin");
  await page.fill("#auth-password", "correct-horse-battery");
  await page.locator("#auth-login-form button[type=submit]").click();

  // No two-factor yet, so the set-up step appears, with the passkey offer beside the code.
  await expect(page.locator("#auth-enrol")).toBeVisible();
  await expect(page.locator("#enrol-qr")).toBeVisible();
  await expect(page.locator("#enrol-passkey")).toBeVisible();
  await expect(page.locator("#enrol-skip")).toHaveText("Skip for now");
  await page.fill("#enrol-passkey-name", "CI laptop");
  await page.locator("#enrol-add-passkey").click();
  await expect(page.locator("#enrol-passkey-note")).toContainText('Passkey "CI laptop" added');
  await expect(page.locator("#enrol-skip")).toHaveText("Continue");
  await expect(page.locator("#enrol-add-passkey")).toHaveText("Add another passkey");
  await page.locator("#enrol-skip").click();
  await expect(page.locator("#view-nav")).toBeVisible();

  // The passkey is listed under Account, and signs in without password or code.
  await page.locator("#nav-settings").click();
  await expect(page.locator("#acct-passkeys")).toContainText("CI laptop");
  await page.locator("#logout-btn").click();
  await expect(page.locator("#auth-login-form")).toBeVisible();
  await page.locator("#auth-passkey-btn").click();
  await expect(page.locator("#view-nav")).toBeVisible();
  await expect(page.locator("#current-user")).toContainText("admin");
});

test("on an IP address the passkey offer explains why it is unavailable", async ({ page }) => {
  await page.goto("/");
  await page.fill("#auth-username", "admin");
  await page.fill("#auth-password", "correct-horse-battery");
  await page.locator("#auth-login-form button[type=submit]").click();
  await expect(page.locator("#auth-enrol")).toBeVisible();
  await expect(page.locator("#enrol-add-passkey")).toBeDisabled();
  await expect(page.locator("#enrol-passkey-note")).toContainText("hostname, not an IP address");
  await page.locator("#enrol-skip").click();
  await expect(page.locator("#view-nav")).toBeVisible();
});
