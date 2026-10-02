// Browser test: one Chromium run against a server started with a seeded, throwaway
// data directory (test/e2e/serve.js). `npm run e2e` locally after
// `npx playwright install chromium`; CI runs it after the unit suites.
const { defineConfig } = require("@playwright/test");

const PORT = Number(process.env.E2E_PORT) || 3991;

module.exports = defineConfig({
  testDir: "test/e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: `node test/e2e/serve.js ${PORT}`,
    url: `http://127.0.0.1:${PORT}/api/auth/me`,
    reuseExistingServer: false,
    timeout: 60_000
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }]
});
