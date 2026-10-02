/**
 * Starts the app for the browser test: a fresh data directory seeded with the
 * example reports (so the dashboard has something to show), no mailbox, no
 * scheduled sync, no update check. Playwright runs this as its web server.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PROJECT = path.join(__dirname, "..", "..");
const PORT = process.argv[2] || "3991";
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-e2e-"));

const { openDatabase } = require(path.join(PROJECT, "db"));
const { parseAggregateReport } = require(path.join(PROJECT, "dmarc-parser"));

const seed = openDatabase({ dataDir: DATA_DIR });
const DAY = 86400;
const today = Math.floor(Date.now() / 1000 / DAY) * DAY;
let n = 0;
// The sample reports carry fixed windows; shift each copy onto a recent day so the
// default "last 30 days" view is not empty, and vary the report id to avoid duplicates.
for (const [file, org] of [["google-aggregate.xml", "google.com"], ["microsoft-aggregate.xml", "Enterprise Outlook"]]) {
  const xml = fs.readFileSync(path.join(PROJECT, "examples", file), "utf8");
  for (let d = 1; d <= 5; d += 1) {
    n += 1;
    const begin = today - d * DAY;
    const shifted = xml
      .replace(/<begin>\d+<\/begin>/, `<begin>${begin}</begin>`)
      .replace(/<end>\d+<\/end>/, `<end>${begin + DAY - 1}</end>`)
      .replace(/<report_id>[^<]*<\/report_id>/, `<report_id>e2e-${org}-${d}</report_id>`);
    seed.recordMessage({ graphId: `e2e-${n}`, receivedAt: begin + DAY, subject: `Report ${d}`, fromAddr: `noreply@${org}`, status: "ingested" });
    seed.insertReport({ messageId: `e2e-${n}`, attachmentName: file, parsed: parseAggregateReport(shifted), xml: shifted });
  }
}
seed.setPtr("198.51.100.7", "mail.spammer.test");
seed.close();

const child = spawn(process.execPath, ["server.js"], {
  cwd: PROJECT,
  env: {
    ...process.env,
    PORT: String(PORT),
    DATA_DIR,
    SYNC_INTERVAL_MINUTES: "0",
    UPDATE_CHECK: "false",
    GEOIP_ONLINE: "false",
    GRAPH_TENANT_ID: "", GRAPH_CLIENT_ID: "", GRAPH_CLIENT_SECRET: "", DMARC_MAILBOX: ""
  },
  stdio: "inherit"
});
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => { child.kill(signal); });
}
child.on("exit", (code) => {
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  process.exit(code === null ? 0 : code);
});
