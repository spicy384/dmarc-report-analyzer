// Runs every test file in sequence and reports a combined result.
const { spawnSync } = require("child_process");
const path = require("path");

const SUITES = [
  "parser.test.js",
  "ipmatch.test.js",
  "dns-records.test.js",
  "db.test.js",
  "mailboxes.test.js",
  "alerts.test.js",
  "geoip.test.js",
  "retention.test.js",
  "sync.test.js",
  "server.test.js",
  "auth.test.js"
];

let failed = 0;

for (const suite of SUITES) {
  const result = spawnSync("node", [path.join(__dirname, suite)], {
    stdio: "inherit",
    cwd: path.join(__dirname, "..")
  });

  if (result.status !== 0) {
    failed += 1;
  }
}

console.log("\n" + "-".repeat(48));
if (failed === 0) {
  console.log(`All ${SUITES.length} suites passed.`);
  process.exit(0);
}

console.log(`${failed} of ${SUITES.length} suites FAILED.`);
process.exit(1);
