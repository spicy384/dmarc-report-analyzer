/** One-time analyses: in-memory databases fed by uploads, isolated from the main store. */
const fs = require("fs");
const path = require("path");
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { createIngest } = require("../ingest");
const { createScratchStore } = require("../scratch");

const { check, report } = createChecker("Scratch analyses: isolation, enrichment, expiry");
const EX = path.join(__dirname, "..", "examples");

let clock = 1_790_000_000_000;
const now = () => clock;
const main = openDatabase({ file: ":memory:" });
// The Google sample report has sources 198.51.100.7 and 203.0.113.10.
main.addKnownSender({ pattern: "203.0.113.0/24", kind: "vendor", label: "Google" });
main.setPtr("198.51.100.7", "mail.badhost.test");
let lookups = 0;
const fakeSync = () => ({ lookupPtrs: async () => { lookups += 1; return 0; }, lookupGeo: async () => 0 });
const store = createScratchStore({ openDatabase, createIngest, createSync: fakeSync, mainDb: main, now, ttlMs: 60_000, max: 2, logger: { warn() {} } });

(async () => {
  const a = store.create("alice");
  check("create: id, owner, empty", /^[0-9a-f]{24}$/.test(a.id) && a.username === "alice" && store.describe(a).reports === 0 && store.describe(a).files.length === 0);
  check("create: known senders copied from the main store", a.db.knownSenders().length === 1 && a.db.knownSenders()[0].label === "Google");

  const xml = fs.readFileSync(path.join(EX, "google-aggregate.xml"));
  const r1 = await store.addFile(a, { bytes: xml, name: "google.xml" });
  check("addFile: report ingested into the scratch db only", r1.aggregate.added === 1 && a.db.stats().reports.reports === 1 && main.stats().reports.reports === 0);
  check("addFile: PTR known to the main store copied in, live lookup attempted for the rest", a.db.ips({}).some((r) => r.ip === "198.51.100.7" && r.ptr === "mail.badhost.test") && lookups === 1, JSON.stringify(a.db.ips({}).map((r) => [r.ip, r.ptr])));
  check("addFile: known-sender label applies", a.db.ips({}).some((r) => r.sender && r.sender.label === "Google"));
  const d = store.describe(a);
  check("describe: files, counts, domains", d.files.length === 1 && d.files[0].aggregate === 1 && d.reports === 1 && d.messages > 0 && d.domains.includes("example.com") && d.expiresAt === Math.floor((clock + 60_000) / 1000), JSON.stringify(d));
  const r2 = await store.addFile(a, { bytes: xml, name: "google-again.xml" });
  check("addFile: duplicate within the analysis is skipped", r2.aggregate.duplicates === 1 && store.describe(a).files.length === 2);
  const junk = await store.addFile(a, { bytes: Buffer.from("nope"), name: "junk.txt" });
  check("addFile: junk is a problem and recorded as such", junk.problems.length === 1 && a.db.stats().messages.errors === 1);

  check("get: owner gets it, anyone else does not", store.get(a.id, "alice") === a && store.get(a.id, "bob") === null && store.get(a.id, null) === null && store.get("nope", "alice") === null);

  // Expiry is measured from the last use.
  clock += 50_000;
  check("get: still alive within the TTL, and touching it extends", store.get(a.id, "alice") === a);
  clock += 50_000;
  check("get: alive because the last use reset the clock", store.get(a.id, "alice") === a);
  clock += 61_000;
  check("get: expired after a quiet hour", store.get(a.id, "alice") === null && store.size() === 0);

  // Capacity: the least recently used analysis goes when a new one is needed.
  const b = store.create("bob");
  clock += 1000;
  const c = store.create("carol");
  clock += 1000;
  store.get(b.id, "bob"); // b is now the more recently used
  const e = store.create("erin");
  check("max: least recently used evicted", store.size() === 2 && store.get(c.id, "carol") === null && store.get(b.id, "bob") === b && store.get(e.id, "erin") === e);
  check("remove: closes and forgets", store.remove(b.id) === true && store.get(b.id, "bob") === null && store.remove(b.id) === false);
  store.stop();
  check("stop: everything gone", store.size() === 0);

  main.close();
  process.exit(report() ? 0 : 1);
})().catch((error) => { console.error(error); process.exit(1); });
