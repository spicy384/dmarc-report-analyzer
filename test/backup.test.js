/** Backup archive round trip, restore into a live database, re-processing stored XML, audit log. */
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { parseAggregateReport } = require("../dmarc-parser");
const { createBackup, restoreBackup, inspectBackup, tarPack, tarUnpack } = require("../backup");

const { check, report } = createChecker("backup: archive, restore, re-process, audit");

const googleXml = fs.readFileSync(path.join(__dirname, "..", "examples", "google-aggregate.xml"), "utf8");
const microsoftXml = fs.readFileSync(path.join(__dirname, "..", "examples", "microsoft-aggregate.xml"), "utf8");

(async () => {
  // --- tar ---
  const packed = tarPack({ "a.txt": Buffer.from("hello"), "dir/b.bin": Buffer.alloc(1000, 7) }, 1_700_000_000_000);
  check("tar: blocks are 512-aligned with the two-block end marker", packed.length === 512 + 512 + 512 + 1024 + 1024);
  const unpacked = tarUnpack(packed);
  check("tar: round trip", unpacked["a.txt"].toString() === "hello" && unpacked["dir/b.bin"].length === 1000 && unpacked["dir/b.bin"][999] === 7);

  // --- a source database with data and settings files ---
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-bk-src-"));
  const src = openDatabase({ dataDir });
  src.recordMessage({ graphId: "m1", mailboxId: "env", receivedAt: 1_700_000_000, subject: "r", from: "a@b", status: "ingested" });
  src.insertReport({ messageId: "m1", mailboxId: "env", attachmentName: "g.zip", parsed: parseAggregateReport(googleXml), xml: googleXml });
  src.insertReport({ messageId: "m2", mailboxId: "env", attachmentName: "m.xml", parsed: parseAggregateReport(microsoftXml), xml: microsoftXml });
  src.addKnownSender({ pattern: "203.0.113.0/24", kind: "ours", label: "Office" }, { createdBy: "admin", source: "manual" });
  src.setSetting("setup_dismissed", "1");
  src.audit({ username: "admin", action: "test.event", target: "x", detail: "d" });
  fs.writeFileSync(path.join(dataDir, "users.json"), JSON.stringify([{ id: "u1", username: "restored-admin", role: "admin" }]));
  fs.writeFileSync(path.join(dataDir, "mailboxes.json"), JSON.stringify([{ id: "abcd1234", name: "Box", tenantId: "t", clientId: "c", clientSecret: "s", mailbox: "x@y.test", folder: "Inbox", enabled: true }]));
  const srcReports = src.stats().reports.reports;

  const archive = path.join(dataDir, "backup.tar.gz");
  const manifest = await createBackup({ db: src, dataDir, dest: archive, version: "test", now: () => 1_700_000_000_000 });
  check("backup: manifest lists database and settings", manifest.files.join(",") === "dmarc.sqlite,users.json,mailboxes.json" && manifest.bytes > 1000 && manifest.createdAt === "2023-11-14T22:13:20.000Z");
  const raw = fs.readFileSync(archive);
  check("backup: is a gzip file", raw[0] === 0x1f && raw[1] === 0x8b);
  const inspected = inspectBackup(raw);
  check("backup: inspect reads the manifest", inspected.manifest.format === "dmarc-report-analyzer-backup" && inspected.entries["users.json"]);
  check("backup: archive opens with standard tools (tar layout)", Object.keys(tarUnpack(zlib.gunzipSync(raw))).includes("manifest.json"));

  // --- restore into a different, non-empty database ---
  const dstDir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-bk-dst-"));
  const dst = openDatabase({ dataDir: dstDir });
  dst.recordMessage({ graphId: "other", mailboxId: "env", receivedAt: 1_600_000_000, subject: "old", from: "z@z", status: "ingested" });
  dst.insertReport({ messageId: "other", mailboxId: "env", attachmentName: "o.xml", parsed: parseAggregateReport(microsoftXml), xml: microsoftXml });
  dst.setSetting("setup_dismissed", "0");
  fs.writeFileSync(path.join(dstDir, "users.json"), JSON.stringify([{ id: "u9", username: "old-admin", role: "admin" }]));

  const result = restoreBackup({ db: dst, dataDir: dstDir, buffer: raw });
  check("restore: reports replaced, not merged", dst.stats().reports.reports === srcReports && result.counts.reports === srcReports, JSON.stringify(result.counts));
  check("restore: records, senders and settings came across; the audit log stays local", dst.knownSenders().length === 1 && dst.getSetting("setup_dismissed") === "1" && !dst.auditLog().entries.some((e) => e.action === "test.event") && dst.ips({}).length === src.ips({}).length);
  check("restore: settings files overwritten", JSON.parse(fs.readFileSync(path.join(dstDir, "users.json"), "utf8"))[0].username === "restored-admin" && fs.existsSync(path.join(dstDir, "mailboxes.json")));
  check("restore: live connection still works afterwards", dst.summary({}).totals.messages > 0 && dst.insertReport({ messageId: "m3", mailboxId: "env", attachmentName: "g2.zip", parsed: parseAggregateReport(googleXml.replace("<report_id>", "<report_id>x")), xml: googleXml }).duplicate === false);

  // --- bad archives change nothing ---
  const before = dst.stats().reports.reports;
  const notGzip = (() => { try { restoreBackup({ db: dst, dataDir: dstDir, buffer: Buffer.from("hello") }); return null; } catch (e) { return e; } })();
  check("restore: not gzip is a 400", notGzip && notGzip.status === 400 && /not a gzip/.test(notGzip.message));
  const noManifest = (() => { try { restoreBackup({ db: dst, dataDir: dstDir, buffer: zlib.gzipSync(tarPack({ "x.txt": Buffer.from("x") })) }); return null; } catch (e) { return e; } })();
  check("restore: missing manifest is a 400", noManifest && noManifest.status === 400);
  const badUsers = (() => {
    const entries = tarUnpack(zlib.gunzipSync(raw));
    entries["users.json"] = Buffer.from("{not json");
    try { restoreBackup({ db: dst, dataDir: dstDir, buffer: zlib.gzipSync(tarPack(entries)) }); return null; } catch (e) { return e; }
  })();
  check("restore: corrupt settings file refused before anything changes", badUsers && badUsers.status === 400 && dst.stats().reports.reports === before);
  const corruptDb = (() => {
    const entries = tarUnpack(zlib.gunzipSync(raw));
    entries["dmarc.sqlite"] = Buffer.from("definitely not sqlite");
    try { restoreBackup({ db: dst, dataDir: dstDir, buffer: zlib.gzipSync(tarPack(entries)) }); return null; } catch (e) { return e; }
  })();
  check("restore: corrupt database refused, live data intact", corruptDb && dst.stats().reports.reports === before, corruptDb && corruptDb.message);

  // --- re-process stored XML ---
  const ids = src.reprocessableIds();
  check("reprocess: every stored report is eligible", ids.length === srcReports);
  const target = ids[0];
  const detailBefore = src.reportById(target);
  src.db.prepare("DELETE FROM records WHERE report_id = ?").run(target);
  src.db.prepare("UPDATE reports SET messages = 0, passed = 0, p = 'none' WHERE id = ?").run(target);
  check("reprocess: setup removed the records", src.reportById(target).records.length === 0);
  const redo = src.reprocessReport(target);
  const detailAfter = src.reportById(target);
  check("reprocess: records and totals rebuilt from the XML", redo.records === detailBefore.records.length && detailAfter.messages === detailBefore.messages && detailAfter.passed === detailBefore.passed && detailAfter.p === detailBefore.p, JSON.stringify(redo));
  check("reprocess: unknown or purged report returns null", src.reprocessReport(999999) === null);

  // --- audit log paging ---
  for (let i = 0; i < 5; i += 1) src.audit({ username: "admin", action: `page.${i}`, target: null, detail: null });
  const page1 = src.auditLog({ limit: 3 });
  check("audit: newest first with a more flag", page1.entries.length === 3 && page1.more === true && page1.entries[0].action === "page.4");
  const page2 = src.auditLog({ limit: 3, before: page1.entries[2].id });
  check("audit: paging continues before an id", page2.entries[0].action === "page.1");
  check("audit: filter by action prefix", src.auditLog({ action: "page." }).entries.length === 5);

  src.close();
  dst.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(dstDir, { recursive: true, force: true });
  process.exitCode = report() ? 0 : 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
