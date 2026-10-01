/** Webhook notifications: message shapes, settings, delivery, alert and weekly gating. */
const http = require("http");
const { createChecker } = require("./helpers/assert");
const { openDatabase } = require("../db");
const { createNotifier, formatMessage } = require("../notify");

const { check, report } = createChecker("notify: Teams, Slack and generic webhooks");

(async () => {
  // --- shapes ---
  const teams = formatMessage("teams", { event: "alerts", title: "T", lines: ["a", "b"], link: "https://app.test" });
  check("teams: an Adaptive Card with title, lines and an open action", teams.type === "message" && teams.attachments[0].contentType === "application/vnd.microsoft.card.adaptive" && teams.attachments[0].content.body.length === 3 && teams.attachments[0].content.body[0].text === "T" && teams.attachments[0].content.actions[0].url === "https://app.test");
  const slack = formatMessage("slack", { event: "weekly", title: "W", lines: ["x"], link: null });
  check("slack: header, section and a plain-text fallback", slack.blocks[0].type === "header" && slack.blocks[1].text.text === "x" && slack.text.startsWith("W") && !slack.blocks.some((b) => b.type === "context"));
  const generic = formatMessage("generic", { event: "test", title: "G", lines: ["1", "2"], link: "https://a" });
  check("generic: plain JSON with event, text and lines", generic.event === "test" && generic.text === "1\n2" && generic.lines.length === 2 && generic.link === "https://a" && generic.sentAt);

  // --- settings ---
  const db = openDatabase({ file: ":memory:" });
  let clock = Date.parse("2026-10-05T07:30:00"); // a Monday, local time
  const received = [];
  const hook = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      received.push({ path: req.url, body: JSON.parse(body) });
      if (req.url === "/bad") { res.writeHead(400); return res.end("no thanks"); }
      res.writeHead(200);
      res.end("1");
    });
  });
  const port = await new Promise((resolve) => hook.listen(0, "127.0.0.1", () => resolve(hook.address().port)));
  const weeklyCalls = [];
  const notifier = createNotifier({ db, now: () => clock, logger: { warn() {} }, buildWeekly: () => { weeklyCalls.push(1); return { text: "DMARC weekly summary: 2026-09-28 to 2026-10-04\nMessages: 10\nPass rate: 90%" }; } });

  check("settings: off until a URL is set", notifier.settings().configured === false && notifier.settings().kind === "teams" && notifier.settings().weeklyDayName === "Monday");
  check("settings: https is required", (() => { try { notifier.save({ url: "http://insecure.test/hook" }); return false; } catch (e) { return e.status === 400; } })());
  check("settings: bad kind, day and hour refused", [{ kind: "pigeon" }, { weeklyDay: 9 }, { weeklyHour: 24 }].every((p) => { try { notifier.save(p); return false; } catch (e) { return e.status === 400; } }));
  // Local test hook is plain http; the validator only allows https, so store the URL directly for delivery tests.
  const saved = notifier.save({ kind: "slack", alerts: true, weekly: true, weeklyDay: 1, weeklyHour: 8, appUrl: "https://dmarc.example.test/" });
  db.setSetting("notify", JSON.stringify({ ...JSON.parse(db.getSetting("notify")), url: `http://127.0.0.1:${port}/hook` }));
  const pub = notifier.settings();
  check("settings: saved and shown without the URL itself", saved.kind === "slack" && pub.configured && pub.host === `127.0.0.1:${port}` && !JSON.stringify(pub).includes("/hook") && pub.appUrl === "https://dmarc.example.test");

  // --- delivery ---
  const t = await notifier.test();
  check("test: delivered and recorded", t.ok && received.length === 1 && received[0].body.blocks[0].text.text.includes("test message") && notifier.settings().lastResult.ok === true && notifier.settings().lastResult.event === "test");
  check("test: the app link rides along", received[0].body.blocks.some((b) => b.type === "context" && b.elements[0].text.includes("https://dmarc.example.test")));

  // --- alerts ---
  const alerts = [{ severity: "high", title: "New failing source 203.0.113.9", detail: "50 of 50 failed" }, { severity: "medium", title: "New reporter yahoo.com", detail: null }];
  const a = await notifier.notifyAlerts(alerts);
  check("alerts: one message listing every alert, high ones marked", a.ok && received.length === 2 && received[1].body.text.includes("2 new alerts (1 high)") && received[1].body.blocks[1].text.text.includes("⚠ New failing source") && received[1].body.blocks[1].text.text.includes("New reporter yahoo.com"));
  check("alerts: nothing sent for an empty list", (await notifier.notifyAlerts([])) === null && received.length === 2);
  notifier.save({ alerts: false });
  check("alerts: switched off means nothing is sent", (await notifier.notifyAlerts(alerts)) === null && received.length === 2);
  notifier.save({ alerts: true });

  // --- weekly ---
  check("weekly: not yet due before the hour", (await notifier.maybeSendWeekly()) === null && weeklyCalls.length === 0);
  clock = Date.parse("2026-10-05T08:10:00");
  const w1 = await notifier.maybeSendWeekly();
  check("weekly: sent once the hour arrives, from the summary builder", w1 && w1.ok && weeklyCalls.length === 1 && received[2].body.text.startsWith("DMARC weekly summary") && received[2].body.blocks[1].text.text.includes("Messages: 10") && notifier.settings().lastWeeklyAt > 0);
  clock = Date.parse("2026-10-05T15:00:00");
  check("weekly: not sent twice the same day", (await notifier.maybeSendWeekly()) === null && received.length === 3);
  clock = Date.parse("2026-10-06T08:10:00");
  check("weekly: not sent on another day", (await notifier.maybeSendWeekly()) === null);
  clock = Date.parse("2026-10-12T08:10:00");
  check("weekly: sent again the next week", (await notifier.maybeSendWeekly()).ok && received.length === 4);
  check("weekly: force sends regardless of schedule", (await notifier.maybeSendWeekly({ force: true })).ok && received.length === 5);

  // --- failure handling ---
  db.setSetting("notify", JSON.stringify({ ...JSON.parse(db.getSetting("notify")), url: `http://127.0.0.1:${port}/bad` }));
  const bad = await notifier.test();
  check("failure: a rejected post is reported with the status and body, never thrown", bad.ok === false && bad.status === 400 && /no thanks/.test(bad.detail) && notifier.settings().lastResult.ok === false);
  await new Promise((resolve) => hook.close(resolve));
  const down = await notifier.test();
  check("failure: an unreachable webhook is reported", down.ok === false && /Could not reach/.test(down.detail));

  db.close();
  process.exitCode = report() ? 0 : 1;
})().catch((e) => { console.error(e); process.exit(1); });
