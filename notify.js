/**
 * Outbound notifications over an incoming webhook: Microsoft Teams (Workflows,
 * Adaptive Card), Slack (Block Kit) or a generic JSON endpoint. Two events:
 * alerts created by a sync, and the weekly summary on a chosen day and hour.
 * Settings live in the settings table under one key; nothing is sent unless a
 * URL is configured and the event is switched on.
 */
const KEY = "notify";
const KINDS = ["teams", "slack", "generic"];
const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const CHECK_EVERY_MS = 15 * 60 * 1000;

const DEFAULTS = { url: "", kind: "teams", alerts: true, weekly: true, weeklyDay: 1, weeklyHour: 8, appUrl: "", lastWeeklyAt: null, lastResult: null };

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

/** Builds the webhook body for one kind. `lines` are plain sentences; Slack gets them as mrkdwn-safe text. */
function formatMessage(kind, { event, title, lines = [], link = null }) {
  if (kind === "slack") {
    const text = lines.join("\n") || title;
    const blocks = [
      { type: "header", text: { type: "plain_text", text: title.slice(0, 150), emoji: true } },
      ...(lines.length ? [{ type: "section", text: { type: "mrkdwn", text: text.slice(0, 2900) } }] : [])
    ];
    if (link) blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: `<${link}|Open the analyzer>` }] });
    return { text: `${title}\n${text}`.slice(0, 3000), blocks };
  }
  if (kind === "generic") {
    return { event, title, text: lines.join("\n"), lines, link, sentAt: new Date().toISOString() };
  }
  // Teams: a Workflows incoming webhook expects an Adaptive Card.
  const body = [
    { type: "TextBlock", size: "Large", weight: "Bolder", text: title, wrap: true },
    ...lines.map((line) => ({ type: "TextBlock", text: line, wrap: true, spacing: "Small" }))
  ];
  const card = { $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4", body };
  if (link) card.actions = [{ type: "Action.OpenUrl", title: "Open the analyzer", url: link }];
  return { type: "message", attachments: [{ contentType: "application/vnd.microsoft.card.adaptive", contentUrl: null, content: card }] };
}

function createNotifier({ db, fetchImpl = globalThis.fetch, logger = console, now = Date.now, buildWeekly = null, appUrl = "" } = {}) {
  let timer = null;

  function settings() {
    let stored = {};
    try {
      stored = JSON.parse(db.getSetting(KEY) || "{}") || {};
    } catch {
      stored = {};
    }
    return { ...DEFAULTS, appUrl, ...stored };
  }

  /** Validates and stores a change; the URL is kept as given, the rest normalised. */
  function save(patch = {}) {
    const current = settings();
    const next = { ...current };
    if (patch.url !== undefined) {
      const url = String(patch.url || "").trim();
      if (url && !/^https:\/\/\S+$/i.test(url)) throw fail(400, "The webhook URL must start with https://.");
      next.url = url;
    }
    if (patch.kind !== undefined) {
      if (!KINDS.includes(patch.kind)) throw fail(400, `Kind must be one of: ${KINDS.join(", ")}.`);
      next.kind = patch.kind;
    }
    if (patch.alerts !== undefined) next.alerts = Boolean(patch.alerts);
    if (patch.weekly !== undefined) next.weekly = Boolean(patch.weekly);
    if (patch.weeklyDay !== undefined) {
      const day = Number(patch.weeklyDay);
      if (!Number.isInteger(day) || day < 0 || day > 6) throw fail(400, "Weekly day must be 0 (Sunday) to 6 (Saturday).");
      next.weeklyDay = day;
    }
    if (patch.weeklyHour !== undefined) {
      const hour = Number(patch.weeklyHour);
      if (!Number.isInteger(hour) || hour < 0 || hour > 23) throw fail(400, "Weekly hour must be 0 to 23.");
      next.weeklyHour = hour;
    }
    if (patch.appUrl !== undefined) next.appUrl = String(patch.appUrl || "").trim().replace(/\/+$/, "");
    const { lastResult, lastWeeklyAt, ...persist } = next;
    db.setSetting(KEY, JSON.stringify({ ...persist, lastResult: current.lastResult, lastWeeklyAt: current.lastWeeklyAt }));
    return publicSettings();
  }

  function remember(patch) {
    const current = settings();
    db.setSetting(KEY, JSON.stringify({ ...current, ...patch }));
  }

  /** What the API shows: the URL is reduced to its host, since a webhook URL is a credential. */
  function publicSettings() {
    const s = settings();
    let host = null;
    try {
      host = s.url ? new URL(s.url).host : null;
    } catch {
      host = null;
    }
    return { configured: Boolean(s.url), host, kind: s.kind, alerts: s.alerts, weekly: s.weekly, weeklyDay: s.weeklyDay, weeklyHour: s.weeklyHour, weeklyDayName: DAY_NAMES[s.weeklyDay], appUrl: s.appUrl, lastWeeklyAt: s.lastWeeklyAt, lastResult: s.lastResult };
  }

  /** Posts one message. Never throws; the outcome is recorded and returned. */
  async function send({ event, title, lines, link }) {
    const s = settings();
    if (!s.url) return { ok: false, detail: "No webhook URL is configured." };
    const body = formatMessage(s.kind, { event, title, lines, link: link === undefined ? (s.appUrl || null) : link });
    let result;
    try {
      const res = await fetchImpl(s.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const text = await res.text().catch(() => "");
      result = res.ok
        ? { ok: true, status: res.status, detail: `Delivered (HTTP ${res.status}).` }
        : { ok: false, status: res.status, detail: `The webhook answered HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ""}` };
    } catch (error) {
      result = { ok: false, status: null, detail: `Could not reach the webhook: ${error.message}` };
    }
    remember({ lastResult: { at: Math.floor(now() / 1000), event, ...result } });
    if (!result.ok) logger.warn?.(`notify: ${event}: ${result.detail}`);
    return result;
  }

  /** New alerts from a sync, as one message. */
  async function notifyAlerts(alerts) {
    const s = settings();
    if (!s.url || !s.alerts || !alerts || !alerts.length) return null;
    const high = alerts.filter((a) => a.severity === "high").length;
    const title = `DMARC: ${alerts.length} new alert${alerts.length === 1 ? "" : "s"}${high ? ` (${high} high)` : ""}`;
    const lines = alerts.slice(0, 10).map((a) => `${a.severity === "high" ? "⚠ " : ""}${a.title}${a.detail ? ` — ${a.detail}` : ""}`);
    if (alerts.length > 10) lines.push(`and ${alerts.length - 10} more`);
    return send({ event: "alerts", title, lines });
  }

  /** The weekly summary, when it is due: once per week on the chosen day and hour (server local time). */
  async function maybeSendWeekly({ force = false } = {}) {
    const s = settings();
    if (!s.url || (!s.weekly && !force) || !buildWeekly) return null;
    const at = new Date(now());
    if (!force) {
      if (at.getDay() !== s.weeklyDay || at.getHours() < s.weeklyHour) return null;
      const startOfDay = Math.floor(new Date(at.getFullYear(), at.getMonth(), at.getDate()).getTime() / 1000);
      if (s.lastWeeklyAt && s.lastWeeklyAt >= startOfDay) return null;
    }
    const w = buildWeekly({});
    const lines = String(w.text || "").split("\n").filter((l) => l.trim()).slice(1);
    const result = await send({ event: "weekly", title: String(w.text || "").split("\n")[0] || "DMARC weekly summary", lines });
    if (result.ok) remember({ lastWeeklyAt: Math.floor(now() / 1000) });
    return result;
  }

  async function test() {
    return send({ event: "test", title: "DMARC Report Analyzer: test message", lines: ["If you can read this, the webhook works. Alerts and the weekly summary will arrive here."] });
  }

  function start() {
    if (timer) return;
    timer = setInterval(() => { maybeSendWeekly().catch((error) => logger.warn?.(`notify: weekly: ${error.message}`)); }, CHECK_EVERY_MS);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { settings: publicSettings, save, send, notifyAlerts, maybeSendWeekly, test, start, stop, formatMessage, KINDS, DAY_NAMES };
}

module.exports = { createNotifier, formatMessage, KINDS, DAY_NAMES };
