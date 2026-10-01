// 09-alerts.js: Alerts banner.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- alerts ----------------------------------------------------------------

const alertsBanner = document.getElementById("alerts-banner");
const alertsTitle = document.getElementById("alerts-title");
const alertsList = document.getElementById("alerts-list");
const alertsAckAll = document.getElementById("alerts-ack-all");
const BASE_TITLE = document.title;

function describeAlert(a) {
  const d = a.detail || {};
  if (a.type === "new_source") {
    const bits = [`${formatNumber(d.failed)} of ${formatNumber(d.total)} messages failed`];
    if (d.headerFroms && d.headerFroms.length) bits.push(`claiming ${d.headerFroms.join(", ")}`);
    if (d.reporters && d.reporters.length) bits.push(`reported by ${d.reporters.join(", ")}`);
    if (d.firstSeen) bits.push(`first seen ${formatUtcDate(d.firstSeen)}`);
    return bits.join("; ");
  }
  if (a.type === "spike") {
    return `${formatNumber(d.recent)} non-forward failures in the last ${d.days} days, ${formatNumber(d.previous)} in the ${d.days} before${d.sender ? ` (known sender: ${d.sender.label})` : ""}`;
  }
  if (a.type === "new_reporter") {
    return `${formatNumber(d.reports)} report${d.reports === 1 ? "" : "s"} covering ${formatNumber(d.messages)} messages`;
  }
  return "";
}

function renderAlerts(alerts) {
  const open = alerts || [];
  document.title = open.length ? `(${open.length}) ${BASE_TITLE}` : BASE_TITLE;
  alertsBanner.hidden = open.length === 0;
  if (!open.length) {
    alertsList.replaceChildren();
    return;
  }
  const high = open.filter((a) => a.severity === "high").length;
  alertsTitle.textContent = `${open.length} alert${open.length === 1 ? "" : "s"} since the last acknowledgement${high ? ` (${high} high)` : ""}`;
  alertsList.replaceChildren(...open.map((a) => {
    const li = document.createElement("li");
    li.className = `alert alert-${a.severity}`;

    const sev = document.createElement("span");
    sev.className = `pill pill-sev-${a.severity}`;
    sev.textContent = a.type === "new_source" ? "new source" : a.type === "spike" ? "spike" : "new reporter";
    li.appendChild(sev);

    const body = document.createElement("div");
    body.className = "alert-body";
    const title = document.createElement("div");
    title.className = "alert-title";
    title.textContent = a.title;
    const desc = document.createElement("div");
    desc.className = "alert-desc";
    desc.textContent = `${describeAlert(a)} - ${formatTimestamp(a.created_at)}`;
    body.append(title, desc);
    li.appendChild(body);

    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (a.type !== "new_reporter") {
      const show = document.createElement("button");
      show.type = "button";
      show.className = "secondary small";
      show.textContent = "Show";
      show.addEventListener("click", () => {
        searchInput.value = a.key;
        rangeSelect.value = "90";
        onRangeChanged();
        document.getElementById("sources-panel").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      actions.appendChild(show);
    }
    if (canWrite()) {
      const ack = document.createElement("button");
      ack.type = "button";
      ack.className = "secondary small";
      ack.textContent = "Acknowledge";
      ack.addEventListener("click", async () => {
        try {
          await api(`/api/alerts/${encodeURIComponent(a.id)}/ack`, { method: "POST", body: "{}" });
          await loadAlerts();
        } catch (error) {
          setStatus(error.message, true);
        }
      });
      actions.appendChild(ack);
    }
    li.appendChild(actions);
    return li;
  }));
}

alertsAckAll.addEventListener("click", async () => {
  try {
    await api("/api/alerts/ack-all", { method: "POST", body: "{}" });
    await loadAlerts();
  } catch (error) {
    setStatus(error.message, true);
  }
});

async function loadAlerts() {
  const data = await api("/api/alerts?open=1");
  renderAlerts(data.alerts || []);
}
