// 04-sources.js: Sending sources table (sort, verdicts, sparklines) and the IP drawer.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- sources ---------------------------------------------------------------

function flagEmoji(cc) {
  const code = String(cc || "").toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : "";
}

function networkCell(r) {
  const td = document.createElement("td");
  td.className = "network";
  if (!r.countryCode && !r.asOrg) {
    td.textContent = "";
    return td;
  }
  const flag = document.createElement("span");
  flag.className = "flag";
  flag.textContent = flagEmoji(r.countryCode);
  td.appendChild(flag);
  td.append(`${r.countryCode || ""}${r.asOrg ? ` ${r.asn ? "AS" + r.asn + " " : ""}${r.asOrg}` : ""}`);
  td.title = [r.country, r.city, r.asn ? `AS${r.asn}` : null, r.asOrg].filter(Boolean).join(", ");
  return td;
}

/**
 * A tiny bar-per-day chart of a source's volume over the period, failures in red.
 * Days are bucketed to at most 30 bars so a 90-day period still fits in a cell.
 */
function sparklineCell(r) {
  const td = document.createElement("td");
  td.className = "spark";
  const days = r.days || [];
  if (!days.length) return td;
  const range = currentRange();
  const first = range.from !== null ? formatUtcDate(range.from) : days[0].day;
  const last = range.to !== null ? formatUtcDate(range.to - 1) : days[days.length - 1].day;
  const start = Date.parse(`${first}T00:00:00Z`) / 1000;
  const end = Date.parse(`${last}T00:00:00Z`) / 1000 + DAY;
  const spanDays = Math.max(1, Math.round((end - start) / DAY));
  const bucketDays = Math.max(1, Math.ceil(spanDays / 30));
  const buckets = Array.from({ length: Math.ceil(spanDays / bucketDays) }, () => ({ total: 0, failed: 0 }));
  for (const d of days) {
    const t = Date.parse(`${d.day}T00:00:00Z`) / 1000;
    const idx = Math.floor((t - start) / DAY / bucketDays);
    if (idx >= 0 && idx < buckets.length) {
      buckets[idx].total += d.total;
      buckets[idx].failed += d.failed;
    }
  }
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const w = 4;
  const gap = 1;
  const h = 22;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${buckets.length * (w + gap)} ${h}`);
  svg.setAttribute("width", String(buckets.length * (w + gap)));
  svg.setAttribute("height", String(h));
  svg.setAttribute("class", "sparkline");
  buckets.forEach((b, i) => {
    if (!b.total) return;
    const total = Math.max(1, Math.round((b.total / max) * h));
    const failed = Math.round((b.failed / max) * h);
    const x = i * (w + gap);
    const pass = document.createElementNS(ns, "rect");
    pass.setAttribute("x", String(x)); pass.setAttribute("y", String(h - total)); pass.setAttribute("width", String(w)); pass.setAttribute("height", String(total));
    pass.setAttribute("class", "spark-pass");
    svg.appendChild(pass);
    if (failed > 0) {
      const fail = document.createElementNS(ns, "rect");
      fail.setAttribute("x", String(x)); fail.setAttribute("y", String(h - failed)); fail.setAttribute("width", String(w)); fail.setAttribute("height", String(failed));
      fail.setAttribute("class", "spark-fail");
      svg.appendChild(fail);
    }
  });
  const peak = Math.max(...buckets.map((b) => b.total));
  td.title = `${buckets.length} ${bucketDays === 1 ? "days" : `buckets of ${bucketDays} days`}, peak ${formatNumber(peak)} messages; red is failures`;
  td.appendChild(svg);
  return td;
}

function ipRow(r) {
  const dispositions = [];
  if (r.failNone) dispositions.push(`${formatNumber(r.failNone)} delivered`);
  if (r.quarantined) dispositions.push(`${formatNumber(r.quarantined)} quarantined`);
  if (r.rejected) dispositions.push(`${formatNumber(r.rejected)} rejected`);
  if (r.likelyForwards) dispositions.push(`${formatNumber(r.likelyForwards)} likely forwards`);

  const failCell = textCell(formatNumber(r.failed), r.failed > 0 ? "num is-fail" : "num");
  const senderCell = document.createElement("td");
  senderCell.className = "nowrap";
  senderCell.appendChild(senderPill(r.sender));
  // Unlabelled but recognisable: say who it looks like, and make labelling one click.
  if (!r.sender && r.catalogue) {
    const hint = document.createElement("span");
    hint.className = "sender-hint";
    hint.textContent = `looks like ${r.catalogue.name}`;
    hint.title = `Reverse DNS or address matches ${r.catalogue.pattern}`;
    senderCell.append(" ", hint);
  }
  if (canWrite()) {
    const labelBtn = document.createElement("button");
    labelBtn.type = "button";
    labelBtn.className = "link-btn small-link";
    labelBtn.textContent = r.sender ? "edit" : "label";
    labelBtn.title = r.sender ? "Edit this known sender" : r.catalogue ? `Label every ${r.catalogue.name} source (${r.catalogue.pattern}) as a vendor` : "Mark this source as yours, a vendor, or other";
    labelBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (r.sender) return openSenderForm({ id: r.sender.id, pattern: r.sender.pattern, kind: r.sender.kind, label: r.sender.label });
      if (r.catalogue) return openSenderForm({ pattern: r.catalogue.pattern, kind: "vendor", label: r.catalogue.name });
      openSenderForm({ pattern: r.ip, kind: "ours", label: r.ptr ? r.ptr.split(".").slice(-3).join(".") : "" });
    });
    senderCell.append(" ", labelBtn);
  }
  const verdictCell = document.createElement("td");
  verdictCell.className = `verdict verdict-${r.verdict ? r.verdict.code : "none"}`;
  verdictCell.textContent = r.verdict ? r.verdict.headline : "";
  verdictCell.title = r.verdict ? `${r.verdict.detail}${r.verdict.action ? `\n\n${r.verdict.action}` : ""}` : "";
  return {
    data: r,
    cells: [
      textCell(r.ip, "mono"),
      textCell(r.ptr || "", "mono muted"),
      networkCell(r),
      senderCell,
      textCell(formatNumber(r.total), "num"),
      failCell,
      textCell(formatPct(r.failPct), "num"),
      verdictCell,
      sparklineCell(r),
      textCell(dispositions.join(", ") || (r.failed ? "" : "all passed"), "muted"),
      textCell(`${r.total ? Math.round((r.spfPassed / r.total) * 100) : 0}% / ${r.total ? Math.round((r.dkimPassed / r.total) * 100) : 0}%`, "num"),
      listCell(r.spfDomains.length ? r.spfDomains : r.envelopeFroms),
      listCell(r.dkimDomains),
      listCell(r.reporterNames, { mono: false }),
      textCell(formatUtcDate(Math.max(r.lastSeen - 1, r.firstSeen)), "nowrap")
    ]
  };
}

// Column -> sort key for the sources table; null columns are not sortable.
const IPS_COLUMNS = [
  { label: "Source IP", key: "ip" },
  { label: "Reverse DNS", key: "ptr" },
  { label: "Network", key: "asOrg" },
  { label: "Sender", key: "senderLabel" },
  { label: "Messages", className: "num", key: "total" },
  { label: "Failed", className: "num", key: "failed" },
  { label: "Fail %", className: "num", key: "failPct" },
  { label: "Why it fails", key: "verdict" },
  { label: "Trend", key: null },
  { label: "Failures by action", key: null },
  { label: "SPF / DKIM pass", className: "num", key: "spfPassed" },
  { label: "SPF domain", key: null },
  { label: "DKIM domain", key: null },
  { label: "Reported by", key: "reporters" },
  { label: "Last seen", key: "lastSeen" }
];
const IPS_DESC_FIRST = ["total", "failed", "failPct", "spfPassed", "reporters", "lastSeen"];
let lastIpRows = [];
let ipsSort = (() => {
  try { return JSON.parse(localStorage.getItem("dmarc-ips-sort")) || { key: "failed", dir: "desc" }; } catch { return { key: "failed", dir: "desc" }; }
})();

function sortIpRows(rows) {
  const { key, dir } = ipsSort;
  const sign = dir === "asc" ? 1 : -1;
  const value = (r) => (key === "senderLabel" ? (r.sender ? r.sender.label : "") : key === "verdict" ? (r.verdict ? r.verdict.headline : "") : r[key]);
  return [...rows].sort((a, b) => {
    const va = value(a);
    const vb = value(b);
    if (va === vb) return b.failed - a.failed || b.total - a.total;
    if (va === null || va === undefined || va === "") return 1;
    if (vb === null || vb === undefined || vb === "") return -1;
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * sign;
    return String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" }) * sign;
  });
}

function renderIps() {
  const rows = sortIpRows(lastIpRows);
  ipsCount.textContent = `${rows.length} source${rows.length === 1 ? "" : "s"}`;
  const arrow = ipsSort.dir === "asc" ? " \u25B2" : " \u25BC";
  const table = buildTable(
    IPS_COLUMNS.map((c) => ({ label: c.label + (c.key === ipsSort.key ? arrow : ""), className: `${c.className || ""}${c.key ? " sortable" : ""}`.trim() })),
    rows.map(ipRow),
    { emptyText: failingOnly.checked ? "No failing sources in this period." : "No sources in this period.", onRowClick: (r) => openIpDetail(r.ip) }
  );
  const ths = table.querySelectorAll ? table.querySelectorAll("thead th") : [];
  ths.forEach((th, i) => {
    const col = IPS_COLUMNS[i];
    if (!col || !col.key) return;
    th.title = "Sort by this column";
    th.addEventListener("click", () => {
      ipsSort = ipsSort.key === col.key
        ? { key: col.key, dir: ipsSort.dir === "asc" ? "desc" : "asc" }
        : { key: col.key, dir: IPS_DESC_FIRST.includes(col.key) ? "desc" : "asc" };
      localStorage.setItem("dmarc-ips-sort", JSON.stringify(ipsSort));
      renderIps();
    });
  });
  ipsResults.replaceChildren(table);
}

async function loadIps() {
  const data = await api(`/api/ips${filterQuery({ failing: failingOnly.checked ? 1 : 0, limit: 500, days: 1 })}`);
  lastIpRows = data.ips || [];
  renderIps();
}

function recordRows(records, { showIp = false } = {}) {
  return records.map((rec) => {
    const auth = [];
    for (const d of rec.dkimResults || []) auth.push(`DKIM ${d.domain || "?"}${d.selector ? ` (${d.selector})` : ""}: ${d.result || "?"}`);
    for (const s of rec.spfResults || []) auth.push(`SPF ${s.domain || "?"}: ${s.result || "?"}`);
    const reasons = (rec.reasons || []).map((x) => x.comment ? `${x.type}: ${x.comment}` : x.type).join("; ");
    const cells = [
      textCell(formatWindow(rec.rangeBegin, rec.rangeEnd), "nowrap"),
      textCell(rec.orgName, "nowrap")
    ];
    if (showIp) {
      cells.push(textCell(rec.sourceIp, "mono"));
    }
    cells.push(
      textCell(formatNumber(rec.count), "num"),
      (() => {
        const td = document.createElement("td");
        td.className = "nowrap";
        td.appendChild(resultBadge(rec.passed, rec.disposition));
        if (rec.likelyForward) {
          const fwd = document.createElement("span");
          fwd.className = "pill pill-forward";
          fwd.textContent = "likely forward";
          fwd.title = "The reporter tagged this as forwarded or list mail, or a DKIM signature for the From domain was present but broken";
          td.append(" ", fwd);
        }
        return td;
      })(),
      textCell(`${rec.spfEval || "-"} / ${rec.dkimEval || "-"}`, "mono"),
      textCell(rec.headerFrom || "", "mono"),
      textCell(rec.envelopeFrom || "", "mono muted"),
      listCell(auth, { mono: false, max: 4 }),
      textCell(reasons, "muted")
    );
    return { data: rec, cells };
  });
}

async function openIpDetail(ip) {
  try {
    const d = await api(`/api/ips/${encodeURIComponent(ip)}${filterQuery()}`);
    ipDetailTitle.textContent = ip + (d.ptr ? `  (${d.ptr})` : "");
    ipDetailSummary.replaceChildren(
      kv("Messages", formatNumber(d.total)),
      kv("Failed", `${formatNumber(d.failed)} (${formatPct(d.failPct)})`),
      kv("Seen", `${formatUtcDate(d.firstSeen)} to ${formatUtcDate(Math.max(d.firstSeen, d.lastSeen - 1))}`),
      kv("Network", d.countryCode || d.asOrg ? [flagEmoji(d.countryCode), d.country, d.city, d.asn ? `AS${d.asn}` : null, d.asOrg].filter(Boolean).join(" ") : "not resolved"),
      kv("Sender", d.sender ? `${d.sender.label} (${KIND_LABEL[d.sender.kind] || d.sender.kind}, ${d.sender.pattern})` : "unknown - not labelled"),
      kv("Reported by", d.reporterNames.join(", ")),
      kv("Header From", d.headerFroms.join(", ") || "-"),
      kv("Envelope From", d.envelopeFroms.join(", ") || "-"),
      kv("SPF domains", d.spfDomains.join(", ") || "-"),
      kv("DKIM domains", d.dkimDomains.join(", ") || "-")
    );
    const hint = document.createElement("p");
    hint.className = "bulk-hint";
    hint.textContent = "Click a report below for Exchange Online queries scoped to that report's window and this IP.";
    ipDetailExo.replaceChildren();
    if (d.verdict) {
      const box = document.createElement("div");
      box.className = `verdict-box verdict-${d.verdict.code}`;
      const head = document.createElement("div");
      head.className = "verdict-head";
      head.textContent = d.verdict.headline;
      const detail = document.createElement("p");
      detail.className = "verdict-detail";
      detail.textContent = d.verdict.detail;
      box.append(head, detail);
      if (d.verdict.action) {
        const action = document.createElement("p");
        action.className = "verdict-action";
        action.textContent = d.verdict.action;
        box.appendChild(action);
      }
      if (!d.sender && d.catalogue) {
        const who = document.createElement("p");
        who.className = "verdict-detail";
        who.textContent = `This address looks like ${d.catalogue.name} (${d.catalogue.pattern}). Label it from the sources table if it is a service you use.`;
        box.appendChild(who);
      }
      ipDetailExo.appendChild(box);
    }
    ipDetailExo.appendChild(hint);
    ipDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(d.records || []),
      { expand: (rec) => exoSearchBlock({ begin: rec.rangeBegin, end: rec.rangeEnd, ip: rec.sourceIp, domain: rec.domain, headerFroms: [rec.headerFrom] }) }
    ));
    ipDetail.hidden = false;
    ipDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
    openIp = ip;
    openReport = null;
    writeHash({ ip });
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("ip-detail-close").addEventListener("click", () => { ipDetail.hidden = true; openIp = null; writeHash(); });

function kv(label, value) {
  const div = document.createElement("div");
  div.className = "kv-item";
  const dt = document.createElement("span");
  dt.className = "kv-label";
  dt.textContent = label;
  const dd = document.createElement("span");
  dd.className = "kv-value";
  dd.textContent = value;
  div.append(dt, dd);
  return div;
}
