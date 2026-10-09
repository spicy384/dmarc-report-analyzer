// 23-headers.js: Analyze email headers page.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- email header analysis -----------------------------------------------------------
//
// The pasted text goes to POST /api/headers/analyze and comes back as a structured
// result; it is never put in the page link, local storage or the database.

const hdrInput = document.getElementById("hdr-input");
const hdrFile = document.getElementById("hdr-file");
const hdrStatus = document.getElementById("hdr-status");
const hdrBadge = document.getElementById("hdr-badge");
const hdrResultsPanel = document.getElementById("headers-results-panel");
const hdrVerdicts = document.getElementById("hdr-verdicts");
const hdrSummary = document.getElementById("hdr-summary");
const hdrFindings = document.getElementById("hdr-findings");
const hdrBody = document.getElementById("hdr-body");
const hdrTabState = { tab: "auth" };
const HDR_MAX_FILE_BYTES = 25 * 1024 * 1024;

function hdrPill(label, result, { good = ["pass"], bad = ["fail", "permerror", "softfail"] } = {}) {
  const pill = document.createElement("span");
  const r = String(result || "none").toLowerCase();
  pill.className = `pill ${good.includes(r) ? "pill-pass" : bad.includes(r) ? "pill-reject" : "pill-quarantine"}`;
  pill.textContent = `${label} ${r}`;
  return pill;
}

function hdrDuration(seconds) {
  if (seconds === null || seconds === undefined) return "";
  const s = Math.abs(Math.round(seconds));
  const sign = seconds < 0 ? "-" : "";
  if (s < 60) return `${sign}${s} s`;
  if (s < 3600) return `${sign}${Math.floor(s / 60)} min ${s % 60} s`;
  if (s < 86400) return `${sign}${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  return `${sign}${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}

function hdrBox(title) {
  const box = document.createElement("div");
  box.className = "policy-box";
  const head = document.createElement("div");
  head.className = "policy-box-head";
  const h = document.createElement("h3");
  h.textContent = title;
  head.appendChild(h);
  box.appendChild(head);
  return box;
}

function hdrTable(header, rows, emptyText) {
  const scroll = document.createElement("div");
  scroll.className = "table-scroll";
  scroll.appendChild(buildTable(header, rows, { emptyText }));
  return scroll;
}

function hdrHeading(text) {
  const h = document.createElement("h4");
  h.textContent = text;
  return h;
}

function renderHeaderAuth(a) {
  const box = hdrBox("Authentication");
  const v = a.verdicts;
  const yesNo = (flag) => (flag ? "yes" : "no");
  box.appendChild(hdrHeading(`Alignment with the From domain${a.summary.from && a.summary.from.domain ? ` (${a.summary.from.domain})` : ""}`));
  box.appendChild(hdrTable(
    ["Check", "Result", "Authenticated domain", "Aligned", "Detail"],
    [
      { data: v.spf, cells: [textCell("SPF"), textCell(v.spf.result || "not recorded", v.spf.result === "pass" ? "" : "is-fail"), textCell(v.spf.domain || "-", "mono"), textCell(v.spf.result === "pass" ? yesNo(v.spf.aligned) : "-", v.spf.result === "pass" && !v.spf.aligned ? "is-warn" : ""), textCell(`${v.spf.strict ? "strict alignment (aspf=s). " : ""}${v.spf.comment || ""}`, "muted")] },
      { data: v.dkim, cells: [textCell("DKIM"), textCell(v.dkim.result, v.dkim.result === "pass" ? "" : "is-fail"), textCell(v.dkim.passingDomains.join(", ") || "-", "mono"), textCell(v.dkim.passingDomains.length ? yesNo(v.dkim.aligned) : "-", v.dkim.passingDomains.length && !v.dkim.aligned ? "is-warn" : ""), textCell(`${formatNumber(v.dkim.signatures)} signature${v.dkim.signatures === 1 ? "" : "s"} on the message${v.dkim.strict ? "; strict alignment (adkim=s)" : ""}`, "muted")] },
      { data: v.dmarc, cells: [textCell("DMARC"), textCell(v.dmarc.computed || "cannot tell", v.dmarc.computed === "pass" ? "" : "is-fail"), textCell(v.dmarc.headerFrom || (a.summary.from && a.summary.from.domain) || "-", "mono"), textCell(v.dmarc.computed === "pass" ? `via ${v.dmarc.via.join(" + ")}` : "-"), textCell([v.dmarc.reported ? `receiver recorded dmarc=${v.dmarc.reported}` : "receiver recorded no DMARC result", v.dmarc.action ? `action=${v.dmarc.action}` : "", v.dmarc.policy ? `published policy p=${v.dmarc.policy}` : "", v.dmarc.comment || ""].filter(Boolean).join("; "), "muted")] }
    ]
  ));
  if (a.dmarcRecord && a.dmarcRecord.found) {
    box.appendChild(hdrHeading(`DMARC record of ${a.dmarcRecord.inheritedFrom || (a.summary.from && a.summary.from.domain)} right now`));
    box.appendChild(recordLine(a.dmarcRecord.record));
  }
  a.authResults.forEach((ar, i) => {
    box.appendChild(hdrHeading(`Authentication-Results${ar.authservId ? ` from ${ar.authservId}` : ""}${i === 0 ? " (the newest: the one to trust)" : " (older; could have been added before delivery)"}`));
    box.appendChild(hdrTable(
      ["Method", "Result", "Properties", "Comment"],
      ar.results.map((r) => ({ data: r, cells: [textCell(r.method, "mono"), textCell(r.result, ["pass", "none", "bestguesspass"].includes(r.result) ? "" : "is-fail"), textCell(Object.entries(r.props).map(([k, val]) => `${k}=${val}`).join("  "), "mono"), textCell(r.comment || "", "muted")] })),
      "No results in this header."
    ));
  });
  if (a.receivedSpf) {
    box.appendChild(hdrHeading("Received-SPF"));
    box.appendChild(recordLine(a.receivedSpf.raw));
  }
  if (a.verdicts.arc) {
    box.appendChild(hdrHeading("ARC chain"));
    box.appendChild(hdrTable(["Instance", "Sealed by", "Chain validation"], a.verdicts.arc.seals.map((s) => ({ data: s, cells: [textCell(String(s.instance || "?")), textCell(s.domain || "-", "mono"), textCell(s.cv || "-", s.cv === "fail" ? "is-fail" : "")] })), "No ARC-Seal headers."));
  }
  return box;
}

function renderHeaderPath(a) {
  const box = hdrBox("Path");
  const facts = [];
  if (a.transit.totalSeconds !== null) facts.push(`Total transit ${hdrDuration(a.transit.totalSeconds)} over ${a.hops.length} hop${a.hops.length === 1 ? "" : "s"}, oldest first.`);
  if (a.transit.slowest && a.transit.slowest.seconds > 60) facts.push(`Longest wait: ${hdrDuration(a.transit.slowest.seconds)} before hop ${a.transit.slowest.index}.`);
  if (facts.length) box.appendChild(warningList(facts, "policy-facts"));
  const worst = Math.max(1, ...a.hops.map((h) => h.delaySeconds || 0));
  box.appendChild(hdrTable(
    [{ label: "#", className: "num" }, "Time (UTC)", "Wait", "From", "Address", "By", "Protocol"],
    a.hops.map((h) => {
      const wait = document.createElement("td");
      wait.className = `nowrap${h.delaySeconds !== null && h.delaySeconds > 300 ? " is-warn" : ""}`;
      if (h.delaySeconds !== null) {
        const bar = document.createElement("span");
        bar.className = "hdr-wait-bar";
        bar.style.width = `${Math.max(2, Math.round((Math.max(0, h.delaySeconds) / worst) * 60))}px`;
        wait.append(bar, ` ${hdrDuration(h.delaySeconds)}`);
      }
      return {
        data: h,
        cells: [
          textCell(String(h.index), "num"),
          textCell(h.date ? formatUtcDateTime(h.date) : "no date", "nowrap"),
          wait,
          textCell(h.from || "-", "mono"),
          textCell(h.fromIp ? `${h.fromIp}${h.private ? " (private)" : ""}` : "-", "mono"),
          textCell(h.by || "-", "mono"),
          textCell([h.with, h.tls].filter(Boolean).join(", ") || "-", h.tls ? "" : "muted")
        ]
      };
    }),
    "No Received headers."
  ));
  return box;
}

function renderHeaderSignatures(a) {
  const box = hdrBox("DKIM signatures");
  box.appendChild(hdrTable(
    ["Selector", "Domain", "Result", "Aligned", "Key in DNS", "Algorithm", "Signed", "Notes"],
    a.signatures.map((s) => {
      const notes = [];
      if (!s.signsFrom) notes.push("does not sign From");
      if (s.expired) notes.push(`expired ${formatUtcDate(s.expiresAt)}`);
      if (s.bodyLength !== null) notes.push(`l=${s.bodyLength}`);
      const key = !s.dns ? "not checked" : s.dns.found ? (s.dns.revoked ? "revoked" : `${s.dns.keyType || "key"}${s.dns.keyBits ? ` ${s.dns.keyBits}-bit` : ""}`) : s.dns.error ? `lookup failed: ${s.dns.error}` : "missing";
      return {
        data: s,
        cells: [
          textCell(s.selector || "-", "mono"),
          textCell(s.domain || "-", "mono"),
          textCell(s.result || "not reported", s.result === "pass" ? "" : s.result ? "is-fail" : "muted"),
          textCell(s.aligned ? "yes" : "no", s.aligned ? "" : "is-warn"),
          textCell(key, s.dns && (!s.dns.found || s.dns.weak || s.dns.revoked) ? "is-warn" : ""),
          textCell(`${s.algorithm || "?"}, ${s.canonicalization}`, "muted"),
          textCell(s.signedAt ? formatUtcDateTime(s.signedAt) : "-", "nowrap"),
          textCell(notes.join("; "), notes.length ? "is-warn" : "")
        ]
      };
    }),
    "The message carries no DKIM-Signature header."
  ));
  for (const s of a.signatures) {
    if (!s.signedHeaders.length) continue;
    box.appendChild(warningList([`${s.selector}._domainkey.${s.domain} signs: ${s.signedHeaders.join(", ")}`], "policy-facts"));
  }
  return box;
}

function renderHeaderSource(a) {
  const box = hdrBox("Sending address");
  const s = a.source;
  if (!s) {
    box.appendChild(warningList(["No delivering address could be found in these headers."], "policy-facts"));
    return box;
  }
  const summary = document.createElement("div");
  summary.className = "detail-summary";
  summary.append(
    kv("Address", `${s.ip}${s.private ? " (private range)" : ""}`),
    kv("Taken from", s.how),
    kv("Reverse DNS", s.ptr ? `${s.ptr}${s.ptrConfirmed === true ? " (forward-confirmed)" : s.ptrConfirmed === false ? " (not forward-confirmed)" : ""}` : "none"),
    kv("Network", s.geo ? [s.geo.country, s.geo.city, s.geo.asn ? `AS${s.geo.asn}` : null, s.geo.asOrg].filter(Boolean).join(", ") : "unknown"),
    kv("Known sender", s.known ? `${s.known.label} (${KIND_LABEL[s.known.kind] || s.known.kind}, ${s.known.pattern})` : s.catalogue ? `not labelled; looks like ${s.catalogue.name} (${s.catalogue.pattern})` : "not labelled"),
    kv("In your DMARC reports", s.seen ? `${formatNumber(s.seen.total)} messages, ${formatNumber(s.seen.failed)} failing, last seen ${formatUtcDate(s.seen.lastSeen)}` : "never seen")
  );
  box.appendChild(summary);
  const actions = document.createElement("div");
  actions.className = "actions";
  const lookup = document.createElement("button");
  lookup.type = "button";
  lookup.className = "secondary small";
  lookup.textContent = "Look up this address";
  lookup.addEventListener("click", async () => {
    await setView("dashboard", { scrollTo: "lookup-panel" });
    lookupInput.value = s.ip;
    runLookup();
  });
  actions.appendChild(lookup);
  if (s.seen) {
    const show = document.createElement("button");
    show.type = "button";
    show.className = "secondary small";
    show.textContent = "Show it in the sources";
    show.addEventListener("click", async () => {
      await setView("dashboard", { scrollTo: "sources-panel" });
      searchInput.value = s.ip;
      rangeSelect.value = "90";
      onRangeChanged();
    });
    actions.appendChild(show);
  }
  box.appendChild(actions);
  // A message trace is precise with the Message-ID and the time the message was sent.
  const when = a.summary.date || (a.hops.length && a.hops[a.hops.length - 1].date) || null;
  if (when) {
    box.appendChild(exoSearchBlock({
      begin: when - 3600,
      end: when + 3600,
      ip: s.private ? null : s.ip,
      domain: a.summary.from ? a.summary.from.domain : null,
      messageId: a.summary.messageId,
      sender: a.summary.from ? a.summary.from.address : null,
      exact: true,
      exactSource: "The headers give"
    }));
  }
  return box;
}

function renderHeaderFilter(a) {
  const box = hdrBox("Spam filter");
  const m = a.microsoft;
  if (m) {
    box.appendChild(hdrHeading("Microsoft 365"));
    const rows = [
      ["Spam confidence level (SCL)", m.scl === null ? null : String(m.scl), m.sclMeaning],
      ["Bulk complaint level (BCL)", m.bcl === null ? null : String(m.bcl), m.bclMeaning],
      ["Filtering verdict (SFV)", m.sfv, m.sfvMeaning],
      ["Category (CAT)", m.cat, m.catMeaning],
      ["Composite authentication", m.compauth ? `${m.compauth.result}${m.compauth.reason ? `, reason ${m.compauth.reason}` : ""}` : null, m.compauth ? m.compauth.meaning : null],
      ["Connecting IP (CIP)", m.cip, m.ptr ? `reverse DNS ${m.ptr}` : null],
      ["Country (CTRY) / language", [m.country, m.language].filter(Boolean).join(" / ") || null, null],
      ["Direction (DIR)", m.direction, m.direction === "INB" ? "inbound" : m.direction === "OUT" ? "outbound" : m.direction === "INT" ? "intra-organisation" : null],
      ["IP verdict (IPV)", m.ipVerdict, m.ipVerdict === "CAL" ? "the address is on the connection filter's allow list" : m.ipVerdict === "NLI" ? "the address is on no reputation list" : null],
      ["Authenticated as", m.authAs, m.authAs === "Anonymous" ? "an outside sender" : m.authAs === "Internal" ? "an authenticated internal sender" : null],
      ["Safety tip (SFTY)", m.safety, null]
    ].filter((r) => r[1]);
    box.appendChild(hdrTable(["Stamp", "Value", "Meaning"], rows.map((r) => ({ data: r, cells: [textCell(r[0]), textCell(r[1], "mono"), textCell(r[2] || "", "muted")] })), "No Microsoft stamps."));
  }
  if (a.otherFilters.length) {
    box.appendChild(hdrHeading(m ? "Other markers" : "Markers on the message"));
    box.appendChild(hdrTable(["Header", "Value", "What it is"], a.otherFilters.map((o) => ({ data: o, cells: [textCell(o.name, "mono nowrap"), textCell(o.value, "mono dns-history-value"), textCell(o.meaning, "muted")] })), ""));
  }
  if (!m && !a.otherFilters.length) {
    box.appendChild(warningList(["No spam-filter headers were found (Microsoft 365, SpamAssassin, Barracuda, Proofpoint and Mimecast stamps are recognised)."], "policy-facts"));
  }
  return box;
}

function renderHeaderAll(a) {
  const box = hdrBox("All headers");
  box.appendChild(hdrTable(
    [{ label: "#", className: "num" }, "Header", "Value"],
    a.headers.map((h, i) => ({ data: h, cells: [textCell(String(i + 1), "num muted"), textCell(h.name, "mono nowrap"), textCell(h.value, "mono dns-history-value")] })),
    ""
  ));
  return box;
}

// --- exporting the report -----------------------------------------------------------
//
// Every export is built in the browser from the analysis already on screen: the
// headers are not sent anywhere again. The report carries the raw headers too, so
// whoever receives it can check the conclusions.

let lastHeaderAnalysis = null;

/** The sections of the report as plain data: [{ title, lines: [..] } | { title, columns, rows }]. */
function headerReportSections(a) {
  const v = a.verdicts;
  const who = (p) => (p ? `${p.name ? `${p.name} ` : ""}<${p.address || "?"}>` : "-");
  const sections = [];
  if (a.assessment) {
    const s = a.assessment;
    sections.push({
      title: "Assessment",
      pairs: [
        ["Verdict", `${s.label} (${s.confidence} confidence, score ${s.score > 0 ? "+" : ""}${s.score})`],
        ["In short", s.summary],
        ...s.reasons.map((r) => [r.effect === "spoofed" ? `Against (${Math.abs(r.weight)})` : `For (${r.weight})`, r.text]),
        ...s.caveats.map((c) => ["Caveat", c])
      ]
    });
  }
  sections.push({
    title: "Message",
    pairs: [
      ["Subject", a.summary.subject || "-"],
      ["From", who(a.summary.from)],
      ["Envelope sender (Return-Path)", a.summary.returnPath ? a.summary.returnPath.address || a.summary.returnPath.raw : "-"],
      ["Reply-To", a.summary.replyTo ? a.summary.replyTo.address : "same as From"],
      ["To", a.summary.to || "-"],
      ["Date", a.summary.date ? formatUtcDateTime(a.summary.date) : a.summary.dateRaw || "-"],
      ["Message-ID", a.summary.messageId || "-"]
    ]
  });
  sections.push({
    title: "Verdicts",
    pairs: [
      ["SPF", `${v.spf.result || "not recorded"}${v.spf.domain ? ` for ${v.spf.domain}` : ""}${v.spf.result === "pass" ? (v.spf.aligned ? ", aligned" : ", NOT aligned") : ""}`],
      ["DKIM", `${v.dkim.result}${v.dkim.passingDomains.length ? ` for ${v.dkim.passingDomains.join(", ")}` : ""}${v.dkim.passingDomains.length ? (v.dkim.aligned ? ", aligned" : ", NOT aligned") : ""}`],
      ["DMARC", `${v.dmarc.computed || "cannot tell"}${v.dmarc.via.length ? ` via ${v.dmarc.via.join(" + ")}` : ""}${v.dmarc.reported ? `; receiver recorded ${v.dmarc.reported}` : ""}${v.dmarc.action ? `, action=${v.dmarc.action}` : ""}${v.dmarc.policy ? `; published policy p=${v.dmarc.policy}` : ""}`],
      ...(v.arc ? [["ARC", `${v.arc.sets} set${v.arc.sets === 1 ? "" : "s"}, chain ${v.arc.chain || "unknown"}${v.arc.result ? `, receiver recorded ${v.arc.result}` : ""}`]] : []),
      ...(a.microsoft && a.microsoft.compauth ? [["Composite authentication", `${a.microsoft.compauth.result}${a.microsoft.compauth.reason ? ` (reason ${a.microsoft.compauth.reason})` : ""}${a.microsoft.compauth.meaning ? `: ${a.microsoft.compauth.meaning}` : ""}`]] : []),
      ...(a.dmarcRecord && a.dmarcRecord.found ? [["DMARC record now", a.dmarcRecord.record]] : [])
    ]
  });
  sections.push({ title: "Findings", findings: a.findings });
  a.authResults.forEach((ar, i) => {
    sections.push({
      title: `Authentication-Results${ar.authservId ? ` from ${ar.authservId}` : ""}${i === 0 ? " (newest)" : " (older)"}`,
      columns: ["Method", "Result", "Properties", "Comment"],
      rows: ar.results.map((r) => [r.method, r.result, Object.entries(r.props).map(([k, val]) => `${k}=${val}`).join(" "), r.comment || ""])
    });
  });
  sections.push({
    title: `Path: ${a.hops.length} hop${a.hops.length === 1 ? "" : "s"}, oldest first${a.transit.totalSeconds !== null ? `, ${hdrDuration(a.transit.totalSeconds)} in transit` : ""}`,
    columns: ["#", "Time (UTC)", "Wait", "From", "Address", "By", "Protocol"],
    rows: a.hops.map((h) => [String(h.index), h.date ? formatUtcDateTime(h.date) : "no date", h.delaySeconds === null ? "" : hdrDuration(h.delaySeconds), h.from || "-", h.fromIp ? `${h.fromIp}${h.private ? " (private)" : ""}` : "-", h.by || "-", [h.with, h.tls].filter(Boolean).join(", ") || "-"])
  });
  sections.push({
    title: "DKIM signatures",
    columns: ["Selector", "Domain", "Result", "Aligned", "Key in DNS", "Algorithm", "Notes"],
    rows: a.signatures.map((s) => [
      s.selector || "-", s.domain || "-", s.result || "not reported", s.aligned ? "yes" : "no",
      !s.dns ? "not checked" : s.dns.found ? (s.dns.revoked ? "revoked" : `${s.dns.keyType || "key"}${s.dns.keyBits ? ` ${s.dns.keyBits}-bit` : ""}`) : s.dns.error ? `lookup failed: ${s.dns.error}` : "missing",
      `${s.algorithm || "?"}, ${s.canonicalization}`,
      [!s.signsFrom ? "does not sign From" : "", s.expired ? `expired ${formatUtcDate(s.expiresAt)}` : "", s.bodyLength !== null ? `l=${s.bodyLength}` : ""].filter(Boolean).join("; ")
    ]),
    empty: "The message carries no DKIM-Signature header."
  });
  if (a.source) {
    const s = a.source;
    sections.push({
      title: "Sending address",
      pairs: [
        ["Address", `${s.ip}${s.private ? " (private range)" : ""}`],
        ["Taken from", s.how],
        ["Reverse DNS", s.ptr ? `${s.ptr}${s.ptrConfirmed === true ? " (forward-confirmed)" : s.ptrConfirmed === false ? " (not forward-confirmed)" : ""}` : "none"],
        ["Network", s.geo ? [s.geo.country, s.geo.city, s.geo.asn ? `AS${s.geo.asn}` : null, s.geo.asOrg].filter(Boolean).join(", ") : "unknown"],
        ["Known sender", s.known ? `${s.known.label} (${s.known.kind}, ${s.known.pattern})` : s.catalogue ? `not labelled; looks like ${s.catalogue.name}` : "not labelled"],
        ["In DMARC reports", s.seen ? `${formatNumber(s.seen.total)} messages, ${formatNumber(s.seen.failed)} failing` : "never seen"]
      ]
    });
  }
  if (a.microsoft) {
    const m = a.microsoft;
    sections.push({
      title: "Microsoft 365 spam filter",
      columns: ["Stamp", "Value", "Meaning"],
      rows: [
        ["Spam confidence level (SCL)", m.scl === null ? null : String(m.scl), m.sclMeaning],
        ["Bulk complaint level (BCL)", m.bcl === null ? null : String(m.bcl), m.bclMeaning],
        ["Filtering verdict (SFV)", m.sfv, m.sfvMeaning],
        ["Category (CAT)", m.cat, m.catMeaning],
        ["Connecting IP (CIP)", m.cip, m.ptr ? `reverse DNS ${m.ptr}` : null],
        ["Country / language", [m.country, m.language].filter(Boolean).join(" / ") || null, null],
        ["Direction (DIR)", m.direction, null],
        ["Authenticated as", m.authAs, null]
      ].filter((r) => r[1]).map((r) => [r[0], r[1], r[2] || ""])
    });
  }
  if (a.otherFilters.length) {
    sections.push({ title: "Other markers", columns: ["Header", "Value", "What it is"], rows: a.otherFilters.map((o) => [o.name, o.value, o.meaning]) });
  }
  sections.push({ title: `All headers (${a.headers.length})`, columns: ["#", "Header", "Value"], rows: a.headers.map((h, i) => [String(i + 1), h.name, h.value]), raw: true });
  return sections;
}

function headerReportTitle(a) {
  return `Email header report${a.summary.subject ? `: ${a.summary.subject}` : ""}`;
}

function headerReportFooter() {
  return `Generated ${formatUtcDateTime(Math.floor(Date.now() / 1000))} by DMARC Report Analyzer${currentUser ? ` (${currentUser.username})` : ""}. Results reflect the headers as pasted and DNS at the time of analysis.`;
}

/** Plain text, for tickets and email. */
function headerReportText(a) {
  const out = [headerReportTitle(a), "=".repeat(Math.min(78, headerReportTitle(a).length)), ""];
  const mark = { good: "[ok]  ", bad: "[!!]  ", warn: "[!]   ", info: "[i]   " };
  for (const s of headerReportSections(a)) {
    out.push(s.title, "-".repeat(Math.min(78, s.title.length)));
    if (s.pairs) {
      const width = Math.max(...s.pairs.map((p) => p[0].length));
      for (const [k, val] of s.pairs) out.push(`${k.padEnd(width)}  ${val}`);
    } else if (s.findings) {
      for (const f of s.findings) out.push(`${mark[f.severity] || ""}${f.text}`);
      if (!s.findings.length) out.push("Nothing to report.");
    } else if (s.raw) {
      for (const r of s.rows) out.push(`${r[1]}: ${r[2]}`);
    } else if (!s.rows.length) {
      out.push(s.empty || "None.");
    } else {
      for (const r of s.rows) out.push(r.map((cell, i) => `${s.columns[i]}: ${cell}`).filter((c) => !/: $/.test(c)).join(" | "));
    }
    out.push("");
  }
  out.push(headerReportFooter());
  return out.join("\n");
}

function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
}

/** A self-contained HTML document: inline styles, no scripts, no external requests. */
function headerReportHtml(a) {
  const e = escapeHtml;
  const v = a.verdicts;
  const pill = (label, result, good) => `<span class="pill ${good ? "good" : /fail|error|not aligned/.test(result) ? "bad" : "warn"}">${e(label)} ${e(result)}</span>`;
  const pills = [
    pill("SPF", v.spf.result ? (v.spf.result === "pass" && !v.spf.aligned ? "pass, not aligned" : v.spf.result) : "none", v.spf.result === "pass" && v.spf.aligned),
    pill("DKIM", v.dkim.passingDomains.length ? (v.dkim.aligned ? "pass" : "pass, not aligned") : v.dkim.result, v.dkim.aligned),
    pill("DMARC", v.dmarc.computed || v.dmarc.reported || "unknown", v.dmarc.computed === "pass")
  ];
  if (v.arc) pills.push(pill("ARC", v.arc.result || v.arc.chain || "present", (v.arc.result || v.arc.chain) === "pass"));
  if (a.microsoft && a.microsoft.compauth) pills.push(pill("compauth", a.microsoft.compauth.result, /pass/.test(a.microsoft.compauth.result)));
  const verdict = a.assessment
    ? `<div class="assessment ${e(a.assessment.level)}"><strong>${e(a.assessment.label)}</strong> <span class="conf">(${e(a.assessment.confidence)} confidence)</span><p>${e(a.assessment.summary)}</p></div>`
    : "";
  const body = [];
  for (const s of headerReportSections(a)) {
    body.push(`<h2>${e(s.title)}</h2>`);
    if (s.pairs) {
      body.push(`<table class="kv">${s.pairs.map(([k, val]) => `<tr><th>${e(k)}</th><td>${e(val)}</td></tr>`).join("")}</table>`);
    } else if (s.findings) {
      body.push(s.findings.length ? `<ul class="findings">${s.findings.map((f) => `<li class="${e(f.severity)}">${e(f.text)}</li>`).join("")}</ul>` : "<p>Nothing to report.</p>");
    } else if (!s.rows.length) {
      body.push(`<p>${e(s.empty || "None.")}</p>`);
    } else {
      body.push(`<table class="grid${s.raw ? " raw" : ""}"><thead><tr>${s.columns.map((c) => `<th>${e(c)}</th>`).join("")}</tr></thead><tbody>${s.rows.map((r) => `<tr>${r.map((cell) => `<td>${e(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    }
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(headerReportTitle(a))}</title>
<style>
  body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #1a1a1a; margin: 0; background: #f5f5f4; }
  main { max-width: 1000px; margin: 0 auto; padding: 24px; background: #fff; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  h2 { font-size: 15px; margin: 24px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #e5e5e5; }
  .pills { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 4px; }
  .pill { padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .pill.good { background: #dcfce7; color: #166534; } .pill.bad { background: #fee2e2; color: #991b1b; } .pill.warn { background: #fef3c7; color: #92400e; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; vertical-align: top; padding: 4px 8px; border-bottom: 1px solid #eee; }
  table.kv th { width: 220px; color: #555; font-weight: 600; }
  table.grid th { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: #555; }
  table.grid td, table.kv td { font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-word; }
  table.raw td:nth-child(2) { white-space: nowrap; }
  ul.findings { list-style: none; padding: 0; margin: 0; }
  ul.findings li { padding: 6px 10px; margin: 4px 0; border-left: 4px solid #a3a3a3; background: #fafafa; }
  ul.findings li.good { border-color: #16a34a; } ul.findings li.bad { border-color: #dc2626; } ul.findings li.warn { border-color: #d97706; }
  footer { margin-top: 28px; font-size: 12px; color: #666; }
  .assessment { margin: 12px 0 4px; padding: 10px 14px; border-left: 6px solid #a3a3a3; background: #fafafa; }
  .assessment strong { font-size: 16px; } .assessment .conf { color: #666; font-size: 12px; } .assessment p { margin: 4px 0 0; }
  .assessment.likely-authorized, .assessment.probably-authorized { border-color: #16a34a; }
  .assessment.suspicious { border-color: #d97706; } .assessment.likely-spoofed { border-color: #dc2626; }
  @media print { body { background: #fff; } main { padding: 0; max-width: none; } tr { break-inside: avoid; } }
</style>
</head>
<body>
<main>
<h1>${e(headerReportTitle(a))}</h1>
<div class="pills">${pills.join("")}</div>
${verdict}
${body.join("\n")}
<footer>${e(headerReportFooter())}</footer>
</main>
</body>
</html>
`;
}

function headerReportFileName(a, extension) {
  const slug = String(a.summary.subject || "message").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "message";
  const day = formatUtcDate(a.summary.date || Math.floor(Date.now() / 1000));
  return `email-header-report-${slug}-${day}.${extension}`;
}

function downloadText(fileName, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

document.getElementById("hdr-export-print").addEventListener("click", () => {
  if (lastHeaderAnalysis) printPanel("headers-results-panel", { title: headerReportTitle(lastHeaderAnalysis), meta: headerReportFooter() });
});
document.getElementById("hdr-export-html").addEventListener("click", () => {
  if (!lastHeaderAnalysis) return;
  downloadText(headerReportFileName(lastHeaderAnalysis, "html"), headerReportHtml(lastHeaderAnalysis), "text/html;charset=utf-8");
});
document.getElementById("hdr-export-json").addEventListener("click", () => {
  if (!lastHeaderAnalysis) return;
  downloadText(headerReportFileName(lastHeaderAnalysis, "json"), `${JSON.stringify(lastHeaderAnalysis, null, 2)}\n`, "application/json");
});
document.getElementById("hdr-export-text").addEventListener("click", async () => {
  if (!lastHeaderAnalysis) return;
  const text = headerReportText(lastHeaderAnalysis);
  const ok = await copyToClipboard(text);
  // Where the browser refuses clipboard access, the text is saved as a file instead.
  if (!ok) downloadText(headerReportFileName(lastHeaderAnalysis, "txt"), text, "text/plain;charset=utf-8");
  hdrStatus.hidden = false;
  hdrStatus.textContent = ok ? "Report copied as text." : "The browser would not allow copying, so the text report was downloaded instead.";
});

/** The one-line answer (spoofed, or an authorized sender?) with its reasons, above the details. */
function renderHeaderAssessment(s) {
  const box = document.getElementById("hdr-assessment");
  box.replaceChildren();
  box.hidden = !s;
  if (!s) return;
  box.className = `hdr-assessment level-${s.level}`;
  const head = document.createElement("div");
  head.className = "hdr-assessment-head";
  const label = document.createElement("span");
  label.className = "hdr-assessment-level";
  label.textContent = s.label;
  const conf = document.createElement("span");
  conf.className = `pill pill-sev-${s.confidence === "high" ? "info" : s.confidence === "medium" ? "medium" : "high"}`;
  conf.textContent = `${s.confidence} confidence`;
  head.append(label, conf);
  const summary = document.createElement("p");
  summary.className = "hdr-assessment-summary";
  summary.textContent = s.summary;
  box.append(head, summary);
  if (s.reasons.length) {
    const ul = document.createElement("ul");
    ul.className = "hdr-assessment-reasons";
    for (const r of s.reasons) {
      const li = document.createElement("li");
      li.className = `effect-${r.effect}`;
      li.textContent = `${r.effect === "spoofed" ? "\u2212" : "+"}${Math.abs(r.weight)}  ${r.text}`;
      li.title = r.effect === "spoofed" ? "Points towards a spoofed message" : "Points towards an authorized sender";
      ul.appendChild(li);
    }
    box.appendChild(ul);
  }
  for (const c of s.caveats) {
    const p = document.createElement("p");
    p.className = "hdr-assessment-caveat";
    p.textContent = c;
    box.appendChild(p);
  }
}

function renderHeaderAnalysis(a) {
  lastHeaderAnalysis = a;
  hdrResultsPanel.hidden = false;
  const v = a.verdicts;
  document.getElementById("hdr-title").textContent = a.summary.subject ? `Result: ${a.summary.subject}` : "Result";
  renderHeaderAssessment(a.assessment || null);
  hdrVerdicts.replaceChildren(
    hdrPill("SPF", v.spf.result ? (v.spf.result === "pass" && !v.spf.aligned ? "pass, not aligned" : v.spf.result) : "none", { good: ["pass"] }),
    hdrPill("DKIM", v.dkim.passingDomains.length ? (v.dkim.aligned ? "pass" : "pass, not aligned") : v.dkim.result, { good: ["pass"] }),
    hdrPill("DMARC", v.dmarc.computed || v.dmarc.reported || "unknown", { good: ["pass"] }),
    ...(v.arc ? [hdrPill("ARC", v.arc.result || v.arc.chain || "present", { good: ["pass"], bad: ["fail"] })] : []),
    ...(a.microsoft && a.microsoft.compauth ? [hdrPill("compauth", a.microsoft.compauth.result, { good: ["pass", "softpass"] })] : [])
  );
  const who = (p) => (p ? `${p.name ? `${p.name} ` : ""}<${p.address || "?"}>` : "-");
  hdrSummary.replaceChildren(
    kv("From", who(a.summary.from)),
    kv("Envelope sender (Return-Path)", a.summary.returnPath ? a.summary.returnPath.address || a.summary.returnPath.raw : "-"),
    kv("Reply-To", a.summary.replyTo ? a.summary.replyTo.address : "same as From"),
    kv("To", a.summary.to || "-"),
    kv("Date", a.summary.date ? `${formatUtcDateTime(a.summary.date)} (${formatTimestamp(a.summary.date)})` : a.summary.dateRaw || "-"),
    kv("Message-ID", a.summary.messageId || "-")
  );
  hdrFindings.replaceChildren(...a.findings.map((f) => {
    const li = document.createElement("li");
    li.className = `hdr-finding sev-${f.severity}`;
    li.textContent = f.text;
    return li;
  }));
  hdrBody.replaceChildren();
  const tabs = [
    { key: "auth", label: "Authentication", box: renderHeaderAuth(a) },
    { key: "path", label: `Path (${a.hops.length})`, box: renderHeaderPath(a) },
    { key: "dkim", label: `DKIM signatures (${a.signatures.length})`, box: renderHeaderSignatures(a) },
    { key: "source", label: "Sending address", box: renderHeaderSource(a) },
    { key: "filter", label: "Spam filter", box: renderHeaderFilter(a) },
    { key: "all", label: `All headers (${a.headers.length})`, box: renderHeaderAll(a) }
  ];
  policyTabs(tabs, hdrBody, hdrTabState);
  hdrBadge.textContent = `${formatNumber(a.counts.headers)} headers, ${formatNumber(a.counts.hops)} hops`;
}

async function analyzeHeaders() {
  const raw = hdrInput.value;
  const button = document.getElementById("hdr-analyze");
  if (!raw.trim()) {
    hdrStatus.hidden = false;
    hdrStatus.textContent = "Paste the message headers first.";
    return;
  }
  button.disabled = true;
  hdrStatus.hidden = false;
  hdrStatus.textContent = "Analysing, including DNS lookups for the sender's records...";
  try {
    const result = await api("/api/headers/analyze", { method: "POST", body: JSON.stringify({ raw }) });
    renderHeaderAnalysis(result);
    hdrStatus.hidden = true;
    hdrResultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    hdrStatus.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

/** Keeps only the header block of a saved message, so a large attachment is never uploaded. */
async function loadHeaderFile(file) {
  if (!file) return;
  if (file.size > HDR_MAX_FILE_BYTES) {
    hdrStatus.hidden = false;
    hdrStatus.textContent = "That file is over 25 MB; paste the headers instead.";
    return;
  }
  const text = await file.slice(0, 512 * 1024).text();
  const normalised = text.replace(/\r\n/g, "\n");
  const end = normalised.indexOf("\n\n");
  hdrInput.value = end > 0 ? normalised.slice(0, end) : normalised;
  analyzeHeaders();
}

document.getElementById("hdr-analyze").addEventListener("click", analyzeHeaders);
document.getElementById("hdr-load").addEventListener("click", () => hdrFile.click());
hdrFile.addEventListener("change", () => {
  loadHeaderFile(hdrFile.files[0]);
  hdrFile.value = "";
});
document.getElementById("hdr-clear").addEventListener("click", () => {
  hdrInput.value = "";
  lastHeaderAnalysis = null;
  hdrResultsPanel.hidden = true;
  hdrStatus.hidden = true;
  hdrBadge.textContent = "";
  hdrInput.focus();
});
hdrInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyzeHeaders();
});
for (const type of ["dragenter", "dragover"]) {
  hdrInput.addEventListener(type, (e) => {
    if (e.dataTransfer && [...e.dataTransfer.types].includes("Files")) {
      e.preventDefault();
      hdrInput.classList.add("is-over");
    }
  });
}
for (const type of ["dragleave", "drop"]) {
  hdrInput.addEventListener(type, () => hdrInput.classList.remove("is-over"));
}
hdrInput.addEventListener("drop", (e) => {
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
    e.preventDefault();
    loadHeaderFile(e.dataTransfer.files[0]);
  }
});
