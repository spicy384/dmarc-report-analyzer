// 07-policy.js: Policy readiness: DMARC, SPF, DKIM and what reject would do.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- policy readiness ---------------------------------------------------------

const policyDomain = document.getElementById("policy-domain");
const policyBody = document.getElementById("policy-body");
const policyBadge = document.getElementById("policy-badge");
const policyRefresh = document.getElementById("policy-refresh");

function populatePolicyDomains(domains) {
  const current = policyDomain.value;
  policyDomain.replaceChildren();
  for (const d of domains) {
    const opt = document.createElement("option");
    opt.value = d.domain;
    opt.textContent = d.domain;
    policyDomain.appendChild(opt);
  }
  policyDomain.value = domainSelect.value || current;
  if (!policyDomain.value && policyDomain.options.length) {
    policyDomain.value = policyDomain.options[0].value;
  }
}

policyDomain.addEventListener("change", () => loadPolicy());
policyRefresh.addEventListener("click", () => loadPolicy({ refresh: true }));

function policyBox(title, { badge, badgeClass } = {}) {
  const box = document.createElement("div");
  box.className = "policy-box";
  const head = document.createElement("div");
  head.className = "policy-box-head";
  const h = document.createElement("h3");
  h.textContent = title;
  head.appendChild(h);
  if (badge) {
    const b = document.createElement("span");
    b.className = `pill ${badgeClass || ""}`;
    b.textContent = badge;
    head.appendChild(b);
  }
  box.appendChild(head);
  box.policyBadge = badge ? { badge, badgeClass } : null;
  return box;
}

function recordLine(text) {
  const pre = document.createElement("pre");
  pre.className = "policy-record mono";
  pre.textContent = text;
  return pre;
}

function warningList(items, className = "policy-warnings") {
  const ul = document.createElement("ul");
  ul.className = className;
  for (const w of items) {
    const li = document.createElement("li");
    li.textContent = w;
    ul.appendChild(li);
  }
  return ul;
}

function sourceList(sources, unit) {
  const ul = document.createElement("ul");
  ul.className = "policy-sources";
  for (const s of sources) {
    const li = document.createElement("li");
    const ip = document.createElement("span");
    ip.className = "mono";
    ip.textContent = s.ip;
    li.appendChild(ip);
    li.append(` ${formatNumber(s.count)} ${unit}${s.sender ? ` - ${s.sender}` : s.ptr ? ` - ${s.ptr}` : ""}`);
    ul.appendChild(li);
  }
  return ul;
}

const DNS_KIND_LABELS = { dmarc: "DMARC", spf: "SPF", mta_sts: "MTA-STS", mta_sts_policy: "MTA-STS policy", tlsrpt: "TLS-RPT" };

/**
 * One box for transport security: the MTA-STS record and policy with MX coverage,
 * the TLS-RPT record, and (when given) what the TLS reports for the period say.
 * Shared by the Policy panel and the Lookup panel.
 */
function transportBox(sts, rpt, { tlsSummary = null } = {}) {
  const mode = sts.found && sts.policy ? sts.policy.mode : null;
  const box = policyBox("MTA-STS and TLS-RPT", {
    badge: !sts.found ? "no MTA-STS" : !sts.policy ? "policy unreachable" : `MTA-STS ${mode || "?"}`,
    badgeClass: mode === "enforce" ? "pill-pass" : mode === "testing" ? "pill-quarantine" : "pill-reject"
  });

  const h1 = document.createElement("h4");
  h1.textContent = "MTA-STS";
  box.appendChild(h1);
  if (sts.found) {
    box.appendChild(recordLine(sts.record));
    const facts = [];
    if (sts.policy) {
      facts.push(`Policy ${sts.policy.mode || "?"}${Number.isFinite(sts.policy.maxAge) ? `, cached by senders for ${formatDurationShort(sts.policy.maxAge)}` : ""}${sts.id ? `, id ${sts.id}` : ""}`);
      if (sts.policy.mx.length) facts.push(`Allowed MX: ${sts.policy.mx.join(", ")}`);
      if (sts.mxCoverage && sts.mxCoverage.length) facts.push(`MX hosts covered: ${sts.mxCoverage.filter((m) => m.covered).length} of ${sts.mxCoverage.length}`);
      if (sts.policyUnchangedSince) facts.push(`Policy unchanged since at least ${formatUtcDate(sts.policyUnchangedSince)} (daily snapshots)`);
    } else {
      facts.push(`Policy file: ${sts.policyUrl}`);
    }
    if (sts.unchangedSince) facts.push(`Record unchanged since at least ${formatUtcDate(sts.unchangedSince)} (daily snapshots)`);
    box.appendChild(warningList(facts, "policy-facts"));
    if (sts.policyText) {
      const pre = recordLine(sts.policyText);
      pre.title = sts.policyUrl;
      box.appendChild(pre);
    }
  }
  if (sts.warnings && sts.warnings.length) box.appendChild(warningList(sts.warnings));

  const h2 = document.createElement("h4");
  h2.textContent = "TLS-RPT";
  box.appendChild(h2);
  if (rpt.found) {
    box.appendChild(recordLine(rpt.record));
    const facts = [`TLS reports to ${(rpt.rua || []).join(", ") || "nobody"}${rpt.toUs ? " (this analyzer)" : ""}`];
    if (rpt.unchangedSince) facts.push(`Record unchanged since at least ${formatUtcDate(rpt.unchangedSince)} (daily snapshots)`);
    box.appendChild(warningList(facts, "policy-facts"));
  }
  if (rpt.warnings && rpt.warnings.length) box.appendChild(warningList(rpt.warnings));

  if (tlsSummary && tlsSummary.reports) {
    const total = (tlsSummary.successful || 0) + (tlsSummary.failed || 0);
    const facts = [`${formatNumber(tlsSummary.reports)} TLS report${tlsSummary.reports === 1 ? "" : "s"} in this period from ${formatNumber(tlsSummary.reporters)} sender${tlsSummary.reporters === 1 ? "" : "s"}: ${formatNumber(tlsSummary.successful)} sessions succeeded, ${formatNumber(tlsSummary.failed)} failed${total ? ` (${(100 * (tlsSummary.failed || 0) / total).toFixed(1)}%)` : ""}.`];
    for (const t of (tlsSummary.byType || []).slice(0, 4)) facts.push(`${formatNumber(t.sessions)} × ${t.resultType}`);
    box.appendChild(warningList(facts, tlsSummary.failed ? "policy-warnings" : "policy-facts"));
  }
  return box;
}

function formatDurationShort(seconds) {
  const s = Number(seconds) || 0;
  if (s >= 7 * 86400) return `${Math.round(s / 86400)} days`;
  if (s >= 86400) return `${Math.round(s / 3600)} hours`;
  if (s >= 3600) return `${Math.round(s / 3600)} h`;
  return `${s} s`;
}

// The four sections are tabs: side by side they squeezed each other and the
// DKIM table spilled into the next column. The chosen tab survives a re-render
// (domain change, Re-check DNS) so the user stays where they were.
const policyTabState = { tab: "dmarc" };

function policyTabs(boxes, container = policyBody, state = policyTabState) {
  const bar = document.createElement("div");
  bar.className = "tabs policy-tabs";
  bar.setAttribute("role", "tablist");
  const show = (key) => {
    state.tab = key;
    for (const b of boxes) {
      const active = b.key === key;
      b.button.classList.toggle("is-active", active);
      b.button.setAttribute("aria-selected", active ? "true" : "false");
      b.box.hidden = !active;
    }
  };
  for (const b of boxes) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "tab";
    button.setAttribute("role", "tab");
    button.textContent = b.label;
    const badge = b.box.policyBadge;
    if (badge) {
      const pill = document.createElement("span");
      pill.className = `pill ${badge.badgeClass || ""}`;
      pill.textContent = badge.badge;
      button.append(" ", pill);
    }
    // The tab already carries the title and badge.
    const head = b.box.querySelector(".policy-box-head");
    if (head) head.remove();
    button.addEventListener("click", () => show(b.key));
    b.button = button;
    b.box.classList.add("tab-panel");
    bar.appendChild(button);
  }
  container.appendChild(bar);
  for (const b of boxes) container.appendChild(b.box);
  show(boxes.some((b) => b.key === state.tab) ? state.tab : boxes[0].key);
}

function renderPolicy(p) {
  policyBody.replaceChildren();
  const tags = p.dmarc.tags || {};
  const tabs = [];

  // --- DMARC record ---
  const level = !p.dmarc.found ? "none" : tags.p || "none";
  const dmarcBox = policyBox("DMARC record", {
    badge: p.dmarc.found ? `p=${tags.p || "?"}${p.dmarc.inheritedFrom ? ` (from ${p.dmarc.inheritedFrom})` : ""}` : "missing",
    badgeClass: level === "reject" ? "pill-pass" : level === "quarantine" ? "pill-quarantine" : "pill-reject"
  });
  if (p.dmarc.found) {
    dmarcBox.appendChild(recordLine(p.dmarc.record));
    const facts = [];
    facts.push(`Policy ${tags.p || "?"}${tags.sp ? `, subdomains ${tags.sp}` : ""}${tags.pct !== undefined ? `, applied to ${tags.pct}%` : ""}`);
    facts.push(`Alignment: DKIM ${tags.adkim === "s" ? "strict" : "relaxed"}, SPF ${tags.aspf === "s" ? "strict" : "relaxed"}`);
    facts.push(`Aggregate reports to ${(tags.rua || []).join(", ") || "nobody"}${p.dmarc.ruaToUs ? " (this analyzer)" : ""}`);
    if (tags.ruf && tags.ruf.length) facts.push(`Forensic reports to ${tags.ruf.join(", ")}`);
    if (p.dmarc.unchangedSince) facts.push(`Unchanged since at least ${formatUtcDate(p.dmarc.unchangedSince)} (daily snapshots)`);
    dmarcBox.appendChild(warningList(facts, "policy-facts"));
  }
  if (p.dmarc.warnings && p.dmarc.warnings.length) dmarcBox.appendChild(warningList(p.dmarc.warnings));
  tabs.push({ key: "dmarc", label: "DMARC record", box: dmarcBox });

  // --- SPF record ---
  const spfBox = policyBox("SPF record", {
    badge: p.spf.found ? `${p.spf.lookups} of 10 lookups` : "missing",
    badgeClass: !p.spf.found || p.spf.tooManyLookups ? "pill-reject" : p.spf.lookups >= 8 ? "pill-quarantine" : "pill-pass"
  });
  if (p.spf.found) {
    spfBox.appendChild(recordLine(p.spf.record));
    const spfFacts = [`${formatNumber(p.spf.networks)} network${p.spf.networks === 1 ? "" : "s"} authorised after expanding includes; ends with ${p.spf.all || "no all mechanism"}`];
    if (p.spf.unchangedSince) spfFacts.push(`Unchanged since at least ${formatUtcDate(p.spf.unchangedSince)} (daily snapshots)`);
    spfBox.appendChild(warningList(spfFacts, "policy-facts"));
  }
  const spfIssues = [...(p.spf.warnings || []), ...(p.spf.errors || [])];
  if (spfIssues.length) spfBox.appendChild(warningList(spfIssues));
  if (p.yoursOutsideSpf.length) {
    spfBox.appendChild(warningList([`${p.yoursOutsideSpf.length} of your labelled sources fail SPF and are not in the record: ${p.yoursOutsideSpf.map((s) => `${s.ip} (${s.sender})`).join(", ")}. Add them, or make sure they sign with DKIM.`]));
  }
  if (p.failingInsideSpf.length) {
    spfBox.appendChild(warningList([`${p.failingInsideSpf.length} source${p.failingInsideSpf.length === 1 ? "" : "s"} authorised by SPF still fail DMARC (alignment or DKIM problem, or a shared provider range): ${p.failingInsideSpf.slice(0, 5).map((s) => `${s.ip} via ${s.via}`).join(", ")}${p.failingInsideSpf.length > 5 ? ", ..." : ""}.`], "policy-facts"));
  }
  tabs.push({ key: "spf", label: "SPF record", box: spfBox });

  // --- DKIM selectors ---
  // Key hygiene: weak or unparsable keys, testing mode, selectors that sign mail but
  // have no key in DNS, and keys that have stood for over a year.
  const hygiene = [];
  const nowSeconds = Math.floor(Date.now() / 1000);
  for (const s of p.dkim) {
    const name = `${s.selector}._domainkey.${s.signingDomain}`;
    if (!s.found && !s.error) hygiene.push(`${name} signed ${formatNumber(s.passed + s.failed)} messages in the period but has no key in DNS: the selector was removed, or the signer is misconfigured.`);
    for (const w of s.warnings || []) hygiene.push(`${name}: ${w}`);
    if (s.found && !s.revoked && s.unchangedSince && nowSeconds - s.unchangedSince > 365 * 86400) hygiene.push(`${name} has not changed since ${formatUtcDate(s.unchangedSince)}: rotate DKIM keys at least yearly.`);
  }
  const dkimBox = policyBox("DKIM selectors seen", {
    badge: hygiene.length ? `${hygiene.length} warning${hygiene.length === 1 ? "" : "s"}` : `${p.dkim.length} selector${p.dkim.length === 1 ? "" : "s"}`,
    badgeClass: hygiene.length ? "pill-quarantine" : ""
  });
  if (!p.dkim.length) {
    const none = document.createElement("p");
    none.className = "empty-state";
    none.textContent = "No DKIM signatures for this domain appear in the period's reports. Sign outbound mail with DKIM so forwarded mail can still pass.";
    dkimBox.appendChild(none);
  } else {
    if (hygiene.length) dkimBox.appendChild(warningList(hygiene));
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    dkimBox.appendChild(scroll);
    const keyText = (s) => {
      if (!s.found) return "-";
      if (s.revoked) return "revoked";
      return `${s.keyType}${s.keyBits ? ` ${formatNumber(s.keyBits)}-bit` : ""}${s.testing ? ", testing" : ""}`;
    };
    scroll.appendChild(buildTable(
      ["Selector", "Signing domain", "In DNS", "Key", { label: "Pass", className: "num" }, { label: "Fail", className: "num" }, "Last seen", "Unchanged since"],
      p.dkim.map((s) => ({
        data: s,
        cells: [
          textCell(s.selector, "mono"),
          textCell(s.signingDomain, "mono"),
          textCell(s.found ? (s.revoked ? "revoked (empty key)" : "yes") : s.error ? `lookup failed: ${s.error}` : "missing", s.found && !s.revoked ? "" : "is-fail"),
          textCell(keyText(s), s.weak || s.testing ? "is-warn" : ""),
          textCell(formatNumber(s.passed), "num"),
          textCell(formatNumber(s.failed), s.failed ? "num is-fail" : "num"),
          textCell(formatUtcDate(s.lastSeen), "nowrap"),
          textCell(s.unchangedSince ? formatUtcDate(s.unchangedSince) : "-", "nowrap muted")
        ]
      }))
    ));
  }
  tabs.push({ key: "dkim", label: "DKIM selectors", box: dkimBox });

  // --- transport security: MTA-STS and TLS-RPT ---
  if (p.transport) {
    tabs.push({ key: "transport", label: "MTA-STS / TLS-RPT", box: transportBox(p.transport.mtaSts, p.transport.tlsRpt, { tlsSummary: p.transport.tlsSummary }) });
  }

  // --- record history ---
  // One row per distinct value the daily snapshot has seen; the first row of each
  // record is the baseline, every further one is a change.
  const history = p.history || [];
  const seenRecords = new Set(history.map((h) => `${h.kind}:${h.selector}:${h.domain}`));
  const changes = history.length - seenRecords.size;
  const historyBox = policyBox("DNS record history", {
    badge: history.length ? (changes ? `${changes} change${changes === 1 ? "" : "s"}` : "no changes yet") : "no snapshot yet",
    badgeClass: changes ? "pill-quarantine" : ""
  });
  if (!history.length) {
    const none = document.createElement("p");
    none.className = "empty-state";
    none.textContent = "The analyzer snapshots this domain's DMARC, SPF and DKIM records once a day and alerts when one changes. The first snapshot runs a minute after start-up; administrators can run it now under Settings → Monitoring.";
    historyBox.appendChild(none);
  } else {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    historyBox.appendChild(scroll);
    const label = (h) => (h.kind === "dkim" ? `DKIM ${h.selector}._domainkey.${h.domain}` : `${DNS_KIND_LABELS[h.kind] || h.kind.toUpperCase()} ${h.domain}`);
    scroll.appendChild(buildTable(
      ["Record", "Value", "First seen", "Last seen"],
      history.map((h) => ({
        data: h,
        cells: [
          textCell(label(h), "nowrap"),
          textCell(h.found ? h.value : "(no record)", h.found ? "mono dns-history-value" : "is-fail"),
          textCell(formatUtcDate(h.first_seen), "nowrap"),
          textCell(formatUtcDate(h.last_seen), "nowrap")
        ]
      }))
    ));
  }
  tabs.push({ key: "history", label: "History", box: historyBox });

  // --- what reject would do ---
  const r = p.reject;
  const ready = r.legitimateRejected.messages === 0 && r.unlabelledFailingSources === 0;
  const rejectBox = policyBox("What p=reject would have done in this period", {
    badge: ready ? "ready" : r.legitimateRejected.messages > 0 ? "not yet" : "label sources first",
    badgeClass: ready ? "pill-pass" : "pill-quarantine"
  });
  const lines = document.createElement("div");
  lines.className = "policy-reject";
  const row = (label, value, sub, tone) => {
    const div = document.createElement("div");
    div.className = `policy-reject-row${tone ? ` tone-${tone}` : ""}`;
    lines.appendChild(div);
    const v = document.createElement("strong");
    v.textContent = formatNumber(value);
    const l = document.createElement("span");
    l.textContent = ` ${label}`;
    div.append(v, l);
    if (sub) {
      const s = document.createElement("div");
      s.className = "policy-reject-sub";
      s.textContent = sub;
      div.appendChild(s);
    }
    return div;
  };
  let card = row("legitimate messages rejected", r.legitimateRejected.messages, "from sources you labelled ours or vendor that fail DMARC; fix their SPF/DKIM before tightening", r.legitimateRejected.messages ? "bad" : "good");
  if (r.legitimateRejected.sources.length) card.appendChild(sourceList(r.legitimateRejected.sources, "failed"));
  card = row("spoofed messages blocked", r.spoofingBlocked.messages, `from ${r.unlabelledFailingSources ? `${r.unlabelledFailingSources} unlabelled and ` : ""}other sources; the point of the policy`, "good");
  if (r.spoofingBlocked.sources.length) card.appendChild(sourceList(r.spoofingBlocked.sources, "failed"));
  card = row("forwarded messages lost", r.forwardsLost.messages, "likely forwards and list mail that fails because it was modified in transit; unavoidable with reject, acceptable for most domains", r.forwardsLost.messages ? "warn" : "good");
  if (r.forwardsLost.sources.length) card.appendChild(sourceList(r.forwardsLost.sources, "forwarded"));
  row("messages unaffected", r.passing, "passed DMARC and would still be delivered");
  rejectBox.appendChild(lines);
  tabs.push({ key: "reject", label: "If p=reject", box: rejectBox });
  policyTabs(tabs);

  policyBadge.textContent = ready ? "Ready for reject" : r.legitimateRejected.messages > 0 ? "Fix your senders first" : "Label your sources";
  policyBadge.className = `badge ${ready ? "badge-ok" : "badge-warn"}`;
}

async function loadPolicy({ refresh = false } = {}) {
  const domain = policyDomain.value;
  if (!domain) {
    policyBody.replaceChildren();
    const p = document.createElement("p");
    p.className = "empty-state";
    p.textContent = "No reports yet, so no domain to check.";
    policyBody.appendChild(p);
    policyBadge.textContent = "";
    return;
  }
  policyBadge.textContent = refresh ? "Checking DNS..." : "Loading...";
  policyBadge.className = "badge";
  try {
    const data = await api(`/api/policy${filterQuery({ domain, refresh: refresh ? 1 : undefined })}`);
    renderPolicy(data);
  } catch (error) {
    policyBadge.textContent = "";
    policyBody.replaceChildren();
    const p = document.createElement("p");
    p.className = "empty-state";
    p.textContent = error.message;
    policyBody.appendChild(p);
  }
}
