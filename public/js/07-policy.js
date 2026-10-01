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
    spfBox.appendChild(warningList([`${formatNumber(p.spf.networks)} network${p.spf.networks === 1 ? "" : "s"} authorised after expanding includes; ends with ${p.spf.all || "no all mechanism"}`], "policy-facts"));
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
  const dkimBox = policyBox("DKIM selectors seen", { badge: `${p.dkim.length} selector${p.dkim.length === 1 ? "" : "s"}` });
  if (!p.dkim.length) {
    const none = document.createElement("p");
    none.className = "empty-state";
    none.textContent = "No DKIM signatures for this domain appear in the period's reports. Sign outbound mail with DKIM so forwarded mail can still pass.";
    dkimBox.appendChild(none);
  } else {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    dkimBox.appendChild(scroll);
    scroll.appendChild(buildTable(
      ["Selector", "Signing domain", "In DNS", { label: "Pass", className: "num" }, { label: "Fail", className: "num" }, "Last seen"],
      p.dkim.map((s) => ({
        data: s,
        cells: [
          textCell(s.selector, "mono"),
          textCell(s.signingDomain, "mono"),
          textCell(s.found ? (s.revoked ? "revoked (empty key)" : `yes (${s.keyType})`) : s.error ? `lookup failed: ${s.error}` : "missing", s.found && !s.revoked ? "" : "is-fail"),
          textCell(formatNumber(s.passed), "num"),
          textCell(formatNumber(s.failed), s.failed ? "num is-fail" : "num"),
          textCell(formatUtcDate(s.lastSeen), "nowrap")
        ]
      }))
    ));
  }
  tabs.push({ key: "dkim", label: "DKIM selectors", box: dkimBox });

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
