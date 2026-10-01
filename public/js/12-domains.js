// 12-domains.js: Reporters, the domain scorecard, domains and subdomains.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- reporters -------------------------------------------------------------

// --- domain scorecard -----------------------------------------------------------------

const SCORE_LABEL = { ok: "Healthy", warn: "Needs attention", critical: "Not enforced" };

async function loadScorecard() {
  const data = await api(`/api/scorecard${filterQuery()}`);
  const rows = data.domains || [];
  document.getElementById("scorecard-count").textContent = `${rows.length} domain${rows.length === 1 ? "" : "s"}`;
  document.getElementById("scorecard-results").replaceChildren(buildTable(
    ["Domain", "Status", "Policy", { label: "Messages", className: "num" }, { label: "Pass", className: "num" }, { label: "SPF / DKIM", className: "num" }, { label: "Unlabelled failing", className: "num" }, { label: "Spoofed subdomains", className: "num" }, { label: "Reporters", className: "num" }, "Last report", "What to do"],
    rows.map((d) => {
      const policy = d.policy.p ? `p=${d.policy.p}${d.policy.sp ? ` sp=${d.policy.sp}` : ""}${d.policy.pct !== null && d.policy.pct < 100 ? ` pct=${d.policy.pct}` : ""}` : "none seen";
      const status = textCell(SCORE_LABEL[d.status] || d.status, `score score-${d.status} nowrap`);
      return {
        data: d,
        cells: [
          textCell(d.domain, "mono"),
          status,
          textCell(policy, d.policy.p === "reject" ? "mono" : "mono is-warn"),
          textCell(formatNumber(d.total), "num"),
          textCell(formatPct(d.passPct), d.passPct < 90 ? "num is-fail" : "num"),
          textCell(`${formatPct(d.spfPct)} / ${formatPct(d.dkimPct)}`, "num muted"),
          textCell(formatNumber(d.unlabelledFailingSources), d.unlabelledFailingSources ? "num is-fail" : "num muted"),
          textCell(formatNumber(d.unusedSubdomains), d.unusedSubdomains ? "num is-fail" : "num muted"),
          textCell(formatNumber(d.reporters), "num"),
          textCell(d.lastSeen ? `${formatUtcDate(d.lastSeen - 1)}${d.silentDays > 7 ? ` (${d.silentDays} days ago)` : ""}` : "never", d.silentDays > 7 ? "nowrap is-warn" : "nowrap"),
          textCell(d.issues.join("; "), "score-issues")
        ]
      };
    }),
    {
      emptyText: "No reports in this period.",
      onRowClick: (d) => {
        domainSelect.value = d.domain;
        if (domainSelect.value !== d.domain) return;
        reportsPage = 1;
        loadAll();
      }
    }
  ));
}

// --- domains and subdomains ---------------------------------------------------------

function subdomainNote(d) {
  if (d.relation === "other") return { text: "From domain is outside the report's domain; the reporter grouped it here.", tone: "muted" };
  if (d.relation === "parent") return { text: `Parent domain; policy p=${d.appliedPolicy || "?"}.`, tone: "muted" };
  const policy = d.appliedPolicy ? `${d.inheritsPolicy ? "inherits p=" : "sp="}${d.appliedPolicy}` : "policy unknown";
  if (d.unused) {
    return d.appliedPolicy === "reject"
      ? { text: `Only failures, so nobody sends from here legitimately; ${policy} already blocks it.`, tone: "good" }
      : { text: `Only failures, so nobody sends from here legitimately: spoofing. ${policy}; set sp=reject to block it.`, tone: "bad" };
  }
  return { text: `In use (${formatPct(100 - d.failPct)} pass); ${policy}.`, tone: d.failPct > 50 ? "warn" : "muted" };
}

async function loadSubdomains() {
  const data = await api(`/api/subdomains${filterQuery()}`);
  const rows = data.subdomains || [];
  document.getElementById("subdomains-count").textContent = `${rows.length} domain${rows.length === 1 ? "" : "s"}`;
  document.getElementById("subdomains-results").replaceChildren(buildTable(
    ["From domain", "Report domain", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, { label: "Fail %", className: "num" }, { label: "Sources", className: "num" }, "Last seen", "What it means"],
    rows.map((d) => {
      const note = subdomainNote(d);
      return {
        data: d,
        cells: [
          textCell(d.domain || "(empty)", d.relation === "subdomain" ? "mono" : "mono muted"),
          textCell(d.policyDomain, "mono muted"),
          textCell(formatNumber(d.total), "num"),
          textCell(formatNumber(d.failed), d.failed ? "num is-fail" : "num"),
          textCell(formatPct(d.failPct), "num"),
          textCell(`${formatNumber(d.sources)}${d.failingSources ? ` (${formatNumber(d.failingSources)} failing)` : ""}`, "num"),
          textCell(formatUtcDate(Math.max(d.lastSeen - 1, d.firstSeen)), "nowrap"),
          textCell(note.text, `subdomain-note tone-${note.tone}`)
        ]
      };
    }),
    {
      emptyText: "No records in this period.",
      onRowClick: (d) => {
        searchInput.value = d.domain;
        reportsPage = 1;
        loadAll();
        document.getElementById("sources-panel").scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  ));
}

async function loadReporters() {
  const data = await api(`/api/reporters${filterQuery()}`);
  const rows = data.reporters || [];
  reportersCount.textContent = `${rows.length} reporter${rows.length === 1 ? "" : "s"}`;
  reportersResults.replaceChildren(buildTable(
    ["Reporter", "Contact", { label: "Reports", className: "num" }, { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, { label: "Fail %", className: "num" }, "First report", "Latest report"],
    rows.map((r) => ({
      data: r,
      cells: [
        textCell(r.orgName),
        textCell(r.orgEmail || "", "mono muted"),
        textCell(formatNumber(r.reports), "num"),
        textCell(formatNumber(r.messages), "num"),
        textCell(formatNumber(r.failed), r.failed ? "num is-fail" : "num"),
        textCell(formatPct(r.failPct), "num"),
        textCell(formatUtcDate(r.firstSeen), "nowrap"),
        textCell(formatUtcDate(Math.max(r.firstSeen, r.lastSeen - 1)), "nowrap")
      ]
    })),
    { emptyText: "No reports in this period." }
  ));

  // Keep the Reports panel's reporter dropdown in step with who actually reported.
  const current = reporterFilter.value;
  reporterFilter.replaceChildren();
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All";
  reporterFilter.appendChild(all);
  for (const r of rows) {
    const opt = document.createElement("option");
    opt.value = r.orgName;
    opt.textContent = r.orgName;
    reporterFilter.appendChild(opt);
  }
  reporterFilter.value = current;
  if (reporterFilter.value !== current) reporterFilter.value = "";
}
