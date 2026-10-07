// 20-tls.js: SMTP TLS reports (RFC 8460) panel.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- TLS reports ------------------------------------------------------------------

const tlsPanel = document.getElementById("tls-panel");
const tlsCountBadge = document.getElementById("tls-count");
const tlsTiles = document.getElementById("tls-tiles");
const tlsBreakdown = document.getElementById("tls-breakdown");
const tlsResults = document.getElementById("tls-results");
const tlsPrev = document.getElementById("tls-prev");
const tlsNext = document.getElementById("tls-next");
const tlsPageLabel = document.getElementById("tls-page-label");
let tlsPage = 1;

tlsPrev.addEventListener("click", () => { tlsPage = Math.max(1, tlsPage - 1); run(loadTls); });
tlsNext.addEventListener("click", () => { tlsPage += 1; run(loadTls); });

const TLS_RESULT_MEANING = {
  "starttls-not-supported": "the receiving server did not offer STARTTLS",
  "certificate-host-mismatch": "the certificate does not match the MX host name",
  "certificate-expired": "the certificate has expired",
  "certificate-not-trusted": "the certificate chain is not trusted",
  "validation-failure": "the certificate failed validation for another reason",
  "tlsa-invalid": "the DANE TLSA record is invalid",
  "dnssec-invalid": "DNSSEC validation of the TLSA record failed",
  "dane-required": "DANE was required but could not be used",
  "sts-policy-fetch-error": "the MTA-STS policy could not be fetched over HTTPS",
  "sts-policy-invalid": "the MTA-STS policy file is invalid",
  "sts-webpki-invalid": "the MTA-STS policy host's certificate is invalid"
};

function tlsModeCell(r) {
  const label = r.policyType === "no-policy-found" ? "no policy" : r.policyType === "tlsa" ? "DANE" : r.policyMode ? `STS ${r.policyMode}` : r.policyType || "?";
  const cls = r.policyType === "no-policy-found" ? "is-warn" : r.policyMode === "testing" ? "is-warn" : "";
  return textCell(label, `nowrap ${cls}`);
}

function tlsDetail(r) {
  const wrap = document.createElement("div");
  const summary = document.createElement("div");
  summary.className = "detail-summary";
  summary.append(
    kv("Reporter", `${r.orgName}${r.contactInfo ? ` (${r.contactInfo})` : ""}`),
    kv("Report id", r.reportId),
    kv("Window", `${formatUtcDateTime(r.rangeBegin)} to ${formatUtcDateTime(r.rangeEnd)} UTC`),
    kv("Policy", `${r.policyType || "?"}${r.policyMode ? `, mode ${r.policyMode}` : ""}${r.mxHosts.length ? `; mx ${r.mxHosts.join(", ")}` : ""}`),
    kv("Sessions", `${formatNumber(r.successful)} succeeded, ${formatNumber(r.failed)} failed`)
  );
  wrap.appendChild(summary);
  if (r.policyString && r.policyString.length) {
    const pre = document.createElement("pre");
    pre.className = "policy-record mono";
    pre.textContent = r.policyString.join("\n");
    wrap.appendChild(pre);
  }
  if (r.failures && r.failures.length) {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.appendChild(buildTable(
      ["Failure", "Sending MTA", "Receiving MX", "Receiving IP", { label: "Sessions", className: "num" }, "Detail"],
      r.failures.map((f) => ({
        data: f,
        cells: [
          textCell(f.resultType, "nowrap is-fail"),
          textCell(f.sendingMtaIp || "-", "mono"),
          textCell(f.receivingMxHostname || f.receivingMxHelo || "-", "mono"),
          textCell(f.receivingIp || "-", "mono"),
          textCell(formatNumber(f.failedSessionCount), "num"),
          textCell([TLS_RESULT_MEANING[f.resultType], f.failureReasonCode, f.additionalInformation].filter(Boolean).join("; "), "muted")
        ]
      }))
    ));
    wrap.appendChild(scroll);
  } else {
    const p = document.createElement("p");
    p.className = "empty-state";
    p.textContent = "Every session in this report succeeded.";
    wrap.appendChild(p);
  }
  const actions = document.createElement("div");
  actions.className = "row-actions";
  const dl = document.createElement("a");
  dl.className = "button-link secondary small";
  dl.href = apiPath(`/api/tls/${encodeURIComponent(r.id)}/json`);
  dl.setAttribute("download", "");
  dl.textContent = "Download JSON";
  actions.appendChild(dl);
  wrap.appendChild(actions);
  return wrap;
}

function renderTlsSummary(s) {
  const total = (s.successful || 0) + (s.failed || 0);
  const failPct = total ? (100 * (s.failed || 0)) / total : 0;
  tlsTiles.replaceChildren(
    statTile("TLS sessions", formatNumber(total), { sub: `${formatNumber(s.reports)} report${s.reports === 1 ? "" : "s"} from ${formatNumber(s.reporters)} sender${s.reporters === 1 ? "" : "s"}` }),
    statTile("Succeeded", formatNumber(s.successful), { tone: "good" }),
    statTile("Failed", formatNumber(s.failed), { sub: total ? `${failPct.toFixed(failPct && failPct < 10 ? 1 : 0)}% of sessions` : "", tone: s.failed ? "bad" : "good" }),
    statTile("Policy mode seen", s.enforceReports && !s.testingReports ? "enforce" : s.testingReports ? `testing${s.enforceReports ? " + enforce" : ""}` : s.noPolicyReports ? "none found" : "-", { small: true, sub: s.noPolicyReports ? `${formatNumber(s.noPolicyReports)} report${s.noPolicyReports === 1 ? "" : "s"} saw no policy` : "" })
  );

  tlsBreakdown.replaceChildren();
  if (!s.failed) return;
  const section = (title, rows, header, cells) => {
    if (!rows.length) return;
    const box = document.createElement("div");
    box.className = "tls-breakdown-box";
    const h = document.createElement("h3");
    h.textContent = title;
    box.appendChild(h);
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.appendChild(buildTable(header, rows.map((r) => ({ data: r, cells: cells(r) }))));
    box.appendChild(scroll);
    tlsBreakdown.appendChild(box);
  };
  section("Failures by reason", s.byType || [], ["Reason", "Meaning", { label: "Sessions", className: "num" }, { label: "Reports", className: "num" }],
    (r) => [textCell(r.resultType, "mono nowrap"), textCell(TLS_RESULT_MEANING[r.resultType] || "", "muted"), textCell(formatNumber(r.sessions), "num is-fail"), textCell(formatNumber(r.reports), "num")]);
  section("Failures by receiving MX", s.byMx || [], ["MX host", { label: "Sessions", className: "num" }, { label: "Reports", className: "num" }],
    (r) => [textCell(r.host, "mono"), textCell(formatNumber(r.sessions), "num is-fail"), textCell(formatNumber(r.reports), "num")]);
  section("Failures by sending MTA", s.bySender || [], ["Sending MTA", { label: "Sessions", className: "num" }, { label: "Reports", className: "num" }],
    (r) => [textCell(r.ip, "mono"), textCell(formatNumber(r.sessions), "num is-fail"), textCell(formatNumber(r.reports), "num")]);
}

async function loadTls() {
  const [data, summary] = await Promise.all([
    api(`/api/tls${filterQuery({ page: tlsPage, pageSize: 50 })}`),
    api(`/api/tls/summary${filterQuery({})}`)
  ]);
  const rows = data.rows || [];
  tlsPanel.hidden = data.total === 0 && tlsPage === 1;
  tlsCountBadge.textContent = `${formatNumber(data.total)} report${data.total === 1 ? "" : "s"}`;
  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  tlsPageLabel.textContent = `Page ${data.page} of ${pages}`;
  tlsPrev.disabled = data.page <= 1;
  tlsNext.disabled = data.page >= pages;
  renderTlsSummary(summary);

  tlsResults.replaceChildren(buildTable(
    ["Window (UTC)", "Domain", "Reporter", "Policy", { label: "Succeeded", className: "num" }, { label: "Failed", className: "num" }, "Failure reasons"],
    rows.map((r) => ({
      data: r,
      cells: [
        textCell(`${formatUtcDate(r.rangeBegin)}${formatUtcDate(r.rangeEnd) !== formatUtcDate(r.rangeBegin) ? ` to ${formatUtcDate(r.rangeEnd)}` : ""}`, "nowrap"),
        textCell(r.policyDomain || "-", "mono"),
        textCell(r.orgName, "trunc"),
        tlsModeCell(r),
        textCell(formatNumber(r.successful), "num"),
        textCell(formatNumber(r.failed), r.failed ? "num is-fail" : "num"),
        textCell(r.failureTypes.join(", "), "muted trunc")
      ]
    })),
    {
      emptyText: "No TLS reports in this period.",
      expand: (r) => {
        const holder = document.createElement("div");
        holder.textContent = "Loading...";
        api(`/api/tls/${encodeURIComponent(r.id)}`)
          .then((full) => holder.replaceChildren(tlsDetail(full)))
          .catch((error) => { holder.textContent = error.message; });
        return holder;
      }
    }
  ));
}
