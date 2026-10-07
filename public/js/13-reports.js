// 13-reports.js: Reports table and the report drawer.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- reports ---------------------------------------------------------------

// The Reports table is paginated on the server, so its search box is a query parameter
// (q2) rather than a filter over the rows on screen; it matches reporter, domain, report
// id and the records' addresses, hosts and domains, on top of the dashboard-wide search.
const reportsFilterInput = document.getElementById("reports-filter");
let reportsFilterTimer = null;
reportsFilterInput.addEventListener("input", () => {
  clearTimeout(reportsFilterTimer);
  reportsFilterTimer = setTimeout(() => {
    reportsPage = 1;
    loadReports().catch((error) => setStatus(error.message, true));
  }, 250);
});
reportsFilterInput.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && reportsFilterInput.value) {
    reportsFilterInput.value = "";
    reportsPage = 1;
    loadReports().catch((error) => setStatus(error.message, true));
  }
});

async function loadReports() {
  const q2 = reportsFilterInput.value.trim();
  reportsFilterInput.classList.toggle("is-active", Boolean(q2));
  const data = await api(`/api/reports${filterQuery({ org: reporterFilter.value, page: reportsPage, pageSize: reportsPageSize, q2: q2 || undefined })}`);
  const rows = data.rows || [];
  reportsCount.textContent = `${formatNumber(data.total)} report${data.total === 1 ? "" : "s"}`;
  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  reportsPageLabel.textContent = `Page ${data.page} of ${pages}`;
  reportsPrev.disabled = data.page <= 1;
  reportsNext.disabled = data.page >= pages;

  reportsResults.replaceChildren(buildTable(
    ["Window", "Reporter", "Domain", "Policy", { label: "Messages", className: "num" }, { label: "Failed", className: "num" }, "Received", ...(mailboxNames.size > 1 ? ["Mailbox"] : []), "Report ID"],
    rows.map((r) => ({
      data: r,
      cells: [
        textCell(formatWindow(r.rangeBegin, r.rangeEnd), "nowrap"),
        textCell(r.orgName, "nowrap"),
        textCell(r.domain, "mono"),
        textCell(`p=${r.p || "?"}${r.pct !== null && r.pct !== 100 ? ` pct=${r.pct}` : ""}`, "mono muted"),
        textCell(formatNumber(r.messages), "num"),
        textCell(formatNumber(r.failed), r.failed ? "num is-fail" : "num"),
        textCell(r.receivedAt ? formatTimestamp(r.receivedAt) : formatTimestamp(r.ingestedAt), "nowrap"),
        ...(mailboxNames.size > 1 ? [textCell(mailboxName(r.mailboxId), "nowrap")] : []),
        textCell(r.reportId, "mono muted trunc")
      ]
    })),
    { emptyText: "No reports in this period.", onRowClick: (r) => openReportDetail(r.id) }
  ));
}

reportsPrev.addEventListener("click", () => { reportsPage = Math.max(1, reportsPage - 1); run(loadReports); });
reportsNext.addEventListener("click", () => { reportsPage += 1; run(loadReports); });

async function openReportDetail(id) {
  try {
    const r = await api(`/api/reports/${encodeURIComponent(id)}`);
    reportDetailTitle.textContent = `${r.orgName} - ${formatWindow(r.rangeBegin, r.rangeEnd)} - ${r.domain}`;
    reportDetailXml.href = apiPath(`/api/reports/${encodeURIComponent(id)}/xml`);
    reportDetailSummary.replaceChildren(
      kv("Report ID", r.reportId),
      kv("Window (UTC)", `${formatUtcDateTime(r.rangeBegin)} to ${formatUtcDateTime(r.rangeEnd)}`),
      kv("Published policy", `p=${r.p || "?"} sp=${r.sp || "?"} pct=${r.pct ?? "?"} adkim=${r.adkim || "?"} aspf=${r.aspf || "?"}`),
      kv("Messages", `${formatNumber(r.messages)} (${formatNumber(r.failed)} failed)`),
      kv("Contact", r.orgEmail || "-"),
      kv("Email received", r.receivedAt ? formatTimestamp(r.receivedAt) : "-"),
      kv("Subject", r.subject || "-"),
      kv("Attachment", r.attachmentName || "-"),
      ...(r.purgedAt ? [kv("Records", `rolled up by retention on ${formatTimestamp(r.purgedAt)}; only the totals remain`)] : [])
    );
    reportDetailExo.replaceChildren(exoSearchBlock({ begin: r.rangeBegin, end: r.rangeEnd, domain: r.domain }));
    reportDetailBody.replaceChildren(buildTable(
      ["Window", "Reporter", "Source IP", { label: "Count", className: "num" }, "Result", "SPF / DKIM", "Header From", "Envelope From", "Auth results", "Reasons"],
      recordRows(r.records || [], { showIp: true }),
      { expand: (rec) => exoSearchBlock({ begin: rec.rangeBegin ?? r.rangeBegin, end: rec.rangeEnd ?? r.rangeEnd, ip: rec.sourceIp, domain: rec.domain || r.domain, headerFroms: [rec.headerFrom] }) }
    ));
    reportDetail.hidden = false;
    reportDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
    openReport = id;
    openIp = null;
    writeHash({ report: id });
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("report-detail-close").addEventListener("click", () => { reportDetail.hidden = true; openReport = null; writeHash(); });
