// 05-forensic.js: Forensic (ruf) reports panel.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- forensic reports -----------------------------------------------------------

const forensicPanel = document.getElementById("forensic-panel");
const forensicResults = document.getElementById("forensic-results");
const forensicCount = document.getElementById("forensic-count");
const forensicPrev = document.getElementById("forensic-prev");
const forensicNext = document.getElementById("forensic-next");
const forensicPageLabel = document.getElementById("forensic-page-label");
let forensicPage = 1;

forensicPrev.addEventListener("click", () => { forensicPage = Math.max(1, forensicPage - 1); loadForensic(); });
forensicNext.addEventListener("click", () => { forensicPage += 1; loadForensic(); });

function forensicDetail(f) {
  const wrap = document.createElement("div");
  const summary = document.createElement("div");
  summary.className = "detail-summary";
  summary.append(
    kv("Arrived at receiver", f.arrivalAt ? `${formatUtcDateTime(f.arrivalAt)} (${formatTimestamp(f.arrivalAt)} local)` : "-"),
    kv("Failure", `${f.authFailure || "?"}${f.deliveryResult ? `, delivered as ${f.deliveryResult}` : ""}`),
    kv("Reported by", f.reportingMta || f.reporterFrom || "-"),
    kv("Original From", f.originalFrom || "-"),
    kv("Original To", f.originalTo || f.originalRcptTo || "-"),
    kv("Envelope From", f.originalMailFrom || "-"),
    kv("Message-ID", f.originalMessageId || "-"),
    kv("Authentication-Results", f.authenticationResults || "-")
  );
  wrap.appendChild(summary);

  if (f.arrivalAt) {
    wrap.appendChild(exoSearchBlock({
      begin: f.arrivalAt - 3600,
      end: f.arrivalAt + 3600,
      ip: f.sourceIp,
      domain: f.reportedDomain,
      messageId: f.originalMessageId,
      sender: bareAddress(f.originalFrom) || bareAddress(f.originalMailFrom),
      exact: true
    }));
  }

  if (f.headers) {
    const h = document.createElement("details");
    const s = document.createElement("summary");
    s.textContent = "Original message headers";
    h.appendChild(s);
    const pre = document.createElement("pre");
    pre.className = "exo-code mono";
    pre.textContent = f.headers;
    h.appendChild(pre);
    wrap.appendChild(h);
  }
  return wrap;
}

async function loadForensic() {
  const data = await api(`/api/forensic${filterQuery({ page: forensicPage, pageSize: 50 })}`);
  const rows = data.rows || [];
  forensicPanel.hidden = data.total === 0 && forensicPage === 1;
  forensicCount.textContent = `${formatNumber(data.total)} report${data.total === 1 ? "" : "s"}`;
  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  forensicPageLabel.textContent = `Page ${data.page} of ${pages}`;
  forensicPrev.disabled = data.page <= 1;
  forensicNext.disabled = data.page >= pages;

  forensicResults.replaceChildren(buildTable(
    ["Arrived (UTC)", "Source IP", "Network", "Domain", "Failure", "Original From", "Subject", "Reported by"],
    rows.map((f) => ({
      data: f,
      cells: [
        textCell(f.arrivalAt ? formatUtcDateTime(f.arrivalAt) : "", "nowrap"),
        textCell(f.sourceIp || "", "mono"),
        networkCell(f),
        textCell(f.reportedDomain || "", "mono"),
        textCell(`${f.authFailure || "?"}${f.deliveryResult ? ` (${f.deliveryResult})` : ""}`, "nowrap"),
        textCell(f.originalFrom || f.originalMailFrom || "", "trunc"),
        textCell(f.originalSubject || "", "trunc"),
        textCell(f.reportingMta ? f.reportingMta.replace(/^dns;\s*/i, "") : f.reporterFrom || "", "muted trunc")
      ]
    })),
    {
      emptyText: "No forensic reports in this period.",
      expand: (f) => {
        const holder = document.createElement("div");
        holder.textContent = "Loading...";
        api(`/api/forensic/${encodeURIComponent(f.id)}`)
          .then((full) => holder.replaceChildren(forensicDetail(full)))
          .catch((error) => { holder.textContent = error.message; });
        return holder;
      }
    }
  ));
}
