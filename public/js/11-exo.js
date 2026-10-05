// 11-exo.js: Exchange Online search snippets.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- Exchange Online search helpers ----------------------------------------

// Get-MessageTraceV2 (ExchangeOnlineManagement 3.7.0+) reaches back 90 days but
// takes at most 10 days per query; Get-MessageTrace (10 days) is being retired.
const TRACE_LIMIT_DAYS = 90;
const TRACE_SPAN_DAYS = 10;
const HISTORICAL_LIMIT_DAYS = 90;

function isoUtc(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

const PS_CONTINUE = String.fromCharCode(96);

function bareAddress(header) {
  const text = String(header || "").trim();
  const angled = text.match(/<([^>]+)>/);
  const addr = (angled ? angled[1] : text).trim();
  return /^[^\s@]+@[^\s@]+$/.test(addr) ? addr : null;
}

function psQuote(text) {
  return `"${String(text).replace(/[`"$]/g, "`$&")}"`;
}

function exoSnippet(title, note, code) {
  const item = document.createElement("div");
  item.className = "exo-item";

  const head = document.createElement("div");
  head.className = "exo-item-head";
  const h = document.createElement("strong");
  h.textContent = title;
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "secondary small";
  copy.textContent = "Copy";
  copy.addEventListener("click", async () => {
    if (await copyToClipboard(code)) {
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy"; }, 1500);
      return;
    }
    // Nothing worked: at least select the script so Ctrl+C / Cmd+C copies it.
    const pre = item.querySelector("pre");
    if (pre) selectText(pre);
    copy.textContent = "Selected: press Ctrl+C";
    setTimeout(() => { copy.textContent = "Copy"; }, 3000);
  });
  head.append(h, copy);
  item.appendChild(head);

  if (note) {
    const p = document.createElement("p");
    p.className = "exo-note";
    p.textContent = note;
    item.appendChild(p);
  }

  const pre = document.createElement("pre");
  pre.className = "exo-code mono";
  pre.textContent = code;
  item.appendChild(pre);
  return item;
}

/**
 * Ready-to-paste Exchange Online queries for the emails behind a report window
 * or a source IP. Message trace results carry FromIP, so an IP filter is exact.
 */
function exoSearchBlock({ begin, end, domain, ip, headerFroms = [], messageId = null, sender = null, exact = false, exactSource = "This forensic report gives" }) {
  const wrap = document.createElement("div");
  wrap.className = "exo";

  const start = isoUtc(begin);
  const stop = isoUtc(end + 1);
  const ageDays = (Date.now() / 1000 - begin) / DAY;
  const domains = domain ? [domain] : headerFroms.filter(Boolean);
  const senderFilter = domains.length === 1
    ? `$_.SenderAddress -like ${psQuote(`*@${domains[0]}`)}`
    : `(${domains.map((d) => `$_.SenderAddress -like ${psQuote(`*@${d}`)}`).join(" -or ")})`;
  const messageIdArg = messageId ? ` -MessageId ${psQuote(messageId)}` : "";

  const title = document.createElement("h4");
  title.textContent = "Find these emails in Exchange Online";
  wrap.appendChild(title);

  const intro = document.createElement("p");
  intro.className = "exo-note";
  intro.textContent = (exact
    ? `${exactSource} the exact time, so the window below is one hour either side${messageId ? " and the Message-ID makes the trace precise" : ""}. `
    : `Window ${start} to ${stop} (UTC), which is ${formatTimestamp(begin)} to ${formatTimestamp(end + 1)} in your local time. `) +
    "A message trace only sees mail that passed through your tenant: outbound mail your Microsoft 365 sent, or inbound mail your tenant received. " +
    "Mail sent from elsewhere straight to another provider never touched Exchange Online and will not appear.";
  wrap.appendChild(intro);

  // A full sender address is an exact server-side filter; a bare domain has to be
  // matched client-side because SenderAddress takes no wildcards.
  const senderArg = sender ? ` -SenderAddress ${psQuote(sender)}` : "";
  const ipArg = ip ? ` -FromIP ${psQuote(ip)}` : "";
  const spanDays = (end + 1 - begin) / DAY;
  const traceNote = ageDays > TRACE_LIMIT_DAYS
    ? `This window is ${Math.floor(ageDays)} days old. Message trace only reaches back ${TRACE_LIMIT_DAYS} days; only an audit log or journal will have it now.`
    : spanDays > TRACE_SPAN_DAYS
      ? `This window spans ${Math.ceil(spanDays)} days. Get-MessageTraceV2 accepts at most ${TRACE_SPAN_DAYS} days per query, so run it once per ${TRACE_SPAN_DAYS}-day slice.`
      : `Needs ExchangeOnlineManagement 3.7.0 or later (Get-MessageTrace is being retired). Reaches back ${TRACE_LIMIT_DAYS} days${ip ? "; FromIP is the sending server, so the IP filter is exact" : ""}. Results are capped at 5000: if you hit that, narrow the window or continue with -StartingRecipientAddress and -EndDate taken from the last row.`;
  wrap.appendChild(exoSnippet("Message trace (PowerShell)", traceNote,
    // Only connects when no session is open, so the same paste works the second time.
    "if (-not (Get-ConnectionInformation | Where-Object State -eq 'Connected')) { Connect-ExchangeOnline }\n" +
    `$trace = Get-MessageTraceV2 -StartDate ${psQuote(start)} -EndDate ${psQuote(stop)}${ipArg}${messageIdArg}${senderArg} -ResultSize 5000` +
    (sender ? "\n" : ` |\n  Where-Object { ${senderFilter} }\n`) +
    "$trace | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP, MessageId, MessageTraceId\n" +
    "# Hops for one of them: $trace | Select-Object -First 1 | Get-MessageTraceDetailV2"));

  const histNote = ageDays > HISTORICAL_LIMIT_DAYS
    ? `This window is older than ${HISTORICAL_LIMIT_DAYS} days, which is as far back as a historical search goes.`
    : "Runs in the background and emails a CSV, so it suits more than 5000 results or a spreadsheet. A sender, recipient or Message-ID is required; only -RecipientAddress takes wildcards. In the CSV, sender_address and original_client_ip are the columns to filter on.";
  const reportTitle = `DMARC ${domains[0] || "report"} ${start.slice(0, 10)}${ip ? ` from ${ip}` : ""}`;
  const exampleDomain = domains[0] || "example.com";
  const histWho = messageId
    ? ` -MessageID ${psQuote(messageId)}`
    : ` -SenderAddress ${psQuote(sender || `someone@${exampleDomain}`)}`;
  const histHint = messageId || sender ? "" : `# Put a real sender here, or use -RecipientAddress ${psQuote(`*@${exampleDomain}`)} for mail your tenant received\n`;
  wrap.appendChild(exoSnippet("Historical search (up to 90 days, CSV by email)", histNote,
    histHint +
    `Start-HistoricalSearch -ReportTitle ${psQuote(reportTitle)} -ReportType MessageTrace ${PS_CONTINUE}\n` +
    `  -StartDate ${psQuote(start)} -EndDate ${psQuote(stop)}${histWho}${ip ? ` -OriginalClientIP ${psQuote(ip)}` : ""} ${PS_CONTINUE}\n` +
    `  -NotifyAddress ${psQuote(`you@${exampleDomain}`)}\n` +
    "# Later: Get-HistoricalSearch | Sort-Object SubmitDate -Descending | Select-Object -First 1 ReportTitle, Status, FileUrl"));

  const dayStart = start.slice(0, 10);
  const dayEnd = isoUtc(Math.max(begin, end - 1)).slice(0, 10);
  const kqlFrom = domains.length ? ` AND (${domains.map((d) => `from:${d}`).join(" OR ")})` : "";
  wrap.appendChild(exoSnippet("Content search (Purview, KQL)",
    "For mail still sitting in your mailboxes, for example spoofs your own tenant received. Dates are whole days; Purview has no sender-IP field.",
    `sent>=${dayStart} AND sent<=${dayEnd}${kqlFrom}`));

  const portal = document.createElement("p");
  portal.className = "exo-note";
  const link = document.createElement("a");
  link.href = "https://admin.exchange.microsoft.com/#/messagetrace";
  link.target = "_blank";
  link.rel = "noopener";
  link.textContent = "Open message trace in the Exchange admin center";
  portal.append(link, document.createTextNode(` and use a custom range of ${formatTimestamp(begin)} to ${formatTimestamp(end + 1)} (the portal works in your local time).`));
  wrap.appendChild(portal);

  return wrap;
}
