// 08-lookup.js: DNS lookup panel.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

// --- DNS lookup --------------------------------------------------------------

const lookupForm = document.getElementById("lookup-form");
const lookupInput = document.getElementById("lookup-input");
const lookupBody = document.getElementById("lookup-body");
const lookupBadge = document.getElementById("lookup-badge");
const lookupRefresh = document.getElementById("lookup-refresh");
const lookupTabState = { tab: "dmarc" };
let lookupQuery = "";

/** A name or address rendered as a link that looks it up in turn. */
function lookupLink(text) {
  const a = document.createElement("a");
  a.href = `#lookup=${encodeURIComponent(text)}`;
  a.className = "mono lookup-link";
  a.textContent = text;
  a.addEventListener("click", (event) => {
    event.preventDefault();
    lookupInput.value = text;
    runLookup();
  });
  return a;
}

function lookupEmpty(text) {
  const p = document.createElement("p");
  p.className = "empty-state";
  p.textContent = text;
  lookupBody.replaceChildren(p);
}

function renderLookupDomain(d) {
  const tabs = [];
  const tags = d.dmarc.tags || {};

  const level = !d.dmarc.found ? "none" : tags.p || "none";
  const dmarcBox = policyBox("DMARC", {
    badge: d.dmarc.found ? `p=${tags.p || "?"}${d.dmarc.inheritedFrom ? ` (from ${d.dmarc.inheritedFrom})` : ""}` : "missing",
    badgeClass: level === "reject" ? "pill-pass" : level === "quarantine" ? "pill-quarantine" : "pill-reject"
  });
  if (d.dmarc.found) {
    dmarcBox.appendChild(recordLine(d.dmarc.record));
    const facts = [];
    facts.push(`Policy ${tags.p || "?"}${tags.sp ? `, subdomains ${tags.sp}` : ""}${tags.pct !== undefined ? `, applied to ${tags.pct}%` : ""}`);
    facts.push(`Alignment: DKIM ${tags.adkim === "s" ? "strict" : "relaxed"}, SPF ${tags.aspf === "s" ? "strict" : "relaxed"}`);
    facts.push(`Aggregate reports to ${(tags.rua || []).join(", ") || "nobody"}`);
    if (tags.ruf && tags.ruf.length) facts.push(`Forensic reports to ${tags.ruf.join(", ")}`);
    if (d.dmarc.inheritedFrom) facts.push(`Looked up _dmarc.${d.query} first, then _dmarc.${d.dmarc.inheritedFrom}`);
    dmarcBox.appendChild(warningList(facts, "policy-facts"));
  }
  if (d.dmarc.warnings && d.dmarc.warnings.length) dmarcBox.appendChild(warningList(d.dmarc.warnings));
  tabs.push({ key: "dmarc", label: "DMARC", box: dmarcBox });

  const spfBox = policyBox("SPF", {
    badge: d.spf.found ? `${d.spf.lookups} of 10 lookups` : "missing",
    badgeClass: !d.spf.found || d.spf.tooManyLookups ? "pill-reject" : d.spf.lookups >= 8 ? "pill-quarantine" : "pill-pass"
  });
  if (d.spf.found) {
    spfBox.appendChild(recordLine(d.spf.record));
    spfBox.appendChild(warningList([`${formatNumber(d.spf.networks.length)} network${d.spf.networks.length === 1 ? "" : "s"} authorised after expanding includes; ends with ${d.spf.all || "no all mechanism"}`], "policy-facts"));
  }
  const spfIssues = [...(d.spf.warnings || []), ...(d.spf.errors || [])];
  if (spfIssues.length) spfBox.appendChild(warningList(spfIssues));
  if (d.spf.found && d.spf.networks.length) {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll lookup-networks";
    scroll.appendChild(buildTable(
      ["Network", "Authorised via"],
      d.spf.networks.map((n) => ({ data: n, cells: [textCell(n.cidr, "mono"), textCell(n.via, "mono")] }))
    ));
    spfBox.appendChild(scroll);
  }
  tabs.push({ key: "spf", label: "SPF", box: spfBox });

  const mxBox = policyBox("MX", {
    badge: d.mx.nullMx ? "null MX" : d.mx.found ? `${d.mx.hosts.length} host${d.mx.hosts.length === 1 ? "" : "s"}` : "missing",
    badgeClass: d.mx.found && !d.mx.nullMx ? "pill-pass" : "pill-quarantine"
  });
  if (d.mx.hosts.length) {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.appendChild(buildTable(
      [{ label: "Priority", className: "num" }, "Host", "Addresses"],
      d.mx.hosts.map((h) => {
        const hostCell = document.createElement("td");
        hostCell.appendChild(lookupLink(h.host));
        const addrCell = document.createElement("td");
        addrCell.className = "mono";
        if (h.addresses.length) {
          h.addresses.forEach((a, i) => {
            if (i) addrCell.append(", ");
            addrCell.appendChild(lookupLink(a));
          });
        } else {
          addrCell.textContent = h.error ? `lookup failed: ${h.error}` : "none";
          addrCell.className = "is-fail";
        }
        return { data: h, cells: [textCell(String(h.priority), "num"), hostCell, addrCell] };
      })
    ));
    mxBox.appendChild(scroll);
  }
  if (d.mx.warnings && d.mx.warnings.length) mxBox.appendChild(warningList(d.mx.warnings));
  tabs.push({ key: "mx", label: "MX", box: mxBox });

  if (d.mtaSts && d.tlsRpt) {
    tabs.push({ key: "transport", label: "MTA-STS / TLS-RPT", box: transportBox(d.mtaSts, d.tlsRpt) });
  }

  const addrBox = policyBox("Addresses", {
    badge: d.addresses.length ? `${d.addresses.length} address${d.addresses.length === 1 ? "" : "es"}` : "none",
    badgeClass: d.addresses.length ? "pill-pass" : ""
  });
  if (d.addresses.length) {
    const ul = document.createElement("ul");
    ul.className = "policy-sources";
    for (const a of d.addresses) {
      const li = document.createElement("li");
      li.appendChild(lookupLink(a));
      ul.appendChild(li);
    }
    addrBox.appendChild(ul);
    addrBox.appendChild(warningList(["Click an address for its reverse DNS."], "policy-facts"));
  } else {
    addrBox.appendChild(warningList([d.addressError ? `Lookup failed: ${d.addressError}` : "No A or AAAA record for the bare domain; that is normal for a domain that only sends mail."], "policy-facts"));
  }
  tabs.push({ key: "addresses", label: "Addresses", box: addrBox });

  policyTabs(tabs, lookupBody, lookupTabState);
}

function renderLookupIp(d) {
  const ptrBox = policyBox("Reverse DNS", {
    badge: !d.ptr.found ? "no PTR" : d.ptr.names.some((n) => n.confirmed) ? "forward-confirmed" : "not confirmed",
    badgeClass: !d.ptr.found ? "pill-reject" : d.ptr.names.some((n) => n.confirmed) ? "pill-pass" : "pill-quarantine"
  });
  if (d.ptr.names.length) {
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.appendChild(buildTable(
      ["PTR name", "Resolves to", "Forward-confirmed"],
      d.ptr.names.map((n) => {
        const nameCell = document.createElement("td");
        nameCell.appendChild(lookupLink(n.name));
        return {
          data: n,
          cells: [
            nameCell,
            textCell(n.addresses.length ? n.addresses.join(", ") : n.error ? `lookup failed: ${n.error}` : "nothing", n.addresses.length ? "mono" : "is-fail"),
            textCell(n.confirmed ? "yes" : "no", n.confirmed ? "is-pass" : "is-fail")
          ]
        };
      })
    ));
    ptrBox.appendChild(scroll);
  }
  if (d.ptr.warnings && d.ptr.warnings.length) ptrBox.appendChild(warningList(d.ptr.warnings));

  const seenBox = policyBox("In your reports", {
    badge: d.seen ? `${formatNumber(d.seen.total)} messages` : "never seen",
    badgeClass: d.seen ? (d.seen.failed ? "pill-quarantine" : "pill-pass") : ""
  });
  const facts = [];
  if (d.known) facts.push(`Labelled ${d.known.kind}: ${d.known.label} (${d.known.pattern})`);
  else facts.push("Not a known sender. Label it from the Sending sources table if it is yours.");
  if (d.seen) {
    facts.push(`${formatNumber(d.seen.total)} messages, ${formatNumber(d.seen.failed)} failed DMARC${d.seen.likelyForwards ? ` (${formatNumber(d.seen.likelyForwards)} likely forwards)` : ""}`);
    facts.push(`Seen ${formatUtcDate(d.seen.firstSeen)} to ${formatUtcDate(Math.max(d.seen.firstSeen, d.seen.lastSeen - 1))}`);
    if (d.seen.ptr) facts.push(`Reverse name recorded at sync time: ${d.seen.ptr}`);
    if (d.seen.asOrg || d.seen.country) facts.push(`Network: ${[d.seen.asn ? `AS${d.seen.asn}` : "", d.seen.asOrg, [d.seen.city, d.seen.country].filter(Boolean).join(", ")].filter(Boolean).join(" ")}`);
  } else {
    facts.push("No aggregate report in the database mentions this address.");
  }
  seenBox.appendChild(warningList(facts, "policy-facts"));
  if (d.seen) {
    const open = document.createElement("button");
    open.type = "button";
    open.className = "secondary small";
    open.textContent = "Open in sources";
    open.addEventListener("click", () => {
      searchInput.value = d.query;
      reportsPage = 1;
      run(loadAll);
      document.getElementById("sources-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    seenBox.appendChild(open);
  }

  policyTabs([
    { key: "ptr", label: "Reverse DNS", box: ptrBox },
    { key: "seen", label: "In your reports", box: seenBox }
  ], lookupBody, { tab: "ptr" });
}

async function runLookup({ refresh = false } = {}) {
  const q = lookupInput.value.trim();
  if (!q) {
    lookupEmpty("Enter a domain or an IP address.");
    lookupBadge.textContent = "";
    lookupRefresh.hidden = true;
    return;
  }
  lookupQuery = q;
  lookupBadge.textContent = refresh ? "Checking DNS..." : "Looking up...";
  lookupBadge.className = "badge";
  try {
    const data = await api(`/api/lookup?q=${encodeURIComponent(q)}${refresh ? "&refresh=1" : ""}`);
    lookupBody.replaceChildren();
    if (data.type === "ip") renderLookupIp(data);
    else renderLookupDomain(data);
    lookupBadge.textContent = data.type === "ip" ? `IP ${data.query}` : data.query;
    lookupRefresh.hidden = false;
    writeHash();
  } catch (error) {
    lookupQuery = ""; // so the same query is tried again from the page link after sign-in
    lookupEmpty(error.message);
    lookupBadge.textContent = "";
    lookupRefresh.hidden = true;
  }
}

lookupForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runLookup();
});
lookupRefresh.addEventListener("click", () => runLookup({ refresh: true }));
