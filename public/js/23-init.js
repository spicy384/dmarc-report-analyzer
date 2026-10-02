// 20-init.js: Boot.
// One of the classic scripts index.html loads in order; they share one global scope,
// so a function or const defined here is visible to the files that follow.

(async function init() {
  applyTheme(localStorage.getItem("dmarc-theme") || "light");
  hideForwards.checked = localStorage.getItem("dmarc-hide-forwards") === "1";
  const savedRange = localStorage.getItem("dmarc-range");
  if (savedRange && [...rangeSelect.options].some((o) => o.value === savedRange)) {
    rangeSelect.value = savedRange;
  }
  const custom = rangeSelect.value === "custom";
  fromLabel.hidden = !custom;
  toLabel.hidden = !custom;
  if (custom) {
    fromDate.value = formatUtcDate(todayUtcStart() - 30 * DAY);
    toDate.value = formatUtcDate(todayUtcStart());
  }
  readHash();

  // Nothing loads until we know who (if anyone) is signed in.
  const signedIn = await refreshIdentity();
  if (signedIn) {
    await onSignedIn();
  }
})();
