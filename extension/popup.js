const API_BASE = "http://localhost:8000";
const POLL_INTERVAL_MS = 2500;
const POLL_MAX_ATTEMPTS = 20;

const app = document.getElementById("app");
let currentTabId = null;
let currentFormUrl = null;
let pollTimer = null;

init();

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId = tab.id;
  currentFormUrl = tab.url;

  if (!tab.url || !tab.url.includes("docs.google.com/forms/")) {
    app.innerHTML = `<div class="muted">Open a Google Form to scan it.</div>`;
    return;
  }

  const stored = await getStoredScan(tab.url);
  if (stored && stored.contentHash) {
    renderLoading("Loading previous result...");
    try {
      const result = await fetchAnalysis(stored.contentHash);
      renderResult(result);
      if (result.status === "pending_osint") startPolling(result.content_hash);
    } catch (e) {
      renderReady();
    }
  } else {
    renderReady();
  }
}

function renderReady() {
  app.innerHTML = `
    <button class="primary" id="scanBtn">Scan this form</button>
    <div style="text-align:center; margin-top:10px;">
      <button class="rescan-link" id="settingsBtn">API key settings</button>
    </div>
  `;
  document.getElementById("scanBtn").addEventListener("click", () => runScan(false));
  document.getElementById("settingsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
}

function renderLoading(message) {
  app.innerHTML = `
    <div class="status-line">${escapeHtml(message)}</div>
    <div class="progress-track"><div class="progress-bar"></div></div>
  `;
}

// async function runScan() {
//   renderLoading("Reading form...");
//   try {
//     const formData = await chrome.tabs.sendMessage(currentTabId, { type: "GET_FORM_DATA" });
//     renderLoading("Analyzing wording...");

//     const response = await fetch(`${API_BASE}/analyze`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify(formData),
//     });
//     if (!response.ok) throw new Error(`Server returned ${response.status}`);

//     const result = await response.json();
//     await storeScan(currentFormUrl, result.content_hash);
//     renderResult(result);
//     if (result.status === "pending_osint") startPolling(result.content_hash);
//   } catch (err) {
//     renderError(err.message);
//   }
// }


async function runScan(force = false) {
  renderLoading(force ? "Rescanning..." : "Reading form...");
  try {
    const formData = await chrome.tabs.sendMessage(currentTabId, { type: "GET_FORM_DATA" });
    formData.force = force;
    renderLoading("Analyzing wording...");
    const keys = await getStoredKeys();

    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Gemini-Key": keys.gemini || "",
        "X-Groq-Key": keys.groq || "",
        "X-Safe-Browsing-Key": keys.safeBrowsing || "",
        "X-Virustotal-Key": keys.virustotal || "",
        "X-Urlscan-Key": keys.urlscan || "",
        "X-Tavily-Key": keys.tavily || "",
      },
      body: JSON.stringify(formData),
    });
    if (!response.ok) {
      let detail = `Server returned ${response.status}`;
      try {
        const errBody = await response.json();
        if (errBody.detail) detail = errBody.detail;
      } catch (e) {}
      throw new Error(detail);
    }

    const result = await response.json();
    await storeScan(currentFormUrl, result.content_hash);
    renderResult(result);
    if (result.status === "pending_osint") startPolling(result.content_hash);
  } catch (err) {
    const isNetworkError = err instanceof TypeError; // fetch throws TypeError on connection failure
    renderError(err.message, isNetworkError);
  }
}


function startPolling(contentHash, attempt = 1) {
  clearTimeout(pollTimer);
  if (attempt > POLL_MAX_ATTEMPTS) return;
  pollTimer = setTimeout(async () => {
    try {
      const result = await fetchAnalysis(contentHash);
      renderResult(result);
      if (result.status === "pending_osint") startPolling(contentHash, attempt + 1);
    } catch (e) {}
  }, POLL_INTERVAL_MS);
}

async function fetchAnalysis(contentHash) {
  const response = await fetch(`${API_BASE}/analyze/${contentHash}`);
  if (!response.ok) throw new Error(`Server returned ${response.status}`);
  return response.json();
}

function renderResult(result) {
  const confidencePct = Math.round(result.confidence * 100);
  const isPending = result.status === "pending_osint";

  let html = `
    <div class="verdict-row">
      <span class="verdict ${result.verdict}">${result.verdict.toUpperCase()}</span>
      <span class="confidence">${confidencePct}% confidence</span>
    </div>
  `;

  if (isPending) {
    html += `
      <div class="status-line" style="text-align:left; margin-top:8px;">Checking link reputation and entities...</div>
      <div class="progress-track"><div class="progress-bar"></div></div>
    `;
  }

  if (result.reasons && result.reasons.length > 0) {
    html += `<ul class="reasons">${result.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`;
  }

  if (!isPending) {
    html += renderChecksTable(result);
    html += `<div class="footer-actions"><button class="rescan-link" id="rescanBtn">Rescan</button></div>`;
  }

  app.innerHTML = html;
  const rescanBtn = document.getElementById("rescanBtn");
  if (rescanBtn) rescanBtn.addEventListener("click", () => runScan(true));
}

// function renderChecksTable(result) {
//   const checks = result.checks || {};
//   let rows = "";

//   rows += checkRow("Form link — Safe Browsing", statusFor(checks.safe_browsing));
//   rows += checkRow("Form link — VirusTotal", statusFor(checks.virustotal, (c) => `${c.malicious_count}/${c.total_engines} flagged`));
//   rows += checkRow("Form link — urlscan.io", historyStatusFor(checks.urlscan));

//   const embedded = checks.embedded_link_checks || {};
//   for (const link of Object.keys(embedded)) {
//     const c = embedded[link];
//     const flagged = (c.safe_browsing && c.safe_browsing.flagged) || (c.virustotal && c.virustotal.flagged);
//     rows += checkRow(`Embedded link: ${truncate(link, 26)}`, { flagged, label: flagged ? "Flagged" : "Clean" });
//   }

//   const entities = result.named_entities || [];
//   const entityChecks = checks.named_entity_checks || {};
//   if (entities.length === 0) {
//     rows += checkRow("Named entities", { flagged: false, label: "None found in form text" });
//   } else {
//     for (const name of entities) {
//       const ec = entityChecks[name];
//       const flagged = ec && ec.relevant;
//       const label = !ec ? "pending" : ec.error ? "n/a" : flagged ? "Linked to scam reports" : "No relevant hits";
//       rows += checkRow(`"${escapeHtml(name)}" — web search`, { flagged: !!flagged, label });
//     }
//   }

//   return `<table class="checks"><tr><th>Check</th><th>Result</th></tr>${rows}</table>`;
// }



function renderChecksTable(result) {
  const checks = result.checks || {};
  let rows = "";

  rows += checkRow("Form link - Safe Browsing", statusFor(checks.safe_browsing));
  rows += checkRow("Form link - VirusTotal", statusFor(checks.virustotal, (c) => `${c.malicious_count}/${c.total_engines} flagged`));
  rows += checkRow("Form link - urlscan.io", historyStatusFor(checks.urlscan));

  const embedded = checks.embedded_link_checks || {};
  for (const link of Object.keys(embedded)) {
    const c = embedded[link];
    const flagged = (c.safe_browsing && c.safe_browsing.flagged) || (c.virustotal && c.virustotal.flagged);
    rows += checkRow(`Embedded link: ${truncate(link, 26)}`, { flagged, label: flagged ? "Flagged" : "Clean" });
  }

  const entities = result.named_entities || [];
  const entityChecks = checks.named_entity_checks || {};
  const skipped = new Set(checks.named_entity_checks_skipped || []);

  if (entities.length === 0) {
    rows += checkRow("Named entities", { flagged: false, label: "None found in form text" });
  } else {
    for (const name of entities) {
      if (skipped.has(name)) {
        rows += checkRow(`"${escapeHtml(name)}" - web search`, { flagged: false, label: "Not checked (limit reached)" });
        continue;
      }
      const ec = entityChecks[name];
      const flagged = ec && ec.relevant;
      const label = !ec ? "n/a" : ec.error ? "n/a" : flagged ? "Linked to scam reports" : "No relevant hits";
      rows += checkRow(`"${escapeHtml(name)}" - web search`, { flagged: !!flagged, label });
      if (flagged && ec.evidence_snippet) {
        rows += evidenceRow(ec.evidence_snippet, ec.evidence_url);
      }
    }
  }

  return `<table class="checks"><tr><th>Check</th><th>Result</th></tr>${rows}</table>`;
}

function evidenceRow(snippet, url) {
  const linkHtml = url ? ` - <a href="${escapeHtml(url)}" target="_blank" rel="noopener">source</a>` : "";
  return `<tr><td colspan="2" class="evidence">"${escapeHtml(truncate(snippet, 140))}"${linkHtml}</td></tr>`;
}



// function statusFor(check, labelFn) {
//   if (!check || check.error) return { flagged: false, label: "n/a" };
//   if (check.flagged) return { flagged: true, label: labelFn ? labelFn(check) : "Flagged" };
//   return { flagged: false, label: "Clean" };
// }

// function historyStatusFor(check) {
//   if (!check || check.error) return { flagged: false, label: "n/a" };
//   if (check.has_history === false) return { flagged: false, label: "No history (new/rare)" };
//   return { flagged: false, label: `${check.scan_count} prior scans` };
// }


function statusFor(check, labelFn) {
  if (!check) return { flagged: false, label: "n/a" };
  if (check.error === "no_api_key") return { flagged: false, label: "Skipped (no key set)" };
  if (check.error) return { flagged: false, label: "n/a" };
  if (check.flagged) return { flagged: true, label: labelFn ? labelFn(check) : "Flagged" };
  return { flagged: false, label: "Clean" };
}

function historyStatusFor(check) {
  if (!check) return { flagged: false, label: "n/a" };
  if (check.error === "no_api_key") return { flagged: false, label: "Skipped (no key set)" };
  if (check.error) return { flagged: false, label: "n/a" };
  if (check.has_history === false) return { flagged: false, label: "No history (new/rare)" };
  return { flagged: false, label: `${check.scan_count} prior scans` };
}


function checkRow(label, status) {
  const dotClass = status.flagged ? "dot-flag" : status.label === "n/a" ? "dot-neutral" : "dot-safe";
  const valClass = status.flagged ? "val-flag" : status.label === "n/a" ? "val-neutral" : "val-safe";
  return `<tr><td><span class="dot ${dotClass}"></span>${escapeHtml(label)}</td><td class="${valClass}">${escapeHtml(status.label)}</td></tr>`;
}

// function renderError(message) {
//   app.innerHTML = `
//     <div class="error">Error: ${escapeHtml(message)}. Is the backend running?</div>
//     <button class="primary" id="retryBtn" style="margin-top:10px;">Try again</button>
//   `;
//   document.getElementById("retryBtn").addEventListener("click", () => runScan(false));
// }

function renderError(message, isNetworkError = false) {
  const suffix = isNetworkError ? " Is the backend running?" : "";
  app.innerHTML = `
    <div class="error">Error: ${escapeHtml(message)}${suffix}</div>
    <button class="primary" id="retryBtn" style="margin-top:10px;">Try again</button>
    <div style="text-align:center; margin-top:10px;">
      <button class="rescan-link" id="settingsBtn">API key settings</button>
    </div>
  `;
  document.getElementById("retryBtn").addEventListener("click", () => runScan(false));
  document.getElementById("settingsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
}

function truncate(str, n) { return str.length > n ? str.slice(0, n) + "..." : str; }

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function getStoredScan(formUrl) {
  return new Promise((resolve) => {
    chrome.storage.local.get([storageKey(formUrl)], (data) => resolve(data[storageKey(formUrl)] || null));
  });
}

function getStoredKeys() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["byokKeys"], (data) => resolve(data.byokKeys || {}));
  });
}

function storeScan(formUrl, contentHash) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [storageKey(formUrl)]: { contentHash } }, resolve);
  });
}

function storageKey(formUrl) {
  return `scan:${formUrl}`;
}