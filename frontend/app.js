// After you deploy the backend (e.g. on Render), set this to its URL,
// e.g. "https://kavach-backend.onrender.com". Leave empty to call the
// same origin the dashboard is served from.
const API_BASE = "https://rakshak-847v.onrender.com";

const backendStatusEl = document.getElementById("backend-status");
const backendLabelEl = document.getElementById("backend-label");
const ledgerBody = document.querySelector("#ledger-table tbody");
const chainBadge = document.getElementById("chain-badge");

async function checkBackendStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    setBackendStatus(res.ok);
  } catch {
    setBackendStatus(false);
  }
}

function setBackendStatus(online) {
  backendStatusEl.classList.toggle("online", online);
  backendStatusEl.classList.toggle("offline", !online);
  backendLabelEl.textContent = online ? "backend online" : "backend offline";
}

async function loadLedger() {
  try {
    const res = await fetch(`${API_BASE}/api/ledger`);
    if (!res.ok) throw new Error("bad response");
    const data = await res.json();
    ledgerBody.innerHTML = "";
    if (!data.records.length) {
      ledgerBody.innerHTML = `<tr class="empty-row"><td colspan="6">no runs recorded yet</td></tr>`;
    } else {
      data.records.forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${String(r.seq).padStart(4, "0")}</td>
          <td class="outcome-${r.outcome}">${r.outcome}</td>
          <td>${r.finding_id || "—"}</td>
          <td>${r.patch_id || "—"}</td>
          <td>${(r.row_hash || "").slice(0, 12)}…</td>
        `;

        const downloadTd = document.createElement("td");
        const downloadBtn = document.createElement("button");
        downloadBtn.className = "run-btn";
        downloadBtn.style.padding = "4px 10px";
        downloadBtn.style.fontSize = "10.5px";
        downloadBtn.textContent = "DOWNLOAD";
        downloadBtn.addEventListener("click", () => downloadLedgerRecord(r));
        downloadTd.appendChild(downloadBtn);
        tr.appendChild(downloadTd);

        ledgerBody.appendChild(tr);
      });
    }
    chainBadge.textContent = "chain: " + (data.chain_ok ? "verified" : "TAMPERED");
    chainBadge.classList.toggle("ok", data.chain_ok);
    chainBadge.classList.toggle("bad", !data.chain_ok);
  } catch {
    ledgerBody.innerHTML = `<tr class="empty-row"><td colspan="6">ledger unavailable — start the backend to view audit history</td></tr>`;
  }
}

function downloadLedgerRecord(record) {
  const serial = String(record.seq).padStart(4, "0");
  const generatedAt = new Date().toLocaleString();

  const knownFields = new Set(["seq", "outcome", "finding_id", "patch_id", "row_hash"]);
  const extraFields = Object.entries(record).filter(([k]) => !knownFields.has(k));

  const outcomeColor = record.outcome === "certified" ? "#6FA287"
    : record.outcome === "rejected" ? "#C1443B"
    : "#C9A15B";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>KAVACH Audit Report — #${serial}</title>
<style>
  body {
    background: #0B0F0E;
    color: #E7EDEA;
    font-family: 'IBM Plex Sans', Arial, sans-serif;
    max-width: 640px;
    margin: 0 auto;
    padding: 48px 32px;
  }
  h1 {
    font-family: 'Oswald', sans-serif;
    font-size: 24px;
    letter-spacing: 0.05em;
    margin: 0 0 4px;
  }
  .subtitle {
    color: #9AAAA6;
    font-size: 12px;
    font-family: 'IBM Plex Mono', monospace;
    margin: 0 0 32px;
  }
  .field-row {
    display: flex;
    justify-content: space-between;
    padding: 12px 0;
    border-bottom: 1px solid #263133;
  }
  .field-label {
    color: #9AAAA6;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .field-value {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 13px;
    text-align: right;
    max-width: 60%;
    word-break: break-all;
  }
  .outcome-badge {
    display: inline-block;
    padding: 3px 10px;
    border: 1px solid ${outcomeColor};
    color: ${outcomeColor};
    border-radius: 2px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
  }
  .footer {
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #263133;
    color: #4B5D62;
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    line-height: 1.6;
  }
  @media print {
    body { background: #fff; color: #000; }
    .field-label, .subtitle, .footer { color: #555; }
    .field-row { border-color: #ccc; }
  }
</style>
</head>
<body>
  <h1>KAVACH — Audit Record</h1>
  <p class="subtitle">closed-loop vulnerability defense — hash-chained audit ledger</p>

  <div class="field-row">
    <span class="field-label">Serial No.</span>
    <span class="field-value">#${serial}</span>
  </div>
  <div class="field-row">
    <span class="field-label">Outcome</span>
    <span class="field-value"><span class="outcome-badge">${escapeHtml(record.outcome || "—")}</span></span>
  </div>
  <div class="field-row">
    <span class="field-label">Finding ID</span>
    <span class="field-value">${escapeHtml(record.finding_id || "—")}</span>
  </div>
  <div class="field-row">
    <span class="field-label">Patch ID</span>
    <span class="field-value">${escapeHtml(record.patch_id || "—")}</span>
  </div>
  <div class="field-row">
    <span class="field-label">Record Hash</span>
    <span class="field-value">${escapeHtml(record.row_hash || "—")}</span>
  </div>
  ${extraFields.map(([k, v]) => `
  <div class="field-row">
    <span class="field-label">${escapeHtml(k.replace(/_/g, " "))}</span>
    <span class="field-value">${escapeHtml(String(v ?? "—"))}</span>
  </div>`).join("")}

  <div class="footer">
    Report generated ${escapeHtml(generatedAt)}.<br/>
    This record is one entry in KAVACH's hash-chained audit ledger. Verify
    chain integrity via the dashboard's "chain" badge before treating this
    record as authoritative — a report exported from a tampered chain
    would still show these values as they were recorded.
  </div>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kavach_audit_report_${serial}_${record.outcome}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

checkBackendStatus();
loadLedger();

// --- Upload & analyze ---
const uploadTextarea = document.getElementById("upload-textarea");
const uploadFileInput = document.getElementById("upload-file");
const languageSelect = document.getElementById("language-select");
const analyzeBtn = document.getElementById("analyze-btn");
const uploadResults = document.getElementById("upload-results");

async function loadLanguages() {
  try {
    const res = await fetch(`${API_BASE}/api/languages`);
    if (!res.ok) throw new Error("bad response");
    const langs = await res.json();
    langs.forEach((l) => {
      const opt = document.createElement("option");
      opt.value = l.id;
      opt.textContent = `${l.name} (${l.pipeline})`;
      languageSelect.appendChild(opt);
    });
  } catch {
    // Auto-detect option alone still works if this fails.
  }
}
loadLanguages();

let selectedFiles = [];

uploadFileInput.addEventListener("change", () => {
  selectedFiles = Array.from(uploadFileInput.files);
  if (selectedFiles.length === 0) return;

  const names = selectedFiles.map((f) => f.name).join(", ");
  uploadTextarea.value = `Selected ${selectedFiles.length} file(s): ${names}`;
  uploadTextarea.disabled = true;
});

let currentApprovedKeys = new Set();

analyzeBtn.addEventListener("click", async () => {
  currentApprovedKeys = new Set();
  await runAnalysis();
});

async function runAnalysis() {
  const hasFiles = selectedFiles.length > 0;
  const source = uploadTextarea.value.trim();

  if (!hasFiles && !source) {
    uploadResults.innerHTML = `<p class="upload-empty">Paste some code or choose file(s) first.</p>`;
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "ANALYZING…";
  uploadResults.innerHTML = `<p class="upload-empty">Scanning for known danger patterns…</p>`;

  try {
    const formData = new FormData();
    if (hasFiles) {
      selectedFiles.forEach((f) => formData.append("files", f));
    } else {
      formData.append("source", source);
    }
    if (languageSelect.value) formData.append("language", languageSelect.value);
    if (currentApprovedKeys.size) formData.append("approved", Array.from(currentApprovedKeys).join(","));
    const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });
    const data = await res.json();
    renderAnalysis(data);
    loadLedger();
  } catch (err) {
    uploadResults.innerHTML = `<p class="upload-empty">Error contacting backend: ${err.message}</p>`;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "ANALYZE";
  }
}

function renderAnalysis(data) {
  const filenames = Object.keys(data.files || {});
  if (filenames.length === 0) {
    uploadResults.innerHTML = `<p class="upload-empty">No results returned.</p>`;
    return;
  }

  uploadResults.innerHTML = filenames.map((filename) => {
    const fileData = data.files[filename];
    return `
      <div class="file-result-group">
        <h3 style="font-family: var(--font-display); font-size: 16px; margin: 20px 0 10px;">${escapeHtml(filename)} <span class="pipeline-tag ${fileData.pipeline}">${fileData.pipeline}</span></h3>
        ${renderFileFindings(filename, fileData)}
      </div>
    `;
  }).join("");

  attachFindingListeners(data);
}

function renderFileFindings(filename, fileData) {
  if (!fileData.findings || fileData.findings.length === 0) {
    return `<p class="upload-empty">No known danger patterns matched for the detected language (${fileData.language || "unknown"}). Doesn't mean the code is safe — just that nothing here matches the current rule set.</p>`;
  }

  let html = fileData.findings.map((f) => {
    const showApprovalCheckbox = f.requires_human_review && f.has_fix;
    return `
      <div class="finding-card">
        <div class="finding-head">
          <span class="cwe-tag">${f.cwe}</span>
          <strong>${f.function || "(top-level)"}</strong>
          <span style="color:var(--text-dim); font-size:11px;">line ${f.line}</span>
          <span class="pipeline-tag ${f.pipeline || ""}">${f.pipeline || ""}</span>
        </div>
        <p class="desc">${f.description}</p>
        ${f.patch_diff ? `<pre>${escapeHtml(f.patch_diff)}</pre>` : ""}
        <div class="rationale">${f.patch_rationale}</div>
        ${f.requires_human_review ? `
          <div class="review-banner">
            ⚠ Requires human review${f.approved ? " — approved, included below" : ""}:
            <ul>${f.review_reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
            ${showApprovalCheckbox ? `
              <label style="display:block; margin-top:8px; cursor:pointer;">
                <input type="checkbox" class="approve-checkbox" data-key="${f.finding_key}" ${f.approved ? "checked" : ""} />
                I've reviewed this and approve including its fix in the corrected file
              </label>
            ` : ""}
          </div>
        ` : ""}
      </div>
    `;
  }).join("");

  if (fileData.patched_source) {
    html += `
      <div class="finding-card" style="border-left-color: var(--ok);">
        <div class="finding-head">
          <strong>Fully Corrected File</strong>
        </div>
        <p class="desc">Includes every non-gated fixable finding, plus any gated finding you've explicitly approved above (${fileData.patched_applied.join(", ")}). Anything left unapproved, or with no safe automatic fix, is left as-is.</p>
        <pre>${escapeHtml(fileData.patched_source)}</pre>
        <button class="run-btn download-patched-btn" data-filename="${escapeHtml(filename)}" style="margin-top:8px;">DOWNLOAD CORRECTED FILE</button>
      </div>
    `;
  } else {
    html += `<p class="upload-empty">No corrected file yet for this file — approve at least one fixable finding above, or there may be no fixable findings at all.</p>`;
  }

  return html;
}

function attachFindingListeners(data) {
  uploadResults.querySelectorAll(".approve-checkbox").forEach((cb) => {
    cb.addEventListener("change", async () => {
      const key = cb.dataset.key;
      if (cb.checked) currentApprovedKeys.add(key);
      else currentApprovedKeys.delete(key);
      await runAnalysis();
    });
  });

  uploadResults.querySelectorAll(".download-patched-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const filename = btn.dataset.filename;
      const fileData = data.files[filename];
      const baseName = filename.replace(/\.[^./]+$/, "");
      const ext = filename.match(/\.[^./]+$/)?.[0] || ".txt";
      const downloadName = `${baseName}_patched${ext}`;

      const blob = new Blob([fileData.patched_source], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  });
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// --- Fuzzing ---
const fuzzTargetSelect = document.getElementById("fuzz-target-select");
const fuzzSecondsInput = document.getElementById("fuzz-seconds-input");
const fuzzBtn = document.getElementById("fuzz-btn");
const fuzzResults = document.getElementById("fuzz-results");

async function loadFuzzTargets() {
  try {
    const res = await fetch(`${API_BASE}/api/fuzz-targets`);
    if (!res.ok) throw new Error("bad response");
    const targets = await res.json();
    fuzzTargetSelect.innerHTML = "";
    if (!targets.length) {
      fuzzTargetSelect.innerHTML = `<option value="">no fuzzable targets configured</option>`;
      fuzzBtn.disabled = true;
      return;
    }
    targets.forEach((t) => {
      const opt = document.createElement("option");
      opt.value = t.name;
      opt.textContent = t.has_seeds ? t.name : `${t.name} (no seeds yet)`;
      fuzzTargetSelect.appendChild(opt);
    });
  } catch {
    fuzzTargetSelect.innerHTML = `<option value="">backend unavailable</option>`;
    fuzzBtn.disabled = true;
  }
}
loadFuzzTargets();

fuzzBtn.addEventListener("click", async () => {
  const target = fuzzTargetSelect.value;
  if (!target) return;

  const seconds = Number(fuzzSecondsInput.value) || 20;

  fuzzBtn.disabled = true;
  fuzzBtn.textContent = "FUZZING…";
  fuzzResults.innerHTML = `<p class="upload-empty">Fuzzing ${escapeHtml(target)} for ${seconds}s — this runs synchronously, hang tight…</p>`;

  try {
    const res = await fetch(`${API_BASE}/api/fuzz`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, max_seconds: seconds }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    renderFuzzResults(data);
    loadLedger();
  } catch (err) {
    fuzzResults.innerHTML = `<p class="upload-empty">Error: ${escapeHtml(err.message)}</p>`;
  } finally {
    fuzzBtn.disabled = false;
    fuzzBtn.textContent = "FUZZ";
  }
});

function renderFuzzResults(data) {
  if (!data.crashes_found) {
    fuzzResults.innerHTML = `<p class="upload-empty">No crashes found in this run for ${escapeHtml(data.target)}. That's not proof the target is safe — just that this run didn't find anything.</p>`;
    return;
  }

  fuzzResults.innerHTML = data.outcomes.map((o) => `
    <div class="finding-card">
      <div class="finding-head">
        <span class="cwe-tag">${escapeHtml(o.cwe)}</span>
        <strong>${escapeHtml(data.target)}</strong>
        <span class="pipeline-tag">${escapeHtml(o.state)}</span>
      </div>
      <p class="desc">${escapeHtml(o.description)}</p>
      ${o.verification ? `<p class="rationale">Verification: ${escapeHtml(o.verification.status)} in ${o.verification.duration_ms.toFixed(1)}ms</p>` : ""}
      ${o.review_reasons && o.review_reasons.length ? `
        <div class="review-banner">
          ⚠ Requires human review:
          <ul>${o.review_reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
        </div>
      ` : ""}
    </div>
  `).join("");
}
