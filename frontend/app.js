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
  // Dumps every field the backend sent for this record, not just the
  // columns shown in the table — so anything present now or added later
  // (verification_id, patch_sha256, recorded_at, etc.) is captured
  // automatically without needing to update this function whenever the
  // ledger schema grows.
  const payload = {
    serial: String(record.seq).padStart(4, "0"),
    ...record,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kavach_audit_${payload.serial}_${record.outcome}.json`;
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

  // Multi-file selections can't be shown as editable text, so we just
  // list what got picked and lock the textarea. Choosing a new set of
  // files (or none) re-runs this listener and updates the message.
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
    // A finding needs an explicit approval checkbox only if it's gated AND
    // has an actual fix to approve into the combined file. Non-gated fixes
    // are always included automatically; gated findings with no available
    // fix have nothing to approve (the rationale explains why).
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
  // Checkboxes re-run the analysis with the updated approval set so the
  // combined file reflects exactly what's been checked. This re-hits the
  // backend rather than trying to recompute the combine client-side, since
  // the combine logic (line-shift-safe bottom-up application) lives there.
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
