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
      ledgerBody.innerHTML = `<tr class="empty-row"><td colspan="5">no runs recorded yet</td></tr>`;
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
        ledgerBody.appendChild(tr);
      });
    }
    chainBadge.textContent = "chain: " + (data.chain_ok ? "verified" : "TAMPERED");
    chainBadge.classList.toggle("ok", data.chain_ok);
    chainBadge.classList.toggle("bad", !data.chain_ok);
  } catch {
    ledgerBody.innerHTML = `<tr class="empty-row"><td colspan="5">ledger unavailable — start the backend to view audit history</td></tr>`;
  }
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

uploadFileInput.addEventListener("change", () => {
  const file = uploadFileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { uploadTextarea.value = reader.result; };
  reader.readAsText(file);
});

let currentApprovedKeys = new Set();

analyzeBtn.addEventListener("click", async () => {
  currentApprovedKeys = new Set();
  await runAnalysis();
});

async function runAnalysis() {
  const source = uploadTextarea.value.trim();
  if (!source) {
    uploadResults.innerHTML = `<p class="upload-empty">Paste some code or choose a file first.</p>`;
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "ANALYZING…";
  uploadResults.innerHTML = `<p class="upload-empty">Scanning for known danger patterns…</p>`;

  try {
    const formData = new FormData();
    formData.append("source", source);
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
  if (!data.findings || data.findings.length === 0) {
    uploadResults.innerHTML = `<p class="upload-empty">No known danger patterns matched for the detected language (${data.language || "unknown"}). Doesn't mean the code is safe — just that nothing here matches the current rule set.</p>`;
    return;
  }

  let html = data.findings.map((f) => {
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

  if (data.patched_source) {
    html += `
      <div class="finding-card" style="border-left-color: var(--ok);">
        <div class="finding-head">
          <strong>Fully Corrected File</strong>
        </div>
        <p class="desc">Includes every non-gated fixable finding, plus any gated finding you've explicitly approved above (${data.patched_applied.join(", ")}). Anything left unapproved, or with no safe automatic fix, is left as-is.</p>
        <pre>${escapeHtml(data.patched_source)}</pre>
        <button class="run-btn" id="download-patched-btn" style="margin-top:8px;">DOWNLOAD CORRECTED FILE</button>
      </div>
    `;
  } else {
    html += `<p class="upload-empty">No corrected file yet — approve at least one fixable finding above, or there may be no fixable findings at all.</p>`;
  }

  uploadResults.innerHTML = html;

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

  if (data.patched_source) {
    const downloadBtn = document.getElementById("download-patched-btn");
    downloadBtn.addEventListener("click", () => {
      const baseName = (data.filename || "uploaded.txt").replace(/\.[^./]+$/, "");
      const ext = (data.filename || "uploaded.txt").match(/\.[^./]+$/)?.[0] || ".txt";
      const downloadName = `${baseName}_patched${ext}`;

      const blob = new Blob([data.patched_source], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
