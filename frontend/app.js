// After you deploy the backend (e.g. on Render), set this to its URL,
// e.g. "https://kavach-backend.onrender.com". Leave empty to call the
// same origin the dashboard is served from.
const API_BASE = "https://rakshak-847v.onrender.com";

const grid = document.getElementById("benchmark-grid");
const backendStatusEl = document.getElementById("backend-status");
const backendLabelEl = document.getElementById("backend-label");
const ledgerBody = document.querySelector("#ledger-table tbody");
const chainBadge = document.getElementById("chain-badge");

const FALLBACK_BENCHMARKS = [
  { name: "packet_parser", cwe: "CWE-119", description: "Tactical packet stream decoder — missing upper bounds check on memcpy" },
  { name: "auth_session", cwe: "CWE-416", description: "Tactical auth session manager — dangling pointer on logout" },
  { name: "frame_alloc", cwe: "CWE-190", description: "Radar frame allocator — integer multiplication wrap-around" },
];

function lockSvg() {
  return `<svg viewBox="0 0 32 32"><circle cx="16" cy="16" r="14"/></svg>`;
}

function renderCard(bench) {
  const card = document.createElement("div");
  card.className = "card";
  card.id = `card-${bench.name}`;
  card.innerHTML = `
    <div class="card-head">
      <span class="cwe-tag">${bench.cwe}</span>
    </div>
    <h3>${bench.name.replace(/_/g, " ")}</h3>
    <p class="desc">${bench.description}</p>
    <div class="locks">
      <div class="lock" data-lock="replay">${lockSvg()}<label>Exploit Replay</label></div>
      <div class="lock" data-lock="regression">${lockSvg()}<label>Regression</label></div>
      <div class="lock" data-lock="cert">${lockSvg()}<label>Certified</label></div>
    </div>
    <button class="run-btn">RUN PIPELINE</button>
    <pre class="log-panel"></pre>
  `;
  const btn = card.querySelector(".run-btn");
  btn.onclick = () => runTarget(bench.name, card, btn, false);
  return card;
}

async function runTarget(name, card, btn, approve = false) {
  btn.disabled = true;
  btn.textContent = approve ? "APPLYING…" : "RUNNING…";
  card.className = "card running";
  const logPanel = card.querySelector(".log-panel");
  logPanel.classList.add("visible");
  logPanel.textContent = approve ? "human approval received, applying…" : "dispatching to orchestrator…";

  try {
    const res = await fetch(`${API_BASE}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: name, approve }),
    });
    const data = await res.json();

    let logText = (data.log || []).join("\n");
    logPanel.textContent = logText;

    if (data.state === "pending_review") {
      card.className = "card pending-review";
      setLock(card, "replay", false);
      setLock(card, "regression", false);
      setLock(card, "cert", false);
      btn.textContent = "APPROVE & APPLY";
      btn.onclick = () => runTarget(name, card, btn, true);
      loadLedger();
      return;
    }

    const certified = data.state === "certified";
    card.className = "card " + (certified ? "certified" : "failed");

    setLock(card, "replay", certified || (data.verification && data.verification.status !== "failed"));
    setLock(card, "regression", certified);
    setLock(card, "cert", certified);

    btn.textContent = certified ? "CERTIFIED ✓" : "RUN PIPELINE (retry)";
    btn.onclick = () => runTarget(name, card, btn, false);
    loadLedger();
  } catch (err) {
    logPanel.textContent = "Error contacting backend: " + err.message +
      "\n\nStart the API with:\n  uvicorn backend.app.main:app --reload --port 8000";
    card.className = "card failed";
    btn.textContent = "RUN PIPELINE (retry)";
    btn.onclick = () => runTarget(name, card, btn, false);
  } finally {
    btn.disabled = false;
  }
}

function setLock(card, which, ok) {
  const el = card.querySelector(`.lock[data-lock="${which}"]`);
  el.classList.remove("done", "fail");
  el.classList.add(ok ? "done" : "fail");
}

async function loadBenchmarks() {
  try {
    const res = await fetch(`${API_BASE}/api/benchmarks`);
    if (!res.ok) throw new Error("bad response");
    const data = await res.json();
    setBackendStatus(true);
    data.forEach((b) => grid.appendChild(renderCard(b)));
  } catch {
    setBackendStatus(false);
    FALLBACK_BENCHMARKS.forEach((b) => grid.appendChild(renderCard(b)));
  }
}

function setBackendStatus(online) {
  backendStatusEl.classList.toggle("online", online);
  backendStatusEl.classList.toggle("offline", !online);
  backendLabelEl.textContent = online ? "backend online" : "backend offline (showing static targets)";
}

async function loadLedger() {
  try {
    const res = await fetch(`${API_BASE}/api/ledger`);
    if (!res.ok) throw new Error("bad response");
    const data = await res.json();
    ledgerBody.innerHTML = "";
    if (!data.records.length) {
      ledgerBody.innerHTML = `<tr class="empty-row"><td colspan="5">no runs recorded yet — trigger a pipeline above</td></tr>`;
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

loadBenchmarks();
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

analyzeBtn.addEventListener("click", async () => {
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
    const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });
    const data = await res.json();

    if (!data.findings || data.findings.length === 0) {
      uploadResults.innerHTML = `<p class="upload-empty">No known danger patterns matched for the detected language (${data.language || "unknown"}). Doesn't mean the code is safe — just that nothing here matches the current rule set.</p>`;
    } else {
      let html = data.findings.map((f) => `
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
              ⚠ Requires human review before applying:
              <ul>${f.review_reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
            </div>
          ` : ""}
        </div>
      `).join("");

      if (data.patched_source) {
        html += `
          <div class="finding-card" style="border-left-color: var(--ok);">
            <div class="finding-head">
              <strong>Fully Corrected File</strong>
            </div>
            <p class="desc">Combines every fixable, non-gated finding above into one file (${data.patched_applied.join(", ")}). Findings needing human review, or with no safe automatic fix, are left as-is — check those manually.</p>
            <pre>${escapeHtml(data.patched_source)}</pre>
            <button class="run-btn" id="download-patched-btn" style="margin-top:8px;">DOWNLOAD CORRECTED FILE</button>
          </div>
        `;
      }

      uploadResults.innerHTML = html;

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
  } catch (err) {
    uploadResults.innerHTML = `<p class="upload-empty">Error contacting backend: ${err.message}</p>`;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "ANALYZE";
  }
});

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
