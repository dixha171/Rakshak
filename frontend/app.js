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
  btn.addEventListener("click", () => runTarget(bench.name, card, btn));
  return card;
}

async function runTarget(name, card, btn) {
  btn.disabled = true;
  btn.textContent = "RUNNING…";
  card.className = "card running";
  const logPanel = card.querySelector(".log-panel");
  logPanel.classList.add("visible");
  logPanel.textContent = "dispatching to orchestrator…";

  try {
    const res = await fetch(`${API_BASE}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: name }),
    });
    const data = await res.json();

    logPanel.textContent = (data.log || []).join("\n");
    const certified = data.state === "certified";
    card.className = "card " + (certified ? "certified" : "failed");

    setLock(card, "replay", certified || (data.verification && data.verification.status !== "failed"));
    setLock(card, "regression", certified);
    setLock(card, "cert", certified);

    btn.textContent = certified ? "CERTIFIED ✓" : "RUN PIPELINE (retry)";
    loadLedger();
  } catch (err) {
    logPanel.textContent = "Error contacting backend: " + err.message +
      "\n\nStart the API with:\n  uvicorn backend.app.main:app --reload --port 8000";
    card.className = "card failed";
    btn.textContent = "RUN PIPELINE (retry)";
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
const analyzeBtn = document.getElementById("analyze-btn");
const uploadResults = document.getElementById("upload-results");

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
    uploadResults.innerHTML = `<p class="upload-empty">Paste some C source or choose a file first.</p>`;
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "ANALYZING…";
  uploadResults.innerHTML = `<p class="upload-empty">Scanning for known danger patterns…</p>`;

  try {
    const formData = new FormData();
    formData.append("source", source);
    const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });
    const data = await res.json();

    if (!data.findings || data.findings.length === 0) {
      uploadResults.innerHTML = `<p class="upload-empty">No known danger patterns matched (CWE-119/120/190/416 templates). Doesn't mean the code is safe — just that nothing here matches the current rule set.</p>`;
    } else {
      uploadResults.innerHTML = data.findings.map((f) => `
        <div class="finding-card">
          <div class="finding-head">
            <span class="cwe-tag">${f.cwe}</span>
            <strong>${f.function || "(top-level)"}</strong>
            <span style="color:var(--text-dim); font-size:11px;">line ${f.line}</span>
          </div>
          <p class="desc">${f.description}</p>
          ${f.patch_diff ? `<pre>${escapeHtml(f.patch_diff)}</pre>` : ""}
          <div class="rationale">${f.patch_rationale}</div>
        </div>
      `).join("");
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
