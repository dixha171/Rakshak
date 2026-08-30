"""
FastAPI REST backend powering the KAVACH operator web dashboard.

Run:
    uvicorn backend.app.main:app --reload --port 8000
"""
from __future__ import annotations

import os
import sys

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from kavach.config import DEFAULT_CONFIG
from kavach.cli import BENCHMARKS
from kavach.models import VulnerabilityFinding
from kavach.analyzers.static_analyzer import StaticAnalyzer
from kavach.agents.orchestrator import Orchestrator
from kavach.agents.patch_agent import PatchAgent
from kavach.ledger.audit_ledger import AuditLedger

app = FastAPI(title="KAVACH API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RunRequest(BaseModel):
    target: str


@app.get("/api/health")
def health():
    return {"status": "ok", "backend": DEFAULT_CONFIG.describe()}


@app.get("/api/benchmarks")
def list_benchmarks():
    return [
        {"name": name, "cwe": meta["cwe"], "description": meta["description"]}
        for name, meta in BENCHMARKS.items()
    ]


@app.post("/api/run")
def run_target(req: RunRequest):
    target = BENCHMARKS.get(req.target)
    if not target:
        raise HTTPException(status_code=404, detail=f"Unknown target '{req.target}'")

    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_file(target["source"])
    findings = [f for f in findings if f.cwe == target["cwe"]] or [
        VulnerabilityFinding(cwe=target["cwe"], file_path=target["source"], description=target["description"])
    ]
    finding = findings[0]
    finding.file_path = target["source"]

    orchestrator = Orchestrator(config=DEFAULT_CONFIG)
    outcome = orchestrator.run(finding, target["source"], target["test_module"], header_path=target.get("header"))

    return {
        "target": req.target,
        "cwe": target["cwe"],
        "state": outcome.state.value,
        "attempts": outcome.attempts,
        "log": outcome.log,
        "verification": (
            {
                "status": outcome.verification.status.value,
                "duration_ms": outcome.verification.duration_ms,
            }
            if outcome.verification
            else None
        ),
    }


@app.get("/api/ledger")
def get_ledger():
    ledger = AuditLedger(DEFAULT_CONFIG.ledger_db_path)
    return {
        "records": ledger.all_records(),
        "chain_ok": ledger.verify_chain(),
    }


MAX_UPLOAD_BYTES = 200_000  # 200 KB — plenty for a single source file


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(None), source: str = Form(None)):
    """
    Static-analysis + suggested-patch endpoint for arbitrary user-submitted
    C source. Deliberately does NOT compile or execute the uploaded code:
    this backend is a public URL, and running stranger-submitted C via gcc
    would be a remote-code-execution hole in the service itself. This
    endpoint only reads the text and reasons about it.
    """
    if file is not None:
        raw = await file.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large (200 KB limit)")
        try:
            source_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must be UTF-8 text")
        filename = file.filename or "uploaded.c"
    elif source:
        if len(source.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Source too large (200 KB limit)")
        source_text = source
        filename = "uploaded.c"
    else:
        raise HTTPException(status_code=400, detail="Provide a file upload or a 'source' form field")

    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_source(filename, source_text)

    patch_agent = PatchAgent(config=DEFAULT_CONFIG)
    results = []
    for finding in findings:
        finding.file_path = filename
        patch = patch_agent.synthesize(finding, source_text)
        results.append(
            {
                "cwe": finding.cwe,
                "line": finding.line,
                "function": finding.function,
                "description": finding.description,
                "severity": finding.severity.value,
                "patch_diff": patch.diff,
                "patch_rationale": patch.rationale,
            }
        )

    return {
        "filename": filename,
        "finding_count": len(findings),
        "findings": results,
        "note": "Static analysis + suggested patch only. Uploaded code is never compiled or executed.",
    }
