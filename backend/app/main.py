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
from kavach.agents import review_gate
from kavach.languages import pipeline_for, display_name
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
    approve: bool = False


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
    outcome = orchestrator.run(
        finding, target["source"], target["test_module"],
        header_path=target.get("header"), force_apply=req.approve,
    )

    return {
        "target": req.target,
        "cwe": target["cwe"],
        "state": outcome.state.value,
        "attempts": outcome.attempts,
        "log": outcome.log,
        "review_reasons": outcome.review_reasons,
        "verification": (
            {
                "status": outcome.verification.status.value,
                "duration_ms": outcome.verification.duration_ms,
            }
            if outcome.verification
            else None
        ),
    }


@app.get("/api/languages")
def list_languages():
    from kavach.languages import LANGUAGE_PIPELINE, LANGUAGE_DISPLAY_NAME
    return [
        {"id": lang, "name": LANGUAGE_DISPLAY_NAME.get(lang, lang), "pipeline": pipeline}
        for lang, pipeline in LANGUAGE_PIPELINE.items()
    ]


@app.get("/api/ledger")
def get_ledger():
    ledger = AuditLedger(DEFAULT_CONFIG.ledger_db_path)
    return {
        "records": ledger.all_records(),
        "chain_ok": ledger.verify_chain(),
    }


MAX_UPLOAD_BYTES = 200_000  # 200 KB — plenty for a single source file


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(None),
    source: str = Form(None),
    language: str = Form(None),
):
    """
    Static-analysis + suggested-patch endpoint for arbitrary user-submitted
    source, across both the software pipeline (C, Python, JavaScript) and
    the hardware pipeline (Verilog, VHDL). Deliberately does NOT compile,
    interpret, or execute the uploaded code: this backend is a public URL,
    and running stranger-submitted code would be a remote-code-execution
    hole in the service itself. This endpoint only reads the text and
    reasons about it.

    `language` is optional: pass it explicitly (e.g. from a dropdown) when
    pasting raw text with no filename to key off of. If omitted, language
    is detected from the uploaded file's extension, or content-sniffed as
    a last resort.

    Findings that trip the human review gate (see kavach.agents.review_gate)
    are flagged as such and excluded from the combined "fully corrected
    file" output — they're shown individually instead, for manual review.
    """
    if file is not None:
        raw = await file.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large (200 KB limit)")
        try:
            source_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must be UTF-8 text")
        filename = file.filename or "uploaded.txt"
    elif source:
        if len(source.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Source too large (200 KB limit)")
        source_text = source
        filename = "uploaded.txt"  # no real extension to key off of for pasted text
    else:
        raise HTTPException(status_code=400, detail="Provide a file upload or a 'source' form field")

    analyzer = StaticAnalyzer()
    lang_override = language if language else None
    findings = analyzer.analyze_source(filename, source_text, language=lang_override)

    patch_agent = PatchAgent(config=DEFAULT_CONFIG)
    results = []
    non_gated_findings = []
    for finding in findings:
        finding.file_path = filename
        patch = patch_agent.synthesize(finding, source_text)
        decision = review_gate.evaluate(finding)
        results.append(
            {
                "cwe": finding.cwe,
                "line": finding.line,
                "function": finding.function,
                "description": finding.description,
                "severity": finding.severity.value,
                "language": finding.language,
                "pipeline": pipeline_for(finding.language),
                "patch_diff": patch.diff,
                "patch_rationale": patch.rationale,
                "requires_human_review": decision.requires_review,
                "review_reasons": decision.reasons,
            }
        )
        if not decision.requires_review:
            non_gated_findings.append(finding)

    patched_source, applied_labels = patch_agent.apply_all(non_gated_findings, source_text)
    combined_patch_available = bool(applied_labels) and patched_source != source_text

    detected_language = findings[0].language if findings else None

    return {
        "filename": filename,
        "language": detected_language,
        "pipeline": pipeline_for(detected_language) if detected_language else None,
        "finding_count": len(findings),
        "findings": results,
        "patched_source": patched_source if combined_patch_available else None,
        "patched_applied": applied_labels,
        "note": "Static analysis + suggested patch only. Uploaded code is never compiled or executed. "
                "Findings requiring human review (see each finding's review_reasons) are excluded from "
                "the combined corrected-file output.",
    }
