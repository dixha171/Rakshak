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
from kavach.models import VulnerabilityFinding, AuditRecord
from kavach.analyzers.static_analyzer import StaticAnalyzer
from kavach.agents.orchestrator import Orchestrator
from kavach.agents.patch_agent import PatchAgent
from kavach.agents import review_gate
from kavach.languages import pipeline_for, display_name, detect_language, extension_for
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


from typing import List

@app.post("/api/analyze")
async def analyze_upload(
    files: List[UploadFile] = File(None),
    source: str = Form(None),
    language: str = Form(None),
    approved: str = Form(None),
):
    """
    Same static-analysis + suggested-patch behavior as before, now looped
    across multiple uploaded files instead of exactly one. Pasted text
    (the `source` field) still works as a single-file fallback for the
    textarea path.
    """
    approved_keys = set()
    if approved:
        approved_keys = {token.strip() for token in approved.split(",") if token.strip()}

    # Build a list of (filename, source_text) pairs from either the
    # multi-file upload or the pasted-text fallback.
    file_inputs = []
    if files:
        for f in files:
            raw = await f.read()
            if len(raw) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail=f"{f.filename}: file too large (200 KB limit)")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise HTTPException(status_code=400, detail=f"{f.filename}: must be UTF-8 text")
            file_inputs.append((f.filename or "uploaded.txt", text))
    elif source:
        if len(source.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Source too large (200 KB limit)")
        lang_override = language if language else None
        resolved = lang_override or detect_language("uploaded.txt", source)
        file_inputs.append((f"uploaded{extension_for(resolved)}", source))
    else:
        raise HTTPException(status_code=400, detail="Provide file upload(s) or a 'source' form field")

    analyzer = StaticAnalyzer()
    patch_agent = PatchAgent(config=DEFAULT_CONFIG)
    ledger = AuditLedger(DEFAULT_CONFIG.ledger_db_path)

    per_file_results = {}

    for filename, source_text in file_inputs:
        resolved_language = language if (language and len(file_inputs) == 1) else detect_language(filename, source_text)
        findings = analyzer.analyze_source(filename, source_text, language=resolved_language)

        results = []
        includable_findings = []
        for finding in findings:
            finding.file_path = filename
            patch = patch_agent.synthesize(finding, source_text)
            decision = review_gate.evaluate(finding)
            finding_key = f"{filename}:{finding.cwe}:{finding.line}"
            is_approved = finding_key in approved_keys
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
                    "finding_key": finding_key,
                    "approved": is_approved,
                    "has_fix": bool(patch.diff),
                }
            )
            if patch.diff:
                if not decision.requires_review or is_approved:
                    includable_findings.append(finding)
                    ledger.record(AuditRecord(finding_id=finding.id, patch_id=patch.id, verification_id="", patch_sha256="", outcome="suggested_included"))
                elif decision.requires_review:
                    ledger.record(AuditRecord(finding_id=finding.id, patch_id=patch.id, verification_id="", patch_sha256="", outcome="pending_review"))

        patched_source, applied_labels = patch_agent.apply_all(includable_findings, source_text)
        combined_patch_available = bool(applied_labels) and patched_source != source_text

        per_file_results[filename] = {
            "language": resolved_language,
            "pipeline": pipeline_for(resolved_language),
            "finding_count": len(findings),
            "findings": results,
            "patched_source": patched_source if combined_patch_available else None,
            "patched_applied": applied_labels,
        }

    return {
        "files": per_file_results,
        "note": "Static analysis + suggested patch only. Uploaded code is never compiled or executed. "
                "Findings requiring human review are excluded from the combined corrected-file output "
                "unless explicitly approved.",
    }
   
