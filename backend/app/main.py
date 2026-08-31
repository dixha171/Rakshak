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


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(None),
    source: str = Form(None),
    language: str = Form(None),
    approved: str = Form(None),
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
    are excluded from the combined "fully corrected file" output UNLESS
    their "cwe:line" identifier appears in `approved` (a comma-separated
    list, e.g. "CWE-798:17,CWE-502:8") — the explicit signal that a human
    reviewed that specific finding and wants its suggested fix included.
    Non-gated findings with an available fix are always included.
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
        was_pasted = False
    elif source:
        if len(source.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Source too large (200 KB limit)")
        source_text = source
        filename = "uploaded.txt"  # placeholder; replaced below once language is resolved
        was_pasted = True
    else:
        raise HTTPException(status_code=400, detail="Provide a file upload or a 'source' form field")

    approved_keys = set()
    if approved:
        approved_keys = {token.strip() for token in approved.split(",") if token.strip()}

    lang_override = language if language else None
    resolved_language = lang_override or detect_language(filename, source_text)

    # Pasted text has no real filename to preserve — build one with the
    # correct extension so the eventual download matches the language the
    # person actually submitted, instead of a generic .txt.
    if was_pasted:
        filename = f"uploaded{extension_for(resolved_language)}"

    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_source(filename, source_text, language=resolved_language)

    patch_agent = PatchAgent(config=DEFAULT_CONFIG)
    ledger = AuditLedger(DEFAULT_CONFIG.ledger_db_path)
    results = []
    includable_findings = []
    for finding in findings:
        finding.file_path = filename
        patch = patch_agent.synthesize(finding, source_text)
        decision = review_gate.evaluate(finding)
        finding_key = f"{finding.cwe}:{finding.line}"
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

        # Ledger logging policy: only log findings with an actual fix to
        # act on — a bare scan with nothing actionable isn't worth an audit
        # entry. Outcome labels are deliberately different from the
        # benchmark pipeline's "certified": nothing here has gone through
        # compile + exploit-replay + regression, so "suggested_included"
        # signals a lower confidence level than a real Triple-Lock
        # certification, and the ledger stays honest about the difference.
        if patch.diff:
            if not decision.requires_review or is_approved:
                includable_findings.append(finding)
                ledger.record(
                    AuditRecord(
                        finding_id=finding.id,
                        patch_id=patch.id,
                        verification_id="",
                        patch_sha256="",
                        outcome="suggested_included",
                    )
                )
            elif decision.requires_review:
                ledger.record(
                    AuditRecord(
                        finding_id=finding.id,
                        patch_id=patch.id,
                        verification_id="",
                        patch_sha256="",
                        outcome="pending_review",
                    )
                )

    patched_source, applied_labels = patch_agent.apply_all(includable_findings, source_text)
    combined_patch_available = bool(applied_labels) and patched_source != source_text

    return {
        "filename": filename,
        "language": resolved_language,
        "pipeline": pipeline_for(resolved_language),
        "finding_count": len(findings),
        "findings": results,
        "patched_source": patched_source if combined_patch_available else None,
        "patched_applied": applied_labels,
        "note": "Static analysis + suggested patch only. Uploaded code is never compiled or executed. "
                "Findings requiring human review are excluded from the combined corrected-file output "
                "unless explicitly approved.",
    }
