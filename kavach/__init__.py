"""KAVACH: Closed-loop vulnerability detection, patching, and verification
for C/C++ codebases.

Package layout:
    kavach.config          - LLM backend configuration (Cloud/Local/Air-gapped)
    kavach.models           - shared dataclasses/schemas
    kavach.analyzers        - static analysis + crash-log analysis
    kavach.agents           - triage, patch synthesis, orchestration
    kavach.sandbox          - compilation, patch application, verification
    kavach.ledger           - tamper-evident audit trail
"""

__version__ = "0.1.0"
