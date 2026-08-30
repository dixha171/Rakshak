"""
Triage agent: correlates static-analyzer findings and dynamic crash
reports (from ASan) into a unified Vulnerability Evidence Graph, so the
patch agent has both "where the risky pattern is" and "how it actually
crashed" for the same root cause.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from kavach.models import VulnerabilityFinding, CrashReport


@dataclass
class EvidenceNode:
    finding: VulnerabilityFinding
    crash_reports: list[CrashReport] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """Findings corroborated by an actual crash are weighted higher
        than static-only pattern matches."""
        return 0.95 if self.crash_reports else 0.55


@dataclass
class EvidenceGraph:
    nodes: list[EvidenceNode] = field(default_factory=list)

    def top(self, n: int = 5) -> list[EvidenceNode]:
        return sorted(self.nodes, key=lambda node: node.confidence, reverse=True)[:n]


class TriageAgent:
    def correlate(
        self,
        findings: list[VulnerabilityFinding],
        crashes: list[CrashReport],
    ) -> EvidenceGraph:
        graph = EvidenceGraph()

        for finding in findings:
            node = EvidenceNode(finding=finding)
            for crash in crashes:
                if self._same_location(finding, crash):
                    node.crash_reports.append(crash)
            graph.nodes.append(node)

        # Any crash that didn't correlate to a static finding still gets
        # surfaced as its own synthetic finding, since a confirmed crash
        # is stronger evidence than a static pattern match.
        matched_crash_ids = {
            id(c) for node in graph.nodes for c in node.crash_reports
        }
        for crash in crashes:
            if id(crash) not in matched_crash_ids:
                synthetic = VulnerabilityFinding(
                    cwe=self._cwe_from_crash_type(crash.crash_type),
                    file_path=crash.faulting_file,
                    line=crash.faulting_line,
                    function=crash.faulting_function,
                    description=f"Crash-only finding: {crash.crash_type}",
                    source="crash_analyzer",
                )
                graph.nodes.append(EvidenceNode(finding=synthetic, crash_reports=[crash]))

        return graph

    @staticmethod
    def _same_location(finding: VulnerabilityFinding, crash: CrashReport) -> bool:
        same_file = (
            finding.file_path
            and crash.faulting_file
            and finding.file_path.split("/")[-1] == crash.faulting_file.split("/")[-1]
        )
        same_function = finding.function and finding.function == crash.faulting_function
        return bool(same_file and (same_function or abs(finding.line - crash.faulting_line) <= 10))

    @staticmethod
    def _cwe_from_crash_type(crash_type: str) -> str:
        mapping = {
            "heap-buffer-overflow": "CWE-122",
            "stack-buffer-overflow": "CWE-121",
            "global-buffer-overflow": "CWE-125",
            "use-after-free": "CWE-416",
            "double-free": "CWE-415",
        }
        for key, cwe in mapping.items():
            if key in crash_type:
                return cwe
        return "CWE-unknown"
