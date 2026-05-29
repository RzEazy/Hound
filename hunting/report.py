"""
Report Generator — produces structured incident reports from a FindingsGraph.
Outputs markdown suitable for Rich rendering in the TUI, or JSON for export.
"""

import json
from datetime import datetime
from typing import Optional

from .findings import FindingsGraph, Finding, Severity, FindingCategory


SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


class ReportGenerator:
    """Generates investigation reports from FindingsGraph."""

    def generate_markdown(self, graph: FindingsGraph) -> str:
        """Generate a full markdown incident report."""
        sections = []

        # Header
        sections.append(self._header(graph))
        sections.append(self._executive_summary(graph))
        sections.append(self._findings_section(graph))
        sections.append(self._indicators_section(graph))
        sections.append(self._evidence_chains_section(graph))
        sections.append(self._conclusion_section(graph))

        return "\n\n".join(sections)

    def generate_brief(self, graph: FindingsGraph) -> str:
        """Generate a brief summary (for TUI inline display)."""
        stats = graph.summary_stats()
        max_sev = graph.max_severity()

        lines = [
            f"**Hunt Complete** | ID: `{graph.hunt_id}` | "
            f"Steps: {len(graph.findings)} | "
            f"Max Severity: {SEVERITY_ICONS.get(max_sev, '')} {max_sev.value.upper()}",
            "",
        ]

        # Stats bar
        stat_parts = []
        for sev in Severity:
            count = stats.get(sev.value, 0)
            if count > 0:
                stat_parts.append(f"{SEVERITY_ICONS[sev]} {count} {sev.value}")
        if stat_parts:
            lines.append(" | ".join(stat_parts))
            lines.append("")

        # Top findings (high+ severity)
        critical_findings = [f for f in graph.findings.values() 
                           if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_findings:
            lines.append("**Key Findings:**")
            for f in critical_findings[:5]:
                lines.append(f"- {SEVERITY_ICONS[f.severity]} **{f.title}**: {f.description}")
            lines.append("")

        # Conclusion
        lines.append(f"**Conclusion** (confidence: {graph.confidence_score:.0%}): {graph.conclusion}")

        # IOCs
        indicators = graph.get_all_indicators()
        if indicators:
            lines.append("")
            lines.append(f"**IOCs:** `{'`, `'.join(indicators[:10])}`")

        return "\n".join(lines)

    def generate_json(self, graph: FindingsGraph) -> str:
        """Export full report as JSON."""
        return graph.to_json()

    # --- Private section builders ---

    def _header(self, graph: FindingsGraph) -> str:
        return (
            f"# Threat Hunt Report\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Hunt ID | `{graph.hunt_id}` |\n"
            f"| Hypothesis | {graph.hypothesis} |\n"
            f"| Started | {graph.started_at} |\n"
            f"| Ended | {graph.ended_at or 'In Progress'} |\n"
            f"| Total Findings | {len(graph.findings)} |\n"
            f"| Confidence | {graph.confidence_score:.0%} |"
        )

    def _executive_summary(self, graph: FindingsGraph) -> str:
        stats = graph.summary_stats()
        max_sev = graph.max_severity()

        summary = f"## Executive Summary\n\n"
        summary += f"**Overall Risk Level:** {SEVERITY_ICONS.get(max_sev, '')} {max_sev.value.upper()}\n\n"

        # Breakdown
        summary += "| Severity | Count |\n|----------|-------|\n"
        for sev in Severity:
            count = stats.get(sev.value, 0)
            if count > 0:
                summary += f"| {SEVERITY_ICONS[sev]} {sev.value.upper()} | {count} |\n"

        summary += f"\n{graph.conclusion}"
        return summary

    def _findings_section(self, graph: FindingsGraph) -> str:
        if not graph.findings:
            return "## Findings\n\nNo findings recorded."

        lines = ["## Detailed Findings\n"]

        # Sort by severity
        sorted_findings = sorted(
            graph.findings.values(),
            key=lambda f: list(Severity).index(f.severity)
        )

        for i, f in enumerate(sorted_findings, 1):
            lines.append(
                f"### {i}. {SEVERITY_ICONS[f.severity]} {f.title}\n\n"
                f"- **Severity:** {f.severity.value.upper()}\n"
                f"- **Category:** {f.category.value}\n"
                f"- **MITRE:** {f.mitre_technique or 'N/A'}\n"
                f"- **Description:** {f.description}\n"
            )
            if f.indicators:
                lines.append(f"- **Indicators:** `{'`, `'.join(f.indicators)}`\n")
            if f.query_used:
                lines.append(f"- **Query:**\n```sql\n{f.query_used}\n```\n")
            if f.raw_data:
                # Show first 3 rows
                lines.append("- **Sample Data:**\n```json\n" + 
                           json.dumps(f.raw_data[:3], indent=2) + "\n```\n")

        return "\n".join(lines)

    def _indicators_section(self, graph: FindingsGraph) -> str:
        indicators = graph.get_all_indicators()
        if not indicators:
            return "## Indicators of Compromise (IOCs)\n\nNo IOCs identified."

        lines = ["## Indicators of Compromise (IOCs)\n"]
        lines.append("| Indicator | Source Finding |")
        lines.append("|-----------|---------------|")

        seen = set()
        for f in graph.findings.values():
            for ioc in f.indicators:
                if ioc not in seen:
                    seen.add(ioc)
                    lines.append(f"| `{ioc}` | {f.title} |")

        return "\n".join(lines)

    def _evidence_chains_section(self, graph: FindingsGraph) -> str:
        """Show parent-child relationships between findings."""
        root_findings = graph.get_root_findings()
        if not root_findings:
            return ""

        lines = ["## Investigation Flow\n"]
        for root in root_findings:
            self._render_tree(root, graph, lines, depth=0)

        return "\n".join(lines)

    def _render_tree(self, finding: Finding, graph: FindingsGraph, 
                     lines: list, depth: int):
        indent = "  " * depth
        icon = SEVERITY_ICONS[finding.severity]
        lines.append(f"{indent}- {icon} **{finding.title}**")
        for child in graph.get_children(finding.id):
            self._render_tree(child, graph, lines, depth + 1)

    def _conclusion_section(self, graph: FindingsGraph) -> str:
        return (
            f"## Conclusion\n\n"
            f"**Confidence:** {graph.confidence_score:.0%}\n\n"
            f"{graph.conclusion}\n\n"
            f"---\n*Report generated by HoundAI Autonomous Threat Hunter*"
        )
