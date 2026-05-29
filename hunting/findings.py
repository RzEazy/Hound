"""
Findings Graph — stores intermediate investigation results, evidence chains,
and relationships between discovered artifacts.
"""

import uuid
import json
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    PROCESS = "process"
    NETWORK = "network"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    INITIAL_ACCESS = "initial_access"
    SYSTEM_INFO = "system_info"


@dataclass
class Finding:
    """A single finding/artifact discovered during investigation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: FindingCategory = FindingCategory.SYSTEM_INFO
    query_used: str = ""
    raw_data: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)  # IOCs extracted
    parent_id: Optional[str] = None  # Links to the finding that triggered this investigation
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    mitre_technique: str = ""  # e.g. "T1059.004"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d


class FindingsGraph:
    """
    Stores all findings from an investigation with parent-child relationships,
    enabling evidence chain reconstruction.
    """

    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self.hunt_id: str = str(uuid.uuid4())[:8]
        self.hypothesis: str = ""
        self.started_at: str = datetime.now().isoformat()
        self.ended_at: Optional[str] = None
        self.conclusion: str = ""
        self.confidence_score: float = 0.0  # 0-1

    def add_finding(self, finding: Finding) -> str:
        """Add a finding and return its ID."""
        self.findings[finding.id] = finding
        return finding.id

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self.findings.get(finding_id)

    def get_children(self, finding_id: str) -> List[Finding]:
        """Get findings that were triggered by a given finding."""
        return [f for f in self.findings.values() if f.parent_id == finding_id]

    def get_root_findings(self) -> List[Finding]:
        """Get top-level findings (no parent)."""
        return [f for f in self.findings.values() if f.parent_id is None]

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings.values() if f.severity == severity]

    def get_findings_by_category(self, category: FindingCategory) -> List[Finding]:
        return [f for f in self.findings.values() if f.category == category]

    def get_all_indicators(self) -> List[str]:
        """Get all IOCs across all findings."""
        indicators = []
        for f in self.findings.values():
            indicators.extend(f.indicators)
        return list(set(indicators))

    def get_evidence_chain(self, finding_id: str) -> List[Finding]:
        """Trace back from a finding to the root, returning the full chain."""
        chain = []
        current = self.findings.get(finding_id)
        while current:
            chain.append(current)
            current = self.findings.get(current.parent_id) if current.parent_id else None
        chain.reverse()
        return chain

    def max_severity(self) -> Severity:
        """Return the highest severity finding in the graph."""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings.values()):
                return sev
        return Severity.INFO

    def summary_stats(self) -> Dict[str, int]:
        stats = {}
        for sev in Severity:
            count = len([f for f in self.findings.values() if f.severity == sev])
            if count > 0:
                stats[sev.value] = count
        return stats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "hypothesis": self.hypothesis,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "conclusion": self.conclusion,
            "confidence_score": self.confidence_score,
            "summary": self.summary_stats(),
            "indicators": self.get_all_indicators(),
            "findings": [f.to_dict() for f in self.findings.values()],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
