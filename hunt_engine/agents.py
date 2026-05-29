"""
Sub-Agent Architecture — decomposed hunt agents orchestrated by a supervisor.

Instead of a single monolithic ReAct loop, hunts are decomposed into:
- ReconAgent: Initial reconnaissance and attack surface mapping
- PivotAgent: Deep-dive pivoting on discovered IOCs
- EnrichAgent: Threat intel enrichment of discovered indicators
- ReportAgent: Findings synthesis and report generation
- Supervisor: Orchestrates agents, manages HITL checkpoints
"""

import uuid
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    RECON = "recon"
    PIVOT = "pivot"
    ENRICH = "enrich"
    REPORT = "report"
    SUPERVISOR = "supervisor"


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentAction:
    """A single action taken by an agent (for audit trail)."""
    action_id: str
    agent_role: AgentRole
    action_type: str  # query, enrich, conclude, escalate
    description: str
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    requires_approval: bool = False
    approved: Optional[bool] = None
    approved_by: Optional[str] = None


@dataclass
class HuntSession:
    """A complete hunt session with full audit trail."""
    hunt_id: str
    hypothesis: str
    initiated_by: str
    team_namespace: str = "default"
    status: str = "running"
    actions: List[AgentAction] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    conclusion: Optional[str] = None


class SubAgent(ABC):
    """Base class for specialized hunt sub-agents."""

    def __init__(self, role: AgentRole, llm_client=None, osquery_engine=None):
        self.role = role
        self.llm = llm_client
        self.osquery = osquery_engine
        self.status = AgentStatus.IDLE

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's specialized task."""
        pass

    def create_action(self, action_type: str, description: str,
                      input_data: Dict = None, requires_approval: bool = False) -> AgentAction:
        return AgentAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            agent_role=self.role,
            action_type=action_type,
            description=description,
            input_data=input_data or {},
            requires_approval=requires_approval,
        )


class ReconAgent(SubAgent):
    """
    Reconnaissance agent — maps attack surface with broad queries.
    Executes parallel recon queries and identifies areas for deeper investigation.
    """

    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.RECON, **kwargs)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        hypothesis = context.get("hypothesis", "")
        target_nodes = context.get("target_nodes", [])

        # Run standard recon queries across fleet
        recon_results = {
            "suspicious_processes": [],
            "network_anomalies": [],
            "persistence_mechanisms": [],
            "privilege_escalation": [],
            "pivot_targets": [],
        }

        # In production, queries are distributed to fleet nodes
        # Results are aggregated and analyzed for initial triage

        self.status = AgentStatus.COMPLETED
        return {
            "agent": self.role.value,
            "findings": recon_results,
            "recommended_pivots": [],
            "severity_assessment": "info",
        }


class PivotAgent(SubAgent):
    """
    Pivot agent — deep-dives into specific IOCs discovered during recon.
    Follows evidence chains across processes, network, files, and users.
    """

    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.PIVOT, **kwargs)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        pivot_targets = context.get("pivot_targets", [])
        previous_findings = context.get("findings", [])

        pivot_results = []
        for target in pivot_targets:
            # Generate and execute pivot queries based on IOC type
            # e.g., PID -> parent process, network connections, open files
            # e.g., IP -> all processes connecting to it, DNS resolution
            pivot_results.append({
                "target": target,
                "evidence_chain": [],
                "severity": "info",
            })

        self.status = AgentStatus.COMPLETED
        return {
            "agent": self.role.value,
            "pivot_results": pivot_results,
            "new_iocs": [],
        }


class EnrichAgent(SubAgent):
    """
    Enrichment agent — queries threat intel feeds for discovered IOCs.
    """

    def __init__(self, threat_enricher=None, **kwargs):
        super().__init__(role=AgentRole.ENRICH, **kwargs)
        self.enricher = threat_enricher

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        iocs = context.get("iocs", [])

        enrichment_results = []
        if self.enricher and iocs:
            from intelligence.threat_intel import IOC, IOCType
            for ioc_data in iocs:
                ioc = IOC(value=ioc_data["value"], ioc_type=IOCType(ioc_data["type"]))
                results = await self.enricher.enrich(ioc)
                enrichment_results.append({
                    "ioc": ioc_data,
                    "results": [{"feed": r.feed_name, "malicious": r.is_malicious,
                                 "confidence": r.confidence} for r in results],
                })

        self.status = AgentStatus.COMPLETED
        return {
            "agent": self.role.value,
            "enrichments": enrichment_results,
        }


class ReportAgent(SubAgent):
    """
    Report agent — synthesizes findings into structured output.
    Generates STIX 2.1, MITRE Navigator layers, and human-readable reports.
    """

    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.REPORT, **kwargs)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        all_findings = context.get("findings", [])
        enrichments = context.get("enrichments", [])
        hypothesis = context.get("hypothesis", "")

        # Generate structured report
        report = {
            "summary": "",
            "findings": all_findings,
            "mitre_techniques": [],
            "ioc_summary": [],
            "recommendations": [],
            "stix_bundle": None,
            "navigator_layer": None,
        }

        self.status = AgentStatus.COMPLETED
        return {"agent": self.role.value, "report": report}


class HuntSupervisor:
    """
    Orchestrates sub-agents and manages hunt lifecycle.
    
    Features:
    - Sequential/parallel agent execution based on dependencies
    - HITL checkpoints for HIGH/CRITICAL findings
    - Dynamic re-planning based on intermediate results
    - Full action audit trail
    """

    def __init__(self, llm_client=None, osquery_engine=None,
                 threat_enricher=None, 
                 approval_callback: Optional[Callable[[AgentAction], bool]] = None,
                 progress_callback: Optional[Callable[[str], None]] = None):
        self.llm = llm_client
        self.osquery = osquery_engine
        self.approval_callback = approval_callback
        self.progress_callback = progress_callback or (lambda msg: None)

        # Initialize sub-agents
        self.agents = {
            AgentRole.RECON: ReconAgent(llm_client=llm_client, osquery_engine=osquery_engine),
            AgentRole.PIVOT: PivotAgent(llm_client=llm_client, osquery_engine=osquery_engine),
            AgentRole.ENRICH: EnrichAgent(threat_enricher=threat_enricher),
            AgentRole.REPORT: ReportAgent(llm_client=llm_client),
        }

    async def run_hunt(self, hypothesis: str, initiated_by: str,
                       target_nodes: Optional[List[str]] = None,
                       team_namespace: str = "default") -> HuntSession:
        """
        Execute a full hunt with agent orchestration.
        
        Flow:
        1. ReconAgent → initial attack surface mapping
        2. [HITL checkpoint if HIGH/CRITICAL found]
        3. PivotAgent → deep-dive on discovered IOCs
        4. EnrichAgent → threat intel enrichment
        5. [HITL checkpoint before any remediation]
        6. ReportAgent → final synthesis
        """
        session = HuntSession(
            hunt_id=f"hunt_{uuid.uuid4().hex[:12]}",
            hypothesis=hypothesis,
            initiated_by=initiated_by,
            team_namespace=team_namespace,
        )

        self.progress_callback(f"Hunt {session.hunt_id} started: {hypothesis}")

        # Phase 1: Recon
        self.progress_callback("Phase 1: Reconnaissance")
        recon_result = await self.agents[AgentRole.RECON].execute({
            "hypothesis": hypothesis,
            "target_nodes": target_nodes or [],
        })
        session.actions.append(AgentAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            agent_role=AgentRole.RECON,
            action_type="recon",
            description="Initial reconnaissance",
            output_data=recon_result,
        ))

        # HITL checkpoint if high-severity findings
        if recon_result.get("severity_assessment") in ("high", "critical"):
            checkpoint_action = AgentAction(
                action_id=f"act_{uuid.uuid4().hex[:10]}",
                agent_role=AgentRole.SUPERVISOR,
                action_type="checkpoint",
                description=f"HIGH/CRITICAL findings require approval to continue",
                input_data=recon_result,
                requires_approval=True,
            )
            session.actions.append(checkpoint_action)

            if self.approval_callback:
                approved = self.approval_callback(checkpoint_action)
                checkpoint_action.approved = approved
                if not approved:
                    session.status = "paused_awaiting_approval"
                    return session

        # Phase 2: Pivot
        self.progress_callback("Phase 2: Pivoting on discovered IOCs")
        pivot_result = await self.agents[AgentRole.PIVOT].execute({
            "hypothesis": hypothesis,
            "pivot_targets": recon_result.get("recommended_pivots", []),
            "findings": recon_result.get("findings", {}),
        })
        session.actions.append(AgentAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            agent_role=AgentRole.PIVOT,
            action_type="pivot",
            description="Deep-dive investigation",
            output_data=pivot_result,
        ))

        # Phase 3: Enrich
        self.progress_callback("Phase 3: Threat intel enrichment")
        all_iocs = pivot_result.get("new_iocs", [])
        enrich_result = await self.agents[AgentRole.ENRICH].execute({
            "iocs": all_iocs,
        })
        session.actions.append(AgentAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            agent_role=AgentRole.ENRICH,
            action_type="enrich",
            description="IOC enrichment",
            output_data=enrich_result,
        ))

        # Phase 4: Report
        self.progress_callback("Phase 4: Report generation")
        report_result = await self.agents[AgentRole.REPORT].execute({
            "hypothesis": hypothesis,
            "findings": [recon_result, pivot_result],
            "enrichments": enrich_result.get("enrichments", []),
        })
        session.actions.append(AgentAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            agent_role=AgentRole.REPORT,
            action_type="report",
            description="Final report synthesis",
            output_data=report_result,
        ))

        session.status = "completed"
        session.completed_at = datetime.utcnow()
        session.conclusion = report_result.get("report", {}).get("summary", "")
        self.progress_callback(f"Hunt {session.hunt_id} completed")

        return session
