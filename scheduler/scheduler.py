"""
Scheduler & Playbooks — YAML-based hunt playbooks with cron and trigger-based execution.
"""

import yaml
import logging
import asyncio
import hashlib
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    """A single step in a hunt playbook."""
    name: str
    query_sql: str
    description: str
    category: str = "system_info"
    severity_threshold: str = "medium"  # Escalate if findings exceed this
    timeout_seconds: int = 30
    continue_on_error: bool = True


@dataclass
class EscalationPath:
    """Defines how to escalate when severity thresholds are met."""
    severity: str  # Trigger at this severity or above
    action: str  # notify, pause, remediate
    targets: List[str] = field(default_factory=list)  # email, slack channel, etc.
    message_template: str = ""


@dataclass
class Playbook:
    """
    A structured hunt playbook defining hypothesis templates,
    query sequences, thresholds, and escalation paths.
    """
    id: str
    name: str
    description: str
    version: str = "1.0"
    author: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Hunt configuration
    hypothesis_template: str = ""
    steps: List[PlaybookStep] = field(default_factory=list)
    escalation_paths: List[EscalationPath] = field(default_factory=list)

    # Scheduling
    schedule_cron: Optional[str] = None  # Cron expression for periodic runs
    trigger_conditions: List[Dict[str, Any]] = field(default_factory=list)

    # Targeting
    target_config_groups: List[str] = field(default_factory=lambda: ["all"])
    target_tags: List[str] = field(default_factory=list)


class PlaybookLoader:
    """Loads and validates YAML playbook definitions."""

    def __init__(self, playbooks_dir: str = "playbooks"):
        self.playbooks_dir = Path(playbooks_dir)
        self._playbooks: Dict[str, Playbook] = {}

    def load_all(self) -> Dict[str, Playbook]:
        """Load all playbooks from the playbooks directory."""
        if not self.playbooks_dir.exists():
            logger.warning(f"Playbooks directory not found: {self.playbooks_dir}")
            return {}

        for yaml_file in self.playbooks_dir.glob("*.yaml"):
            try:
                playbook = self.load_file(yaml_file)
                self._playbooks[playbook.id] = playbook
            except Exception as e:
                logger.error(f"Failed to load playbook {yaml_file}: {e}")

        logger.info(f"Loaded {len(self._playbooks)} playbooks")
        return self._playbooks

    def load_file(self, path: Path) -> Playbook:
        """Load a single playbook from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        steps = [
            PlaybookStep(
                name=s["name"],
                query_sql=s["query"],
                description=s.get("description", ""),
                category=s.get("category", "system_info"),
                severity_threshold=s.get("severity_threshold", "medium"),
                timeout_seconds=s.get("timeout", 30),
            )
            for s in data.get("steps", [])
        ]

        escalations = [
            EscalationPath(
                severity=e["severity"],
                action=e["action"],
                targets=e.get("targets", []),
                message_template=e.get("message", ""),
            )
            for e in data.get("escalation", [])
        ]

        return Playbook(
            id=data.get("id", path.stem),
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            author=data.get("author", ""),
            tags=data.get("tags", []),
            mitre_techniques=data.get("mitre_techniques", []),
            hypothesis_template=data.get("hypothesis_template", ""),
            steps=steps,
            escalation_paths=escalations,
            schedule_cron=data.get("schedule", {}).get("cron"),
            trigger_conditions=data.get("triggers", []),
            target_config_groups=data.get("targets", {}).get("config_groups", ["all"]),
            target_tags=data.get("targets", {}).get("tags", []),
        )

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self._playbooks.get(playbook_id)


class HuntScheduler:
    """
    Cron-style scheduler for periodic and trigger-based hunts.
    
    Features:
    - Cron expression parsing for nightly/hourly baselines
    - Trigger-based hunts (new CVE → auto-hunt for exploit indicators)
    - Deduplication (don't re-run same playbook within cooldown)
    """

    def __init__(self, hunt_supervisor=None, playbook_loader: Optional[PlaybookLoader] = None,
                 message_queue=None):
        self.supervisor = hunt_supervisor
        self.loader = playbook_loader or PlaybookLoader()
        self.mq = message_queue
        self._running = False
        self._scheduled_tasks: Dict[str, asyncio.Task] = {}
        self._last_run: Dict[str, datetime] = {}
        self._trigger_handlers: Dict[str, Callable] = {}

    async def start(self):
        """Start the scheduler — loads playbooks and sets up cron jobs."""
        self._running = True
        playbooks = self.loader.load_all()

        for pb_id, playbook in playbooks.items():
            if playbook.schedule_cron:
                task = asyncio.create_task(self._cron_loop(playbook))
                self._scheduled_tasks[pb_id] = task
                logger.info(f"Scheduled playbook '{playbook.name}' with cron: {playbook.schedule_cron}")

            for trigger in playbook.trigger_conditions:
                trigger_type = trigger.get("type", "")
                if trigger_type == "new_cve":
                    self._register_cve_trigger(playbook, trigger)
                elif trigger_type == "alert":
                    self._register_alert_trigger(playbook, trigger)

        # Subscribe to trigger events from message queue
        if self.mq:
            await self.mq.subscribe("triggers.*", self._handle_trigger)

        logger.info(f"Scheduler started with {len(self._scheduled_tasks)} cron jobs")

    async def stop(self):
        self._running = False
        for task in self._scheduled_tasks.values():
            task.cancel()

    async def run_playbook(self, playbook: Playbook,
                            context: Dict[str, Any] = None) -> Optional[str]:
        """
        Execute a playbook immediately.
        Returns hunt_id.
        """
        if not self.supervisor:
            logger.error("No hunt supervisor configured")
            return None

        hypothesis = playbook.hypothesis_template
        if context:
            # Template substitution for trigger context
            for key, value in context.items():
                hypothesis = hypothesis.replace(f"{{{key}}}", str(value))

        session = await self.supervisor.run_hunt(
            hypothesis=hypothesis or f"Playbook: {playbook.name}",
            initiated_by=f"scheduler/{playbook.id}",
            target_nodes=None,  # Determined by playbook target config
        )
        return session.hunt_id

    async def _cron_loop(self, playbook: Playbook):
        """Run a playbook on its cron schedule."""
        while self._running:
            next_run = self._calculate_next_run(playbook.schedule_cron)
            sleep_seconds = max((next_run - datetime.utcnow()).total_seconds(), 60)
            await asyncio.sleep(sleep_seconds)

            if not self._running:
                break

            logger.info(f"Cron executing playbook: {playbook.name}")
            await self.run_playbook(playbook)
            self._last_run[playbook.id] = datetime.utcnow()

    def _calculate_next_run(self, cron_expr: str) -> datetime:
        """Parse cron expression and calculate next run time."""
        # Simplified: in production use croniter
        # For now, default to 1 hour from now
        from datetime import timedelta
        return datetime.utcnow() + timedelta(hours=1)

    async def _handle_trigger(self, message: Dict[str, Any]):
        """Handle trigger events from message queue."""
        trigger_type = message.get("type", "")
        handler = self._trigger_handlers.get(trigger_type)
        if handler:
            await handler(message)

    def _register_cve_trigger(self, playbook: Playbook, trigger: Dict[str, Any]):
        """Register a CVE-based trigger for a playbook."""
        async def handler(message: Dict[str, Any]):
            cve_id = message.get("cve_id", "")
            logger.info(f"CVE trigger fired: {cve_id} → playbook {playbook.name}")
            await self.run_playbook(playbook, context={"cve_id": cve_id, "indicators": message.get("indicators", [])})

        self._trigger_handlers["new_cve"] = handler

    def _register_alert_trigger(self, playbook: Playbook, trigger: Dict[str, Any]):
        """Register an alert-based trigger."""
        async def handler(message: Dict[str, Any]):
            await self.run_playbook(playbook, context=message)

        self._trigger_handlers[f"alert_{trigger.get('name', '')}"] = handler
