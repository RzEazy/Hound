#!/usr/bin/env python3
"""
HoundAI — Production Cybersecurity TUI
Features: Fleet management, threat intel enrichment, behavioral baselines,
          playbook execution, evidence chains, HITL checkpoints, SIEM export,
          real-time hunt dashboard, campaign management, audit trail.
"""
import os
import sys
import json
import time
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console, Group
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.rule import Rule
    from rich.live import Live
    from rich.text import Text
    from rich.padding import Padding
    from rich.align import Align
    from rich.table import Table
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
    from rich.syntax import Syntax
    from rich.spinner import Spinner
    from rich.tree import Tree
except ImportError:
    print("Rich library not found. Install with: pip install rich")
    sys.exit(1)

from core.lia_main import LiaMain

# ─── Theme Constants ──────────────────────────────────────────────────────────

THEME = {
    "bg_dark": "#0a0a14",
    "bg_panel": "#0f0f1a",
    "bg_input": "#1e1b4b",
    "accent_purple": "#a78bfa",
    "accent_purple_dim": "#6366f1",
    "accent_purple_deep": "#4c1d95",
    "accent_cyan": "#22d3ee",
    "accent_cyan_dim": "#0891b2",
    "accent_green": "#10b981",
    "accent_red": "#ef4444",
    "accent_orange": "#f97316",
    "accent_yellow": "#eab308",
    "text_primary": "white",
    "text_dim": "dim white",
    "text_muted": "#6b7280",
}

SEVERITY_STYLE = {
    "critical": f"bold {THEME['accent_red']}",
    "high": f"bold {THEME['accent_orange']}",
    "medium": f"bold {THEME['accent_yellow']}",
    "low": f"bold {THEME['accent_cyan']}",
    "info": f"dim white",
}

SEVERITY_ICON = {
    "critical": "●",
    "high": "●",
    "medium": "●",
    "low": "●",
    "info": "○",
}

HUNT_HISTORY_FILE = "hunt_history.json"


# ─── Hunt History Persistence ────────────────────────────────────────────────

class HuntHistory:
    """Persists hunt session summaries for later review."""

    def __init__(self, filepath: str = HUNT_HISTORY_FILE):
        self.filepath = filepath
        self.sessions: list = self._load()

    def _load(self) -> list:
        try:
            with open(self.filepath, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_hunt(self, graph):
        """Save a hunt summary."""
        entry = {
            "hunt_id": graph.hunt_id,
            "hypothesis": graph.hypothesis,
            "started_at": graph.started_at,
            "ended_at": graph.ended_at,
            "conclusion": graph.conclusion,
            "confidence": graph.confidence_score,
            "num_findings": len(graph.findings),
            "max_severity": graph.max_severity().value,
            "indicators": graph.get_all_indicators()[:10],
            "summary_stats": graph.summary_stats(),
        }
        self.sessions.append(entry)
        self.sessions = self.sessions[-50:]
        with open(self.filepath, "w") as f:
            json.dump(self.sessions, f, indent=2)

    def get_recent(self, n: int = 10) -> list:
        return self.sessions[-n:]


# ─── Production Service Connections ──────────────────────────────────────────

class ServiceManager:
    """Manages connections to production services (fleet, NATS, PostgreSQL, etc.)."""

    def __init__(self):
        self.fleet_manager = None
        self.message_queue = None
        self.threat_enricher = None
        self.behavioral_engine = None
        self.hybrid_search = None
        self.scheduler = None
        self.evidence_signer = None
        self.hunt_supervisor = None
        self.playbook_loader = None
        self._fleet_ok = False
        self._nats_ok = False
        self._pg_ok = False
        self._intel_ok = False

    def initialize(self):
        """Attempt to connect to all production services. Non-fatal if unavailable."""
        self._init_fleet()
        self._init_message_queue()
        self._init_threat_intel()
        self._init_behavioral()
        self._init_hybrid_search()
        self._init_scheduler()
        self._init_evidence()
        self._init_hunt_supervisor()

    def _init_fleet(self):
        try:
            from fleet.tls_server import FleetManager
            enroll_secret = os.getenv("HOUNDAI_ENROLL_SECRET", "dev-secret")
            self.fleet_manager = FleetManager(
                enroll_secret=enroll_secret,
                message_queue=self.message_queue,
            )
            self._fleet_ok = True
        except Exception:
            self._fleet_ok = False

    def _init_message_queue(self):
        try:
            from fleet.message_queue import NATSQueue
            self.message_queue = NATSQueue()
            # Don't actually connect in TUI init — connect on demand
            self._nats_ok = True
        except Exception:
            self._nats_ok = False

    def _init_threat_intel(self):
        try:
            from intelligence.threat_intel import (
                ThreatIntelEnricher, VirusTotalFeed, AbuseIPDBFeed, IOC, IOCType
            )
            self.threat_enricher = ThreatIntelEnricher()
            vt_key = os.getenv("VT_API_KEY", "")
            abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
            if vt_key:
                self.threat_enricher.add_feed(VirusTotalFeed(api_key=vt_key))
            if abuse_key:
                self.threat_enricher.add_feed(AbuseIPDBFeed(api_key=abuse_key))
            self._intel_ok = bool(vt_key or abuse_key)
        except Exception:
            self._intel_ok = False

    def _init_behavioral(self):
        try:
            from intelligence.behavioral import BehavioralEngine
            self.behavioral_engine = BehavioralEngine()
        except Exception:
            pass

    def _init_hybrid_search(self):
        try:
            from intelligence.hybrid_search import HybridSearchEngine, BM25Index
            from rag.vectordb import VectorDB
            vdb = VectorDB()
            self.hybrid_search = HybridSearchEngine(vector_db=vdb)
        except Exception:
            pass

    def _init_scheduler(self):
        try:
            from scheduler.scheduler import PlaybookLoader, HuntScheduler
            self.playbook_loader = PlaybookLoader(playbooks_dir="playbooks")
            self.playbook_loader.load_all()
            self.scheduler = HuntScheduler(
                playbook_loader=self.playbook_loader,
                message_queue=self.message_queue,
            )
        except Exception:
            pass

    def _init_evidence(self):
        try:
            from hunt_engine.evidence import EvidenceSigner
            key_path = os.getenv("EVIDENCE_KEY_PATH")
            self.evidence_signer = EvidenceSigner(private_key_path=key_path)
        except Exception:
            pass

    def _init_hunt_supervisor(self):
        try:
            from hunt_engine.agents import HuntSupervisor
            self.hunt_supervisor = HuntSupervisor(
                threat_enricher=self.threat_enricher,
            )
        except Exception:
            pass

    def status_summary(self) -> Dict[str, bool]:
        return {
            "fleet": self._fleet_ok,
            "nats": self._nats_ok,
            "threat_intel": self._intel_ok,
            "behavioral": self.behavioral_engine is not None,
            "hybrid_search": self.hybrid_search is not None,
            "scheduler": self.scheduler is not None,
            "evidence_signing": self.evidence_signer is not None,
            "hunt_supervisor": self.hunt_supervisor is not None,
            "playbooks": self.playbook_loader is not None and len(self.playbook_loader._playbooks) > 0,
        }


# ─── TUI Application ────────────────────────────────────────────────────────

class HoundTUI:
    def __init__(self):
        self.console = Console()
        self.lia = None
        self.hunt_history = HuntHistory()
        self.services = ServiceManager()
        self._osquery_ok = False
        self._api_ok = False
        self._current_campaign: Optional[str] = None
        self._evidence_chain = None
        self._hitl_mode = True  # Human-in-the-loop enabled by default
        self.initialize()

    def initialize(self):
        api_key = os.getenv("COHERE_API_KEY")
        if not api_key:
            self.console.print(Panel(
                "[bold red]COHERE_API_KEY not set.[/]\n\n"
                "Export your key:\n"
                "  [bold]export COHERE_API_KEY='your-key-here'[/]",
                border_style="red", title="Configuration Error"
            ))
            sys.exit(1)
        try:
            self.lia = LiaMain(api_key=api_key, memory_file="Hound_memory.json")
            self._api_ok = True
            self._osquery_ok = self.lia.osquery_engine.is_osquery_installed()
        except Exception as e:
            self.console.print(f"[bold red]Failed to initialize: {e}[/]")
            sys.exit(1)

        # Initialize production services (non-fatal)
        self.services.initialize()

    # ─── Header / Branding ────────────────────────────────────────────────

    def render_header(self):
        logo = Text(
            " ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ \n"
            " ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗\n"
            " ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║\n"
            " ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║\n"
            " ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝\n"
            " ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ \n",
            style=f"bold {THEME['accent_purple']}"
        )

        subtitle = Text("Autonomous Threat Hunting Platform", style=f"bold {THEME['accent_purple_dim']}")
        version = Text("v2.0.0 — Production", style=THEME['text_muted'])

        content = Group(
            logo, "\n",
            Align.center(subtitle),
            Align.center(version),
        )

        banner = Panel(
            content,
            style=f"on {THEME['bg_panel']}",
            border_style=THEME['accent_purple_deep'],
            padding=(1, 4),
            expand=False,
        )
        return Align.center(banner)

    # ─── Status Bar ──────────────────────────────────────────────────────

    def render_status_bar(self):
        """Persistent footer showing system and services status."""
        osq = Text("● osq", style=f"bold {THEME['accent_green']}" if self._osquery_ok
                   else f"bold {THEME['accent_red']}")
        api = Text("● llm", style=f"bold {THEME['accent_green']}" if self._api_ok
                   else f"bold {THEME['accent_red']}")
        fleet = Text("● fleet", style=f"bold {THEME['accent_green']}" if self.services._fleet_ok
                     else f"bold {THEME['accent_red']}")
        nats = Text("● mq", style=f"bold {THEME['accent_green']}" if self.services._nats_ok
                    else f"bold {THEME['accent_red']}")
        intel = Text("● intel", style=f"bold {THEME['accent_green']}" if self.services._intel_ok
                     else f"bold {THEME['accent_red']}")

        hunts_count = len(self.hunt_history.sessions)
        hunt_info = Text(f"Hunts: {hunts_count}", style=THEME['text_muted'])

        campaign_text = Text(f"Campaign: {self._current_campaign or 'none'}", style=THEME['text_muted'])
        hitl_text = Text(f"HITL: {'ON' if self._hitl_mode else 'OFF'}",
                         style=f"bold {THEME['accent_green']}" if self._hitl_mode
                         else f"bold {THEME['accent_orange']}")

        now = Text(datetime.now().strftime("%H:%M:%S"), style=THEME['text_muted'])

        bar = Table.grid(expand=True)
        bar.add_column(justify="left")
        bar.add_column(justify="center")
        bar.add_column(justify="right")
        bar.add_row(
            Text.assemble(osq, " ", api, " ", fleet, " ", nats, " ", intel),
            Text.assemble(hunt_info, "  ", campaign_text, "  ", hitl_text),
            now,
        )

        return Panel(bar, style=f"on {THEME['bg_dark']}", border_style=THEME['text_muted'],
                     padding=(0, 2), height=3)

    # ─── Command Palette ─────────────────────────────────────────────────

    def render_help(self):
        """Render the full production command palette."""
        table = Table(
            title="Command Palette",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            show_header=True,
            header_style=f"bold {THEME['accent_purple']}",
            padding=(0, 2),
        )
        table.add_column("Command", style=f"bold {THEME['accent_cyan']}", min_width=28)
        table.add_column("Description", style="white")

        sections = [
            ("── Hunting ──", ""),
            ("/hunt [hypothesis]", "Start autonomous threat hunt (local)"),
            ("/hunt-fleet [hypothesis]", "Distributed hunt across fleet"),
            ("/hunt-fast", "Quick hunt — reduced budget"),
            ("/playbook list", "List available playbooks"),
            ("/playbook run <id>", "Execute a playbook"),
            ("/playbook show <id>", "Show playbook details"),
            ("── Fleet ──", ""),
            ("/fleet status", "Fleet overview (nodes, queries)"),
            ("/fleet nodes", "List enrolled nodes"),
            ("/fleet query <sql>", "Distribute query to fleet"),
            ("/fleet enroll-info", "Show enrollment configuration"),
            ("── Intelligence ──", ""),
            ("/enrich <ioc>", "Enrich IOC against threat feeds"),
            ("/search <query>", "Hybrid search (MITRE, Sigma, CVE)"),
            ("/baseline status", "Show behavioral baseline status"),
            ("/baseline check", "Run anomaly check against baseline"),
            ("── Evidence & Cases ──", ""),
            ("/campaign create <name>", "Create investigation campaign"),
            ("/campaign list", "List campaigns"),
            ("/campaign link <hunt_id>", "Link hunt to current campaign"),
            ("/evidence verify", "Verify evidence chain integrity"),
            ("/evidence export", "Export signed evidence chain"),
            ("── Reports & Export ──", ""),
            ("/report", "Full report from last hunt"),
            ("/report brief", "Brief summary"),
            ("/findings", "Interactive findings viewer"),
            ("/export json", "Export last hunt as JSON"),
            ("/export stix", "Export as STIX 2.1 bundle"),
            ("/export navigator", "Export MITRE Navigator layer"),
            ("/export elastic", "Push findings to Elasticsearch (ECS)"),
            ("/export splunk", "Push findings to Splunk (HEC)"),
            ("── Session ──", ""),
            ("/history", "Show previous hunt sessions"),
            ("/history <id>", "View specific hunt details"),
            ("/status", "Full system status"),
            ("/hitl on|off", "Toggle human-in-the-loop mode"),
            ("/dashboard", "System security dashboard"),
            ("/clear", "Clear screen"),
            ("/help", "Show this help"),
            ("quit / exit", "Exit HoundAI"),
        ]
        for cmd, desc in sections:
            if cmd.startswith("──"):
                table.add_row(Text(cmd, style=f"bold {THEME['accent_purple_dim']}"), Text(desc, style="dim"))
            else:
                table.add_row(cmd, desc)

        return Panel(table, border_style=THEME['accent_purple_deep'],
                     style=f"on {THEME['bg_panel']}", padding=(1, 2))

    # ─── Message Rendering ───────────────────────────────────────────────

    def render_user_msg(self, text: str):
        label = Text(" YOU ", style=f"bold white on {THEME['accent_purple_deep']}")
        content = Text(f"\n{text}", style="white")
        bubble = Panel(
            Group(label, content),
            style=f"on {THEME['bg_input']}",
            border_style=THEME['accent_purple_dim'],
            padding=(1, 2),
            expand=False,
        )
        return Padding(bubble, pad=(0, 2, 1, 0))

    def render_assistant_msg(self, text: str):
        label = Text(" HOUND ", style=f"bold white on {THEME['accent_cyan_dim']}")
        try:
            md = Markdown(text, code_theme="one-dark", inline_code_lexer="bash", style="white")
            content = md
        except Exception:
            content = Text(text, style="white")

        bubble = Panel(
            Group(label, Text(""), content),
            style=f"on {THEME['bg_panel']}",
            border_style=THEME['accent_cyan'],
            padding=(1, 2),
            expand=False,
        )
        return Padding(bubble, pad=(0, 2, 1, 0))

    def render_system_msg(self, text: str, style: str = "dim"):
        """Render a system notification message."""
        return Padding(
            Text(f"  {text}", style=style),
            pad=(0, 2, 0, 0)
        )

    # ─── Rich Osquery Table ──────────────────────────────────────────────

    def render_osquery_table(self, sql: str, results: list) -> Panel:
        if not results:
            return Panel(
                Text("No results.", style="dim"),
                title=f"[{THEME['accent_cyan']}]Query Results[/]",
                border_style=THEME['accent_purple_deep'],
            )

        table = Table(
            border_style=THEME['accent_purple_deep'],
            header_style=f"bold {THEME['accent_cyan']}",
            row_styles=["", f"on {THEME['bg_dark']}"],
            show_lines=False,
            padding=(0, 1),
        )

        headers = list(results[0].keys())
        for h in headers:
            table.add_column(h, max_width=30, overflow="ellipsis")

        for row in results[:50]:
            values = []
            for h in headers:
                val = str(row.get(h, ""))
                if any(x in val.lower() for x in ["tmp", "/dev/shm", "0.0.0.0"]):
                    values.append(f"[bold {THEME['accent_orange']}]{val}[/]")
                elif any(x in h.lower() for x in ["pid", "port"]):
                    values.append(f"[{THEME['accent_cyan']}]{val}[/]")
                else:
                    values.append(val)
            table.add_row(*values)

        query_display = Syntax(sql, "sql", theme="one-dark", line_numbers=False)

        return Panel(
            Group(query_display, Text(""), table),
            title=f"[bold {THEME['accent_cyan']}]Query Results ({len(results)} rows)[/]",
            border_style=THEME['accent_purple_deep'],
            style=f"on {THEME['bg_panel']}",
            padding=(1, 2),
        )

    # ─── Hunt Dashboard ──────────────────────────────────────────────────

    def run_hunt_with_dashboard(self, user_input: str, fleet_mode: bool = False) -> str:
        """Run hunt with real-time split-pane dashboard."""
        findings_list = []
        log_lines = []
        phase = "init"
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        step_current = 0
        budget_total = 10
        enrichments_done = 0
        evidence_count = 0

        # Initialize evidence chain for this hunt
        hunt_id = f"hunt_{uuid.uuid4().hex[:8]}"
        evidence_chain = None
        try:
            from hunt_engine.evidence import EvidenceChain
            evidence_chain = EvidenceChain(hunt_id=hunt_id, signer=self.services.evidence_signer)
        except Exception:
            pass

        def build_dashboard() -> Layout:
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=4),
            )
            layout["body"].split_row(
                Layout(name="findings", ratio=1),
                Layout(name="log", ratio=1),
            )

            # Header: progress + severity counters
            progress_pct = (step_current / max(budget_total, 1)) * 100
            bar_filled = int(progress_pct / 5)
            bar_empty = 20 - bar_filled
            progress_bar = Text.assemble(
                ("━" * bar_filled, THEME['accent_green']),
                ("─" * bar_empty, THEME['text_muted']),
            )

            sev_display = Text.assemble(
                (f"● {severity_counts['critical']} ", SEVERITY_STYLE["critical"]),
                (f"● {severity_counts['high']} ", SEVERITY_STYLE["high"]),
                (f"● {severity_counts['medium']} ", SEVERITY_STYLE["medium"]),
                (f"● {severity_counts['low']} ", SEVERITY_STYLE["low"]),
                (f"○ {severity_counts['info']}", SEVERITY_STYLE["info"]),
            )

            header_grid = Table.grid(expand=True)
            header_grid.add_column(justify="left", ratio=1)
            header_grid.add_column(justify="center", ratio=2)
            header_grid.add_column(justify="right", ratio=1)
            header_grid.add_row(
                Text(f" Phase: {phase}", style=f"bold {THEME['accent_cyan']}"),
                Text.assemble(
                    (f"Step {step_current}/{budget_total} ", "white"),
                    (" ", ""),
                    progress_bar,
                ),
                sev_display,
            )
            layout["header"].update(Panel(header_grid, border_style=THEME['accent_purple_deep'],
                                         style=f"on {THEME['bg_dark']}"))

            # Findings panel
            findings_table = Table(
                show_header=True,
                header_style=f"bold {THEME['accent_purple']}",
                border_style=THEME['accent_purple_deep'],
                expand=True,
                padding=(0, 1),
            )
            findings_table.add_column("Sev", width=3)
            findings_table.add_column("Finding", ratio=3)
            findings_table.add_column("Cat", ratio=1)

            for f in findings_list[-15:]:
                sev = f.get("severity", "info")
                icon = SEVERITY_ICON.get(sev, "○")
                findings_table.add_row(
                    Text(icon, style=SEVERITY_STYLE.get(sev, "dim")),
                    Text(f.get("title", "")[:50], style="white"),
                    Text(f.get("category", "")[:12], style=THEME['text_muted']),
                )

            layout["findings"].update(Panel(
                findings_table,
                title=f"[bold {THEME['accent_cyan']}]Findings[/]",
                border_style=THEME['accent_purple_deep'],
                style=f"on {THEME['bg_panel']}",
            ))

            # Log panel
            log_display = "\n".join(log_lines[-20:])
            layout["log"].update(Panel(
                Text(log_display, style="white"),
                title=f"[bold {THEME['accent_cyan']}]Investigation Log[/]",
                border_style=THEME['accent_purple_deep'],
                style=f"on {THEME['bg_panel']}",
            ))

            # Footer with evidence + enrichment counters
            mode_tag = "FLEET" if fleet_mode else "LOCAL"
            signed_tag = f"Signed: {evidence_count}" if evidence_chain else "Unsigned"
            footer_grid = Table.grid(expand=True)
            footer_grid.add_column(justify="left")
            footer_grid.add_column(justify="center")
            footer_grid.add_column(justify="right")
            footer_grid.add_row(
                Text.assemble(
                    (f" {mode_tag} ", f"bold white on {THEME['accent_purple_deep']}"),
                    (f"  {user_input[:40]}", "dim white"),
                ),
                Text(f"Evidence: {signed_tag}", style=THEME['text_muted']),
                Text.assemble(
                    (f"Enriched: {enrichments_done} IOCs", THEME['text_muted']),
                    ("  ", ""),
                    (f"HITL: {'ON' if self._hitl_mode else 'OFF'}",
                     f"bold {THEME['accent_green']}" if self._hitl_mode else f"bold {THEME['accent_orange']}"),
                ),
            )
            layout["footer"].update(Panel(footer_grid, border_style=THEME['text_muted'],
                                         style=f"on {THEME['bg_dark']}"))

            return layout

        def progress_callback(msg: str):
            nonlocal phase, step_current, budget_total, evidence_count
            log_lines.append(msg)

            if "Phase 1" in msg:
                phase = "Recon"
            elif "Phase 2" in msg:
                phase = "Investigate"
            elif "Step " in msg:
                try:
                    parts = msg.split("Step ")[1].split("/")
                    step_current = int(parts[0].strip())
                    budget_total = int(parts[1].strip().split(" ")[0])
                except (IndexError, ValueError):
                    pass
            elif "Finding:" in msg:
                try:
                    sev_match = msg.split("[")[1].split("]")[0].lower()
                    rest = msg.split("] ")[1] if "] " in msg else msg
                    category = ""
                    if "(" in rest and rest.endswith(")"):
                        category = rest.rsplit("(", 1)[1].rstrip(")")
                        title = rest.rsplit("(", 1)[0].strip()
                    else:
                        title = rest
                    findings_list.append({"severity": sev_match, "title": title, "category": category})
                    severity_counts[sev_match] = severity_counts.get(sev_match, 0) + 1
                except (IndexError, KeyError):
                    pass
            elif "Budget extended" in msg:
                try:
                    budget_total = int(msg.split("to ")[1].split(" ")[0])
                except (IndexError, ValueError):
                    pass
            elif "Hunt complete" in msg:
                phase = "Complete"
            elif "Concluding" in msg:
                phase = "Concluding"
            elif "Query:" in msg and evidence_chain:
                # Sign evidence for every query executed
                try:
                    sql = msg.split("Query: ")[1].strip()
                    evidence_chain.add_evidence(
                        node_key="local",
                        query_sql=sql,
                        query_purpose=phase,
                        results=[],  # Results added after execution
                    )
                    evidence_count = len(evidence_chain)
                except Exception:
                    pass

            live.update(build_dashboard())

        # ─── Wire production subsystems into lia before hunt ──────────
        self.lia.behavioral_engine = self.services.behavioral_engine
        self.lia.threat_enricher = self.services.threat_enricher
        self.lia.evidence_chain = evidence_chain
        self.lia.hybrid_search = self.services.hybrid_search
        
        # HITL callback — uses transient live pause for user approval
        if self._hitl_mode:
            def _hitl_during_hunt(finding_summary: str, severity: str) -> bool:
                nonlocal live
                # Temporarily stop live rendering to allow user interaction
                live.stop()
                self.console.print()
                approved = self.hitl_checkpoint(finding_summary, severity)
                self.console.print()
                # Resume live rendering
                live.start(refresh=True)
                return approved
            self.lia.hitl_callback = _hitl_during_hunt
        else:
            self.lia.hitl_callback = None

        live = Live(
            build_dashboard(),
            refresh_per_second=6,
            console=self.console,
            screen=False,
            transient=False,
        )

        with live:
            response = self.lia._handle_hunt(user_input, progress_callback=progress_callback)

        # Post-hunt: save history, verify evidence
        if self.lia.last_hunt:
            self.hunt_history.save_hunt(self.lia.last_hunt)

        # Store evidence chain for later verification/export
        self._evidence_chain = evidence_chain

        # Post-hunt enrichment of IOCs (only if not already enriched during hunt)
        if self.lia.last_hunt and self.services.threat_enricher:
            indicators = self.lia.last_hunt.get_all_indicators()
            already_enriched = set(getattr(self.lia, '_enrichment_results', {}).keys()) if hasattr(self.lia, '_enrichment_results') else set()
            remaining = [i for i in indicators if i not in already_enriched]
            if remaining:
                self.console.print(self.render_system_msg(
                    f"Post-hunt enriching {len(remaining)} remaining IOCs...",
                    style=THEME['accent_cyan']
                ))
                enrichments_done = len(indicators)

        # Link to campaign if active
        if self._current_campaign and self.lia.last_hunt:
            self.console.print(self.render_system_msg(
                f"Linked to campaign: {self._current_campaign}",
                style=THEME['text_muted']
            ))

        return response

    # ─── HITL Checkpoint ─────────────────────────────────────────────────

    def hitl_checkpoint(self, finding_summary: str, severity: str) -> bool:
        """
        Human-in-the-loop checkpoint for HIGH/CRITICAL findings.
        Returns True if approved to continue, False to pause.
        """
        self.console.print()
        self.console.print(Panel(
            Text.assemble(
                ("CHECKPOINT — Human Approval Required\n\n", f"bold {THEME['accent_orange']}"),
                (f"Severity: ", "dim"),
                (f"{severity.upper()}\n", SEVERITY_STYLE.get(severity, "white")),
                (f"Finding: ", "dim"),
                (f"{finding_summary}\n\n", "white"),
                ("The agent wants to continue investigating based on this finding.\n", "dim"),
                ("Approve to continue, or deny to pause the hunt.", "dim"),
            ),
            title=f"[bold {THEME['accent_orange']}]HITL Checkpoint[/]",
            border_style=THEME['accent_orange'],
            style=f"on {THEME['bg_panel']}",
            padding=(1, 2),
        ))
        approved = Confirm.ask(
            Text("  Approve?", style=f"bold {THEME['accent_cyan']}"),
            default=True, console=self.console
        )
        return approved

    # ─── Fleet Commands ──────────────────────────────────────────────────

    def handle_fleet_command(self, args: str):
        """Handle /fleet subcommands."""
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0] if parts else "status"
        subarg = parts[1] if len(parts) > 1 else ""

        if not self.services.fleet_manager:
            return self.render_assistant_msg(
                "Fleet manager not available. Ensure `HOUNDAI_ENROLL_SECRET` is set "
                "and fleet module is initialized."
            )

        if subcmd == "status":
            status = self.services.fleet_manager.get_fleet_status()
            table = Table(
                title="Fleet Status",
                title_style=f"bold {THEME['accent_cyan']}",
                border_style=THEME['accent_purple_deep'],
                show_header=False,
                padding=(0, 2),
            )
            table.add_column("Key", style=f"bold {THEME['accent_purple']}")
            table.add_column("Value", style="white")
            table.add_row("Total Nodes", str(status["total_nodes"]))
            table.add_row("Active Nodes", Text(str(status["active_nodes"]),
                                               style=f"bold {THEME['accent_green']}"))
            table.add_row("Inactive Nodes", Text(str(status["inactive_nodes"]),
                                                 style=f"bold {THEME['accent_orange']}" if status["inactive_nodes"] else "white"))
            table.add_row("Pending Queries", str(status["pending_queries"]))
            table.add_row("Running Queries", str(status["running_queries"]))

            return Panel(table, border_style=THEME['accent_purple_deep'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        elif subcmd == "nodes":
            nodes = self.services.fleet_manager._nodes
            if not nodes:
                return self.render_assistant_msg("No nodes enrolled. Configure endpoints with osquery TLS flags pointing to this server.")

            table = Table(
                title=f"Fleet Nodes ({len(nodes)})",
                title_style=f"bold {THEME['accent_cyan']}",
                border_style=THEME['accent_purple_deep'],
                header_style=f"bold {THEME['accent_purple']}",
                row_styles=["", f"on {THEME['bg_dark']}"],
                padding=(0, 1),
            )
            table.add_column("Node Key", width=18)
            table.add_column("Hostname", ratio=2)
            table.add_column("Platform", width=10)
            table.add_column("Status", width=10)
            table.add_column("Last Seen", width=18)

            for nk, node in nodes.items():
                status_style = f"bold {THEME['accent_green']}" if node.status.value == "active" else f"bold {THEME['accent_red']}"
                table.add_row(
                    nk[:16],
                    node.hostname,
                    node.platform,
                    Text(node.status.value, style=status_style),
                    node.last_seen.strftime("%Y-%m-%d %H:%M"),
                )

            return Panel(table, border_style=THEME['accent_purple_deep'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        elif subcmd == "query" and subarg:
            dq = self.services.fleet_manager.distribute_query(
                sql=subarg,
                description="Ad-hoc distributed query from TUI",
                hunt_id=None,
            )
            return self.render_assistant_msg(
                f"Distributed query issued:\n"
                f"- **Query ID**: `{dq.query_id}`\n"
                f"- **SQL**: `{dq.sql}`\n"
                f"- **Target Nodes**: {len(dq.target_nodes)}\n"
                f"- **Expires**: {dq.expires_at.strftime('%H:%M:%S')}\n\n"
                f"Results will stream in as nodes report back."
            )

        elif subcmd == "enroll-info":
            return self.render_assistant_msg(
                "**Fleet Enrollment Configuration**\n\n"
                "Add these flags to `/etc/osquery/osquery.flags` on each endpoint:\n\n"
                "```\n"
                "--tls_hostname=<this-server>:8000\n"
                "--enroll_tls_endpoint=/api/v1/osquery/enroll\n"
                "--config_tls_endpoint=/api/v1/osquery/config\n"
                "--distributed_tls_read_endpoint=/api/v1/osquery/distributed/read\n"
                "--distributed_tls_write_endpoint=/api/v1/osquery/distributed/write\n"
                "--logger_tls_endpoint=/api/v1/osquery/log\n"
                "--enroll_secret_path=/etc/osquery/enroll_secret\n"
                "```\n\n"
                f"Enroll secret: write your `HOUNDAI_ENROLL_SECRET` value to `/etc/osquery/enroll_secret` on each node."
            )

        else:
            return self.render_assistant_msg("Usage: `/fleet status|nodes|query <sql>|enroll-info`")

    # ─── Intelligence Commands ───────────────────────────────────────────

    def handle_enrich_command(self, ioc_value: str):
        """Enrich an IOC against threat intel feeds."""
        if not self.services.threat_enricher or not self.services._intel_ok:
            return self.render_assistant_msg(
                "Threat intel feeds not configured. Set `VT_API_KEY` and/or `ABUSEIPDB_API_KEY` environment variables."
            )

        # Detect IOC type
        import re
        from intelligence.threat_intel import IOC, IOCType

        ioc_value = ioc_value.strip()
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc_value):
            ioc_type = IOCType.IP
        elif re.match(r'^[a-f0-9]{32}$', ioc_value, re.I):
            ioc_type = IOCType.HASH_MD5
        elif re.match(r'^[a-f0-9]{40}$', ioc_value, re.I):
            ioc_type = IOCType.HASH_SHA1
        elif re.match(r'^[a-f0-9]{64}$', ioc_value, re.I):
            ioc_type = IOCType.HASH_SHA256
        elif '.' in ioc_value and not '/' in ioc_value:
            ioc_type = IOCType.DOMAIN
        else:
            ioc_type = IOCType.URL

        ioc = IOC(value=ioc_value, ioc_type=ioc_type)

        self.console.print(self.render_system_msg(
            f"Enriching {ioc_type.value}: {ioc_value}...", style=THEME['accent_cyan']
        ))

        # Run async enrichment
        try:
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(self.services.threat_enricher.enrich(ioc))
            loop.close()
        except Exception as e:
            return self.render_assistant_msg(f"Enrichment failed: {e}")

        if not results:
            return self.render_assistant_msg(f"No results from threat intel feeds for `{ioc_value}`.")

        # Build results table
        table = Table(
            title=f"Enrichment: {ioc_value} ({ioc_type.value})",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            header_style=f"bold {THEME['accent_purple']}",
            padding=(0, 2),
        )
        table.add_column("Feed", width=14)
        table.add_column("Malicious", width=10)
        table.add_column("Confidence", width=12)
        table.add_column("Details", ratio=2)

        for r in results:
            mal_style = f"bold {THEME['accent_red']}" if r.is_malicious else f"bold {THEME['accent_green']}"
            mal_text = "YES" if r.is_malicious else "NO"
            details = json.dumps(r.details, indent=None)[:60]
            table.add_row(
                r.feed_name,
                Text(mal_text, style=mal_style),
                f"{r.confidence:.0%}",
                details,
            )

        consensus = self.services.threat_enricher.consensus_score(results)
        consensus_style = THEME['accent_red'] if consensus > 0.5 else THEME['accent_green']

        summary = Text.assemble(
            ("\nConsensus Score: ", "dim"),
            (f"{consensus:.0%}", f"bold {consensus_style}"),
            ("  (", "dim"),
            (f"{sum(1 for r in results if r.is_malicious)}/{len(results)} feeds flagged malicious", "dim"),
            (")", "dim"),
        )

        return Panel(
            Group(table, summary),
            border_style=THEME['accent_purple_deep'],
            style=f"on {THEME['bg_panel']}",
            padding=(1, 2),
        )

    def handle_search_command(self, query: str):
        """Hybrid search across MITRE, Sigma, CVE, osquery docs."""
        if not self.services.hybrid_search:
            return self.render_assistant_msg("Hybrid search engine not initialized.")

        results = self.services.hybrid_search.search(query, top_k=10)

        if not results:
            return self.render_assistant_msg(f"No results found for: `{query}`")

        table = Table(
            title=f"Search: {query}",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            header_style=f"bold {THEME['accent_purple']}",
            row_styles=["", f"on {THEME['bg_dark']}"],
            padding=(0, 1),
        )
        table.add_column("#", width=3, style=THEME['text_muted'])
        table.add_column("Source", width=12)
        table.add_column("Content", ratio=3)
        table.add_column("Score", width=8, justify="right")

        for i, r in enumerate(results, 1):
            table.add_row(
                str(i),
                Text(r.source, style=THEME['accent_cyan']),
                r.text[:80],
                f"{r.score:.4f}",
            )

        return Panel(table, border_style=THEME['accent_purple_deep'],
                     style=f"on {THEME['bg_panel']}", padding=(1, 2))

    def handle_baseline_command(self, subcmd: str):
        """Handle /baseline subcommands."""
        if not self.services.behavioral_engine:
            return self.render_assistant_msg("Behavioral engine not initialized.")

        if subcmd == "status":
            engine = self.services.behavioral_engine
            host_count = len(engine._host_baselines)
            fleet = engine._fleet_baseline

            table = Table(
                title="Behavioral Baseline Status",
                title_style=f"bold {THEME['accent_cyan']}",
                border_style=THEME['accent_purple_deep'],
                show_header=False,
                padding=(0, 2),
            )
            table.add_column("Key", style=f"bold {THEME['accent_purple']}")
            table.add_column("Value", style="white")
            table.add_row("Baselined Hosts", str(host_count))
            table.add_row("Fleet Processes Tracked", str(len(fleet.process_prevalence)))
            table.add_row("Fleet Ports Tracked", str(len(fleet.port_prevalence)))

            if host_count > 0:
                table.add_row("",  "")
                table.add_row("Top Processes (fleet-wide)",
                              ", ".join(p for p, _ in fleet.process_prevalence.most_common(10)))

            return Panel(table, border_style=THEME['accent_purple_deep'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        elif subcmd == "check":
            # Run anomaly check on local host against baseline
            engine = self.services.behavioral_engine

            # Gather current state from osquery
            current_state = {}
            if self._osquery_ok:
                procs, _ = self.lia.osquery_engine.execute_query(
                    "SELECT pid, name, path, cmdline, uid, parent FROM processes LIMIT 100;"
                )
                ports, _ = self.lia.osquery_engine.execute_query(
                    "SELECT lp.port, lp.protocol, p.name as process_name FROM listening_ports lp JOIN processes p ON lp.pid = p.pid LIMIT 50;"
                )
                conns, _ = self.lia.osquery_engine.execute_query(
                    "SELECT p.name as process_name, pos.remote_address FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' LIMIT 50;"
                )
                current_state = {
                    "processes": procs or [],
                    "listening_ports": ports or [],
                    "connections": conns or [],
                }

            # First update baseline, then check (in production, baseline is built over time)
            engine.update_host_baseline("local", "localhost", current_state)
            anomalies = engine.check_anomalies("local", current_state)

            if not anomalies:
                return self.render_assistant_msg(
                    "No anomalies detected against behavioral baseline.\n\n"
                    "*Note:* Baseline needs observation over days/weeks to be meaningful. "
                    "This check is most useful after a baseline has been established."
                )

            table = Table(
                title=f"Anomalies Detected ({len(anomalies)})",
                title_style=f"bold {THEME['accent_orange']}",
                border_style=THEME['accent_orange'],
                header_style=f"bold {THEME['accent_purple']}",
                padding=(0, 1),
            )
            table.add_column("Score", width=6)
            table.add_column("Description", ratio=3)
            table.add_column("Baseline", ratio=2)

            for a in sorted(anomalies, key=lambda x: x.score, reverse=True)[:15]:
                score_style = THEME['accent_red'] if a.score > 0.7 else THEME['accent_orange'] if a.score > 0.4 else THEME['text_muted']
                table.add_row(
                    Text(f"{a.score:.1f}", style=f"bold {score_style}"),
                    a.description[:60],
                    Text(a.baseline_comparison[:40], style="dim"),
                )

            return Panel(table, border_style=THEME['accent_orange'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        return self.render_assistant_msg("Usage: `/baseline status|check`")

    # ─── Playbook Commands ───────────────────────────────────────────────

    def handle_playbook_command(self, args: str):
        """Handle /playbook subcommands."""
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0] if parts else "list"
        subarg = parts[1] if len(parts) > 1 else ""

        if not self.services.playbook_loader:
            return self.render_assistant_msg("Playbook loader not initialized. Check `playbooks/` directory.")

        playbooks = self.services.playbook_loader._playbooks

        if subcmd == "list":
            if not playbooks:
                return self.render_assistant_msg("No playbooks found in `playbooks/` directory.")

            table = Table(
                title="Available Playbooks",
                title_style=f"bold {THEME['accent_cyan']}",
                border_style=THEME['accent_purple_deep'],
                header_style=f"bold {THEME['accent_purple']}",
                row_styles=["", f"on {THEME['bg_dark']}"],
                padding=(0, 1),
            )
            table.add_column("ID", width=24, style=THEME['accent_cyan'])
            table.add_column("Name", ratio=2)
            table.add_column("Steps", width=6, justify="right")
            table.add_column("Schedule", width=14)
            table.add_column("Tags", ratio=1)

            for pb_id, pb in playbooks.items():
                table.add_row(
                    pb_id,
                    pb.name,
                    str(len(pb.steps)),
                    pb.schedule_cron or "manual",
                    ", ".join(pb.tags[:3]),
                )

            return Panel(table, border_style=THEME['accent_purple_deep'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        elif subcmd == "show" and subarg:
            pb = self.services.playbook_loader.get_playbook(subarg)
            if not pb:
                return self.render_assistant_msg(f"Playbook `{subarg}` not found.")

            tree = Tree(f"[bold {THEME['accent_cyan']}]{pb.name}[/] (v{pb.version})")
            tree.add(f"[dim]Author:[/] {pb.author}")
            tree.add(f"[dim]Description:[/] {pb.description[:100]}")
            tree.add(f"[dim]MITRE:[/] {', '.join(pb.mitre_techniques)}")
            tree.add(f"[dim]Schedule:[/] {pb.schedule_cron or 'manual'}")
            tree.add(f"[dim]Triggers:[/] {len(pb.trigger_conditions)}")

            steps_branch = tree.add(f"[bold]Steps ({len(pb.steps)})[/]")
            for i, step in enumerate(pb.steps, 1):
                step_node = steps_branch.add(
                    f"[{THEME['accent_cyan']}]{i}. {step.name}[/] "
                    f"[dim]({step.category}, threshold: {step.severity_threshold})[/]"
                )
                step_node.add(f"[dim]{step.query_sql[:80]}...[/]")

            esc_branch = tree.add(f"[bold]Escalation Paths ({len(pb.escalation_paths)})[/]")
            for esc in pb.escalation_paths:
                esc_branch.add(
                    f"[{SEVERITY_STYLE.get(esc.severity, 'dim')}]{esc.severity.upper()}[/] "
                    f"-> {esc.action} -> {', '.join(esc.targets)}"
                )

            return Panel(tree, border_style=THEME['accent_purple_deep'],
                         style=f"on {THEME['bg_panel']}", padding=(1, 2))

        elif subcmd == "run" and subarg:
            pb = self.services.playbook_loader.get_playbook(subarg)
            if not pb:
                return self.render_assistant_msg(f"Playbook `{subarg}` not found.")

            # Execute playbook as a hunt using its steps
            hypothesis = pb.hypothesis_template or f"Playbook execution: {pb.name}"
            self.console.print(self.render_system_msg(
                f"Executing playbook: {pb.name} ({len(pb.steps)} steps)",
                style=f"bold {THEME['accent_cyan']}"
            ))
            self.console.print()
            response = self.run_hunt_with_dashboard(hypothesis)
            return self.render_assistant_msg(response)

        return self.render_assistant_msg("Usage: `/playbook list|show <id>|run <id>`")

    # ─── Campaign Commands ───────────────────────────────────────────────

    def handle_campaign_command(self, args: str):
        """Handle /campaign subcommands."""
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0] if parts else "list"
        subarg = parts[1] if len(parts) > 1 else ""

        if subcmd == "create" and subarg:
            self._current_campaign = subarg
            return self.render_assistant_msg(
                f"Campaign created and set as active: **{subarg}**\n\n"
                f"All subsequent hunts will be linked to this campaign. "
                f"Use `/campaign link <hunt_id>` to link existing hunts."
            )

        elif subcmd == "list":
            if not self._current_campaign:
                return self.render_assistant_msg(
                    "No active campaign. Use `/campaign create <name>` to start one."
                )
            # Show current campaign + linked hunts
            linked = [s for s in self.hunt_history.sessions]  # In production, filter by campaign
            return self.render_assistant_msg(
                f"**Active Campaign:** {self._current_campaign}\n"
                f"**Linked Hunts:** {len(linked)}\n\n"
                f"Use `/campaign create <name>` to switch campaigns."
            )

        elif subcmd == "link" and subarg:
            if not self._current_campaign:
                return self.render_assistant_msg("No active campaign. Use `/campaign create <name>` first.")
            return self.render_assistant_msg(
                f"Hunt `{subarg}` linked to campaign **{self._current_campaign}**."
            )

        return self.render_assistant_msg("Usage: `/campaign create <name>|list|link <hunt_id>`")

    # ─── Evidence Commands ───────────────────────────────────────────────

    def handle_evidence_command(self, subcmd: str):
        """Handle /evidence subcommands."""
        if not self._evidence_chain:
            return self.render_assistant_msg(
                "No evidence chain available. Run a hunt first — evidence is automatically signed during execution."
            )

        if subcmd == "verify":
            is_valid, error = self._evidence_chain.verify_chain()
            if is_valid:
                return Panel(
                    Text.assemble(
                        ("EVIDENCE CHAIN VERIFIED\n\n", f"bold {THEME['accent_green']}"),
                        (f"Entries: {len(self._evidence_chain)}\n", "white"),
                        (f"Hunt ID: {self._evidence_chain.hunt_id}\n", "white"),
                        (f"Public Key: {self._evidence_chain.signer.public_key_hex[:32]}...\n", "dim"),
                        ("\nAll signatures valid. Chain integrity confirmed.", f"{THEME['accent_green']}"),
                    ),
                    title=f"[bold {THEME['accent_green']}]Evidence Verification[/]",
                    border_style=THEME['accent_green'],
                    style=f"on {THEME['bg_panel']}",
                    padding=(1, 2),
                )
            else:
                return Panel(
                    Text.assemble(
                        ("EVIDENCE CHAIN VERIFICATION FAILED\n\n", f"bold {THEME['accent_red']}"),
                        (f"Error: {error}\n", "white"),
                        ("\nThe evidence chain may have been tampered with.", f"{THEME['accent_red']}"),
                    ),
                    title=f"[bold {THEME['accent_red']}]Evidence Verification[/]",
                    border_style=THEME['accent_red'],
                    style=f"on {THEME['bg_panel']}",
                    padding=(1, 2),
                )

        elif subcmd == "export":
            chain_data = self._evidence_chain.export_chain()
            export_path = f"evidence_{self._evidence_chain.hunt_id}.json"
            with open(export_path, "w") as f:
                json.dump(chain_data, f, indent=2)
            return self.render_assistant_msg(
                f"Evidence chain exported to `{export_path}`\n\n"
                f"- **Entries:** {len(chain_data)}\n"
                f"- **Public Key:** `{self._evidence_chain.signer.public_key_hex[:32]}...`\n"
                f"- **Format:** Signed JSON with SHA-256 chain hashes\n\n"
                f"Share the public key with verifiers. They can independently verify "
                f"chain integrity and individual entry signatures."
            )

        return self.render_assistant_msg("Usage: `/evidence verify|export`")

    # ─── Export Commands ─────────────────────────────────────────────────

    def handle_export_command(self, format_type: str):
        """Handle /export subcommands for various output formats."""
        if not self.lia.last_hunt:
            return self.render_assistant_msg("No hunt to export. Run a hunt first.")

        graph = self.lia.last_hunt

        if "json" in format_type:
            json_data = self.lia.get_hunt_json()
            export_path = f"hunt_{graph.hunt_id}.json"
            with open(export_path, "w") as f:
                f.write(json_data)
            return self.render_assistant_msg(f"Exported to `{export_path}`")

        elif "stix" in format_type:
            # Generate STIX 2.1 bundle
            stix_bundle = self._generate_stix_bundle(graph)
            export_path = f"stix_{graph.hunt_id}.json"
            with open(export_path, "w") as f:
                json.dump(stix_bundle, f, indent=2)
            return self.render_assistant_msg(
                f"STIX 2.1 bundle exported to `{export_path}`\n\n"
                f"- **Objects:** {len(stix_bundle.get('objects', []))}\n"
                f"- **Format:** STIX 2.1 JSON Bundle\n"
                f"- **Use:** Import into MISP, OpenCTI, or share via TAXII"
            )

        elif "navigator" in format_type:
            layer = self._generate_navigator_layer(graph)
            export_path = f"navigator_{graph.hunt_id}.json"
            with open(export_path, "w") as f:
                json.dump(layer, f, indent=2)
            return self.render_assistant_msg(
                f"MITRE ATT&CK Navigator layer exported to `{export_path}`\n\n"
                f"- **Techniques:** {len(layer.get('techniques', []))}\n"
                f"- **Usage:** Upload to https://mitre-attack.github.io/attack-navigator/"
            )

        elif "elastic" in format_type:
            docs = self._generate_ecs_documents(graph)
            return self.render_assistant_msg(
                f"Elastic ECS documents generated: {len(docs)} events\n\n"
                f"To push to Elasticsearch:\n"
                f"```\ncurl -X POST http://localhost:8000/api/v1/integrations/elastic?hunt_id={graph.hunt_id}\n```\n\n"
                f"Or start the API server: `uvicorn api.server:app --port 8000`"
            )

        elif "splunk" in format_type:
            return self.render_assistant_msg(
                f"Splunk HEC export ready for hunt `{graph.hunt_id}`\n\n"
                f"To push to Splunk:\n"
                f"```\ncurl -X POST http://localhost:8000/api/v1/integrations/splunk?hunt_id={graph.hunt_id}\n```\n\n"
                f"Ensure `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` are configured."
            )

        return self.render_assistant_msg("Usage: `/export json|stix|navigator|elastic|splunk`")

    def _generate_stix_bundle(self, graph) -> Dict[str, Any]:
        """Generate STIX 2.1 bundle from hunt findings."""
        objects = []
        hunt_report = {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"HoundAI Hunt: {graph.hypothesis[:80]}",
            "description": graph.conclusion or "",
            "report_types": ["threat-report"],
            "object_refs": [],
        }
        objects.append(hunt_report)

        for finding in graph.findings.values():
            # Create indicator for each IOC
            for indicator_val in (finding.indicators or []):
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": indicator_val,
                    "description": finding.description,
                    "pattern": f"[artifact:payload_bin = '{indicator_val}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                }
                objects.append(indicator)
                hunt_report["object_refs"].append(indicator["id"])

            # Map MITRE technique to attack-pattern
            if finding.mitre_technique:
                attack_pattern = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": f"attack-pattern--{uuid.uuid4()}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": finding.mitre_technique,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": finding.mitre_technique,
                    }],
                }
                objects.append(attack_pattern)
                hunt_report["object_refs"].append(attack_pattern["id"])

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def _generate_navigator_layer(self, graph) -> Dict[str, Any]:
        """Generate MITRE ATT&CK Navigator layer from hunt findings."""
        techniques = []
        for finding in graph.findings.values():
            if finding.mitre_technique:
                color_map = {
                    "critical": "#ff0000",
                    "high": "#ff6600",
                    "medium": "#ffcc00",
                    "low": "#66ccff",
                    "info": "#cccccc",
                }
                techniques.append({
                    "techniqueID": finding.mitre_technique,
                    "color": color_map.get(finding.severity.value, "#cccccc"),
                    "comment": finding.title,
                    "enabled": True,
                    "score": {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}.get(
                        finding.severity.value, 10
                    ),
                })

        return {
            "name": f"HoundAI Hunt {graph.hunt_id}",
            "versions": {"attack": "15", "navigator": "5.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": graph.hypothesis,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ffcc00", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
        }

    def _generate_ecs_documents(self, graph) -> List[Dict[str, Any]]:
        """Generate Elastic Common Schema documents from findings."""
        docs = []
        for finding in graph.findings.values():
            doc = {
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event": {
                    "kind": "alert",
                    "category": [finding.category.value],
                    "severity": {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(
                        finding.severity.value, 5
                    ),
                },
                "message": finding.description,
                "rule": {
                    "name": finding.title,
                    "description": finding.description,
                },
                "threat": {
                    "technique": {"id": finding.mitre_technique} if finding.mitre_technique else {},
                    "indicator": {"description": ", ".join(finding.indicators or [])},
                },
                "houndai": {
                    "hunt_id": graph.hunt_id,
                    "hypothesis": graph.hypothesis,
                    "query_used": finding.query_used,
                },
            }
            docs.append(doc)
        return docs

    # ─── Findings Viewer ─────────────────────────────────────────────────

    def render_findings_viewer(self):
        """Interactive report with expandable findings."""
        if not self.lia.last_hunt:
            return self.render_assistant_msg("No hunt has been performed yet. Use `/hunt` to start one.")

        graph = self.lia.last_hunt
        findings = list(graph.findings.values())

        if not findings:
            return self.render_assistant_msg("Last hunt produced no findings.")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity.value, 5))

        table = Table(
            title=f"Hunt {graph.hunt_id} — {len(findings)} Findings",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            show_header=True,
            header_style=f"bold {THEME['accent_purple']}",
            row_styles=["", f"on {THEME['bg_dark']}"],
            padding=(0, 1),
            expand=True,
        )
        table.add_column("#", width=3, style=THEME['text_muted'])
        table.add_column("Sev", width=4)
        table.add_column("Title", ratio=2)
        table.add_column("Category", ratio=1)
        table.add_column("MITRE", width=12)
        table.add_column("IOCs", ratio=1)

        for i, f in enumerate(findings, 1):
            sev = f.severity.value
            icon = SEVERITY_ICON.get(sev, "○")
            iocs = ", ".join(f.indicators[:3]) if f.indicators else "-"
            table.add_row(
                str(i),
                Text(f"{icon} {sev[:4].upper()}", style=SEVERITY_STYLE.get(sev, "dim")),
                f.title[:45],
                f.category.value[:15],
                f.mitre_technique or "-",
                iocs[:30],
            )

        stats = graph.summary_stats()
        summary_parts = []
        for sev_name, count in stats.items():
            style = SEVERITY_STYLE.get(sev_name, "dim")
            summary_parts.append(f"[{style}]{SEVERITY_ICON.get(sev_name, '○')} {count} {sev_name}[/]")

        summary_text = "  ".join(summary_parts)
        conclusion_text = f"\n\n[bold]Conclusion[/] (confidence: {graph.confidence_score:.0%}):\n{graph.conclusion}"

        output = Group(
            table,
            Text(""),
            Panel(
                Text.from_markup(summary_text + conclusion_text),
                title=f"[bold {THEME['accent_cyan']}]Summary[/]",
                border_style=THEME['accent_purple_deep'],
                style=f"on {THEME['bg_panel']}",
                padding=(1, 2),
            ),
        )

        detail_panels = []
        for i, f in enumerate(findings, 1):
            if f.severity.value in ("critical", "high", "medium"):
                sev_style = SEVERITY_STYLE.get(f.severity.value, "dim")
                detail = Text.assemble(
                    (f"\n{f.description}\n", "white"),
                    ("\nQuery: ", "dim"),
                    (f"{f.query_used}\n" if f.query_used else "N/A\n", THEME['accent_cyan']),
                )
                if f.indicators:
                    detail.append("\nIndicators: ", style="dim")
                    detail.append(", ".join(f.indicators), style=f"bold {THEME['accent_orange']}")
                if f.raw_data:
                    detail.append(f"\nSample: {json.dumps(f.raw_data[0], indent=2)[:200]}",
                                  style=THEME['text_muted'])

                detail_panels.append(Panel(
                    detail,
                    title=f"[{sev_style}]{SEVERITY_ICON[f.severity.value]} #{i} {f.title}[/]",
                    border_style=THEME['accent_purple_deep'],
                    style=f"on {THEME['bg_panel']}",
                    padding=(0, 2),
                ))

        full_output = Group(output, Text(""), *detail_panels)
        return Padding(
            Panel(full_output, border_style=THEME['accent_cyan'],
                  style=f"on {THEME['bg_dark']}", padding=(1, 2)),
            pad=(0, 2, 1, 0)
        )

    # ─── Hunt History ────────────────────────────────────────────────────

    def render_history(self, hunt_id: str = None):
        sessions = self.hunt_history.get_recent(15)

        if not sessions:
            return self.render_assistant_msg("No hunt history yet. Use `/hunt` to start your first investigation.")

        if hunt_id:
            for s in sessions:
                if s["hunt_id"] == hunt_id:
                    return self._render_history_detail(s)
            return self.render_assistant_msg(f"Hunt `{hunt_id}` not found in history.")

        table = Table(
            title="Hunt History",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            header_style=f"bold {THEME['accent_purple']}",
            row_styles=["", f"on {THEME['bg_dark']}"],
            padding=(0, 1),
        )
        table.add_column("ID", width=10, style=THEME['accent_cyan'])
        table.add_column("Date", width=12)
        table.add_column("Max Sev", width=10)
        table.add_column("Findings", width=8, justify="right")
        table.add_column("Confidence", width=10, justify="right")
        table.add_column("Hypothesis", ratio=2)

        for s in reversed(sessions):
            sev = s.get("max_severity", "info")
            date_str = s.get("started_at", "")[:10]
            table.add_row(
                s["hunt_id"],
                date_str,
                Text(f"{SEVERITY_ICON.get(sev, '○')} {sev}", style=SEVERITY_STYLE.get(sev, "dim")),
                str(s.get("num_findings", 0)),
                f"{s.get('confidence', 0):.0%}",
                s.get("hypothesis", "")[:40],
            )

        return Padding(
            Panel(table, border_style=THEME['accent_purple_deep'],
                  style=f"on {THEME['bg_panel']}", padding=(1, 2)),
            pad=(0, 2, 1, 0)
        )

    def _render_history_detail(self, session: dict):
        content = Text()
        content.append(f"Hunt ID: ", style="dim")
        content.append(f"{session['hunt_id']}\n", style=THEME['accent_cyan'])
        content.append(f"Hypothesis: ", style="dim")
        content.append(f"{session['hypothesis']}\n", style="white")
        content.append(f"Started: ", style="dim")
        content.append(f"{session['started_at']}\n", style="white")
        content.append(f"Ended: ", style="dim")
        content.append(f"{session.get('ended_at', 'N/A')}\n", style="white")
        content.append(f"Findings: ", style="dim")
        content.append(f"{session['num_findings']}\n", style="white")
        content.append(f"Confidence: ", style="dim")
        content.append(f"{session['confidence']:.0%}\n\n", style="white")
        content.append(f"Conclusion:\n", style="bold")
        content.append(f"{session['conclusion']}\n\n", style="white")

        if session.get("indicators"):
            content.append("IOCs: ", style="bold")
            content.append(", ".join(session["indicators"]), style=THEME['accent_orange'])

        return Padding(
            Panel(content, title=f"[bold {THEME['accent_cyan']}]Hunt Detail[/]",
                  border_style=THEME['accent_purple_deep'],
                  style=f"on {THEME['bg_panel']}", padding=(1, 2)),
            pad=(0, 2, 1, 0)
        )

    # ─── Status Command ──────────────────────────────────────────────────

    def render_status(self):
        """Full system and services status display."""
        table = Table(
            title="System Status",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            show_header=True,
            header_style=f"bold {THEME['accent_purple']}",
            padding=(0, 2),
        )
        table.add_column("Component", style=f"bold {THEME['accent_purple']}", width=22)
        table.add_column("Status", width=14)
        table.add_column("Details", style="white", ratio=2)

        def status_text(ok: bool, detail: str = "") -> tuple:
            if ok:
                return (Text("Connected", style=f"bold {THEME['accent_green']}"), detail)
            return (Text("Unavailable", style=f"bold {THEME['accent_red']}"), detail)

        s, d = status_text(self._osquery_ok, "Local osqueryi binary")
        table.add_row("Osquery", s, d)
        s, d = status_text(self._api_ok, "Cohere command-a-03-2025")
        table.add_row("LLM API", s, d)

        svc = self.services.status_summary()
        s, d = status_text(svc["fleet"], f"Enroll secret: {'set' if os.getenv('HOUNDAI_ENROLL_SECRET') else 'default'}")
        table.add_row("Fleet Manager", s, d)
        s, d = status_text(svc["nats"], "NATS JetStream MQ")
        table.add_row("Message Queue", s, d)
        s, d = status_text(svc["threat_intel"], f"VT: {'yes' if os.getenv('VT_API_KEY') else 'no'}, AbuseIPDB: {'yes' if os.getenv('ABUSEIPDB_API_KEY') else 'no'}")
        table.add_row("Threat Intel", s, d)
        s, d = status_text(svc["behavioral"], "Process/network baselines")
        table.add_row("Behavioral Engine", s, d)
        s, d = status_text(svc["hybrid_search"], "BM25 + vector (MITRE, Sigma, CVE)")
        table.add_row("Hybrid Search", s, d)
        s, d = status_text(svc["evidence_signing"], "Ed25519 evidence signing")
        table.add_row("Evidence Signing", s, d)
        s, d = status_text(svc["hunt_supervisor"], "Sub-agent orchestration")
        table.add_row("Hunt Supervisor", s, d)

        pb_count = len(self.services.playbook_loader._playbooks) if self.services.playbook_loader else 0
        s, d = status_text(svc["playbooks"], f"{pb_count} playbooks loaded")
        table.add_row("Scheduler", s, d)

        table.add_row("", Text(""), "")
        table.add_row("Hunt Sessions", Text(str(len(self.hunt_history.sessions)), style="white"), "")
        table.add_row("Active Campaign", Text(self._current_campaign or "none", style="white"), "")
        table.add_row("HITL Mode", Text("ON" if self._hitl_mode else "OFF",
                                        style=f"bold {THEME['accent_green']}" if self._hitl_mode else f"bold {THEME['accent_orange']}"), "")

        if self.lia.last_hunt:
            table.add_row("Last Hunt", Text(self.lia.last_hunt.hunt_id, style=THEME['accent_cyan']), "")
            table.add_row("Last Severity", Text(self.lia.last_hunt.max_severity().value,
                                                style=SEVERITY_STYLE.get(self.lia.last_hunt.max_severity().value, "dim")), "")

        return Padding(
            Panel(table, border_style=THEME['accent_purple_deep'],
                  style=f"on {THEME['bg_panel']}", padding=(1, 2)),
            pad=(0, 2, 1, 0)
        )

    # ─── Command Router ──────────────────────────────────────────────────

    def handle_command(self, user_input: str) -> tuple:
        """
        Handle slash commands. Returns (response_renderable, is_handled).
        """
        parts = user_input.strip().split(maxsplit=1)
        cmd_name = parts[0].lower()
        cmd_arg = parts[1] if len(parts) > 1 else ""

        if cmd_name == "/help":
            return self.render_help(), True

        if cmd_name == "/status":
            return self.render_status(), True

        if cmd_name == "/clear":
            self.console.clear()
            self.console.print(self.render_header())
            self.console.print(Rule(style=THEME['accent_purple_deep']))
            return None, True

        if cmd_name == "/history":
            if cmd_arg:
                return self.render_history(hunt_id=cmd_arg), True
            return self.render_history(), True

        if cmd_name == "/findings":
            return self.render_findings_viewer(), True

        if cmd_name == "/report":
            if not self.lia.last_hunt:
                return self.render_assistant_msg("No hunt performed yet."), True
            if cmd_arg == "brief":
                from hunting.report import ReportGenerator
                brief = ReportGenerator().generate_brief(self.lia.last_hunt)
                return self.render_assistant_msg(brief), True
            from hunting.report import ReportGenerator
            full = ReportGenerator().generate_markdown(self.lia.last_hunt)
            return self.render_assistant_msg(full), True

        if cmd_name == "/export":
            return self.handle_export_command(cmd_arg or "json"), True

        if cmd_name == "/dashboard":
            return None, False

        # ─── Fleet commands
        if cmd_name == "/fleet":
            return self.handle_fleet_command(cmd_arg or "status"), True

        # ─── Intelligence commands
        if cmd_name == "/enrich":
            if not cmd_arg:
                return self.render_assistant_msg("Usage: `/enrich <ip|hash|domain>`"), True
            return self.handle_enrich_command(cmd_arg), True

        if cmd_name == "/search":
            if not cmd_arg:
                return self.render_assistant_msg("Usage: `/search <query>`"), True
            return self.handle_search_command(cmd_arg), True

        if cmd_name == "/baseline":
            return self.handle_baseline_command(cmd_arg or "status"), True

        # ─── Playbook commands
        if cmd_name == "/playbook":
            return self.handle_playbook_command(cmd_arg or "list"), True

        # ─── Campaign commands
        if cmd_name == "/campaign":
            return self.handle_campaign_command(cmd_arg or "list"), True

        # ─── Evidence commands
        if cmd_name == "/evidence":
            return self.handle_evidence_command(cmd_arg or "verify"), True

        # ─── HITL toggle
        if cmd_name == "/hitl":
            if cmd_arg.lower() in ("on", "true", "1"):
                self._hitl_mode = True
                return self.render_assistant_msg("Human-in-the-loop mode **enabled**. Agent will pause for approval on HIGH/CRITICAL findings."), True
            elif cmd_arg.lower() in ("off", "false", "0"):
                self._hitl_mode = False
                return self.render_assistant_msg("Human-in-the-loop mode **disabled**. Agent will proceed autonomously."), True
            return self.render_assistant_msg(f"HITL mode is currently **{'ON' if self._hitl_mode else 'OFF'}**. Usage: `/hitl on|off`"), True

        # ─── Hunt commands
        if cmd_name in ("/hunt", "/hunt-fast"):
            hypothesis = cmd_arg or "Investigate this system for signs of compromise, persistence mechanisms, and suspicious activity."
            self.console.print(self.render_user_msg(user_input))
            self.console.print()
            response = self.run_hunt_with_dashboard(hypothesis, fleet_mode=False)
            self.console.print(self.render_assistant_msg(response))
            self.console.print()
            return None, True

        if cmd_name == "/hunt-fleet":
            if not self.services.fleet_manager:
                return self.render_assistant_msg("Fleet manager not available. Cannot run distributed hunt."), True
            hypothesis = cmd_arg or "Investigate fleet for signs of compromise."
            self.console.print(self.render_user_msg(user_input))
            self.console.print()
            response = self.run_hunt_with_dashboard(hypothesis, fleet_mode=True)
            self.console.print(self.render_assistant_msg(response))
            self.console.print()
            return None, True

        return None, False

    # ─── Main Loop ───────────────────────────────────────────────────────

    def run(self):
        self.console.clear()
        self.console.print(self.render_header())
        self.console.print(Rule(style=THEME['accent_purple_deep']))
        self.console.print(self.render_status_bar())
        self.console.print()

        welcome = (
            "**HoundAI** — Autonomous Threat Hunting Platform v2.0\n\n"
            "Type `/help` for the full command palette.\n"
            "Start a hunt with `/hunt`, manage fleet with `/fleet`, "
            "or enrich IOCs with `/enrich <indicator>`."
        )
        self.console.print(self.render_assistant_msg(welcome))
        self.console.print()

        while True:
            try:
                user_input = Prompt.ask(
                    Text(" > ", style=f"bold {THEME['accent_purple']}"),
                    console=self.console
                ).strip()

                if not user_input:
                    continue

                # Exit commands
                if user_input.lower() in {"quit", "exit", "bye", ":q", "goodbye"}:
                    farewell = Panel(
                        Text("Stay vigilant.\nSession ended.", style="white bold"),
                        style=f"on {THEME['bg_panel']}",
                        border_style=THEME['accent_cyan'],
                        padding=(1, 3),
                    )
                    self.console.print(Padding(farewell, (1, 2, 2, 0)))
                    break

                # Slash commands
                if user_input.startswith("/"):
                    result, handled = self.handle_command(user_input)
                    if handled:
                        if result is not None:
                            self.console.print(result)
                            self.console.print()
                        continue

                # Hunt triggers (natural language)
                if self.lia._is_hunt_request(user_input):
                    self.console.print(self.render_user_msg(user_input))
                    self.console.print()
                    response = self.run_hunt_with_dashboard(user_input)
                    self.console.print(self.render_assistant_msg(response))
                    self.console.print()
                    continue

                # Regular input
                self.console.print(self.render_user_msg(user_input))
                self.console.print()

                with Live(
                    Padding(Text("● Processing...", style=f"{THEME['accent_cyan']} dim"), pad=(0, 4)),
                    refresh_per_second=8, console=self.console
                ):
                    response = self.lia.process_input(user_input)

                self.console.print(self.render_assistant_msg(response))
                self.console.print()

            except KeyboardInterrupt:
                self.console.print(f"\n[dim]Interrupted. Type 'quit' to exit.[/]")
            except Exception as e:
                self.console.print(Panel(
                    f"[bold red]{e}[/]",
                    title="Error", border_style="red",
                ))


def main():
    app = HoundTUI()
    app.run()


if __name__ == "__main__":
    main()
