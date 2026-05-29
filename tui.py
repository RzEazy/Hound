#!/usr/bin/env python3
"""
HoundAI — Professional Cybersecurity TUI
Features: Real-time hunt dashboard, command palette, session history,
          rich tables, status bar, themed branding, interactive reports.
"""
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console, Group
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
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


# ─── Hunt History Persistence (#7) ───────────────────────────────────────────

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
        # Keep last 50
        self.sessions = self.sessions[-50:]
        with open(self.filepath, "w") as f:
            json.dump(self.sessions, f, indent=2)

    def get_recent(self, n: int = 10) -> list:
        return self.sessions[-n:]


# ─── TUI Components ─────────────────────────────────────────────────────────

class HoundTUI:
    def __init__(self):
        self.console = Console()
        self.lia = None
        self.hunt_history = HuntHistory()
        self._osquery_ok = False
        self._api_ok = False
        self.initialize_lia()

    def initialize_lia(self):
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

    # ─── Header / Branding (#8) ──────────────────────────────────────────

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

        subtitle = Text("Autonomous Threat Hunting Engine", style=f"bold {THEME['accent_purple_dim']}")
        version = Text("v1.0.0", style=THEME['text_muted'])

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

    # ─── Status Bar (#3) ─────────────────────────────────────────────────

    def render_status_bar(self):
        """Persistent footer showing system status."""
        osquery_status = Text("● osquery", style=f"bold {THEME['accent_green']}" if self._osquery_ok 
                             else f"bold {THEME['accent_red']}")
        api_status = Text("● API", style=f"bold {THEME['accent_green']}" if self._api_ok 
                         else f"bold {THEME['accent_red']}")

        hunts_count = len(self.hunt_history.sessions)
        hunt_info = Text(f"Hunts: {hunts_count}", style=THEME['text_muted'])

        last_hunt = ""
        if self.hunt_history.sessions:
            last = self.hunt_history.sessions[-1]
            last_hunt = f"Last: {last['hunt_id']}"
        last_hunt_text = Text(last_hunt, style=THEME['text_muted'])

        now = Text(datetime.now().strftime("%H:%M:%S"), style=THEME['text_muted'])

        bar = Table.grid(expand=True)
        bar.add_column(justify="left")
        bar.add_column(justify="center")
        bar.add_column(justify="right")
        bar.add_row(
            Text.assemble(osquery_status, "  ", api_status),
            Text.assemble(hunt_info, "  ", last_hunt_text),
            now,
        )

        return Panel(bar, style=f"on {THEME['bg_dark']}", border_style=THEME['text_muted'],
                     padding=(0, 2), height=3)

    # ─── Command Palette (#5) ────────────────────────────────────────────

    def render_help(self):
        """Render the /help command palette."""
        table = Table(
            title="Command Palette",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            show_header=True,
            header_style=f"bold {THEME['accent_purple']}",
            padding=(0, 2),
        )
        table.add_column("Command", style=f"bold {THEME['accent_cyan']}", min_width=20)
        table.add_column("Description", style="white")

        commands = [
            ("/hunt [hypothesis]", "Start autonomous threat hunt"),
            ("/hunt-fast", "Quick hunt — reduced budget, faster results"),
            ("/report", "Show full report from last hunt"),
            ("/report brief", "Show brief summary of last hunt"),
            ("/export json", "Export last hunt as JSON"),
            ("/history", "Show previous hunt sessions"),
            ("/history <id>", "View details of a specific hunt"),
            ("/dashboard", "System security dashboard"),
            ("/findings", "Interactive findings viewer for last hunt"),
            ("/status", "Show system status"),
            ("/clear", "Clear screen"),
            ("/help", "Show this help"),
            ("quit / exit", "Exit HoundAI"),
        ]
        for cmd, desc in commands:
            table.add_row(cmd, desc)

        return Panel(table, border_style=THEME['accent_purple_deep'], 
                     style=f"on {THEME['bg_panel']}", padding=(1, 2))

    # ─── Message Bubbles (#8) ────────────────────────────────────────────

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

    # ─── Rich Osquery Table (#6) ─────────────────────────────────────────

    def render_osquery_table(self, sql: str, results: list) -> Panel:
        """Render osquery results as a professional Rich table."""
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
                # Highlight suspicious values
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

    # ─── Hunt Dashboard (#1 + #4) ───────────────────────────────────────

    def run_hunt_with_dashboard(self, user_input: str) -> str:
        """Run hunt with real-time split-pane dashboard."""
        findings_list = []
        log_lines = []
        phase = "init"
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        step_current = 0
        budget_total = 10

        def build_dashboard() -> Layout:
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3),
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
            findings_table.add_column("Category", ratio=1)

            for f in findings_list[-15:]:  # Show last 15
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

            # Footer
            layout["footer"].update(Panel(
                Text.assemble(
                    (" HUNTING ", f"bold white on {THEME['accent_purple_deep']}"),
                    (f"  {user_input[:60]}", "dim white"),
                ),
                border_style=THEME['text_muted'],
                style=f"on {THEME['bg_dark']}",
            ))

            return layout

        def progress_callback(msg: str):
            nonlocal phase, step_current, budget_total
            log_lines.append(msg)

            # Parse progress info from messages
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
                # Parse finding from log — format: "Finding: [SEV] title (category)"
                try:
                    sev_match = msg.split("[")[1].split("]")[0].lower()
                    rest = msg.split("] ")[1] if "] " in msg else msg
                    # Extract category from parentheses at end
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

            live.update(build_dashboard())

        live = Live(
            build_dashboard(),
            refresh_per_second=6,
            console=self.console,
            screen=False,
        )

        with live:
            response = self.lia._handle_hunt(user_input, progress_callback=progress_callback)

        # Save to history
        if self.lia.last_hunt:
            self.hunt_history.save_hunt(self.lia.last_hunt)

        return response

    # ─── Interactive Findings Viewer (#2) ────────────────────────────────

    def render_findings_viewer(self):
        """Interactive report with expandable findings."""
        if not self.lia.last_hunt:
            return self.render_assistant_msg("No hunt has been performed yet. Use `/hunt` to start one.")

        graph = self.lia.last_hunt
        findings = list(graph.findings.values())

        if not findings:
            return self.render_assistant_msg("Last hunt produced no findings.")

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity.value, 5))

        # Build detailed table
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

        # Summary panel
        stats = graph.summary_stats()
        max_sev = graph.max_severity()

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

        # Show details for each finding
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

    # ─── Hunt History (#7) ───────────────────────────────────────────────

    def render_history(self, hunt_id: str = None):
        """Show hunt history or details of a specific hunt."""
        sessions = self.hunt_history.get_recent(15)

        if not sessions:
            return self.render_assistant_msg("No hunt history yet. Use `/hunt` to start your first investigation.")

        if hunt_id:
            # Show specific hunt
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
        """Render details of a historical hunt."""
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

    # ─── Status Command (#3) ─────────────────────────────────────────────

    def render_status(self):
        """Full status display."""
        table = Table(
            title="System Status",
            title_style=f"bold {THEME['accent_cyan']}",
            border_style=THEME['accent_purple_deep'],
            show_header=False,
            padding=(0, 2),
        )
        table.add_column("Key", style=f"bold {THEME['accent_purple']}")
        table.add_column("Value", style="white")

        osq_text = Text("Connected", style=f"bold {THEME['accent_green']}") if self._osquery_ok else Text("Not Available", style=f"bold {THEME['accent_red']}")
        api_text = Text("Connected", style=f"bold {THEME['accent_green']}") if self._api_ok else Text("Error", style=f"bold {THEME['accent_red']}")

        table.add_row("Osquery", osq_text)
        table.add_row("Cohere API", api_text)
        table.add_row("Hunt Sessions", str(len(self.hunt_history.sessions)))
        table.add_row("Memory File", "Hound_memory.json")
        table.add_row("RAG Collections", "osquery_docs, os_commands")

        if self.lia.last_hunt:
            table.add_row("Last Hunt", self.lia.last_hunt.hunt_id)
            table.add_row("Last Hunt Severity", self.lia.last_hunt.max_severity().value)

        return Padding(
            Panel(table, border_style=THEME['accent_purple_deep'],
                  style=f"on {THEME['bg_panel']}", padding=(1, 2)),
            pad=(0, 2, 1, 0)
        )

    # ─── Command Router ──────────────────────────────────────────────────

    def handle_command(self, user_input: str) -> tuple:
        """
        Handle slash commands. Returns (response_renderable, is_handled).
        If is_handled is True, the response should be printed directly.
        """
        cmd = user_input.strip().lower()
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
            if not self.lia.last_hunt:
                return self.render_assistant_msg("No hunt to export."), True
            if "json" in cmd_arg.lower():
                json_data = self.lia.get_hunt_json()
                export_path = f"hunt_{self.lia.last_hunt.hunt_id}.json"
                with open(export_path, "w") as f:
                    f.write(json_data)
                return self.render_assistant_msg(f"Exported to `{export_path}`"), True
            return self.render_assistant_msg("Usage: `/export json`"), True

        if cmd_name == "/dashboard":
            # Use existing dashboard
            return None, False  # Let it pass through to lia

        if cmd_name in ("/hunt", "/hunt-fast"):
            hypothesis = cmd_arg or "Investigate this system for signs of compromise, persistence mechanisms, and suspicious activity."
            self.console.print(self.render_user_msg(user_input))
            self.console.print()
            response = self.run_hunt_with_dashboard(hypothesis)
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

        # Welcome
        welcome = (
            "**HoundAI** — Autonomous Threat Hunting Engine\n\n"
            "Type `/help` for commands, or just ask me anything.\n"
            "Start a hunt with `/hunt` or describe what to investigate."
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

                # Show thinking spinner
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
