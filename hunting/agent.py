"""
Autonomous Threat Hunting Agent — the core reasoning loop.

Takes a high-level hypothesis, plans investigation steps, executes osquery queries,
analyzes results, pivots dynamically based on findings, and produces a conclusion.
"""

import cohere
import json
import re
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from .findings import FindingsGraph, Finding, Severity, FindingCategory


# Maximum investigation steps to prevent runaway loops
MAX_STEPS = 15

PLANNER_PROMPT = """You are an expert threat hunter performing an autonomous investigation on a live system using osquery.

INVESTIGATION HYPOTHESIS:
{hypothesis}

FINDINGS SO FAR:
{findings_context}

STEP {step_number} of max {max_steps}.

Based on the findings so far, decide the NEXT action. DO NOT conclude early — investigate thoroughly. Only conclude after at least 8 steps or when you've checked: processes, network connections, persistence (crontab, startup_items), privilege escalation (suid_bin), shell history, and file anomalies. You must respond with EXACTLY one JSON object (no extra text):

{{
  "action": "query" | "conclude",
  "reasoning": "<1-2 sentence explanation of why this step is needed>",
  "query_purpose": "<what you're looking for>",
  "osquery_sql": "<valid osquery SQL if action=query, else empty string>",
  "category": "process|network|persistence|credential_access|lateral_movement|exfiltration|privilege_escalation|defense_evasion|initial_access|system_info",
  "conclusion": "<final conclusion if action=conclude, else empty string>",
  "confidence": <0.0-1.0 confidence in conclusion if concluding, else 0>
}}

RULES:
- Always use LIMIT clauses (max 50 rows)
- SELECT specific columns, never SELECT *
- If you have enough evidence OR exhausted useful avenues, set action to "conclude"
- Each query should build on previous findings — pivot on PIDs, IPs, filenames, users discovered
- Focus on indicators of compromise: unusual processes, suspicious network connections, persistence mechanisms, privilege escalation artifacts
- MITRE ATT&CK categories: process, network, persistence, credential_access, lateral_movement, exfiltration, privilege_escalation, defense_evasion, initial_access, system_info

AVAILABLE OSQUERY TABLES (use ONLY these columns):
- processes: pid, name, path, cmdline, uid, parent, state, start_time, on_disk, root
- users: uid, gid, username, description, directory, shell
- listening_ports: pid, port, protocol, family, address
- process_open_sockets: pid, fd, socket, family, protocol, local_address, local_port, remote_address, remote_port, state
- logged_in_users: type, user, tty, host, time, pid
- system_info: hostname, uuid, cpu_type, cpu_brand, physical_memory, hardware_model
- os_version: name, version, major, minor, patch, build
- interface_addresses: interface, address, mask, broadcast
- startup_items: name, path, args, type, source, status
- kernel_modules: name, size, used_by, status, address
- file: path, directory, filename, size, mtime, atime, ctime, uid, gid, mode, type
- hash: path, md5, sha1, sha256
- crontab: event, minute, hour, day_of_month, month, day_of_week, command, path (NOTE: NO 'user' column — join with processes or filter by path)
- shell_history: uid, command, history_file, time
- suid_bin: path, unix_user, unix_group, permissions
- docker_containers: id, name, image, status, pid (if docker installed)
- authorized_keys: uid, algorithm, key, key_file
- etc_hosts: address, hostnames
- iptables: filter_name, chain, policy, target, protocol, src_ip, dst_ip, src_port, dst_port

IMPORTANT: Do NOT guess column names. Only use columns listed above. If a query fails, fix the columns — do not retry with the same broken query.
"""

ANALYZER_PROMPT = """You are analyzing osquery results as part of an autonomous threat hunt.

HYPOTHESIS: {hypothesis}
QUERY PURPOSE: {query_purpose}
SQL EXECUTED: {sql_query}

RESULTS ({num_rows} rows):
{results_json}

Analyze these results and respond with EXACTLY one JSON object:

{{
  "title": "<short finding title>",
  "description": "<2-3 sentence analysis of what these results mean>",
  "severity": "critical|high|medium|low|info",
  "indicators": [<list of specific IOCs: suspicious IPs, PIDs, filenames, ports, users>],
  "is_suspicious": true|false,
  "mitre_technique": "<MITRE ATT&CK ID if applicable, else empty string>",
  "pivot_suggestions": ["<next query ideas based on these results>"]
}}

Be objective. Not everything is malicious — flag truly suspicious items and label benign results as "info" severity.
"""


class ThreatHuntingAgent:
    """
    Autonomous threat hunting agent that plans, executes, and pivots
    through an investigation using osquery.
    """

    def __init__(self, co_client: cohere.Client, osquery_engine, safety_checker, 
                 progress_callback: Optional[Callable[[str], None]] = None):
        """
        Args:
            co_client: Cohere client for LLM calls
            osquery_engine: OsqueryEngine instance for executing queries
            safety_checker: SafetyChecker instance for validating queries
            progress_callback: Optional callback to report progress (for TUI updates)
        """
        self.co = co_client
        self.osquery_engine = osquery_engine
        self.safety = safety_checker
        self.progress_callback = progress_callback or (lambda msg: None)

    def hunt(self, hypothesis: str, max_steps: int = MAX_STEPS) -> FindingsGraph:
        """
        Execute an autonomous threat hunt.

        Args:
            hypothesis: High-level investigation goal (e.g. "Check if this system is compromised")
            max_steps: Maximum investigation steps

        Returns:
            FindingsGraph containing all findings, evidence chains, and conclusion
        """
        graph = FindingsGraph()
        graph.hypothesis = hypothesis

        self.progress_callback(f"Starting hunt: {hypothesis}")
        self.progress_callback(f"Max steps: {max_steps}")

        for step in range(1, max_steps + 1):
            self.progress_callback(f"\n--- Step {step}/{max_steps} ---")

            # Build context from existing findings
            findings_context = self._build_findings_context(graph)

            # Ask LLM to plan next action
            action = self._plan_next_step(hypothesis, findings_context, step, max_steps)

            if action is None:
                self.progress_callback("Failed to plan next step, concluding.")
                break

            if action.get("action") == "conclude":
                graph.conclusion = action.get("conclusion", "Investigation complete.")
                graph.confidence_score = action.get("confidence", 0.5)
                self.progress_callback(f"Concluding: {graph.conclusion}")
                break

            # Execute the planned query
            sql_query = action.get("osquery_sql", "")
            purpose = action.get("query_purpose", "")
            category_str = action.get("category", "system_info")
            reasoning = action.get("reasoning", "")

            self.progress_callback(f"Purpose: {purpose}")
            self.progress_callback(f"Reasoning: {reasoning}")
            self.progress_callback(f"Query: {sql_query}")

            if not sql_query:
                self.progress_callback("No query generated, skipping step.")
                continue

            # Safety check
            is_safe, reason = self.safety.is_osquery_sql_safe(sql_query)
            if not is_safe:
                self.progress_callback(f"Query blocked: {reason}")
                continue

            # Execute query
            results, error = self.osquery_engine.execute_query(sql_query)

            if error:
                self.progress_callback(f"Query error: {error}")
                # Record the error as an info finding with the error details
                finding = Finding(
                    title=f"Query failed: {purpose}",
                    description=f"Query `{sql_query}` failed with error: {error}. Do NOT retry with same columns.",
                    severity=Severity.INFO,
                    category=self._parse_category(category_str),
                    query_used=sql_query,
                )
                graph.add_finding(finding)
                continue

            self.progress_callback(f"Got {len(results)} rows")

            # Sanitize results
            sanitized = self.safety.sanitize_osquery_result(results)

            # Analyze results with LLM
            analysis = self._analyze_results(hypothesis, purpose, sql_query, sanitized)

            if analysis is None:
                # Fallback: record raw finding
                finding = Finding(
                    title=purpose,
                    description=f"Returned {len(sanitized)} rows",
                    severity=Severity.INFO,
                    category=self._parse_category(category_str),
                    query_used=sql_query,
                    raw_data=sanitized[:20],  # Cap stored data
                )
                graph.add_finding(finding)
                continue

            # Create finding from analysis
            finding = Finding(
                title=analysis.get("title", purpose),
                description=analysis.get("description", ""),
                severity=self._parse_severity(analysis.get("severity", "info")),
                category=self._parse_category(category_str),
                query_used=sql_query,
                raw_data=sanitized[:20],
                indicators=analysis.get("indicators", []),
                mitre_technique=analysis.get("mitre_technique", ""),
            )

            graph.add_finding(finding)
            self.progress_callback(f"Finding: [{finding.severity.value.upper()}] {finding.title}")

        # If loop exhausted without concluding
        if not graph.conclusion:
            graph.conclusion = "Investigation reached maximum steps without definitive conclusion."
            graph.confidence_score = 0.3

        graph.ended_at = datetime.now().isoformat()
        self.progress_callback(f"\nHunt complete. {len(graph.findings)} findings.")
        return graph

    def _build_findings_context(self, graph: FindingsGraph) -> str:
        """Build a text summary of findings so far for the planner prompt."""
        if not graph.findings:
            return "No findings yet. This is the first step — start with broad reconnaissance."

        lines = []
        for f in graph.findings.values():
            severity_tag = f"[{f.severity.value.upper()}]"
            lines.append(f"{severity_tag} {f.title}: {f.description}")
            if f.indicators:
                lines.append(f"  IOCs: {', '.join(f.indicators[:5])}")
            if f.raw_data:
                # Show first 3 rows as context
                for row in f.raw_data[:3]:
                    lines.append(f"  Data: {json.dumps(row)}")
        return "\n".join(lines)

    def _plan_next_step(self, hypothesis: str, findings_context: str, 
                        step: int, max_steps: int) -> Optional[Dict[str, Any]]:
        """Ask LLM to decide the next investigation step."""
        prompt = PLANNER_PROMPT.format(
            hypothesis=hypothesis,
            findings_context=findings_context,
            step_number=step,
            max_steps=max_steps,
        )

        try:
            response = self.co.chat(
                model="command-a-03-2025",
                message=prompt,
                temperature=0.2,
            )
            return self._parse_json_response(response.text)
        except Exception as e:
            self.progress_callback(f"Planner error: {e}")
            return None

    def _analyze_results(self, hypothesis: str, purpose: str, 
                         sql_query: str, results: List[Dict]) -> Optional[Dict[str, Any]]:
        """Ask LLM to analyze query results."""
        # Truncate results for prompt size
        results_to_show = results[:15]
        results_json = json.dumps(results_to_show, indent=2)

        prompt = ANALYZER_PROMPT.format(
            hypothesis=hypothesis,
            query_purpose=purpose,
            sql_query=sql_query,
            num_rows=len(results),
            results_json=results_json,
        )

        try:
            response = self.co.chat(
                model="command-a-03-2025",
                message=prompt,
                temperature=0.1,
            )
            return self._parse_json_response(response.text)
        except Exception as e:
            self.progress_callback(f"Analyzer error: {e}")
            return None

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        # Try direct parse
        text = text.strip()
        # Remove markdown code blocks
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    return None
        return None

    def _parse_severity(self, sev_str: str) -> Severity:
        try:
            return Severity(sev_str.lower())
        except ValueError:
            return Severity.INFO

    def _parse_category(self, cat_str: str) -> FindingCategory:
        try:
            return FindingCategory(cat_str.lower())
        except ValueError:
            return FindingCategory.SYSTEM_INFO
