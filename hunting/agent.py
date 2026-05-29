"""
Autonomous Threat Hunting Agent — Production Grade.

Takes a high-level hypothesis, plans investigation steps, executes osquery queries,
analyzes results, pivots dynamically based on findings, and produces a conclusion.

Production enhancements over v1:
1. Schema-grounded query generation (live pragma_table_info)
2. Query validation with retry-from-error correction loop
3. RAG over osquery_docs for context-aware query generation
4. Few-shot golden investigation traces
5. Parallel independent queries for initial recon
6. Dynamic step budget
7. LLM response caching for unchanged contexts
8. Batch queries into single osquery call
9. ** Behavioral baseline anomaly detection during hunt **
10. ** Live IOC enrichment mid-hunt (not just post-hunt) **
11. ** HITL checkpoints on HIGH/CRITICAL with pause capability **
12. ** Cryptographic evidence signing of every query-result pair **
13. ** Hybrid search (MITRE/Sigma/CVE) for technique correlation **
"""

import cohere
import json
import re
import hashlib
import uuid
import asyncio
from typing import Dict, Any, List, Optional, Callable, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .findings import FindingsGraph, Finding, Severity, FindingCategory


# Safety ceiling
MAX_STEPS_CEILING = 25
DEFAULT_BUDGET = 10
BUDGET_EXTENSION_ON_HIGH = 5
CONSECUTIVE_INFO_TO_CONCLUDE = 4

# Few-shot golden investigation trace (#4)
GOLDEN_TRACE = """
EXAMPLE INVESTIGATION TRACE (for reference):
Step 1: Query processes for suspicious names/paths → Found crypto miner "xmrig" running as root
Step 2: Pivot on xmrig PID to check network connections → Found C2 connection to 185.220.101.x:4444
Step 3: Check parent process of xmrig → Spawned from /tmp/.hidden/loader.sh
Step 4: Check crontab for persistence → Found @reboot entry running /tmp/.hidden/loader.sh
Step 5: Check shell_history for initial access → Found wget downloading payload from attacker IP
Step 6: Check suid_bin for privilege escalation → Found unusual SUID on /tmp/.hidden/escalate
Step 7: Check authorized_keys for backdoors → Found unknown SSH key added to root
Step 8: Conclude with HIGH confidence — confirmed compromise with persistence, C2, and priv esc
"""

PLANNER_PROMPT = """You are an expert threat hunter performing an autonomous investigation on a live system using osquery.

INVESTIGATION HYPOTHESIS:
{hypothesis}

{golden_trace}

FINDINGS SO FAR:
{findings_context}

{anomaly_context}

{enrichment_context}

STEP {step_number} | Budget remaining: {budget_remaining} steps.

{schema_context}

{rag_context}

Based on the findings so far, decide the NEXT action. DO NOT conclude early — investigate thoroughly. Only conclude when you've covered sufficient attack surface (processes, network, persistence, privilege escalation, shell history, file anomalies) OR found definitive evidence. Respond with EXACTLY one JSON object (no extra text):

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
- ONLY use columns that exist in the VERIFIED SCHEMA below
- Each query should build on previous findings — pivot on PIDs, IPs, filenames, users discovered
- If a previous query FAILED, do NOT retry with the same columns — use the verified schema
- Focus on IOCs: unusual processes, suspicious network connections, persistence mechanisms, privilege escalation artifacts
- Do NOT investigate the same process/table repeatedly if previous queries returned no suspicious results
- If ANOMALY CONTEXT shows behavioral deviations, prioritize investigating those

KNOWN-GOOD BASELINES (do NOT flag these as suspicious unless behavior is anomalous):
- Firefox, Chrome, Chromium and their wrappers (.firefox-wrappe, chrome-sandbox) making HTTPS connections to known CDNs/services
- System processes: systemd, init, kthreadd, kworker, rcu_*, irq/*, ksoftirqd
- Package managers: apt, dpkg, pacman, nix-daemon, nix-build
- Desktop processes: Xorg, Wayland, gnome-*, plasma-*, dbus-daemon
- Servers (if intentionally installed): httpd, nginx, sshd, postgres, mysql, docker*
- Tor is suspicious ONLY if: running as root, listening on non-standard ports, or making connections to known C2 IPs

FAILED TABLES/QUERIES (do NOT use these again):
{failed_context}
"""

ANALYZER_PROMPT = """You are analyzing osquery results as part of an autonomous threat hunt.

HYPOTHESIS: {hypothesis}
QUERY PURPOSE: {query_purpose}
SQL EXECUTED: {sql_query}

RESULTS ({num_rows} rows):
{results_json}

{enrichment_note}

{anomaly_note}

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

BASELINE AWARENESS — do NOT flag these as suspicious:
- Browsers (firefox, chrome, .firefox-wrappe) connecting to well-known IPs (Google, Cloudflare, GitHub, Meta, etc.) on port 443
- Standard system processes (systemd, init, dbus, NetworkManager, pulseaudio, pipewire)
- httpd/nginx if multiple workers exist under a single parent (normal MPM behavior)
- Docker daemon and containers (unless running suspicious binaries)
- Tor ONLY if running under a dedicated 'tor' user with standard config

WHAT IS ACTUALLY SUSPICIOUS:
- Processes running from /tmp, /dev/shm, /var/tmp
- Processes with no path on disk (on_disk = 0)
- Connections to known-bad ports (4444, 5555, 6666, 31337, 9001 from non-Tor)
- SUID binaries outside /usr/bin, /usr/sbin, /usr/lib
- Cron entries with wget/curl/base64/eval
- Shell history containing encoded commands, reverse shells, or credential theft

Be objective and precise. Mark genuinely benign findings as "info" severity.
"""

QUERY_FIX_PROMPT = """The following osquery SQL query failed with an error. Fix it using ONLY the verified columns listed.

FAILED QUERY: {failed_query}
ERROR: {error}
PURPOSE: {purpose}

VERIFIED SCHEMA FOR RELEVANT TABLES:
{table_schema}

Respond with ONLY the corrected SQL query, nothing else. Use ONLY columns from the verified schema above.
"""

# Initial recon queries for parallel execution (#5)
RECON_QUERIES = [
    {
        "purpose": "Identify suspicious or unusual processes",
        "sql": "SELECT pid, name, path, cmdline, uid, parent FROM processes WHERE on_disk = 0 OR path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' OR name IN ('nc', 'ncat', 'socat', 'xmrig', 'minergate', 'kworker') LIMIT 50;",
        "category": "process",
    },
    {
        "purpose": "Check for suspicious network connections",
        "sql": "SELECT p.name, p.pid, pos.remote_address, pos.remote_port, pos.local_port, pos.state FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '0.0.0.0' AND pos.remote_address != '::' AND pos.remote_address != '127.0.0.1' AND pos.state = 'ESTABLISHED' LIMIT 50;",
        "category": "network",
    },
    {
        "purpose": "Check persistence mechanisms (crontab)",
        "sql": "SELECT command, path, minute, hour, day_of_month FROM crontab WHERE command != '' LIMIT 50;",
        "category": "persistence",
    },
    {
        "purpose": "Check for SUID binaries in unusual locations",
        "sql": "SELECT path, unix_user, unix_group, permissions FROM suid_bin WHERE path LIKE '/tmp/%' OR path LIKE '/home/%' OR path LIKE '/var/tmp/%' OR path LIKE '/dev/shm/%' LIMIT 50;",
        "category": "privilege_escalation",
    },
    {
        "purpose": "Check listening ports for backdoors",
        "sql": "SELECT lp.port, lp.protocol, lp.address, p.name, p.pid, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port NOT IN (22, 80, 443, 53, 8080, 3306, 5432) LIMIT 50;",
        "category": "network",
    },
]


class ThreatHuntingAgent:
    """
    Autonomous threat hunting agent that plans, executes, and pivots
    through an investigation using osquery.
    
    Production integration points:
    - behavioral_engine: anomaly detection against host baselines
    - threat_enricher: live IOC enrichment during hunt
    - evidence_chain: cryptographic signing of query-result pairs
    - hybrid_search: MITRE/Sigma/CVE correlation
    - hitl_callback: human-in-the-loop approval for HIGH/CRITICAL actions
    """

    def __init__(self, co_client: cohere.Client, osquery_engine, safety_checker,
                 retriever=None,
                 progress_callback: Optional[Callable[[str], None]] = None,
                 # Production subsystems (all optional — graceful degradation)
                 behavioral_engine=None,
                 threat_enricher=None,
                 evidence_chain=None,
                 hybrid_search=None,
                 hitl_callback: Optional[Callable[[str, str], bool]] = None):
        """
        Args:
            co_client: Cohere client for LLM calls
            osquery_engine: OsqueryEngine instance for executing queries
            safety_checker: SafetyChecker instance for validating queries
            retriever: Optional RAG retriever for osquery docs
            progress_callback: Optional callback to report progress (for TUI updates)
            behavioral_engine: BehavioralEngine for anomaly detection
            threat_enricher: ThreatIntelEnricher for live IOC enrichment
            evidence_chain: EvidenceChain for cryptographic signing
            hybrid_search: HybridSearchEngine for MITRE/Sigma correlation
            hitl_callback: Callable(finding_summary, severity) -> bool for HITL approval
        """
        self.co = co_client
        self.osquery_engine = osquery_engine
        self.safety = safety_checker
        self.retriever = retriever
        self.progress_callback = progress_callback or (lambda msg: None)
        
        # Production subsystems
        self.behavioral_engine = behavioral_engine
        self.threat_enricher = threat_enricher
        self.evidence_chain = evidence_chain
        self.hybrid_search = hybrid_search
        self.hitl_callback = hitl_callback
        
        # Internal state
        self._schema_cache: Dict[str, List[str]] = {}
        self._llm_cache: Dict[str, Dict[str, Any]] = {}
        self._failed_queries: set = set()
        self._failed_tables: set = set()
        self._enrichment_results: Dict[str, Any] = {}  # IOC -> enrichment result
        self._anomalies_detected: List[Dict[str, Any]] = []
        self._hunt_paused: bool = False

    def hunt(self, hypothesis: str) -> FindingsGraph:
        """
        Execute an autonomous threat hunt with dynamic budget.

        Production flow:
        1. Behavioral anomaly pre-check (if baseline available)
        2. Parallel recon queries
        3. Live IOC enrichment on discovered indicators
        4. HITL checkpoint on HIGH/CRITICAL findings
        5. Adaptive investigation with enrichment-informed pivoting
        6. Evidence signing throughout
        7. MITRE/Sigma correlation on conclusion
        """
        graph = FindingsGraph()
        graph.hypothesis = hypothesis

        budget = DEFAULT_BUDGET
        consecutive_info = 0
        steps_taken = 0

        self.progress_callback(f"Starting hunt: {hypothesis}")
        self.progress_callback(f"Initial budget: {budget} steps (dynamic)")

        # ─── Pre-Hunt: Behavioral Anomaly Check ──────────────────────
        if self.behavioral_engine:
            self.progress_callback("\n=== Pre-Hunt: Behavioral Anomaly Check ===")
            self._run_anomaly_precheck(graph)

        # ─── Phase 1: Parallel Initial Recon ─────────────────────────
        self.progress_callback("\n=== Phase 1: Parallel Reconnaissance ===")
        recon_findings = self._run_parallel_recon(hypothesis)
        for finding in recon_findings:
            graph.add_finding(finding)
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                budget += BUDGET_EXTENSION_ON_HIGH
                self.progress_callback(f"  Budget extended to {budget} (found {finding.severity.value} severity)")
                
                # HITL checkpoint on HIGH/CRITICAL during recon
                if self.hitl_callback and finding.severity in (Severity.HIGH, Severity.CRITICAL):
                    self.progress_callback(f"  [HITL] Requesting approval for: {finding.title}")
                    approved = self.hitl_callback(finding.title, finding.severity.value)
                    if not approved:
                        self._hunt_paused = True
                        self.progress_callback("  [HITL] Hunt paused by operator.")
                        graph.conclusion = "Hunt paused by operator at HITL checkpoint during recon phase."
                        graph.confidence_score = 0.3
                        graph.ended_at = datetime.now().isoformat()
                        return graph
                        
            self.progress_callback(f"  [{finding.severity.value.upper()}] {finding.title}")
            
            # Live enrichment of IOCs discovered during recon
            if finding.indicators:
                self._enrich_indicators_sync(finding.indicators)
                
        steps_taken += 1

        # ─── Phase 2: Adaptive Investigation Loop ────────────────────
        self.progress_callback(f"\n=== Phase 2: Adaptive Investigation ===")

        while steps_taken < min(budget, MAX_STEPS_CEILING):
            steps_taken += 1
            self.progress_callback(f"\n--- Step {steps_taken}/{budget} ---")

            # Build context from existing findings
            findings_context = self._build_findings_context(graph)

            # Get RAG context
            rag_context = self._get_rag_context(hypothesis, findings_context)

            # Get live schema for relevant tables
            schema_context = self._get_schema_context(findings_context)

            # Build anomaly context for the planner
            anomaly_context = self._build_anomaly_context()

            # Build enrichment context for the planner
            enrichment_context = self._build_enrichment_context()

            # Check cache
            cache_key = self._cache_key(findings_context + anomaly_context + enrichment_context)
            if cache_key in self._llm_cache and not self._failed_queries:
                action = self._llm_cache[cache_key]
                self.progress_callback("  (using cached plan)")
            else:
                # Ask LLM to plan next action
                action = self._plan_next_step(
                    hypothesis, findings_context, steps_taken, budget,
                    schema_context, rag_context, anomaly_context, enrichment_context
                )
                if action:
                    self._llm_cache[cache_key] = action

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

            self.progress_callback(f"  Purpose: {purpose}")
            self.progress_callback(f"  Reasoning: {reasoning}")
            self.progress_callback(f"  Query: {sql_query}")

            if not sql_query:
                self.progress_callback("  No query generated, skipping.")
                continue

            if sql_query in self._failed_queries:
                self.progress_callback("  Skipping — this query already failed previously.")
                continue

            # Safety check
            is_safe, reason = self.safety.is_osquery_sql_safe(sql_query)
            if not is_safe:
                self.progress_callback(f"  Query blocked: {reason}")
                continue

            # Execute query with retry-from-error
            results, error = self.osquery_engine.execute_query(sql_query)

            if error:
                self.progress_callback(f"  Query error: {error}")
                self._failed_queries.add(sql_query)
                if "no such table" in error.lower():
                    table_match = re.search(r'no such table:\s*(\w+)', error, re.IGNORECASE)
                    if table_match:
                        self._failed_tables.add(table_match.group(1))
                # Attempt fix
                fixed_sql = self._fix_query(sql_query, error, purpose)
                if fixed_sql and fixed_sql != sql_query and fixed_sql not in self._failed_queries:
                    self.progress_callback(f"  Retrying with fixed query: {fixed_sql}")
                    results, error = self.osquery_engine.execute_query(fixed_sql)
                    sql_query = fixed_sql
                    if error:
                        self._failed_queries.add(fixed_sql)

                if error:
                    finding = Finding(
                        title=f"Query failed: {purpose}",
                        description=f"Query `{sql_query}` failed: {error}. Table/columns may not exist on this system.",
                        severity=Severity.INFO,
                        category=self._parse_category(category_str),
                        query_used=sql_query,
                    )
                    graph.add_finding(finding)
                    consecutive_info += 1
                    if consecutive_info >= CONSECUTIVE_INFO_TO_CONCLUDE:
                        self.progress_callback(f"  {CONSECUTIVE_INFO_TO_CONCLUDE} consecutive low-value steps, wrapping up.")
                        break
                    continue

            self.progress_callback(f"  Got {len(results)} rows")

            # ─── Sign evidence ────────────────────────────────────────
            if self.evidence_chain:
                try:
                    self.evidence_chain.add_evidence(
                        node_key="local",
                        query_sql=sql_query,
                        query_purpose=purpose,
                        results=results,
                        metadata={"step": steps_taken, "category": category_str},
                    )
                    self.progress_callback(f"  [Evidence] Signed entry #{len(self.evidence_chain)}")
                except Exception as e:
                    self.progress_callback(f"  [Evidence] Signing failed: {e}")

            # Sanitize results
            sanitized = self.safety.sanitize_osquery_result(results)

            # ─── Live IOC enrichment on results ───────────────────────
            result_indicators = self._extract_indicators_from_results(sanitized)
            enrichment_note = ""
            if result_indicators:
                self._enrich_indicators_sync(result_indicators)
                # Build enrichment note for the analyzer
                enrichment_note = self._build_enrichment_note_for_indicators(result_indicators)

            # ─── Anomaly detection on results ─────────────────────────
            anomaly_note = ""
            if self.behavioral_engine and sanitized:
                anomaly_note = self._check_result_anomalies(sanitized, category_str)

            # Analyze results with LLM (enrichment + anomaly context included)
            analysis = self._analyze_results(hypothesis, purpose, sql_query, sanitized,
                                             enrichment_note, anomaly_note)

            if analysis is None:
                finding = Finding(
                    title=purpose,
                    description=f"Returned {len(sanitized)} rows",
                    severity=Severity.INFO,
                    category=self._parse_category(category_str),
                    query_used=sql_query,
                    raw_data=sanitized[:20],
                )
                graph.add_finding(finding)
                consecutive_info += 1
            else:
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
                self.progress_callback(f"  Finding: [{finding.severity.value.upper()}] {finding.title} ({finding.category.value})")

                # ─── HITL checkpoint on HIGH/CRITICAL ─────────────────
                if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                    budget = min(budget + BUDGET_EXTENSION_ON_HIGH, MAX_STEPS_CEILING)
                    consecutive_info = 0
                    self.progress_callback(f"  Budget extended to {budget}")

                    if self.hitl_callback:
                        self.progress_callback(f"  [HITL] Requesting approval to continue...")
                        approved = self.hitl_callback(finding.title, finding.severity.value)
                        if not approved:
                            self._hunt_paused = True
                            self.progress_callback("  [HITL] Hunt paused by operator.")
                            graph.conclusion = f"Hunt paused at step {steps_taken} by operator. Last finding: {finding.title}"
                            graph.confidence_score = 0.5
                            graph.ended_at = datetime.now().isoformat()
                            return graph

                    # Enrich newly discovered IOCs
                    if finding.indicators:
                        self._enrich_indicators_sync(finding.indicators)

                    # MITRE/Sigma correlation on high-severity findings
                    if self.hybrid_search and finding.mitre_technique:
                        self._correlate_mitre(finding)

                elif finding.severity == Severity.INFO:
                    consecutive_info += 1
                else:
                    consecutive_info = 0

            # Early conclusion check
            if consecutive_info >= CONSECUTIVE_INFO_TO_CONCLUDE:
                self.progress_callback(f"  {CONSECUTIVE_INFO_TO_CONCLUDE} consecutive info-level results, concluding.")
                break

        # If loop exhausted without concluding, generate a proper conclusion
        if not graph.conclusion:
            graph.conclusion = self._generate_conclusion(hypothesis, graph)
            graph.confidence_score = self._calculate_confidence(graph)

        # ─── Post-hunt: Final MITRE correlation ───────────────────────
        if self.hybrid_search:
            self._final_mitre_correlation(graph)

        graph.ended_at = datetime.now().isoformat()
        self.progress_callback(f"\nHunt complete. {len(graph.findings)} findings. Budget used: {steps_taken}/{budget}")
        
        # Summary of production subsystem contributions
        if self._enrichment_results:
            malicious_count = sum(1 for r in self._enrichment_results.values() if r.get("is_malicious"))
            self.progress_callback(f"  Enriched {len(self._enrichment_results)} IOCs — {malicious_count} flagged malicious")
        if self._anomalies_detected:
            self.progress_callback(f"  Behavioral anomalies detected: {len(self._anomalies_detected)}")
        if self.evidence_chain:
            self.progress_callback(f"  Evidence chain: {len(self.evidence_chain)} signed entries")
            
        return graph

    # ─── Behavioral Anomaly Pre-Check ─────────────────────────────────

    def _run_anomaly_precheck(self, graph: FindingsGraph):
        """Run behavioral anomaly detection before the main hunt."""
        try:
            # Gather current state
            current_state = {}
            procs, _ = self.osquery_engine.execute_query(
                "SELECT pid, name, path, cmdline, uid, parent FROM processes LIMIT 100;"
            )
            ports, _ = self.osquery_engine.execute_query(
                "SELECT lp.port, lp.protocol, p.name as process_name FROM listening_ports lp "
                "JOIN processes p ON lp.pid = p.pid LIMIT 50;"
            )
            conns, _ = self.osquery_engine.execute_query(
                "SELECT p.name as process_name, pos.remote_address FROM process_open_sockets pos "
                "JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' "
                "AND pos.remote_address != '127.0.0.1' LIMIT 50;"
            )
            current_state = {
                "processes": procs or [],
                "listening_ports": ports or [],
                "connections": conns or [],
            }

            # Update baseline (builds over time)
            self.behavioral_engine.update_host_baseline("local", "localhost", current_state)

            # Check anomalies
            anomalies = self.behavioral_engine.check_anomalies("local", current_state)
            
            if anomalies:
                self._anomalies_detected = [
                    {"description": a.description, "score": a.score, "context": a.context}
                    for a in anomalies
                ]
                # Add high-scoring anomalies as findings
                for a in anomalies:
                    if a.score >= 0.6:
                        severity = Severity.MEDIUM if a.score < 0.8 else Severity.HIGH
                        finding = Finding(
                            title=f"Behavioral Anomaly: {a.description[:60]}",
                            description=f"Score: {a.score:.2f}. {a.description}. Baseline: {a.baseline_comparison}",
                            severity=severity,
                            category=FindingCategory.DEFENSE_EVASION,
                            indicators=[str(v) for v in a.context.values() if v][:5],
                        )
                        graph.add_finding(finding)
                        self.progress_callback(f"  [ANOMALY] {a.description} (score: {a.score:.2f})")
                
                self.progress_callback(f"  Total anomalies: {len(anomalies)} ({sum(1 for a in anomalies if a.score >= 0.6)} significant)")
            else:
                self.progress_callback("  No behavioral anomalies detected.")
        except Exception as e:
            self.progress_callback(f"  Anomaly pre-check failed: {e}")

    def _build_anomaly_context(self) -> str:
        """Build anomaly context string for the LLM planner."""
        if not self._anomalies_detected:
            return ""
        
        lines = ["BEHAVIORAL ANOMALIES DETECTED (investigate these first):"]
        for a in sorted(self._anomalies_detected, key=lambda x: x["score"], reverse=True)[:5]:
            lines.append(f"- [Score {a['score']:.2f}] {a['description']}")
        return "\n".join(lines)

    def _check_result_anomalies(self, results: List[Dict], category: str) -> str:
        """Check query results against behavioral baseline."""
        try:
            state_key = {
                "process": "processes",
                "network": "connections", 
                "persistence": "processes",
            }.get(category, "processes")
            
            current_state = {state_key: results}
            anomalies = self.behavioral_engine.check_anomalies("local", current_state)
            
            if anomalies:
                high_anomalies = [a for a in anomalies if a.score >= 0.5]
                if high_anomalies:
                    self._anomalies_detected.extend([
                        {"description": a.description, "score": a.score, "context": a.context}
                        for a in high_anomalies
                    ])
                    lines = ["ANOMALY DETECTION NOTE:"]
                    for a in high_anomalies[:3]:
                        lines.append(f"- [{a.score:.2f}] {a.description}")
                    return "\n".join(lines)
        except Exception:
            pass
        return ""

    # ─── Live IOC Enrichment ──────────────────────────────────────────

    def _enrich_indicators_sync(self, indicators: List[str]):
        """Enrich indicators synchronously (wraps async enricher)."""
        if not self.threat_enricher:
            return

        try:
            import re as regex
            from intelligence.threat_intel import IOC, IOCType

            iocs_to_enrich = []
            for indicator in indicators[:10]:  # Limit to avoid rate limits
                indicator = str(indicator).strip()
                if indicator in self._enrichment_results:
                    continue  # Already enriched
                    
                # Detect IOC type
                if regex.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
                    iocs_to_enrich.append(IOC(value=indicator, ioc_type=IOCType.IP))
                elif regex.match(r'^[a-f0-9]{32}$', indicator, regex.I):
                    iocs_to_enrich.append(IOC(value=indicator, ioc_type=IOCType.HASH_MD5))
                elif regex.match(r'^[a-f0-9]{64}$', indicator, regex.I):
                    iocs_to_enrich.append(IOC(value=indicator, ioc_type=IOCType.HASH_SHA256))
                elif regex.match(r'^[a-z0-9][a-z0-9\-]*\.[a-z]{2,}$', indicator, regex.I):
                    iocs_to_enrich.append(IOC(value=indicator, ioc_type=IOCType.DOMAIN))

            if not iocs_to_enrich:
                return

            # Run async enrichment in sync context
            loop = None
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    loop = asyncio.new_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()

            async def _do_enrich():
                for ioc in iocs_to_enrich:
                    try:
                        results = await self.threat_enricher.enrich(ioc)
                        if results:
                            is_malicious = any(r.is_malicious for r in results)
                            max_confidence = max((r.confidence for r in results), default=0)
                            self._enrichment_results[ioc.value] = {
                                "is_malicious": is_malicious,
                                "confidence": max_confidence,
                                "feeds": [r.feed_name for r in results],
                                "tags": [t for r in results for t in r.tags][:5],
                            }
                            if is_malicious:
                                self.progress_callback(
                                    f"  [ENRICHMENT] {ioc.value} flagged MALICIOUS "
                                    f"(confidence: {max_confidence:.0%}, feeds: {', '.join(r.feed_name for r in results if r.is_malicious)})"
                                )
                    except Exception:
                        pass

            loop.run_until_complete(_do_enrich())
        except Exception as e:
            self.progress_callback(f"  [ENRICHMENT] Error: {e}")

    def _build_enrichment_context(self) -> str:
        """Build enrichment context string for the LLM planner."""
        if not self._enrichment_results:
            return ""
        
        malicious = {k: v for k, v in self._enrichment_results.items() if v.get("is_malicious")}
        if not malicious:
            return ""
        
        lines = ["THREAT INTEL ENRICHMENT (confirmed malicious IOCs — prioritize investigating these):"]
        for ioc_val, result in malicious.items():
            lines.append(f"- {ioc_val}: MALICIOUS (confidence: {result['confidence']:.0%}, tags: {', '.join(result.get('tags', [])[:3])})")
        return "\n".join(lines)

    def _build_enrichment_note_for_indicators(self, indicators: List[str]) -> str:
        """Build enrichment note for the analyzer about specific indicators."""
        notes = []
        for ind in indicators:
            result = self._enrichment_results.get(str(ind))
            if result:
                status = "MALICIOUS" if result["is_malicious"] else "clean"
                notes.append(f"- {ind}: {status} (confidence: {result['confidence']:.0%})")
        
        if notes:
            return "THREAT INTEL ENRICHMENT FOR THESE RESULTS:\n" + "\n".join(notes)
        return ""

    def _extract_indicators_from_results(self, results: List[Dict]) -> List[str]:
        """Extract potential IOCs from query results for enrichment."""
        import re as regex
        indicators = set()
        
        ip_pattern = regex.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for row in results[:20]:
            for key, value in row.items():
                val = str(value)
                # Extract IPs (skip private ranges)
                for ip in ip_pattern.findall(val):
                    parts = ip.split(".")
                    first_octet = int(parts[0])
                    if first_octet not in (10, 127, 169, 172, 192, 0, 255):
                        indicators.add(ip)
                # Extract hashes
                if regex.match(r'^[a-f0-9]{32}$', val, regex.I):
                    indicators.add(val)
                elif regex.match(r'^[a-f0-9]{64}$', val, regex.I):
                    indicators.add(val)
        
        return list(indicators)[:10]

    # ─── MITRE/Sigma Correlation ──────────────────────────────────────

    def _correlate_mitre(self, finding: Finding):
        """Search hybrid index for related MITRE techniques and Sigma rules."""
        if not self.hybrid_search:
            return
        try:
            query = f"{finding.mitre_technique} {finding.title} {finding.description[:100]}"
            results = self.hybrid_search.search(query, collections=["mitre_attack", "sigma_rules"], top_k=3)
            if results:
                correlations = [f"{r.source}:{r.doc_id}" for r in results[:3]]
                self.progress_callback(f"  [MITRE] Correlated: {', '.join(correlations)}")
        except Exception:
            pass

    def _final_mitre_correlation(self, graph: FindingsGraph):
        """Post-hunt correlation of all findings against MITRE/Sigma."""
        try:
            techniques_found = set()
            for f in graph.findings.values():
                if f.mitre_technique:
                    techniques_found.add(f.mitre_technique)
            
            if techniques_found:
                self.progress_callback(f"  MITRE techniques observed: {', '.join(sorted(techniques_found))}")
        except Exception:
            pass

    # ─── Phase 1: Parallel Recon ──────────────────────────────────────

    def _run_parallel_recon(self, hypothesis: str) -> List[Finding]:
        """Execute initial recon queries in parallel."""
        findings = []

        def execute_recon(query_spec: Dict) -> Tuple[Dict, List[Dict], str]:
            sql = query_spec["sql"]
            is_safe, _ = self.safety.is_osquery_sql_safe(sql)
            if not is_safe:
                return query_spec, [], "blocked"
            results, error = self.osquery_engine.execute_query(sql)
            return query_spec, results, error

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(execute_recon, q): q for q in RECON_QUERIES}
            for future in as_completed(futures):
                try:
                    spec, results, error = future.result()
                    if error:
                        self.progress_callback(f"  Recon '{spec['purpose']}': error - {error}")
                        continue

                    sanitized = self.safety.sanitize_osquery_result(results)
                    
                    # Sign recon evidence
                    if self.evidence_chain:
                        try:
                            self.evidence_chain.add_evidence(
                                node_key="local",
                                query_sql=spec["sql"],
                                query_purpose=spec["purpose"],
                                results=sanitized,
                                metadata={"phase": "recon", "category": spec["category"]},
                            )
                        except Exception:
                            pass

                    if not sanitized:
                        self.progress_callback(f"  Recon '{spec['purpose']}': no results")
                        finding = Finding(
                            title=f"Clear: {spec['purpose']}",
                            description="No suspicious results found.",
                            severity=Severity.INFO,
                            category=self._parse_category(spec["category"]),
                            query_used=spec["sql"],
                        )
                        findings.append(finding)
                        continue

                    # Analyze results
                    analysis = self._analyze_results(hypothesis, spec["purpose"], spec["sql"], sanitized)
                    if analysis:
                        finding = Finding(
                            title=analysis.get("title", spec["purpose"]),
                            description=analysis.get("description", ""),
                            severity=self._parse_severity(analysis.get("severity", "info")),
                            category=self._parse_category(spec["category"]),
                            query_used=spec["sql"],
                            raw_data=sanitized[:20],
                            indicators=analysis.get("indicators", []),
                            mitre_technique=analysis.get("mitre_technique", ""),
                        )
                    else:
                        finding = Finding(
                            title=spec["purpose"],
                            description=f"Returned {len(sanitized)} rows",
                            severity=Severity.INFO,
                            category=self._parse_category(spec["category"]),
                            query_used=spec["sql"],
                            raw_data=sanitized[:20],
                        )
                    findings.append(finding)
                except Exception as e:
                    self.progress_callback(f"  Recon error: {e}")

        return findings

    # ─── Schema Grounding ─────────────────────────────────────────────

    def _get_table_schema(self, table_name: str) -> List[str]:
        """Get live column names for a table via pragma_table_info."""
        if table_name in self._schema_cache:
            return self._schema_cache[table_name]

        sql = f"PRAGMA table_info({table_name});"
        results, error = self.osquery_engine.execute_query(sql)
        if error or not results:
            return []

        columns = [row.get("name", "") for row in results if row.get("name")]
        self._schema_cache[table_name] = columns
        return columns

    def _get_schema_context(self, findings_context: str) -> str:
        """Build verified schema context for tables likely needed next."""
        key_tables = ["processes", "listening_ports", "process_open_sockets",
                      "users", "crontab", "startup_items", "shell_history",
                      "suid_bin", "file", "hash", "kernel_modules",
                      "logged_in_users", "authorized_keys", "etc_hosts"]

        schema_lines = ["VERIFIED TABLE SCHEMAS (use ONLY these columns):"]
        for table in key_tables:
            cols = self._get_table_schema(table)
            if cols:
                schema_lines.append(f"- {table}: {', '.join(cols)}")

        return "\n".join(schema_lines)

    # ─── RAG Integration ──────────────────────────────────────────────

    def _get_rag_context(self, hypothesis: str, findings_context: str) -> str:
        """Retrieve relevant osquery documentation via RAG."""
        if not self.retriever:
            return ""

        try:
            query = f"{hypothesis} {findings_context[:200]}"
            docs = self.retriever.search(
                query=query,
                collection="osquery_docs",
                n_results=5
            )
            if docs:
                rag_text = "RELEVANT OSQUERY DOCUMENTATION (from RAG):\n"
                for doc in docs:
                    rag_text += f"- {doc['text'][:300]}\n"
                return rag_text
        except Exception:
            pass
        return ""

    # ─── Query Fix with Retry ─────────────────────────────────────────

    def _fix_query(self, failed_sql: str, error: str, purpose: str) -> Optional[str]:
        """Attempt to fix a failed query using error message and live schema."""
        table_matches = re.findall(r'\bFROM\s+(\w+)', failed_sql, re.IGNORECASE)
        table_matches += re.findall(r'\bJOIN\s+(\w+)', failed_sql, re.IGNORECASE)

        schema_lines = []
        for table in set(table_matches):
            cols = self._get_table_schema(table)
            if cols:
                schema_lines.append(f"{table}: {', '.join(cols)}")

        if not schema_lines:
            return None

        prompt = QUERY_FIX_PROMPT.format(
            failed_query=failed_sql,
            error=error,
            purpose=purpose,
            table_schema="\n".join(schema_lines),
        )

        try:
            response = self.co.chat(
                model="command-a-03-2025",
                message=prompt,
                temperature=0.1,
            )
            fixed = response.text.strip()
            fixed = re.sub(r'^```(?:sql)?\s*', '', fixed)
            fixed = re.sub(r'\s*```$', '', fixed)
            fixed = fixed.strip()
            if not fixed.endswith(';'):
                fixed += ';'
            if fixed.lower().startswith('select') and 'from' in fixed.lower():
                return fixed
        except Exception:
            pass
        return None

    # ─── Conclusion Generation ────────────────────────────────────────

    def _generate_conclusion(self, hypothesis: str, graph: FindingsGraph) -> str:
        """Generate a proper conclusion using LLM based on all findings."""
        findings_summary = self._build_findings_context(graph)
        stats = graph.summary_stats()

        # Include enrichment and anomaly data in conclusion
        enrichment_summary = ""
        if self._enrichment_results:
            malicious = {k: v for k, v in self._enrichment_results.items() if v.get("is_malicious")}
            if malicious:
                enrichment_summary = f"\nTHREAT INTEL: {len(malicious)} IOCs confirmed malicious by external feeds: {', '.join(list(malicious.keys())[:5])}"

        anomaly_summary = ""
        if self._anomalies_detected:
            high_anomalies = [a for a in self._anomalies_detected if a["score"] >= 0.6]
            if high_anomalies:
                anomaly_summary = f"\nBEHAVIORAL ANOMALIES: {len(high_anomalies)} significant deviations from baseline detected."

        prompt = f"""Based on this autonomous threat hunt, generate a concise 2-3 sentence conclusion.

HYPOTHESIS: {hypothesis}
FINDINGS SUMMARY:
{findings_summary}
{enrichment_summary}
{anomaly_summary}

SEVERITY BREAKDOWN: {json.dumps(stats)}

Respond with ONLY the conclusion text (no JSON, no formatting). Be specific about what was found or not found. If threat intel confirmed IOCs as malicious or behavioral anomalies were detected, mention this."""

        try:
            response = self.co.chat(
                model="command-a-03-2025",
                message=prompt,
                temperature=0.1,
            )
            return response.text.strip()
        except Exception:
            return "Investigation complete. No definitive indicators of compromise found."

    def _calculate_confidence(self, graph: FindingsGraph) -> float:
        """Calculate confidence score based on findings quality + enrichment."""
        if not graph.findings:
            return 0.3

        total = len(graph.findings)
        high_plus = len([f for f in graph.findings.values()
                        if f.severity in (Severity.HIGH, Severity.CRITICAL)])
        medium = len([f for f in graph.findings.values()
                     if f.severity == Severity.MEDIUM])
        failed = len([f for f in graph.findings.values()
                     if "failed" in f.title.lower()])

        success_rate = (total - failed) / max(total, 1)
        
        # Enrichment confirmation boosts confidence
        enrichment_boost = 0.0
        if self._enrichment_results:
            malicious_count = sum(1 for v in self._enrichment_results.values() if v.get("is_malicious"))
            if malicious_count > 0:
                enrichment_boost = min(malicious_count * 0.05, 0.15)

        if high_plus > 0:
            return min(0.95, 0.6 + (high_plus * 0.1) + enrichment_boost)
        elif medium > 0:
            return min(0.85, 0.5 + (medium * 0.05) + (success_rate * 0.2) + enrichment_boost)
        else:
            return min(0.7, 0.4 + (success_rate * 0.3) + enrichment_boost)

    # ─── Core Planning & Analysis ─────────────────────────────────────

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
                for row in f.raw_data[:3]:
                    lines.append(f"  Data: {json.dumps(row)}")
        return "\n".join(lines)

    def _plan_next_step(self, hypothesis: str, findings_context: str,
                        step: int, budget: int,
                        schema_context: str, rag_context: str,
                        anomaly_context: str = "", enrichment_context: str = "") -> Optional[Dict[str, Any]]:
        """Ask LLM to decide the next investigation step."""
        failed_parts = []
        if self._failed_tables:
            failed_parts.append(f"Tables that do NOT exist: {', '.join(self._failed_tables)}")
        if self._failed_queries:
            failed_parts.append(f"Queries that failed (do not retry): {'; '.join(list(self._failed_queries)[-5:])}")
        failed_context = "\n".join(failed_parts) if failed_parts else "None"

        prompt = PLANNER_PROMPT.format(
            hypothesis=hypothesis,
            findings_context=findings_context,
            step_number=step,
            budget_remaining=budget - step,
            schema_context=schema_context,
            rag_context=rag_context,
            golden_trace=GOLDEN_TRACE if step <= 3 else "",
            failed_context=failed_context,
            anomaly_context=anomaly_context,
            enrichment_context=enrichment_context,
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
                         sql_query: str, results: List[Dict],
                         enrichment_note: str = "", anomaly_note: str = "") -> Optional[Dict[str, Any]]:
        """Ask LLM to analyze query results with enrichment/anomaly context."""
        results_to_show = results[:15]
        results_json = json.dumps(results_to_show, indent=2)

        prompt = ANALYZER_PROMPT.format(
            hypothesis=hypothesis,
            query_purpose=purpose,
            sql_query=sql_query,
            num_rows=len(results),
            results_json=results_json,
            enrichment_note=enrichment_note,
            anomaly_note=anomaly_note,
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
        text = text.strip()
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
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

    # ─── LLM Cache ────────────────────────────────────────────────────

    def _cache_key(self, context: str) -> str:
        return hashlib.md5(context.encode()).hexdigest()

    # ─── Batch Queries ────────────────────────────────────────────────

    def _execute_batch(self, queries: List[str]) -> List[Tuple[str, List[Dict], str]]:
        """Execute multiple queries efficiently (parallel via threads)."""
        results = []

        def run_one(sql: str) -> Tuple[str, List[Dict], str]:
            r, e = self.osquery_engine.execute_query(sql)
            return sql, r, e

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_one, q) for q in queries]
            for f in as_completed(futures):
                results.append(f.result())

        return results
