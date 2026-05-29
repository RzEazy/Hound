"""
Behavioral Baselining — per-host and per-fleet process/network profiles.

Builds statistical models of normal behavior to detect anomalies:
- Process execution patterns (what runs on each host)
- Network connection profiles (normal destinations per process)
- Port listening patterns
- User activity patterns (login times, commands)
"""

import math
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ProcessProfile:
    """Baseline profile for a process on a host."""
    name: str
    paths_seen: Set[str] = field(default_factory=set)
    typical_parent: Optional[str] = None
    typical_uid: Optional[int] = None
    typical_ports: Set[int] = field(default_factory=set)
    typical_remote_ips: Set[str] = field(default_factory=set)
    execution_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class HostBaseline:
    """Behavioral baseline for a single host."""
    hostname: str
    node_key: str
    processes: Dict[str, ProcessProfile] = field(default_factory=dict)
    listening_ports: Set[int] = field(default_factory=set)
    normal_users: Set[str] = field(default_factory=set)
    typical_cron_commands: Set[str] = field(default_factory=set)
    network_destinations: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    last_updated: Optional[datetime] = None
    observation_window_days: int = 0


@dataclass
class FleetBaseline:
    """Aggregate behavioral baseline across the fleet."""
    process_prevalence: Counter = field(default_factory=Counter)  # process_name -> count of hosts
    port_prevalence: Counter = field(default_factory=Counter)     # port -> count of hosts
    total_hosts: int = 0


@dataclass
class AnomalyScore:
    """Result of anomaly detection against baseline."""
    description: str
    score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    context: Dict[str, Any] = field(default_factory=dict)
    baseline_comparison: str = ""


class BehavioralEngine:
    """
    Builds and queries behavioral baselines for anomaly detection.
    
    The agent uses this to say "this binary listening on port 4444 is anomalous
    for this machine" rather than generic pattern matching.
    """

    # Known-good processes that should never be flagged as anomalous.
    # Maps process name -> set of acceptable UIDs (None means any UID is fine).
    KNOWN_GOOD: Dict[str, Optional[Set[int]]] = {
        "systemd": {0},
        "systemd-journald": {0},
        "systemd-logind": {0},
        "systemd-udevd": {0},
        "systemd-resolved": {193, 0},
        "systemd-timesyncd": {0},
        "systemd-networkd": {0},
        "init": {0},
        "kthreadd": {0},
        "agetty": {0},
        "login": {0},
        "sshd": {0},
        "dbus-daemon": None,  # runs as messagebus or root
        "polkitd": None,
        "NetworkManager": {0},
        "accounts-daemon": {0},
        "udisksd": {0},
        # NixOS-specific wrappers
        ".agent-wrapped": None,
        ".dbus-daemon-wrapped": None,
        ".polkit-agent-helper-1-wrapped": None,
    }

    # Minimum number of observation updates before the engine starts flagging.
    # This prevents cold-start false positives where the first observation
    # becomes the baseline and the second observation is flagged as deviant.
    MIN_OBSERVATION_UPDATES: int = 3

    def __init__(self, db_session=None):
        self.db = db_session
        self._host_baselines: Dict[str, HostBaseline] = {}
        self._fleet_baseline = FleetBaseline()
        self._observation_counts: Dict[str, int] = {}  # node_key -> update count

    def update_host_baseline(self, node_key: str, hostname: str,
                              observations: Dict[str, Any]):
        """
        Update baseline with new observations from a host.
        
        Called periodically with osquery scheduled query results:
        - processes list
        - listening_ports
        - logged_in_users
        - crontab entries
        - network connections
        """
        if node_key not in self._host_baselines:
            self._host_baselines[node_key] = HostBaseline(
                hostname=hostname, node_key=node_key
            )

        baseline = self._host_baselines[node_key]
        now = datetime.utcnow()
        baseline.last_updated = now
        self._observation_counts[node_key] = self._observation_counts.get(node_key, 0) + 1

        # Update process profiles
        for proc in observations.get("processes", []):
            name = proc.get("name", "")
            if not name:
                continue
            if name not in baseline.processes:
                baseline.processes[name] = ProcessProfile(name=name, first_seen=now)
            profile = baseline.processes[name]
            profile.last_seen = now
            profile.execution_count += 1
            if proc.get("path"):
                profile.paths_seen.add(proc["path"])
            if proc.get("uid") is not None:
                profile.typical_uid = int(proc["uid"])
            if proc.get("parent"):
                profile.typical_parent = proc["parent"]

        # Update listening ports
        for port_entry in observations.get("listening_ports", []):
            port = int(port_entry.get("port", 0))
            if port:
                baseline.listening_ports.add(port)

        # Update users
        for user in observations.get("users", []):
            username = user.get("username", "")
            if username:
                baseline.normal_users.add(username)

        # Update network destinations
        for conn in observations.get("connections", []):
            proc_name = conn.get("process_name", "unknown")
            remote = conn.get("remote_address", "")
            if remote:
                baseline.network_destinations[proc_name].add(remote)
                if proc_name in baseline.processes:
                    baseline.processes[proc_name].typical_remote_ips.add(remote)

        # Update fleet-level stats
        self._update_fleet_baseline()

    def check_anomalies(self, node_key: str,
                         current_state: Dict[str, Any]) -> List[AnomalyScore]:
        """
        Check current observations against baseline for anomalies.
        
        Returns list of anomaly scores for any deviations detected.
        """
        baseline = self._host_baselines.get(node_key)
        if not baseline:
            return []  # No baseline yet, can't detect anomalies

        # Cold-start guard: don't flag until we have enough observations
        obs_count = self._observation_counts.get(node_key, 0)
        if obs_count < self.MIN_OBSERVATION_UPDATES:
            logger.info(f"Baseline for {node_key} has only {obs_count} observations "
                        f"(need {self.MIN_OBSERVATION_UPDATES}); skipping anomaly detection")
            return []

        anomalies = []
        _seen_keys: set = set()  # For deduplication

        # Check processes
        for proc in current_state.get("processes", []):
            name = proc.get("name", "")
            path = proc.get("path", "")
            uid = proc.get("uid")

            # Skip known-good system processes
            if name in self.KNOWN_GOOD:
                allowed_uids = self.KNOWN_GOOD[name]
                if allowed_uids is None or (uid is not None and int(uid) in allowed_uids):
                    continue

            if name and name not in baseline.processes:
                # New process never seen on this host
                fleet_prevalence = self._fleet_baseline.process_prevalence.get(name, 0)
                fleet_ratio = fleet_prevalence / max(self._fleet_baseline.total_hosts, 1)

                if fleet_ratio < 0.1:  # Seen on fewer than 10% of fleet
                    anomalies.append(AnomalyScore(
                        description=f"Process '{name}' never seen on this host and rare in fleet ({fleet_prevalence}/{self._fleet_baseline.total_hosts} hosts)",
                        score=0.7 if fleet_ratio < 0.01 else 0.4,
                        context={"process": name, "path": path, "uid": uid},
                        baseline_comparison=f"Fleet prevalence: {fleet_ratio:.1%}",
                    ))

            elif name in baseline.processes:
                profile = baseline.processes[name]
                # Check if running from unusual path
                if path and profile.paths_seen and path not in profile.paths_seen:
                    anomalies.append(AnomalyScore(
                        description=f"Process '{name}' running from unusual path '{path}' (normally: {', '.join(list(profile.paths_seen)[:3])})",
                        score=0.8,
                        context={"process": name, "path": path, "expected_paths": list(profile.paths_seen)},
                        baseline_comparison=f"Known paths: {profile.paths_seen}",
                    ))
                # Check if running as unusual UID
                if uid is not None and profile.typical_uid is not None:
                    if int(uid) != profile.typical_uid:
                        anomalies.append(AnomalyScore(
                            description=f"Process '{name}' running as UID {uid} (normally UID {profile.typical_uid})",
                            score=0.6,
                            context={"process": name, "uid": uid, "expected_uid": profile.typical_uid},
                        ))

        # Check listening ports
        for port_entry in current_state.get("listening_ports", []):
            port = int(port_entry.get("port", 0))
            proc_name = port_entry.get("process_name", "unknown")
            if port and port not in baseline.listening_ports:
                fleet_port_prev = self._fleet_baseline.port_prevalence.get(port, 0)
                score = 0.8 if fleet_port_prev == 0 else 0.5
                anomalies.append(AnomalyScore(
                    description=f"New listening port {port} ({proc_name}) — never seen on this host",
                    score=score,
                    context={"port": port, "process": proc_name},
                    baseline_comparison=f"Host ports: {sorted(baseline.listening_ports)}, Fleet prevalence: {fleet_port_prev}",
                ))

        # Check network destinations
        for conn in current_state.get("connections", []):
            proc_name = conn.get("process_name", "unknown")
            remote = conn.get("remote_address", "")
            if remote and proc_name in baseline.network_destinations:
                known_dests = baseline.network_destinations[proc_name]
                if remote not in known_dests:
                    anomalies.append(AnomalyScore(
                        description=f"Process '{proc_name}' connecting to new destination {remote}",
                        score=0.4,
                        context={"process": proc_name, "remote": remote,
                                 "known_destinations_sample": list(known_dests)[:5]},
                    ))

        # Deduplicate: same process + same anomaly type = one finding
        deduped = []
        seen_keys = set()
        for a in anomalies:
            key = (a.context.get("process", ""), a.context.get("uid"), a.context.get("port"), a.context.get("remote", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(a)

        return deduped

    def get_host_summary(self, node_key: str) -> Optional[Dict[str, Any]]:
        """Get a summary of a host's baseline for the hunt agent."""
        baseline = self._host_baselines.get(node_key)
        if not baseline:
            return None

        return {
            "hostname": baseline.hostname,
            "known_processes": len(baseline.processes),
            "known_ports": sorted(baseline.listening_ports),
            "known_users": sorted(baseline.normal_users),
            "observation_days": baseline.observation_window_days,
            "last_updated": baseline.last_updated.isoformat() if baseline.last_updated else None,
            "top_processes": [
                {"name": p.name, "paths": list(p.paths_seen)[:2], "count": p.execution_count}
                for p in sorted(baseline.processes.values(), key=lambda x: x.execution_count, reverse=True)[:20]
            ],
        }

    def _update_fleet_baseline(self):
        """Recalculate fleet-wide statistics."""
        self._fleet_baseline = FleetBaseline(total_hosts=len(self._host_baselines))

        for baseline in self._host_baselines.values():
            for proc_name in baseline.processes:
                self._fleet_baseline.process_prevalence[proc_name] += 1
            for port in baseline.listening_ports:
                self._fleet_baseline.port_prevalence[port] += 1
