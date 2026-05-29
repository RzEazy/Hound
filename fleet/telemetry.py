"""
Telemetry collectors — auditd and eBPF (Falco/Tetragon) integration.

Provides fine-grained syscall telemetry beyond what osquery captures:
- auditd: file opens, execve, ptrace, network syscalls
- eBPF: Falco rules or Tetragon policies for kernel event capture
"""

import json
import logging
import asyncio
import subprocess
from typing import Dict, Any, List, Optional, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class TelemetrySource(Enum):
    AUDITD = "auditd"
    FALCO = "falco"
    TETRAGON = "tetragon"


@dataclass
class TelemetryEvent:
    """Normalized telemetry event from any source."""
    source: TelemetrySource
    timestamp: datetime
    hostname: str
    event_type: str  # execve, open, connect, ptrace, etc.
    pid: int
    process_name: str
    uid: int
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    rule_name: Optional[str] = None
    node_key: Optional[str] = None


class TelemetryCollector(ABC):
    """Base class for telemetry collectors."""

    @abstractmethod
    async def start(self):
        """Start collecting telemetry."""
        pass

    @abstractmethod
    async def stop(self):
        """Stop collecting telemetry."""
        pass

    @abstractmethod
    async def stream_events(self) -> AsyncGenerator[TelemetryEvent, None]:
        """Stream telemetry events."""
        pass


class AuditdCollector(TelemetryCollector):
    """
    Collects auditd events via audit log parsing or audit-go library.
    
    Monitors syscalls:
    - execve: process execution
    - open/openat: file access
    - connect: network connections
    - ptrace: process tracing (debugger/injection detection)
    - unlink/rename: file modifications
    """

    def __init__(self, log_path: str = "/var/log/audit/audit.log",
                 rules: Optional[List[Dict[str, str]]] = None):
        self.log_path = log_path
        self.rules = rules or self._default_rules()
        self._running = False
        self._process: Optional[asyncio.subprocess.Process] = None

    async def start(self):
        """Start tailing auditd logs."""
        self._running = True
        logger.info("AuditdCollector started")

    async def stop(self):
        """Stop the collector."""
        self._running = False
        if self._process:
            self._process.terminate()
        logger.info("AuditdCollector stopped")

    async def stream_events(self) -> AsyncGenerator[TelemetryEvent, None]:
        """
        Stream parsed auditd events.
        
        In production, this tails /var/log/audit/audit.log or connects
        to audisp plugin for real-time event delivery.
        """
        self._process = await asyncio.create_subprocess_exec(
            "tail", "-F", self.log_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while self._running and self._process.stdout:
            line = await self._process.stdout.readline()
            if not line:
                break
            event = self._parse_audit_line(line.decode().strip())
            if event:
                yield event

    def _parse_audit_line(self, line: str) -> Optional[TelemetryEvent]:
        """Parse a raw auditd log line into a TelemetryEvent."""
        if not line or "type=" not in line:
            return None

        # Extract key fields from audit format: type=X msg=audit(T.M:ID): key=val ...
        fields = {}
        for part in line.split():
            if "=" in part:
                key, _, val = part.partition("=")
                fields[key] = val.strip('"')

        audit_type = fields.get("type", "")
        syscall = fields.get("syscall", "")

        # Map to our event type
        event_type_map = {
            "EXECVE": "execve",
            "SYSCALL": syscall,
            "PATH": "file_access",
            "SOCKADDR": "connect",
        }
        event_type = event_type_map.get(audit_type, audit_type.lower())

        return TelemetryEvent(
            source=TelemetrySource.AUDITD,
            timestamp=datetime.utcnow(),
            hostname=fields.get("node", "unknown"),
            event_type=event_type,
            pid=int(fields.get("pid", 0)),
            process_name=fields.get("comm", fields.get("exe", "unknown")),
            uid=int(fields.get("uid", -1)),
            data=fields,
        )

    def _default_rules(self) -> List[Dict[str, str]]:
        """Default auditd rules for threat hunting."""
        return [
            {"rule": "-a always,exit -F arch=b64 -S execve -k exec_monitor",
             "description": "Monitor all process executions"},
            {"rule": "-a always,exit -F arch=b64 -S ptrace -k ptrace_monitor",
             "description": "Monitor ptrace (injection/debugging)"},
            {"rule": "-w /tmp -p wxa -k tmp_write",
             "description": "Monitor writes/executions in /tmp"},
            {"rule": "-w /etc/passwd -p wa -k passwd_changes",
             "description": "Monitor password file changes"},
            {"rule": "-w /etc/shadow -p wa -k shadow_changes",
             "description": "Monitor shadow file changes"},
            {"rule": "-a always,exit -F arch=b64 -S connect -k net_connect",
             "description": "Monitor network connections"},
        ]

    async def install_rules(self) -> bool:
        """Install auditd rules (requires root)."""
        try:
            for rule_spec in self.rules:
                proc = await asyncio.create_subprocess_exec(
                    "auditctl", *rule_spec["rule"].split(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.wait()
            return True
        except Exception as e:
            logger.error(f"Failed to install audit rules: {e}")
            return False


class FalcoCollector(TelemetryCollector):
    """
    Collects events from Falco's gRPC output API.
    
    Falco provides eBPF-based kernel event capture with rule-based
    detection for suspicious behavior patterns.
    """

    def __init__(self, grpc_address: str = "unix:///var/run/falco/falco.sock",
                 custom_rules_path: Optional[str] = None):
        self.grpc_address = grpc_address
        self.custom_rules_path = custom_rules_path
        self._running = False

    async def start(self):
        self._running = True
        logger.info(f"FalcoCollector started (gRPC: {self.grpc_address})")

    async def stop(self):
        self._running = False
        logger.info("FalcoCollector stopped")

    async def stream_events(self) -> AsyncGenerator[TelemetryEvent, None]:
        """
        Stream Falco alerts via gRPC outputs API.
        
        In production, connects to Falco's gRPC server and receives
        structured alert events in real-time.
        """
        # Placeholder: In production, use grpcio to connect to Falco
        # from falco_grpc_client import FalcoOutputsClient
        while self._running:
            await asyncio.sleep(1)
            # Each alert from Falco would be yielded as:
            # yield TelemetryEvent(
            #     source=TelemetrySource.FALCO,
            #     timestamp=alert.time,
            #     hostname=alert.hostname,
            #     event_type=alert.rule,
            #     pid=alert.output_fields.get("proc.pid", 0),
            #     process_name=alert.output_fields.get("proc.name", ""),
            #     uid=alert.output_fields.get("user.uid", -1),
            #     data=alert.output_fields,
            #     severity=alert.priority.name.lower(),
            #     rule_name=alert.rule,
            # )
            return  # Placeholder termination


class TetragonCollector(TelemetryCollector):
    """
    Collects events from Cilium Tetragon's JSON export.
    
    Tetragon provides eBPF-based observability with TracingPolicies
    for fine-grained kernel-level monitoring.
    """

    def __init__(self, export_path: str = "/var/run/tetragon/tetragon.log",
                 policies: Optional[List[Dict[str, Any]]] = None):
        self.export_path = export_path
        self.policies = policies or []
        self._running = False

    async def start(self):
        self._running = True
        logger.info("TetragonCollector started")

    async def stop(self):
        self._running = False

    async def stream_events(self) -> AsyncGenerator[TelemetryEvent, None]:
        """Stream Tetragon events from JSON export file."""
        process = await asyncio.create_subprocess_exec(
            "tail", "-F", self.export_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while self._running and process.stdout:
            line = await process.stdout.readline()
            if not line:
                break
            try:
                event_data = json.loads(line.decode())
                event = self._parse_tetragon_event(event_data)
                if event:
                    yield event
            except json.JSONDecodeError:
                continue

    def _parse_tetragon_event(self, data: Dict[str, Any]) -> Optional[TelemetryEvent]:
        """Parse a Tetragon JSON event."""
        process_exec = data.get("process_exec") or data.get("process_kprobe")
        if not process_exec:
            return None

        proc = process_exec.get("process", {})
        return TelemetryEvent(
            source=TelemetrySource.TETRAGON,
            timestamp=datetime.fromisoformat(data.get("time", datetime.utcnow().isoformat())),
            hostname=data.get("node_name", "unknown"),
            event_type=data.get("event_type", "process_exec"),
            pid=proc.get("pid", 0),
            process_name=proc.get("binary", "unknown"),
            uid=proc.get("uid", -1),
            data=data,
            severity="info",
        )


class TelemetryPipeline:
    """
    Aggregates events from multiple collectors and publishes to message queue.
    """

    def __init__(self, message_queue=None):
        self.mq = message_queue
        self.collectors: List[TelemetryCollector] = []
        self._running = False

    def add_collector(self, collector: TelemetryCollector):
        self.collectors.append(collector)

    async def start(self):
        """Start all collectors and begin aggregating events."""
        self._running = True
        tasks = []
        for collector in self.collectors:
            await collector.start()
            tasks.append(asyncio.create_task(self._consume(collector)))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self):
        self._running = False
        for collector in self.collectors:
            await collector.stop()

    async def _consume(self, collector: TelemetryCollector):
        """Consume events from a collector and publish to MQ."""
        async for event in collector.stream_events():
            if not self._running:
                break
            if self.mq:
                self.mq.publish(
                    topic="telemetry.events",
                    message={
                        "source": event.source.value,
                        "timestamp": event.timestamp.isoformat(),
                        "hostname": event.hostname,
                        "event_type": event.event_type,
                        "pid": event.pid,
                        "process_name": event.process_name,
                        "uid": event.uid,
                        "severity": event.severity,
                        "rule_name": event.rule_name,
                        "data": event.data,
                    }
                )
