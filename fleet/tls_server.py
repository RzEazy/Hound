"""
osquery TLS Remote API Server — handles fleet enrollment, configuration, 
distributed queries, and result streaming.

This implements the osquery TLS remote API endpoints:
- /enroll          — node enrollment with pre-shared key
- /config          — push configuration (packs, decorators)
- /distributed/read  — issue queries to specific nodes
- /distributed/write — receive query results from nodes
- /log             — status/result log ingestion
"""

import uuid
import time
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    REVOKED = "revoked"


@dataclass
class FleetNode:
    """Represents an enrolled osquery agent in the fleet."""
    node_key: str
    hostname: str
    platform: str
    os_version: str
    osquery_version: str
    enrolled_at: datetime
    last_seen: datetime
    status: NodeStatus = NodeStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    config_group: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DistributedQuery:
    """A query to be distributed to one or more fleet nodes."""
    query_id: str
    sql: str
    description: str
    target_nodes: List[str]  # node_keys or "all"
    created_at: datetime
    expires_at: datetime
    hunt_id: Optional[str] = None
    results: Dict[str, List[Dict]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    status: str = "pending"  # pending, running, completed, expired


class FleetManager:
    """
    Manages osquery fleet enrollment, configuration, and distributed queries.
    
    Production deployment: This sits behind the FastAPI server and handles
    all TLS remote API logic. Nodes are stored in PostgreSQL (via models layer).
    """

    def __init__(self, enroll_secret: str, db_session=None, message_queue=None):
        """
        Args:
            enroll_secret: Pre-shared secret for node enrollment
            db_session: SQLAlchemy async session (None for in-memory dev mode)
            message_queue: MessageQueue instance for streaming results
        """
        self.enroll_secret = enroll_secret
        self.db = db_session
        self.mq = message_queue
        
        # In-memory state (replaced by PostgreSQL in production)
        self._nodes: Dict[str, FleetNode] = {}
        self._pending_queries: Dict[str, DistributedQuery] = {}
        self._config_groups: Dict[str, Dict[str, Any]] = {
            "default": self._default_config()
        }

    def enroll(self, enroll_secret: str, host_identifier: str,
               host_details: Dict[str, Any]) -> Optional[str]:
        """
        Enroll a new node. Returns node_key on success, None on failure.
        
        Implements: POST /enroll
        """
        if enroll_secret != self.enroll_secret:
            logger.warning(f"Enrollment rejected: invalid secret from {host_identifier}")
            return None

        node_key = f"node_{uuid.uuid4().hex[:16]}"
        now = datetime.utcnow()

        node = FleetNode(
            node_key=node_key,
            hostname=host_details.get("hostname", host_identifier),
            platform=host_details.get("platform", "unknown"),
            os_version=host_details.get("os_version", ""),
            osquery_version=host_details.get("osquery_version", ""),
            enrolled_at=now,
            last_seen=now,
            tags=host_details.get("tags", []),
            config_group=host_details.get("config_group", "default"),
        )
        self._nodes[node_key] = node
        logger.info(f"Enrolled node: {node.hostname} ({node_key})")
        return node_key

    def get_config(self, node_key: str) -> Optional[Dict[str, Any]]:
        """
        Return osquery config for a node.
        
        Implements: POST /config
        """
        node = self._nodes.get(node_key)
        if not node or node.status == NodeStatus.REVOKED:
            return None

        node.last_seen = datetime.utcnow()
        return self._config_groups.get(node.config_group, self._default_config())

    def distribute_query(self, sql: str, description: str,
                         target_nodes: Optional[List[str]] = None,
                         hunt_id: Optional[str] = None,
                         ttl_seconds: int = 300) -> DistributedQuery:
        """
        Issue a distributed query to fleet nodes.
        
        Args:
            sql: The osquery SQL to execute
            description: Human-readable description
            target_nodes: List of node_keys, or None for all active nodes
            hunt_id: Optional hunt session ID for correlation
            ttl_seconds: Time-to-live before query expires
        """
        now = datetime.utcnow()
        query = DistributedQuery(
            query_id=f"dq_{uuid.uuid4().hex[:12]}",
            sql=sql,
            description=description,
            target_nodes=target_nodes or list(self._active_node_keys()),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            hunt_id=hunt_id,
            status="pending",
        )
        self._pending_queries[query.query_id] = query
        logger.info(f"Distributed query {query.query_id}: {description} -> {len(query.target_nodes)} nodes")
        return query

    def get_distributed_queries(self, node_key: str) -> Dict[str, str]:
        """
        Get pending queries for a specific node.
        
        Implements: POST /distributed/read
        Returns: {query_id: sql_query}
        """
        node = self._nodes.get(node_key)
        if not node:
            return {}

        node.last_seen = datetime.utcnow()
        now = datetime.utcnow()
        queries = {}

        for qid, dq in self._pending_queries.items():
            if dq.status == "pending" and dq.expires_at > now:
                if node_key in dq.target_nodes:
                    queries[qid] = dq.sql
                    dq.status = "running"

        return queries

    def submit_distributed_results(self, node_key: str,
                                    results: Dict[str, List[Dict[str, Any]]],
                                    statuses: Dict[str, int]) -> bool:
        """
        Receive distributed query results from a node.
        
        Implements: POST /distributed/write
        """
        node = self._nodes.get(node_key)
        if not node:
            return False

        node.last_seen = datetime.utcnow()

        for query_id, rows in results.items():
            dq = self._pending_queries.get(query_id)
            if dq:
                dq.results[node_key] = rows
                status_code = statuses.get(query_id, 0)
                if status_code != 0:
                    dq.errors[node_key] = f"Status code: {status_code}"

                # Check if all nodes have reported
                reported = set(dq.results.keys()) | set(dq.errors.keys())
                if reported >= set(dq.target_nodes):
                    dq.status = "completed"

                # Publish to message queue if available
                if self.mq:
                    self.mq.publish(
                        topic="fleet.query.results",
                        message={
                            "query_id": query_id,
                            "node_key": node_key,
                            "hostname": node.hostname,
                            "hunt_id": dq.hunt_id,
                            "rows": rows,
                            "status": status_code,
                        }
                    )

        return True

    def ingest_log(self, node_key: str, log_type: str,
                   data: List[Dict[str, Any]]) -> bool:
        """
        Ingest status/result logs from a node.
        
        Implements: POST /log
        """
        node = self._nodes.get(node_key)
        if not node:
            return False

        node.last_seen = datetime.utcnow()

        if self.mq:
            self.mq.publish(
                topic=f"fleet.log.{log_type}",
                message={
                    "node_key": node_key,
                    "hostname": node.hostname,
                    "log_type": log_type,
                    "data": data,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        return True

    def get_fleet_status(self) -> Dict[str, Any]:
        """Get fleet overview statistics."""
        now = datetime.utcnow()
        stale_threshold = now - timedelta(minutes=5)

        active = [n for n in self._nodes.values()
                  if n.last_seen > stale_threshold and n.status == NodeStatus.ACTIVE]
        inactive = [n for n in self._nodes.values()
                    if n.last_seen <= stale_threshold and n.status == NodeStatus.ACTIVE]

        return {
            "total_nodes": len(self._nodes),
            "active_nodes": len(active),
            "inactive_nodes": len(inactive),
            "pending_queries": len([q for q in self._pending_queries.values() if q.status == "pending"]),
            "running_queries": len([q for q in self._pending_queries.values() if q.status == "running"]),
        }

    def revoke_node(self, node_key: str) -> bool:
        """Revoke a node's enrollment."""
        node = self._nodes.get(node_key)
        if node:
            node.status = NodeStatus.REVOKED
            return True
        return False

    def _active_node_keys(self) -> List[str]:
        """Get all active node keys."""
        now = datetime.utcnow()
        stale = now - timedelta(minutes=5)
        return [k for k, n in self._nodes.items()
                if n.status == NodeStatus.ACTIVE and n.last_seen > stale]

    def _default_config(self) -> Dict[str, Any]:
        """Default osquery configuration for enrolled nodes."""
        return {
            "options": {
                "logger_plugin": "tls",
                "distributed_plugin": "tls",
                "distributed_interval": 10,
                "distributed_tls_max_attempts": 3,
            },
            "schedule": {
                "process_monitor": {
                    "query": "SELECT pid, name, path, cmdline, uid, parent FROM processes WHERE on_disk = 0 OR path LIKE '/tmp/%';",
                    "interval": 60,
                    "description": "Monitor suspicious processes"
                },
                "network_monitor": {
                    "query": "SELECT p.name, p.pid, pos.remote_address, pos.remote_port FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' AND pos.state = 'ESTABLISHED';",
                    "interval": 30,
                    "description": "Monitor network connections"
                },
            },
            "packs": {},
        }
