"""
FastAPI Backend — API-first delivery with SSE streaming, SIEM push, STIX export.
"""

import uuid
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

app = FastAPI(
    title="HoundAI",
    description="Autonomous Threat Hunting Platform — API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure per deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request/Response Models ────────────────────────────────────────

class HuntRequest(BaseModel):
    hypothesis: str
    target_nodes: Optional[List[str]] = None
    playbook_id: Optional[str] = None
    priority: str = "medium"


class HuntResponse(BaseModel):
    hunt_id: str
    status: str
    hypothesis: str
    created_at: str


class FindingResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    category: str
    indicators: List[str] = []
    mitre_technique: str = ""
    timestamp: str


class FleetStatusResponse(BaseModel):
    total_nodes: int
    active_nodes: int
    inactive_nodes: int
    pending_queries: int


class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: str
    schedule_cron: Optional[str]
    tags: List[str]


# ─── SSE Streaming ──────────────────────────────────────────────────

class HuntEventStream:
    """Server-Sent Events stream for live hunt progress."""

    def __init__(self):
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}

    def subscribe(self, hunt_id: str) -> asyncio.Queue:
        """Subscribe to events for a specific hunt."""
        queue = asyncio.Queue()
        if hunt_id not in self._subscribers:
            self._subscribers[hunt_id] = []
        self._subscribers[hunt_id].append(queue)
        return queue

    def unsubscribe(self, hunt_id: str, queue: asyncio.Queue):
        """Remove a subscriber."""
        if hunt_id in self._subscribers:
            self._subscribers[hunt_id] = [q for q in self._subscribers[hunt_id] if q is not queue]

    async def publish(self, hunt_id: str, event_type: str, data: Dict[str, Any]):
        """Publish an event to all subscribers of a hunt."""
        if hunt_id in self._subscribers:
            event = {"type": event_type, "data": data, "timestamp": datetime.utcnow().isoformat()}
            for queue in self._subscribers[hunt_id]:
                await queue.put(event)


event_stream = HuntEventStream()


# ─── API Routes ─────────────────────────────────────────────────────

@app.post("/api/v1/hunts", response_model=HuntResponse)
async def create_hunt(request: HuntRequest):
    """
    Initiate a new threat hunt.
    Returns immediately with hunt_id; use SSE endpoint to stream progress.
    """
    hunt_id = f"hunt_{uuid.uuid4().hex[:12]}"

    # In production: dispatch to hunt supervisor via task queue
    response = HuntResponse(
        hunt_id=hunt_id,
        status="running",
        hypothesis=request.hypothesis,
        created_at=datetime.utcnow().isoformat(),
    )

    # Publish start event
    await event_stream.publish(hunt_id, "hunt.started", {
        "hunt_id": hunt_id,
        "hypothesis": request.hypothesis,
    })

    return response


@app.get("/api/v1/hunts/{hunt_id}/stream")
async def stream_hunt_events(hunt_id: str):
    """
    SSE endpoint for streaming live hunt progress.
    
    Events:
    - hunt.started
    - hunt.step (agent action with reasoning)
    - hunt.finding (new finding discovered)
    - hunt.checkpoint (HITL approval needed)
    - hunt.completed
    """
    queue = event_stream.subscribe(hunt_id)

    async def generate():
        try:
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=300)
                yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
                if event["type"] == "hunt.completed":
                    break
        except asyncio.TimeoutError:
            yield f"event: timeout\ndata: {{}}\n\n"
        finally:
            event_stream.unsubscribe(hunt_id, queue)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/api/v1/hunts/{hunt_id}", response_model=Dict[str, Any])
async def get_hunt(hunt_id: str):
    """Get hunt details and findings."""
    # In production: query PostgreSQL
    return {"hunt_id": hunt_id, "status": "completed", "findings": []}


@app.get("/api/v1/hunts/{hunt_id}/findings", response_model=List[FindingResponse])
async def get_hunt_findings(hunt_id: str, severity: Optional[str] = None):
    """Get findings for a hunt, optionally filtered by severity."""
    return []


@app.post("/api/v1/hunts/{hunt_id}/approve")
async def approve_checkpoint(hunt_id: str, approved: bool = True):
    """Approve or reject a HITL checkpoint."""
    await event_stream.publish(hunt_id, "hunt.checkpoint_resolved", {
        "approved": approved,
    })
    return {"status": "ok"}


@app.get("/api/v1/fleet/status", response_model=FleetStatusResponse)
async def get_fleet_status():
    """Get fleet overview."""
    return FleetStatusResponse(
        total_nodes=0, active_nodes=0, inactive_nodes=0, pending_queries=0
    )


@app.get("/api/v1/fleet/nodes")
async def list_fleet_nodes(status: Optional[str] = None, tag: Optional[str] = None):
    """List fleet nodes with optional filters."""
    return []


# ─── osquery TLS Remote API endpoints ───────────────────────────────

@app.post("/api/v1/osquery/enroll")
async def osquery_enroll(request: Request):
    """osquery TLS enrollment endpoint."""
    body = await request.json()
    # Delegate to FleetManager
    return {"node_key": "", "node_invalid": False}


@app.post("/api/v1/osquery/config")
async def osquery_config(request: Request):
    """osquery TLS config endpoint."""
    body = await request.json()
    return {"schedule": {}, "options": {}}


@app.post("/api/v1/osquery/distributed/read")
async def osquery_distributed_read(request: Request):
    """osquery distributed query read endpoint."""
    body = await request.json()
    return {"queries": {}}


@app.post("/api/v1/osquery/distributed/write")
async def osquery_distributed_write(request: Request):
    """osquery distributed query results endpoint."""
    body = await request.json()
    return {}


@app.post("/api/v1/osquery/log")
async def osquery_log(request: Request):
    """osquery log ingestion endpoint."""
    body = await request.json()
    return {}


# ─── SIEM Integration Endpoints ─────────────────────────────────────

@app.get("/api/v1/export/stix/{hunt_id}")
async def export_stix(hunt_id: str):
    """
    Export hunt findings as STIX 2.1 bundle.
    
    Maps findings to STIX objects:
    - Indicators (IOCs)
    - Observed Data
    - Attack Patterns (MITRE techniques)
    - Reports
    """
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [],
    }
    return stix_bundle


@app.get("/api/v1/export/navigator/{hunt_id}")
async def export_navigator_layer(hunt_id: str):
    """Export MITRE ATT&CK Navigator layer JSON."""
    layer = {
        "name": f"HoundAI Hunt {hunt_id}",
        "versions": {"attack": "15", "navigator": "5.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [],
    }
    return layer


@app.post("/api/v1/integrations/elastic")
async def push_to_elastic(hunt_id: str):
    """Push findings to Elasticsearch in ECS format."""
    return {"status": "ok", "documents_sent": 0}


@app.post("/api/v1/integrations/splunk")
async def push_to_splunk(hunt_id: str):
    """Push findings to Splunk via HEC."""
    return {"status": "ok", "events_sent": 0}


# ─── Playbook & Scheduler Endpoints ─────────────────────────────────

@app.get("/api/v1/playbooks", response_model=List[PlaybookResponse])
async def list_playbooks():
    """List available hunt playbooks."""
    return []


@app.post("/api/v1/playbooks/{playbook_id}/run")
async def run_playbook(playbook_id: str):
    """Manually trigger a playbook execution."""
    return {"hunt_id": f"hunt_{uuid.uuid4().hex[:12]}", "status": "started"}


# ─── Search Endpoints ────────────────────────────────────────────────

@app.get("/api/v1/search/findings")
async def search_findings(q: str = Query(...), severity: Optional[str] = None,
                           mitre: Optional[str] = None, limit: int = 50):
    """Full-text search over all findings (PostgreSQL FTS)."""
    return {"query": q, "results": [], "total": 0}


@app.get("/api/v1/search/hunts")
async def search_hunts(q: str = Query(...), status: Optional[str] = None,
                        limit: int = 20):
    """Search hunts by hypothesis/conclusion text."""
    return {"query": q, "results": [], "total": 0}
