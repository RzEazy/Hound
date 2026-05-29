# HoundAI — Autonomous Threat Hunting Platform

An LLM-powered cybersecurity platform that performs **autonomous threat investigations** at scale. HoundAI doesn't just answer questions — it plans, executes, pivots, and reports like a human threat hunter, with full production infrastructure for fleet-wide deployment.

```
 ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
 ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
 ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
 ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
 ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
```

---

## Platform Overview

HoundAI is a 6-layer production threat hunting platform:

| Layer | Component | Purpose |
|-------|-----------|---------|
| Collection | Fleet Manager | osquery TLS enrollment, distributed queries, auditd/Falco/Tetragon telemetry |
| Intelligence | Hybrid Search + Threat Intel + Behavioral Engine | BM25+vector RRF search, multi-feed IOC enrichment, per-host anomaly baselines |
| Hunt Engine | Autonomous Agent + Sub-agents + Evidence Chain | ReAct loop with behavioral pre-check, live enrichment, MITRE mapping, Ed25519 signed evidence |
| Scheduler | Playbook Engine | YAML playbooks with cron/trigger execution |
| Auth | OIDC + RBAC | SSO, role-based access, team namespaces, multi-tenancy |
| API | FastAPI + SSE | REST API, real-time streaming, SIEM/STIX/Navigator export |

All production subsystems are **optional** — HoundAI degrades gracefully to a standalone TUI forensics tool if services aren't configured.

---

## Architecture

```
                          ┌─────────────────────────────────┐
                          │         FastAPI Server          │
                          │   REST + SSE + SIEM Export      │
                          └──────────────┬──────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
     ┌────────▼────────┐      ┌─────────▼─────────┐     ┌─────────▼─────────┐
     │  Auth / RBAC    │      │   Scheduler       │     │   TUI (Rich)      │
     │  OIDC + Teams   │      │   Playbooks       │     │   30+ Commands    │
     └─────────────────┘      └─────────┬─────────┘     └─────────┬─────────┘
                                         │                          │
                              ┌──────────▼──────────────────────────▼──────┐
                              │          Hunt Engine                        │
                              │  ┌─────────────────────────────────────┐   │
                              │  │ ThreatHuntingAgent (ReAct Loop)     │   │
                              │  │  • Behavioral pre-check             │   │
                              │  │  • Live IOC enrichment              │   │
                              │  │  • HITL checkpoints (HIGH/CRIT)     │   │
                              │  │  • Evidence signing (Ed25519)       │   │
                              │  │  • MITRE ATT&CK correlation         │   │
                              │  └─────────────────────────────────────┘   │
                              └──────────────────┬────────────────────────-┘
                                                 │
              ┌──────────────────────────────────┼──────────────────────────┐
              │                                  │                          │
    ┌─────────▼─────────┐          ┌─────────────▼──────────┐   ┌─────────▼─────────┐
    │ Behavioral Engine │          │  Threat Intel          │   │  Hybrid Search    │
    │ Per-host baselines│          │  VT/AbuseIPDB/MISP    │   │  BM25 + Vector    │
    │ Fleet anomalies   │          │  STIX/TAXII feeds     │   │  RRF fusion       │
    └───────────────────┘          └────────────────────────┘   └───────────────────┘
              │
    ┌─────────▼─────────────────────────────────────────────────┐
    │                    Fleet Collection                        │
    │  osquery TLS Server │ auditd/Falco/Tetragon │ NATS/Kafka  │
    └───────────────────────────────────────────────────────────┘
```

### Directory Structure

```
HoundAI/
├── tui.py                        # Production TUI (entry point, 30+ commands)
├── core/
│   ├── lia_main.py               # Central orchestrator
│   ├── router.py                 # LLM intent classifier
│   ├── memory.py                 # Conversation persistence
│   └── safety.py                 # Multi-layer safety checker
├── hunting/
│   ├── agent.py                  # Autonomous hunt agent (ReAct + subsystems)
│   ├── findings.py               # Findings graph (evidence chains)
│   └── report.py                 # Report generator (markdown/JSON)
├── fleet/
│   ├── tls_server.py             # osquery TLS enrollment + distributed queries
│   ├── telemetry.py              # auditd/Falco/Tetragon collectors
│   └── message_queue.py          # NATS/Kafka abstraction
├── intelligence/
│   ├── hybrid_search.py          # BM25 + vector search with RRF
│   ├── threat_intel.py           # VT/AbuseIPDB/MISP/STIX-TAXII feeds
│   └── behavioral.py             # Per-host/fleet behavioral baselines
├── hunt_engine/
│   ├── agents.py                 # Sub-agent supervisor (recon/pivot/enrich/report)
│   └── evidence.py               # Ed25519 signed evidence chains
├── models/
│   └── database.py               # PostgreSQL models (hunts, findings, campaigns)
├── scheduler/
│   └── scheduler.py              # YAML playbook loader + cron/trigger engine
├── auth/
│   └── auth.py                   # OIDC/SSO + RBAC + multi-tenancy
├── api/
│   └── server.py                 # FastAPI + SSE + SIEM integrations
├── config/
│   └── settings.py               # Centralized env-based configuration
├── playbooks/
│   ├── ransomware_precursors.yaml
│   └── cve_auto_hunt.yaml
├── chains/                       # LLM chain abstractions
├── engines/                      # osquery/command execution
├── rag/                          # ChromaDB + embeddings
├── tools/                        # Formatters + dashboards
├── shell.nix                     # NixOS dev environment (PostgreSQL + NATS auto-start)
└── requirements.txt              # All dependencies
```

---

## Features

### Autonomous Threat Hunting
- **ReAct loop** — plans, executes, analyzes, pivots dynamically based on findings
- **Behavioral anomaly detection** — per-host baselines with cold-start protection and known-good whitelisting
- **Live IOC enrichment** — VirusTotal, AbuseIPDB, MISP lookups during hunts
- **MITRE ATT&CK mapping** — automatic technique correlation (T1036, T1055, T1071, etc.)
- **Evidence signing** — Ed25519 with blockchain-style hash chaining for forensic integrity
- **Human-in-the-loop** — pauses for analyst confirmation on HIGH/CRITICAL findings
- **Dynamic budget** — starts at 10 steps, extends to 25 when threats appear

### Fleet Management
- **osquery TLS server** — remote enrollment, distributed query dispatch, result collection
- **Multi-source telemetry** — auditd, Falco, Tetragon event ingestion
- **Message queue** — NATS (real-time, <10k nodes) or Kafka (high-volume) transport

### Intelligence
- **Hybrid search** — BM25 + vector similarity with Reciprocal Rank Fusion
- **Multi-feed threat intel** — VirusTotal, AbuseIPDB, MISP, STIX/TAXII
- **Behavioral baselining** — learns normal per-host process/network/port patterns, flags deviations

### Scheduling & Playbooks
- **YAML playbooks** — declarative hunt definitions with parameters, schedules, triggers
- **Cron execution** — nightly/weekly scheduled hunts
- **Trigger-based** — auto-launch hunts on CVE advisories or alert conditions

### Production Infrastructure
- **OIDC/SSO authentication** — Google, Okta, Azure AD
- **Role-based access** — admin/analyst/viewer/api roles with team namespaces
- **FastAPI server** — REST endpoints + Server-Sent Events for live hunt streaming
- **SIEM integration** — Splunk HEC, Elasticsearch bulk, QRadar LEEF export
- **STIX/Navigator export** — ATT&CK Navigator JSON layers, STIX 2.1 bundles

### Professional TUI
- **30+ commands** — full command palette for all operations
- **Real-time hunt dashboard** — split-pane with findings table + live investigation log
- **Service status bar** — shows PostgreSQL, NATS, fleet, behavioral engine status
- **Interactive findings viewer** — severity-sorted with expandable details
- **Hunt history** — persisted sessions with replay

---

## Installation

### Using Nix (recommended)

```bash
nix-shell
python tui.py
```

The `shell.nix` automatically:
- Creates a Python venv and installs all dependencies
- Starts PostgreSQL on port 5433
- Starts NATS on port 4222
- Initializes the database
- Provides `houndai_stop` helper to cleanly shut down services

### Manual Setup

```bash
# 1. Install system dependencies
# osquery, PostgreSQL, NATS (optional for fleet mode)

# 2. Create venv and install deps
python3.12 -m venv env
source env/bin/activate
pip install -r requirements.txt

# 3. Set required env vars
export COHERE_API_KEY="your-key-here"

# 4. Set optional env vars for production features
export VT_API_KEY="..."              # VirusTotal enrichment
export ABUSEIPDB_API_KEY="..."       # AbuseIPDB enrichment
export DATABASE_URL="postgresql://..."  # PostgreSQL (default: localhost:5433)
export NATS_URL="nats://localhost:4222" # NATS message queue

# 5. Populate RAG database (optional but recommended)
cd rag/ingestion
python ingest_osquery.py
python ingest_commands.py

# 6. Run
python tui.py
```

---

## Usage

### TUI Commands

| Command | Description |
|---------|-------------|
| `/hunt [hypothesis]` | Start autonomous threat hunt |
| `/hunt-fast` | Quick hunt with reduced budget |
| `/findings` | Interactive findings viewer |
| `/report` | Full markdown report |
| `/export json` | Export hunt as JSON |
| `/history` | View past hunt sessions |
| `/playbooks` | List available playbooks |
| `/playbook run <name>` | Execute a playbook |
| `/fleet status` | Fleet enrollment status |
| `/baseline status` | Behavioral engine status |
| `/services` | Production service health |
| `/dashboard` | System security dashboard |
| `/status` | System health check |
| `/help` | Full command palette |

### Natural Language

```
> show me all listening ports
> are there any unauthorized SSH keys on this system
> hunt for persistence mechanisms
> investigate lateral movement attempts
```

### Hunt Examples

```
> /hunt investigate if this system has been compromised
> /hunt check for cryptocurrency miners and C2 channels
> /hunt look for lateral movement and privilege escalation
> /hunt ransomware precursor activity
```

---

## How the Hunt Works

1. **Behavioral Pre-check** — queries the behavioral engine for host anomalies before starting
2. **Parallel Recon** — 5 queries fire simultaneously (processes, network, crontab, SUID, ports)
3. **Adaptive Investigation** — LLM plans each step with enrichment-informed prompts:
   - Live IOC lookup for suspicious IPs/hashes/domains
   - Pivots on discovered PIDs, IPs, usernames, file paths
   - MITRE ATT&CK technique mapping
   - Budget extends dynamically when threats are found
4. **HITL Checkpoints** — pauses for analyst on HIGH/CRITICAL findings
5. **Evidence Signing** — each finding is Ed25519-signed with hash chain
6. **Report Generation** — severity-scored findings, IOC lists, MITRE mapping, confidence scores

---

## Behavioral Engine

The behavioral engine builds per-host baselines of normal activity:

- **Process profiles** — what runs, from where, as which UID
- **Network patterns** — normal destinations per process
- **Port baselines** — expected listening ports
- **Fleet aggregation** — cross-host prevalence scoring

**Anti-false-positive measures:**
- Known-good whitelist (systemd, dbus, NixOS wrappers)
- Cold-start protection (minimum 3 observations before flagging)
- Deduplication of identical findings
- Fleet prevalence scoring (common processes aren't flagged)

---

## Playbooks

Playbooks are YAML-defined hunt templates:

```yaml
# playbooks/ransomware_precursors.yaml
name: Ransomware Precursor Detection
schedule: "0 2 * * *"  # Nightly at 2 AM
hypothesis: "Detect ransomware staging activity"
steps:
  - query: "SELECT * FROM processes WHERE name IN ('vssadmin', 'wbadmin', 'bcdedit')"
    description: "Check for shadow copy deletion tools"
```

---

## Safety

- Blocks destructive OS commands (`rm -rf`, `mkfs`, `shutdown`, fork bombs)
- Prevents SQL injection and destructive osquery operations
- Strips sensitive columns (passwords, tokens, secrets) from results
- 30-second timeout on all executions
- Dynamic budget ceiling (25 steps max)
- Ed25519 evidence signing for forensic chain of custody
- RBAC enforcement on all API endpoints

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.12 |
| LLM | Cohere (`command-a-03-2025`) |
| System Forensics | osquery |
| Database | PostgreSQL + SQLAlchemy |
| Vector Database | ChromaDB |
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`) |
| Message Queue | NATS / Kafka |
| API Framework | FastAPI + SSE |
| Auth | OIDC (authlib) + JWT |
| Evidence Signing | Ed25519 (cryptography) |
| TUI | Rich |
| Dev Environment | Nix |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `COHERE_API_KEY` | Yes | Cohere LLM API key |
| `VT_API_KEY` | No | VirusTotal threat intel |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB enrichment |
| `DATABASE_URL` | No | PostgreSQL connection (default: localhost:5433) |
| `NATS_URL` | No | NATS server (default: nats://localhost:4222) |
| `OIDC_ISSUER` | No | OIDC provider URL |
| `OIDC_CLIENT_ID` | No | OIDC client ID |
| `OIDC_CLIENT_SECRET` | No | OIDC client secret |
| `JWT_SECRET` | No | JWT signing key (auto-generated if unset) |
| `EVIDENCE_KEY_DIR` | No | Ed25519 key directory (default: evidence_keys/) |

---

## License

MIT
