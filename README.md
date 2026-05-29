# HoundAI — Autonomous Threat Hunting Engine

An LLM-powered cybersecurity assistant that performs **autonomous threat investigations** using osquery. HoundAI doesn't just answer questions — it plans, executes, pivots, and reports like a human threat hunter.

```
 ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
 ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
 ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
 ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
 ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
```

## What Makes This Different

Most security tools require you to know what to look for. HoundAI takes a hypothesis — *"is this machine compromised?"* — and autonomously:

1. **Plans** investigation steps using chain-of-thought reasoning
2. **Executes** osquery queries against the live system
3. **Analyzes** results and identifies indicators of compromise
4. **Pivots** dynamically based on what it finds (suspicious PID → trace network connections → check persistence)
5. **Concludes** with a confidence-scored report and IOC list

No pre-written rules. No static playbooks. The agent *reasons* about findings in real-time.

---

## Features

### Autonomous Threat Hunting
- **Dynamic budget system** — starts with 10 steps, extends automatically when HIGH/CRITICAL findings appear (ceiling: 25)
- **Parallel initial recon** — 5 queries run simultaneously at hunt start (processes, network, crontab, SUID, listening ports)
- **Schema-grounded queries** — uses live `PRAGMA table_info` to prevent column hallucination
- **Auto-retry with error correction** — failed queries are fixed using verified schema and retried
- **RAG-enhanced planning** — retrieves relevant osquery documentation for each investigation step
- **Few-shot investigation traces** — guides the LLM with golden examples of real investigations
- **LLM response caching** — avoids redundant API calls when context hasn't changed

### Professional TUI
- **Real-time hunt dashboard** — split-pane layout with findings table + live investigation log
- **Progress tracking** — step counter, severity counters, dynamic budget bar
- **Interactive findings viewer** — severity-sorted table with expandable detail panels
- **Command palette** — structured `/commands` for all operations
- **Hunt history** — persisted sessions, viewable anytime
- **Themed branding** — consistent purple/cyan color palette throughout
- **Rich osquery tables** — styled output with suspicious value highlighting

### Core Capabilities
- **Natural language chat** — general conversation via Cohere LLM
- **OS command execution** — translates natural language to safe system commands
- **Osquery security engine** — translates questions to osquery SQL with RAG
- **Multi-layer safety** — command blocklists, SQL injection prevention, sensitive column stripping, 30s timeouts

---

## Architecture

```
User Input (TUI)
  │
  ├─ /hunt ─→ ThreatHuntingAgent
  │             ├─ Phase 1: Parallel Recon (5 queries, ThreadPoolExecutor)
  │             └─ Phase 2: Adaptive Loop
  │                  ├─ _get_schema_context() → PRAGMA table_info (live)
  │                  ├─ _get_rag_context() → ChromaDB retrieval
  │                  ├─ _plan_next_step() → Cohere LLM (planner)
  │                  ├─ execute_query() → osqueryi --json
  │                  ├─ _fix_query() → retry on error with verified schema
  │                  ├─ _analyze_results() → Cohere LLM (analyzer)
  │                  └─ FindingsGraph ← store finding + adjust budget
  │             └─ ReportGenerator → markdown/JSON report
  │
  ├─ Chat ──→ IntentRouter → ChatChain → Cohere LLM
  ├─ OS ────→ IntentRouter → OSCommandChain → RAG → CommandEngine
  └─ Query ─→ IntentRouter → OsqueryChain → RAG → OsqueryEngine
```

```
HoundAI/
├── tui.py                    # Professional TUI (entry point)
├── core/
│   ├── lia_main.py           # Central orchestrator
│   ├── router.py             # LLM intent classifier
│   ├── memory.py             # Conversation persistence
│   └── safety.py             # Multi-layer safety checker
├── hunting/
│   ├── agent.py              # Autonomous threat hunting agent
│   ├── findings.py           # Findings graph (evidence chains)
│   └── report.py             # Report generator (markdown/JSON)
├── chains/
│   ├── base_chain.py         # Abstract base
│   ├── chat_chain.py         # General chat
│   ├── os_chain.py           # NL → OS commands
│   └── osquery_chain.py      # NL → osquery SQL
├── engines/
│   ├── command_engine.py     # subprocess execution
│   └── osquery_engine.py     # osqueryi execution
├── rag/
│   ├── vectordb.py           # ChromaDB wrapper
│   ├── retriever.py          # Similarity search
│   ├── embedder.py           # sentence-transformers
│   └── ingestion/            # Data ingestion scripts
├── tools/
│   ├── formatter.py          # Output formatting
│   └── security_dashboard.py # Security overview
├── data/chroma_db/           # Persistent vector store
├── hunt_history.json         # Hunt session history
└── Hound_memory.json         # Conversation memory
```

---

## Installation

### Using Nix (recommended)

```bash
nix-shell
python tui.py
```

The `shell.nix` automatically creates a venv, installs all dependencies, and sets up the environment.

### Manual Setup

```bash
# 1. Install osquery
# Ubuntu/Debian
sudo apt-get install osquery
# macOS
brew install osquery
# NixOS
nix-env -iA nixpkgs.osquery

# 2. Create venv and install deps
python3.12 -m venv env
source env/bin/activate
pip install -r requirements.txt

# 3. Set API key
export COHERE_API_KEY="your-key-here"

# 4. Populate RAG database (optional but recommended)
cd rag/ingestion
python ingest_osquery.py
python ingest_commands.py

# 5. Run
python tui.py
```

---

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `/hunt [hypothesis]` | Start autonomous threat hunt |
| `/hunt-fast` | Quick hunt with reduced budget |
| `/findings` | Interactive findings viewer |
| `/report` | Full markdown report |
| `/report brief` | Brief summary |
| `/export json` | Export hunt as JSON |
| `/history` | View past hunt sessions |
| `/history <id>` | View specific hunt details |
| `/dashboard` | System security dashboard |
| `/status` | System health check |
| `/help` | Command palette |
| `/clear` | Clear screen |

### Natural Language

Just type normally for chat, OS commands, or security questions:

```
> show me all listening ports
> what processes are using the most memory
> are there any unauthorized SSH keys on this system
```

### Hunt Examples

```
> /hunt investigate if this system has been compromised
> /hunt check for cryptocurrency miners and C2 channels
> /hunt look for lateral movement and privilege escalation
> hunt for persistence mechanisms
> investigate unauthorized access
```

---

## How the Hunt Works

1. **Parallel Recon** — 5 queries fire simultaneously:
   - Suspicious processes (running from /tmp, known malware names, not on disk)
   - External network connections (ESTABLISHED to non-local IPs)
   - Crontab entries (persistence)
   - SUID binaries in unusual locations (priv esc)
   - Non-standard listening ports (backdoors)

2. **Adaptive Investigation** — LLM plans each step based on findings:
   - Pivots on discovered PIDs, IPs, usernames, file paths
   - Uses MITRE ATT&CK framework for categorization
   - Budget extends dynamically when threats are found
   - Auto-concludes after 4 consecutive low-value steps

3. **Error Recovery** — failed queries are automatically fixed:
   - Extracts table names from failed SQL
   - Fetches live schema via `PRAGMA table_info`
   - LLM rewrites query using only verified columns

4. **Report Generation** — produces:
   - Severity-scored findings with IOC lists
   - Evidence chains showing investigation flow
   - MITRE ATT&CK technique mapping
   - Confidence-scored conclusion
   - Exportable JSON for SIEM integration

---

## Safety

- Blocks destructive OS commands (`rm -rf`, `mkfs`, `shutdown`, fork bombs)
- Prevents SQL injection and destructive osquery operations
- Strips sensitive columns (passwords, tokens, secrets) from results
- 30-second timeout on all executions
- Dynamic budget ceiling (25 steps max) prevents runaway investigations
- All queries validated before execution

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.12 |
| LLM | Cohere (`command-a-03-2025`) |
| System Forensics | osquery |
| Vector Database | ChromaDB |
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`) |
| TUI | Rich |
| Parallelism | ThreadPoolExecutor |
| Dev Environment | Nix |

---

## License

MIT
