# HoundAI — 0.3.0

HoundAI has evolved into a modular, LLM-powered cyber-OS assistant with three core capabilities:

1. **Natural Language Chat** - General conversation and assistance
2. **OS Command Execution** - Safe execution of system commands
3. **Osquery Security Engine** - Security questioning and system forensics

## 🏗️ System Architecture

LiaAI follows a modular, chain-based architecture that separates concerns and enables extensibility. The system consists of several interconnected components that work together to process user input and generate appropriate responses.

```
lia_ai/
├── core/                  # Core modules (router, memory, safety)
├── chains/                # Processing chains (chat, OS, osquery)
├── tools/                 # Formatting and utility tools
├── engines/               # Execution engines (OS, osquery)
├── rag/                   # Retrieval-Augmented Generation components
├── utils/                 # Utilities and templates
├── data/                  # Persistent data storage (ChromaDB)
├── Docs/                  # Documentation and prompts
├── app.py                 # Main application entry point
└── lia_ai.py              # Legacy implementation (deprecated)
```

### Component Design

#### Core Modules (`core/`)
- **IntentRouter**: Classifies user input into appropriate processing chains
- **MemoryManager**: Manages conversation history and context
- **SafetyChecker**: Validates commands and queries for security compliance

#### Processing Chains (`chains/`)
- **ChatChain**: Handles general conversation using LLM
- **OSCommandChain**: Converts natural language to safe OS commands
- **OsqueryChain**: Translates security questions to osquery SQL with RAG support

#### Execution Engines (`engines/`)
- **CommandEngine**: Safely executes OS commands with timeout protection
- **OsqueryEngine**: Executes osquery SQL statements and returns results

#### RAG Components (`rag/`)
- **VectorDB**: ChromaDB wrapper for document storage and retrieval
- **Retriever**: Finds relevant documentation for query context
- **Embedder**: Converts text to vector embeddings (handled by Cohere)
- **Ingestion**: Scripts to populate vector database with osquery documentation

#### Tools (`tools/`)
- **ResultFormatter**: Formats output for clean, readable presentation
- **SecurityDashboard**: Generates comprehensive security status reports

#### Utilities (`utils/`)
- **PromptTemplates**: Standardized prompt formats for consistency
- **Configuration**: Shared constants and configuration values

## 🔄 Workflow Process

1. **Input Reception**: User input is received through the CLI interface in `app.py`

2. **Context Retrieval**: 
   - MemoryManager retrieves conversation history and previous queries
   - Context is passed to subsequent processing steps

3. **Intent Classification**:
   - IntentRouter analyzes input using LLM classification
   - Determines appropriate processing chain (Chat, OS Command, or Osquery)

4. **Chain Processing**:
   - **Chat Chain**: Direct LLM processing for conversational queries
   - **OS Command Chain**: 
     * Converts natural language to system commands
     * Applies safety checks before execution
   - **Osquery Chain**:
     * Uses RAG to retrieve relevant osquery documentation
     * Generates SQL queries with contextual examples
     * Applies comprehensive security validation

5. **Execution**:
   - **Command Engine**: Executes validated OS commands with timeout protection
   - **Osquery Engine**: Runs validated SQL queries against system database

6. **Result Processing**:
   - SafetyChecker sanitizes output to remove sensitive information
   - ResultFormatter structures data for clean presentation
   - MemoryManager stores interaction for future context

7. **Response Delivery**: Formatted response is returned to user through CLI

### Data Flow Diagram

```
User Input → [Intent Router] → [Processing Chain] → [Execution Engine] → [Safety Check] → [Formatting] → User Output
     ↑              ↓                ↓                    ↓                 ↓              ↓              ↑
   Memory ← [Context Retrieval] → [RAG Retrieval] → [Query Generation] → [Validation] → [Presentation] → Memory
```

### RAG Pipeline

1. **Document Ingestion**:
   - Osquery table schemas fetched from GitHub specifications
   - Documentation parsed into structured format
   - Text converted to embeddings using Cohere
   - Stored in ChromaDB vector database

2. **Query-Time Retrieval**:
   - User input embedded using Cohere
   - Similarity search against document vectors
   - Top-k relevant documents retrieved
   - Documents injected into LLM prompt context

3. **Enhanced Generation**:
   - LLM generates SQL with relevant table/column context
   - Examples from documentation guide proper syntax
   - Reduced hallucination through grounded retrieval

## 🛠️ Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Install osquery:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install osquery
   
   # macOS
   brew install osquery
   
   # Windows
   Download from https://osquery.io/downloads
   ```

3. Set up RAG database:
   ```bash
   # Navigate to the ingestion directory
   cd rag/ingestion
   
   # Run the ingestion scripts to populate the vector database
   python ingest_commands.py
   python ingest_osquery.py
   
   # Copy the database to the main application directory
   cp -r data/chroma_db/* ../../data/chroma_db/
   ```

## 🚨 Troubleshooting

### Collection Does Not Exist Error
If you encounter "Collection [osquery_docs] does not exist" errors:
1. Ensure you've run the ingestion scripts in `rag/ingestion/`
2. Verify that the database files were copied from `rag/ingestion/data/chroma_db/` to `data/chroma_db/`
3. Check that the ChromaDB service is running and accessible

### Database Path Issues
The application and ingestion scripts must use the same database path. The default path is `data/chroma_db/` relative to the project root.

### Module Import Errors
If you encounter import errors when running ingestion scripts:
```bash
# Run from the project root with PYTHONPATH set
cd /path/to/LiaAI
PYTHONPATH=. python rag/ingestion/ingest_osquery.py
```

### Checking ChromaDB Embeddings
To verify that embeddings have been properly ingested, you can check the database directly:

```bash
# List collections and document counts
sqlite3 data/chroma_db/chroma.sqlite3 "SELECT c.name, COUNT(s.id) as segments, COUNT(e.id) as embeddings FROM collections c LEFT JOIN segments s ON c.id = s.collection LEFT JOIN embeddings e ON s.id = e.segment_id GROUP BY c.id, c.name;"

# List available collections
sqlite3 data/chroma_db/chroma.sqlite3 "SELECT id, name, dimension FROM collections;"
```

## ▶️ Usage

Run the application:
```bash
python app.py
```

Then interact with LiaAI using natural language:

### Chat Examples
- "Hello, how are you?"
- "What can you help me with?"

### OS Command Examples
- "Create a folder called projects"
- "List all files in the current directory"
- "Show me the disk usage"

### Osquery Examples
- "Show me all running processes"
- "What network ports are listening?"
- "Are there any suspicious login attempts?"
- "List all users on this system"
- "Show me recently modified files"

## 🚀 Key Features

- **Multi-Modal Processing**: Seamlessly handles chat, OS commands, and security queries
- **Intent Classification**: Automatically routes requests to the appropriate processor
- **OS Command Execution**: Converts natural language to safe system commands
- **Osquery Integration**: Translates security questions to osquery SQL and executes them
- **Retrieval-Augmented Generation**: Uses RAG for accurate, context-aware SQL generation
- **Memory Management**: Remembers conversations and previous queries for context
- **Comprehensive Safety Controls**: Multi-layer protection against dangerous operations
- **Intelligent Formatting**: Clean, readable results with tabular output
- **Extensible Architecture**: Modular design for easy feature additions

## 🛡️ Safety Features

- Blocks dangerous OS commands (`rm -rf`, `format`, etc.)
- Prevents destructive osquery operations (`DROP`, `DELETE`, `INSERT`)
- Protects against SQL injection attacks
- Sanitizes sensitive data from results
- Implements timeouts to prevent hanging operations

## 🧩 Modular Design

The new architecture makes it easy to extend LiaAI with additional capabilities:

- Add new processing chains in `chains/`
- Implement new tools in `tools/`
- Extend execution engines in `engines/`
- Customize core functionality in `core/`

## 🔮 Future Expansion Opportunities

- Anomaly detection
- Persistence scanning
- Real-time monitoring
- Fleet-wide querying
- Self-healing automations
- Threat hunting packs

## 📄 License

MIT
