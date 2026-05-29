import cohere
from typing import Dict, Any, Optional, Callable
from core.router import IntentRouter, Intent
from core.memory import MemoryManager
from core.safety import SafetyChecker
from chains.chat_chain import ChatChain
from chains.os_chain import OSCommandChain
from chains.osquery_chain import OsqueryChain
from engines.command_engine import CommandEngine
from engines.osquery_engine import OsqueryEngine
from tools.formatter import ResultFormatter
from hunting.agent import ThreatHuntingAgent
from hunting.findings import FindingsGraph
from hunting.report import ReportGenerator

class LiaMain:
    def __init__(self, api_key: str, memory_file: str = "lia_memory.json"):
        # Initialize core components
        self.co = cohere.Client(api_key)
        self.router = IntentRouter(self.co)
        self.memory = MemoryManager(memory_file)
        self.safety = SafetyChecker()
        
        # Initialize chains
        self.chat_chain = ChatChain(self.co)
        self.os_chain = OSCommandChain(self.co)
        self.osquery_chain = OsqueryChain(self.co)
        
        # Initialize engines
        self.command_engine = CommandEngine()
        self.osquery_engine = OsqueryEngine()
        
        # Initialize formatter
        self.formatter = ResultFormatter()
        
        # Initialize threat hunting components
        self.report_generator = ReportGenerator()
        self.last_hunt: Optional[FindingsGraph] = None

    
    def process_input(self, user_input: str) -> str:
        """Main entry point for processing user input"""

        if "dashboard" in user_input.lower() or "security status" in user_input.lower():
            from tools.security_dashboard import SecurityDashboard
            dashboard = SecurityDashboard(self)
            return dashboard.generate_dashboard()

        # Threat hunt trigger
        if self._is_hunt_request(user_input):
            return self._handle_hunt(user_input)

        # Hunt report request
        if user_input.lower().strip() in ("hunt report", "last hunt", "show hunt"):
            return self._show_last_hunt_report()

        # Get context from memory
        context = self.memory.get_memory_context()
        
        # Classify intent
        intent = self.router.classify_intent(user_input)
        
        # Process based on intent
        if intent == Intent.CHAT:
            return self._handle_chat(user_input, context)
        elif intent == Intent.OS_COMMAND:
            return self._handle_os_command(user_input, context)
        elif intent == Intent.OSQUERY:
            return self._handle_osquery(user_input, context)
        else:
            # Default to chat for unknown intents
            return self._handle_chat(user_input, context)
    
    def _handle_chat(self, user_input: str, context: Dict[str, Any]) -> str:
        """Handle chat intent"""
        result = self.chat_chain.process(user_input, context)
        response = result["response"]
        
        # Save to memory
        self.memory.add_conversation(user_input, response)
        
        return response
    
    def _handle_os_command(self, user_input: str, context: Dict[str, Any]) -> str:
        """Handle OS command intent"""
        # Generate command
        result = self.os_chain.process(user_input, context)
        command = result["response"]
        
        if not command:
            # Fall back to chat if no command generated
            return self._handle_chat(user_input, context)
        
        # Safety check
        if not self.safety.is_os_command_safe(command):
            error_msg = "⚠ This command has been blocked for security reasons."
            self.memory.add_conversation(user_input, error_msg)
            return error_msg
        
        # Execute command
        output, error = self.command_engine.execute_command(command)
        
        if error:
            formatted_response = self.formatter.format_error(f"Failed to execute command: {error}")
        else:
            formatted_response = self.formatter.format_os_result(command, output)
        
        # Save to memory
        self.memory.add_conversation(user_input, formatted_response)
        
        return formatted_response
    
    def _handle_osquery(self, user_input: str, context: Dict[str, Any]) -> str:
        """Handle osquery intent"""
        # Check if osquery is installed
        if not self.osquery_engine.is_osquery_installed():
            error_msg = "⚠ Osquery is not installed or not accessible. Please install osquery to use this feature."
            self.memory.add_conversation(user_input, error_msg)
            return error_msg
        
        # Generate SQL query
        result = self.osquery_chain.process(user_input, context)
        sql_query = result["response"]
        
        if not sql_query:
            # Fall back to chat if no query generated
            return self._handle_chat(user_input, context)
        
        # Safety check
        is_safe, reason = self.safety.is_osquery_sql_safe(sql_query)
        if not is_safe:
            error_msg = f"⚠ This query has been blocked for security reasons: {reason}"
            self.memory.add_conversation(user_input, error_msg)
            return error_msg
        
        # Execute query
        results, error = self.osquery_engine.execute_query(sql_query)
        
        if error:
            formatted_response = self.formatter.format_error(f"Failed to execute query: {error}")
        else:
            # Sanitize results
            sanitized_results = self.safety.sanitize_osquery_result(results)
            formatted_response = self.formatter.format_osquery_result(sql_query, sanitized_results)
        
        # Save to memory
        self.memory.add_conversation(user_input, formatted_response)
        if not error:
            self.memory.add_query(sql_query, str(results))
        
        return formatted_response

    # ─── Threat Hunting ───────────────────────────────────────────────

    def _is_hunt_request(self, user_input: str) -> bool:
        """Detect if the user wants to start an autonomous hunt."""
        triggers = [
            "hunt", "threat hunt", "investigate", "autonomous",
            "is this machine compromised", "full investigation",
            "deep scan", "hunt for threats", "start hunt",
        ]
        lower = user_input.lower().strip()
        return any(t in lower for t in triggers)

    def _handle_hunt(self, user_input: str, 
                     progress_callback: Optional[Callable[[str], None]] = None) -> str:
        """Execute an autonomous threat hunt."""
        if not self.osquery_engine.is_osquery_installed():
            return "Osquery is not installed. The threat hunter requires osquery to investigate this system."

        # Use the user input as the hypothesis, or a default
        hypothesis = user_input.strip()
        if len(hypothesis) < 10:
            hypothesis = "Investigate this system for signs of compromise, persistence mechanisms, and suspicious activity."

        # Set up RAG retriever if available
        retriever = None
        try:
            from rag.retriever import Retriever
            from rag.vectordb import VectorDB
            vectordb = VectorDB()
            retriever = Retriever(vectordb)
        except Exception:
            pass

        agent = ThreatHuntingAgent(
            co_client=self.co,
            osquery_engine=self.osquery_engine,
            safety_checker=self.safety,
            retriever=retriever,
            progress_callback=progress_callback or (lambda msg: None),
        )

        graph = agent.hunt(hypothesis)
        self.last_hunt = graph

        # Generate brief report for inline display
        brief = self.report_generator.generate_brief(graph)

        # Save to memory
        self.memory.add_conversation(user_input, f"[HUNT:{graph.hunt_id}] {graph.conclusion}")

        return brief

    def _show_last_hunt_report(self) -> str:
        """Show the full report from the last hunt."""
        if self.last_hunt is None:
            return "No hunt has been performed yet. Type `hunt` or describe what to investigate."
        return self.report_generator.generate_markdown(self.last_hunt)

    def get_hunt_json(self) -> Optional[str]:
        """Export last hunt as JSON (for saving/sharing)."""
        if self.last_hunt is None:
            return None
        return self.report_generator.generate_json(self.last_hunt)

